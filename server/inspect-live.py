#!/usr/bin/env python3
"""Read-only WireGuard, routing, firewall and persistence inventory (no keys)."""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def command(*argv, as_json=False):
    """Return an explicit success/error record; never execute a shell."""
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"ok": False, "error": str(error)}
    if result.returncode:
        return {"ok": False, "exit_code": result.returncode,
                "error": result.stderr.strip()[:1000]}
    text = result.stdout.strip()
    if as_json:
        try:
            return {"ok": True, "value": json.loads(text)}
        except ValueError:
            return {"ok": False, "error": "Invalid JSON from inventory command"}
    return {"ok": True, "value": text}


def public_profile(text):
    """Expose only known public fields; omit secrets and arbitrary hook bodies."""
    allowed = {"address", "listenport", "mtu", "table", "saveconfig", "publickey",
               "allowedips", "endpoint", "persistentkeepalive", "dns"}
    sections, current = [], None
    hooks = []
    for line in text.splitlines():
        line = line.strip()
        if line in ("[Interface]", "[Peer]"):
            current = {"section": line[1:-1], "fields": {}}
            sections.append(current)
        elif "=" in line and not line.startswith(("#", ";")):
            name, value = (s.strip() for s in line.split("=", 1))
            if name.lower() in allowed and current is not None:
                current["fields"].setdefault(name.lower(), []).append(value)
            elif name.lower() in ("preup", "postup", "predown", "postdown"):
                hooks.append(name)
    return {"sections": sections, "hook_directives_present": hooks}


def file_record(path, parse=None):
    path = Path(path)
    try:
        data = path.read_bytes()
        record = {"present": True, "sha256": hashlib.sha256(data).hexdigest(),
                  "mode": oct(path.stat().st_mode & 0o777)}
        if parse:
            record["public_fields"] = parse(data.decode())
        return record
    except FileNotFoundError:
        return {"present": False}
    except (OSError, ValueError) as error:
        return {"present": path.exists(), "error": str(error)}


def gateway_metadata(text):
    value = json.loads(text)
    # Ownership tokens and any future unknown fields stay on the VPS.
    return {key: value[key] for key in ("peer", "port", "wan", "index") if key in value}


def service_record(name):
    fields = ("Id", "LoadState", "ActiveState", "SubState", "UnitFileState",
              "FragmentPath", "DropInPaths", "After", "Before")
    return command("systemctl", "show", name, "--no-pager",
                   "--property=" + ",".join(fields))


def inventory():
    interfaces = command("wg", "show", "interfaces")
    wireguard = {}
    if interfaces["ok"]:
        for iface in interfaces["value"].split():
            # Explicit public selectors: dump/showconf can disclose private keys.
            wireguard[iface] = {
                selector: command("wg", "show", iface, selector)
                for selector in ("public-key", "listen-port", "fwmark", "peers",
                                 "allowed-ips", "endpoints", "latest-handshakes",
                                 "transfer", "persistent-keepalive")
            }
    profiles = {str(p): file_record(p, public_profile)
                for p in sorted(Path("/etc/wireguard").glob("*.conf"))}
    data = Path("/var/lib/rn-public-gateway")
    gateway = {name: file_record(data / name, gateway_metadata)
               for name in ("active.json", "settings.json")}
    gateway["program"] = file_record("/usr/local/sbin/rn-gateway")
    gateway["server_key_present"] = (data / "server.key").is_file()
    gateway["trial_pending"] = Path("/run/rn-public-gateway/trial.json").exists()
    units = {"rn-public-gateway.service", "nftables.service", "ufw.service",
             "netfilter-persistent.service", "firewalld.service",
             "systemd-networkd.service", "docker.service", "tailscaled.service"}
    units.update("wg-quick@" + p.stem + ".service"
                 for p in Path("/etc/wireguard").glob("*.conf"))
    units.update("wg-quick@" + name + ".service" for name in wireguard)
    discovered_units = command("systemctl", "list-units", "--all", "--type=service",
                               "--no-legend", "--no-pager", "--plain")
    if discovered_units["ok"]:
        for line in discovered_units["value"].splitlines():
            if any(word in line.lower() for word in
                   ("wireguard", "wg-quick", "rn-", "racknerd", "gateway", "nftables",
                    "firewall", "iptables", "netfilter", "ufw", "vpn")):
                fields = line.split()
                if fields and fields[0].endswith(".service"):
                    units.add(fields[0])
    return {
        "schema": "racknerd-live-inventory/1",
        "captured_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "wireguard_interfaces": interfaces,
        "wireguard": wireguard,
        "links": command("ip", "-j", "-d", "link", "show", as_json=True),
        "ipv4_addresses": command("ip", "-j", "-4", "address", "show", as_json=True),
        "ipv6_addresses": command("ip", "-j", "-6", "address", "show", as_json=True),
        "ipv4_routes": command("ip", "-j", "-4", "route", "show", "table", "all", as_json=True),
        "ipv6_routes": command("ip", "-j", "-6", "route", "show", "table", "all", as_json=True),
        "ipv4_policy_rules": command("ip", "-j", "-4", "rule", "show", as_json=True),
        "forwarding": {str(p): p.read_text().strip()
                       for p in Path("/proc/sys/net/ipv4/conf").glob("*/forwarding")},
        "global_sysctls": {str(p): p.read_text().strip() for p in map(Path, (
            "/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding",
            "/proc/sys/net/ipv4/conf/all/rp_filter")) if p.is_file()},
        "firewall": {
            "nftables": command("nft", "-j", "-a", "list", "ruleset", as_json=True),
            "iptables": command("iptables-save", "-c"),
            "iptables_legacy": command("iptables-legacy-save", "-c"),
            "ip6tables": command("ip6tables-save", "-c"),
            "ufw": command("ufw", "status", "verbose"),
        },
        "persistence": {
            "unit_discovery": discovered_units,
            "services": {name: service_record(name) for name in sorted(units)},
            "wireguard_profiles": profiles,
            "rn_public_gateway": gateway,
            "networkd_files": [str(p) for p in Path("/etc/systemd/network").glob("*")
                               if p.is_file()],
            "nftables_config": file_record("/etc/nftables.conf"),
            "iptables_persistent_v4": file_record("/etc/iptables/rules.v4"),
            "iptables_persistent_v6": file_record("/etc/iptables/rules.v6"),
        },
        "scope": "Read-only. No network, service, firewall or key mutations.",
        "windows_exit_verified": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("Run with root read access on the Ubuntu VPS.")
    os.environ.update(PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                      LC_ALL="C")
    json.dump(inventory(), sys.stdout, indent=2)
    print()


if __name__ == "__main__":
    main()
