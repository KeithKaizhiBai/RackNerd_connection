"""Read-only admission checks for a second WireGuard interface on the reviewed VPS."""
import hashlib
import ipaddress
import json
from pathlib import Path
import subprocess

IFACE = "rn-mac"
PORT = 51821
UNIT = "racknerd-mac-independent.service"


def independent_rules(addon, reference, token):
    rules = addon["mac_rules"](reference, token)
    for rule in rules:
        for expr in rule["expr"]:
            match = expr.get("match", {})
            if match.get("left") in ({"meta": {"key": "iifname"}}, {"meta": {"key": "oifname"}}):
                if match["right"] == "wg0":
                    match["right"] = IFACE
    return rules


def check_addresses(inv, reference, gateway):
    candidates = {ipaddress.IPv4Address(ip) for ip in (reference["address"], gateway)}
    used = []
    for row in inv["ipv4_routes"]["value"]:
        if row["dst"] != "default":
            used.append(ipaddress.IPv4Network(row["dst"], strict=False))
    for link in inv["ipv4_addresses"]["value"]:
        for entry in link["addr_info"]:
            used.append(ipaddress.IPv4Network((entry["local"], entry["prefixlen"]), strict=False))
    for peer in inv["wireguard"].values():
        for line in peer["allowed-ips"]["value"].splitlines():
            for cidr in line.split()[1:]:
                used.append(ipaddress.ip_network(cidr.strip(","), strict=False))
    if any(ip in net for ip in candidates for net in used if net.version == 4):
        raise ValueError("Candidate tunnel address overlaps a VPS route, address or peer")


def inspect_candidate(inspector, addon, reference, gateway, *, managed_install=False):
    def command(*args, data=None):
        return subprocess.run(args, text=True, input=data, capture_output=True,
                              check=True, timeout=60).stdout.strip()

    def require(condition, message):
        if not condition:
            raise ValueError(message)

    inv = inspector["inventory"]()
    before = addon["projection"](inv)
    require(addon["without_handles"](before) == reference["base"], "Original VPS state differs from the trial baseline")
    for name, digest in reference["source_hashes"].items():
        require(hashlib.sha256(Path(name).read_bytes()).hexdigest() == digest, "Original source changed: " + name)
    require(not command("systemctl", "list-jobs", "--no-legend", "--no-pager"), "Pending systemd job")
    require(not Path("/sys/class/net", IFACE).exists(), "Candidate interface already exists")
    require(not command("ss", "-H", "-u", "-a", "-n", "sport", "=", ":" + str(PORT)), "Candidate UDP port in use")
    require(not any(str(PORT) == wg["listen-port"]["value"] for wg in inv["wireguard"].values()),
            "Candidate port in use by WireGuard")
    for profile in inv["persistence"]["wireguard_profiles"].values():
        for section in profile["public_fields"]["sections"]:
            require(str(PORT) not in section["fields"].get("listenport", []), "Port reserved by saved profile")
    for name in (("racknerd-mac.service",) if managed_install else (UNIT, "racknerd-mac.service")):
        # systemctl show may return a nonzero status for a missing unit.
        result = subprocess.run(["systemctl", "show", "-p", "LoadState", "--value", name],
                                capture_output=True, text=True, timeout=20)
        require(result.stdout.strip() == "not-found", "Existing or unverified unit: " + name)
    paths = ["/etc/wireguard/rn-mac.conf"]
    if not managed_install:
        paths.extend(("/etc/racknerd-mac-independent", "/usr/local/lib/racknerd-mac-independent"))
    for name in paths:
        require(not Path(name).exists() and not Path(name).is_symlink(), "Existing Mac resource: " + name)
    timer = command("systemctl", "list-timers", "--all", "--no-legend", "--no-pager")
    require(not any(x in timer for x in ("rn-gateway-undo", "rn-mac-full-", "rn-mac-probe-")), "Outstanding rollback timer")
    check_addresses(inv, reference, gateway)
    rules = independent_rules(addon, reference, "isolated-check")
    batch = {"nftables": [{"add": {"rule": r}} for r in rules]}
    command("nft", "-j", "--check", "-f", "-", data=json.dumps(batch))
    require(addon["projection"](inspector["inventory"]()) == before, "Protected state changed during inspection")
    return {"interface": IFACE, "port": PORT, "server_address": gateway, "client_address": reference["address"],
            "nft_check": True, "protected_state_unchanged": True, "activated": False}
