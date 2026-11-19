"""Lifecycle for the Mac-only device. Run inside racknerd-mac-independent.service."""
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import runpy
import secrets
import subprocess
import sys

LIB = Path(__file__).resolve().parent
CONF = Path("/etc/racknerd-mac-independent")
STATE = Path("/run/racknerd-mac-independent")
MAC = runpy.run_path(str(LIB / "check-mac-interface.py"))
ORIGINAL = runpy.run_path(str(LIB / "wg0-mac.py"))
INSPECT = runpy.run_path(str(LIB / "inspect-live.py"))
IFACE = MAC["IFACE"]


def command(*args, data=None):
    return subprocess.run(args, text=True, input=data, capture_output=True, check=True,
                          timeout=30).stdout.strip()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def firewall_rules():
    objects = json.loads(command("nft", "-j", "-a", "list", "ruleset"))["nftables"]
    return [obj["rule"] for obj in objects if "rule" in obj]


def owned_rules(rules, expected):
    handles = []
    tags = {rule["comment"]: rule for rule in expected}
    seen = set()
    for actual in rules:
        tag = actual.get("comment")
        if tag not in tags:
            continue
        fields = dict(actual)
        handle = fields.pop("handle")
        require(fields == tags[tag] and tag not in seen and isinstance(handle, int) and handle > 0,
                "Ambiguous Mac rule ownership")
        seen.add(tag)
        handles.append({k: actual[k] for k in ("family", "table", "chain", "handle")})
    return handles


def nft_batch(operations):
    if operations:
        data = json.dumps({"nftables": operations})
        command("nft", "-j", "--check", "-f", "-", data=data)
        command("nft", "-j", "-f", "-", data=data)


def protected(inv, expected):
    # Compare source gateway state before/after each mutation. A second WG
    # device and its link-specific kernel objects have no wg0 counterpart.
    interfaces = ORIGINAL["value"](inv["wireguard_interfaces"]).split()
    require("wg0" in interfaces and set(interfaces) <= {"wg0", IFACE}, "Unexpected interface topology")
    inv = dict(inv, wireguard_interfaces={"ok": True, "value": "wg0"})
    view = ORIGINAL["projection"](inv)
    view["addresses"].pop(IFACE, None)
    view["forwarding"].pop("/proc/sys/net/ipv4/conf/" + IFACE + "/forwarding", None)
    view["routes"] = [r for r in view["routes"] if r.get("dev") != IFACE]
    rules = [obj["rule"] for obj in view["rules"] if "rule" in obj]
    owned = owned_rules(rules, expected)
    view["rules"] = [obj for obj in view["rules"] if "rule" not in obj or
                     {k: obj["rule"][k] for k in ("family", "table", "chain", "handle")} not in owned]
    return view


def control(action):
    require(os.geteuid() == 0 and os.environ.get("RUNTIME_DIRECTORY") == str(STATE),
            "Requires the dedicated systemd runtime directory")
    os.environ.update(PATH="/usr/sbin:/usr/bin:/sbin:/bin", LC_ALL="C")
    journal = STATE / "owner"
    if action == "down" and not journal.exists():
        return
    cfg = json.loads((CONF / "reference.json").read_text())
    device = Path("/sys/class/net") / IFACE
    if action == "up":
        require(not journal.exists() and not device.exists(), "Existing Mac state requires inspection")
        for path, digest in cfg["source_hashes"].items():
            require(hashlib.sha256(Path(path).read_bytes()).hexdigest() == digest, "Gateway source changed")
        inv = INSPECT["inventory"]()
        baseline = ORIGINAL["projection"](inv)
        require(ORIGINAL["without_handles"](baseline) == cfg["base"], "Original VPS baseline changed")
        gateway = str(ipaddress.IPv4Address(cfg["address"]) + 1)
        MAC["check_addresses"](inv, cfg, gateway)
        port = str(MAC["PORT"])
        require(not command("ss", "-Huan", "sport", "=", ":" + port), "Mac port in use")
        token = secrets.token_hex(16)
        with journal.open("x") as f:
            json.dump(token, f)
    else:
        token = json.loads(journal.read_text())
    alias = "racknerd-mac-" + token
    temporary = device.parent / ("rnm" + token[:12])
    index = STATE / "ifindex"
    expected = MAC["independent_rules"](ORIGINAL, cfg, token)
    if action == "down":
        # On upstream shutdown its table or our link might already be gone.
        # Neither condition justifies creating a table or touching another link.
        if device.exists():
            require((device / "ifalias").read_text().strip() == alias and
                    (device / "ifindex").read_text() == index.read_text(), "Foreign interface at the Mac name")
            command("ip", "link", "del", "dev", IFACE)
        if temporary.exists():
            require(index.exists() and (temporary / "ifindex").read_text() == index.read_text() and
                    (temporary / "ifalias").read_text().strip() in ("", alias), "Unverified temporary interface")
            command("ip", "link", "del", "dev", temporary.name)
        nft_batch([{"delete": {"rule": r}} for r in owned_rules(firewall_rules(), expected)])
        require(not device.exists() and not owned_rules(firewall_rules(), expected), "Mac cleanup incomplete")
        index.unlink(missing_ok=True)
        journal.unlink()
        return

    def verify():
        require(protected(INSPECT["inventory"](), expected) == baseline, "Protected VPS state changed")
        if device.exists():
            require((device / "ifalias").read_text().strip() == alias and
                    (device / "ifindex").read_text() == index.read_text(), "Mac interface ownership changed")

    nft_batch([{"add": {"rule": rule}} for rule in expected])
    require(len(owned_rules(firewall_rules(), expected)) == len(expected), "Mac rules missing")
    verify()
    require(not index.exists() and not temporary.exists(), "Existing temporary Mac device or index")
    command("ip", "link", "add", "name", temporary.name, "type", "wireguard")
    index.write_text((temporary / "ifindex").read_text())
    command("ip", "link", "set", "dev", temporary.name, "alias", alias)
    require((temporary / "ifalias").read_text().strip() == alias, "Mac ownership tag unavailable")
    command("ip", "link", "set", "dev", temporary.name, "name", IFACE)
    verify()
    command("wg", "set", IFACE, "listen-port", port, "private-key", str(CONF / "server.key"),
            "peer", cfg["key"], "allowed-ips", cfg["address"] + "/32")
    verify()
    command("ip", "-4", "addr", "add", gateway + "/32", "dev", IFACE)
    verify()
    command("ip", "link", "set", "dev", IFACE, "mtu", "1380", "up")
    verify()
    command("ip", "-4", "route", "add", cfg["address"] + "/32", "dev", IFACE, "src", gateway)
    verify()
    link_forwarding = Path("/proc/sys/net/ipv4/conf") / IFACE / "forwarding"
    if link_forwarding.read_text().strip() != "1":
        link_forwarding.write_text("1\n")
    require(link_forwarding.read_text().strip() == "1", "Mac interface forwarding unavailable")
    verify()


if __name__ == "__main__":
    if sys.argv[1:] not in (["up"], ["down"]) or os.environ.get("RUNTIME_DIRECTORY") != str(STATE):
        sys.exit("Use the dedicated Mac systemd unit")
    with (STATE / "lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        control(sys.argv[1])
