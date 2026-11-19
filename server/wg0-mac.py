#!/usr/bin/env python3
"""Mac-only addition for the reviewed wg0 gateway. 'prepare' runs entirely offline."""
import argparse
import base64
import copy
import fcntl
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys

IFACE = "wg0"
WAN = "eth0"
TABLE = "rn_gateway"
BASE = "racknerd-gateway.service"
QUICK = "wg-quick@wg0.service"
PROXY = "racknerd-web-proxy.service"
SOURCE_FILES = ("/etc/racknerd-gateway/gateway.sh", "/etc/systemd/system/" + BASE,
                "/etc/systemd/system/" + PROXY, "/etc/nftables.conf")
CONFIG = Path("/etc/racknerd-mac/reference.json")
STATE = Path("/run/racknerd-mac/journal.json")
FWD = "authorized_forward"
NAT = "egress_nat"
METRIC = 45404


def require(condition, message):
    if not condition:
        raise ValueError(message)


def value(record):
    require(record.get("ok") is True, "Incomplete inventory field")
    return record["value"]


def nft_objects(data):
    result = []
    for entry in value(data["firewall"]["nftables"])["nftables"]:
        if "metainfo" in entry:
            continue
        entry = copy.deepcopy(entry)
        if "counter" in entry:
            for field in ("packets", "bytes"):
                entry["counter"].pop(field, None)
        result.append(entry)
    return result


def projection(data):
    require(data["schema"] == "racknerd-live-inventory/1" and
            value(data["wireguard_interfaces"]) == IFACE, "Unexpected WireGuard topology")
    wg = data["wireguard"][IFACE]
    peers = dict(line.split(None, 1) for line in value(wg["allowed-ips"]).splitlines())
    require(set(peers) == set(value(wg["peers"]).split()), "Peer inventory mismatch")
    keepalive = dict(line.split(None, 1) for line in value(wg["persistent-keepalive"]).splitlines())
    require(set(keepalive) == set(peers), "Incomplete keepalive inventory")
    services = {}
    for name in (BASE, QUICK, PROXY, "nftables.service"):
        props = dict(line.split("=", 1) for line in
                     value(data["persistence"]["services"][name]).splitlines())
        services[name] = {k: props[k] for k in ("LoadState", "ActiveState", "SubState",
                                                "FragmentPath", "DropInPaths", "UnitFileState")}
    return {
        "interface": {k: value(wg[k]) for k in ("listen-port", "public-key", "fwmark")},
        "peers": peers, "keepalive": keepalive, "rules": nft_objects(data),
        "addresses": {link["ifname"]: sorted((a["local"] + "/" + str(a["prefixlen"]))
                                             for a in link["addr_info"])
                      for link in value(data["ipv4_addresses"])},
        "routes": sorted(value(data["ipv4_routes"]), key=lambda row: json.dumps(row, sort_keys=True)),
        "policy": value(data["ipv4_policy_rules"]), "forwarding": data["forwarding"],
        "sysctls": data["global_sysctls"], "services": services,
        "profiles": data["persistence"]["wireguard_profiles"],
        "firewalls": {k: value(data["firewall"][k]) for k in
                      ("iptables", "iptables_legacy", "ip6tables", "ufw")},
    }


def without_handles(snapshot):
    snapshot = copy.deepcopy(snapshot)
    for obj in snapshot["rules"]:
        next(iter(obj.values())).pop("handle", None)
    return snapshot


def prepare(data, source, enrollment):
    base = without_handles(projection(data))
    key = enrollment["mac_public_key"]
    raw_key = base64.b64decode(key, validate=True)
    require(len(raw_key) == 32 and any(raw_key) and base64.b64encode(raw_key).decode() == key, "Invalid Mac public key")
    addr = ipaddress.IPv4Address(enrollment["address"])
    gateway = ipaddress.IPv4Address(enrollment["gateway"])
    require(enrollment["interface"] == IFACE and base["addresses"][IFACE] == [str(gateway) + "/32"]
            and addr == gateway + 3 and addr.is_private, "Unexpected Mac address or tunnel")
    require(all(base["services"][n]["DropInPaths"] == ""
            for n in (BASE, QUICK, PROXY)), "Unexpected base service drop-in")
    require(enrollment["server_public_key"] == base["interface"]["public-key"]
            and base["interface"]["listen-port"] == "51820" and key not in base["peers"]
            and key != enrollment["server_public_key"], "Unexpected WireGuard identity")
    require(sorted(base["peers"].values()) == [str(gateway + i) + "/32" for i in (1, 2)],
            "Expected original two peers")
    require(all(addr not in ipaddress.ip_network(r["dst"], strict=False) for r in base["routes"]
                if r["dst"] != "default"), "Mac route conflict")
    require(all(addr != ipaddress.ip_interface(c).ip for group in base["addresses"].values()
                for c in group), "Mac IPv4 already assigned")
    require(any(ipaddress.ip_interface(c).ip == ipaddress.IPv4Address(enrollment["endpoint"])
                for c in base["addresses"][WAN]), "Unexpected public interface")
    require(base["sysctls"]["/proc/sys/net/ipv4/ip_forward"] == "1" and
            all(base["services"][n]["ActiveState"] == "active" for n in (BASE, QUICK, PROXY)),
            "Base gateway inactive")
    chains = [(o["chain"]["name"], o["chain"]["hook"], o["chain"]["policy"])
              for o in base["rules"] if "chain" in o]
    require(chains == [(FWD, "forward", "drop"), (NAT, "postrouting", "accept")]
            and all(o.get("table", {}).get("name", TABLE) == TABLE for o in base["rules"]),
            "Unexpected firewall ownership")
    profile = base["profiles"]["/etc/wireguard/wg0.conf"]["public_fields"]
    disk_interfaces = [s["fields"] for s in profile["sections"] if s["section"] == "Interface"]
    require(len(disk_interfaces) == 1 and disk_interfaces[0].get("address") == [str(gateway) + "/32"]
            and disk_interfaces[0].get("listenport") == ["51820"]
            and [v.lower() for v in disk_interfaces[0].get("saveconfig", ["false"])] == ["false"],
            "Unexpected persistent interface settings")
    disk_peers = [s["fields"] for s in profile["sections"] if s["section"] == "Peer"]
    stored_key = next(k for k, v in base["peers"].items() if v == str(gateway + 1) + "/32")
    require(disk_peers == [{"publickey": [stored_key], "allowedips": [str(gateway + 1) + "/32"]}]
            and not profile["hook_directives_present"], "Unexpected wg-quick boot peer or hooks")
    require(source["schema"] == "racknerd-gateway-source/1", "Missing source review")
    hashes = {p: source["files"][p]["sha256"] for p in SOURCE_FILES}
    cfg = {"base": base, "key": key, "address": str(addr), "windows": str(gateway + 2),
           "source_hashes": hashes}
    mac_rules(cfg, "review")
    return cfg


def mac_rules(cfg, token):
    """Construct four fixed expressions, deriving the blocked set from the audited rule."""
    originals = [o["rule"] for o in cfg["base"]["rules"] if "rule" in o]
    require(len(originals) == 4, "Unexpected number of original rules")
    deny_expr = originals[0]["expr"]
    blocked = deny_expr[3]["match"]["right"]
    require(isinstance(blocked.get("set"), list) and blocked["set"], "Missing blocked networks")

    def match(left, right):
        return {"match": {"op": "==", "left": left, "right": right}}

    result = []
    for i, (incoming, outgoing, field, verdict) in enumerate((
            (IFACE, WAN, "saddr", "drop"), (IFACE, WAN, "saddr", "accept"),
            (WAN, IFACE, "daddr", "accept"), (IFACE, WAN, "saddr", "masquerade"))):
        chain = NAT if i == 3 else FWD
        expr = [match({"meta": {"key": "iifname"}}, incoming),
                match({"meta": {"key": "oifname"}}, outgoing),
                match({"payload": {"protocol": "ip", "field": field}}, cfg["windows"])]
        if i == 0:
            expr.append(match({"payload": {"protocol": "ip", "field": "daddr"}}, blocked))
        if i in (1, 2):
            states = ["established", "related"] + (["new"] if i == 1 else [])
            expr.append(match({"ct": {"key": "state"}}, {"set": states}))
        if i:
            expr.append({"counter": ("", "outbound", "inbound", "translated")[i]})
        expr.append({verdict: None})
        rule = {"family": "ip", "table": TABLE, "chain": chain, "expr": expr}
        require(originals[i] == rule, "Windows firewall expression differs from reviewed layout")
        expr[2]["match"]["right"] = cfg["address"]
        if i:
            del expr[-2]  # Windows named counters belong exclusively to Windows.
        rule["comment"] = f"rn-mac:{token}:{i}"
        result.append(rule)
    return result


def components(cfg, journal, snapshot, removing=False):
    """Return owned components only if every other peer, route and firewall object matches."""
    rest = copy.deepcopy(snapshot)
    key, addr = cfg["key"], cfg["address"]
    peer = rest["peers"].pop(key, None)
    require(peer in (None, addr + "/32"), "Mac key has different AllowedIPs")
    require(rest["keepalive"].pop(key, None) == ("off" if peer else None),
            "Unexpected Mac peer keepalive")
    routes = [r for r in rest["routes"] if r["dst"] in (addr, addr + "/32")]
    require(len(routes) <= 1, "Ambiguous Mac route")
    if routes:
        r = routes[0]
        require(dict(r, dst=addr) == {"dst": addr, "dev": IFACE, "protocol": "static",
                "scope": "link", "metric": METRIC, "flags": []}, "Mac route ownership mismatch")
        rest["routes"].remove(r)
    expected = mac_rules(cfg, journal["token"])
    owned, tails = [], set()
    for obj in list(rest["rules"]):
        if "rule" not in obj:
            continue
        rule = obj["rule"].copy()
        handle = rule.pop("handle")
        if rule in expected:
            require(isinstance(handle, int) and handle > 0, "Missing Mac firewall handle")
            owned.append((rule, handle))
            tails.add(rule["chain"])
            rest["rules"].remove(obj)
        else:
            require(rule["chain"] not in tails, "Mac rule precedes an existing rule")
    found = [r for r, _ in owned]
    # During removal some of our tagged rules may already be gone. Match each
    # surviving expression in original order, rejecting duplicates and edits.
    if removing:
        expected = [r for r in expected if r in found]
    require(not found or found == expected, "Incomplete or reordered Mac rules")
    require(rest == journal["base"], "Protected server state changed; inspect before proceeding")
    for name, exists in (("peer", peer), ("route", routes), ("rules", owned)):
        require(not exists or name in journal["claimed"], "Unexpected Mac object without journal entry")
    return bool(peer), bool(routes), owned


def update(cfg, journal, read, execute, adding, persist=None):
    # Add firewall and exclusive route first. Install the peer last. Remove in reverse.
    steps = ("route", "peer") if cfg.get("probe_only", False) else ("rules", "route", "peer")
    for step in steps if adding else reversed(steps):
        peer, route, rules = components(cfg, journal, read(), removing=not adding)
        present = {"peer": peer, "route": route, "rules": bool(rules)}
        if present[step] == adding:
            continue
        if adding and step not in journal["claimed"]:
            journal["claimed"].append(step)
            if persist:
                persist(journal)
        addr = cfg["address"] + "/32"
        if step == "rules":
            if adding:
                batch = [{"add": {"rule": r}} for r in mac_rules(cfg, journal["token"])]
            else:
                batch = [{"delete": {"rule": {k: r[k] for k in ("family", "table", "chain")}
                                       | {"handle": h}}} for r, h in rules]
            payload = json.dumps({"nftables": batch})
            execute(["nft", "-j", "-c", "-f", "-"], payload)
            execute(["nft", "-j", "-f", "-"], payload)
        elif step == "route":
            execute(["ip", "-4", "route", "add" if adding else "del", addr, "dev", IFACE,
                     "proto", "static", "metric", str(METRIC)], None)
        else:
            execute(["wg", "set", IFACE, "peer", cfg["key"]] +
                    (["allowed-ips", addr] if adding else ["remove"]), None)
        actual = components(cfg, journal, read(), removing=not adding)
        present[step] = adding
        require([bool(v) for v in actual] == [present[k] for k in ("peer", "route", "rules")],
                "Unexpected change after Mac operation")


def control(action):
    require(sys.platform == "linux" and os.geteuid() == 0, "Requires Linux service context")
    require(os.environ.get("RUNTIME_DIRECTORY") == str(STATE.parent), "Requires Mac service runtime")
    os.environ.update(PATH="/usr/sbin:/usr/bin:/sbin:/bin", LC_ALL="C")
    cfg = json.loads(CONFIG.read_text())
    spec = importlib.util.spec_from_file_location("inventory", Path(__file__).with_name("inspect-live.py"))
    inspector = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(inspector)

    def read():
        for path in SOURCE_FILES:
            require(hashlib.sha256(Path(path).read_bytes()).hexdigest() == cfg["source_hashes"][path],
                    "Base service or firewall source changed")
        return projection(inspector.inventory())

    def execute(argv, data):
        subprocess.run(argv, input=data, text=True, check=True, timeout=20)

    with (STATE.parent / "lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        def persist(journal):
            temp = STATE.with_suffix(".tmp")
            temp.write_text(json.dumps(journal))
            os.replace(temp, STATE)

        if not STATE.exists():
            if action == "down":
                return
            baseline = read()
            require(without_handles(baseline) == cfg["base"], "Fresh state differs from reviewed reference")
            journal = {"token": secrets.token_hex(12), "base": baseline, "claimed": [],
                       "reference": hashlib.sha256(CONFIG.read_bytes()).hexdigest()}
            persist(journal)
        journal = json.loads(STATE.read_text())
        require(journal["reference"] == hashlib.sha256(CONFIG.read_bytes()).hexdigest() and
                without_handles(journal["base"]) == cfg["base"], "Reference changed since enrollment")
        update(cfg, journal, read, execute, action == "up", persist)
        if action == "down":
            STATE.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    p = commands.add_parser("prepare", help="read three local JSON files and print public reference")
    p.add_argument("--probe-only", action="store_true", help="Peer and host route only")
    for name in ("inventory", "source", "enrollment"):
        p.add_argument(name, type=Path)
    for name in ("up", "down"):
        commands.add_parser(name, help="Mac service lifecycle")
    args = parser.parse_args()
    if args.action == "prepare":
        cfg = prepare(*(json.loads(p.read_text()) for p in (args.inventory, args.source, args.enrollment)))
        if args.probe_only:
            cfg["probe_only"] = True
        print(json.dumps(cfg, indent=2))
    else:
        control(args.action)


if __name__ == "__main__":
    main()
