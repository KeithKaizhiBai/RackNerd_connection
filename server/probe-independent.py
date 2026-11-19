"""Bounded probe and Internet trials for the staged Mac interface."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys
import time

STAGE = Path("/var/lib/racknerd-mac-independent-staging/prepared")
DEVICE = "rn-mac"
LINK = Path("/sys/class/net") / DEVICE


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def cmd(*args):
    return subprocess.check_output(args, text=True, timeout=60).strip()


def active(unit):
    return subprocess.run(["systemctl", "is-active", "--quiet", unit]).returncode == 0


def snapshot():
    inspector = runpy.run_path(str(STAGE / "inspect-live.py"))
    return inspector["inventory"]()


def base_view(expected=()):
    inspector = runpy.run_path(str(STAGE / "interface.py"))
    return inspector["protected"](snapshot(), expected)


def inspect_trial(name):
    require(re.fullmatch(r"rn-independent-(?:probe|full)-[0-9a-f]{16}", name), "Invalid trial name")
    folder = Path("/run") / name
    baseline = json.loads((folder / "before.json").read_text())
    cfg = json.loads((STAGE / "reference.json").read_text())
    unit = name + ".service"
    status = subprocess.run(["systemctl", "show", unit, "--no-pager",
                             "--property=LoadState,ActiveState,SubState,Result"],
                            capture_output=True, text=True, timeout=20)
    require(status.stdout.strip(), "Could not read unit state")
    result = {"unit": status.stdout.splitlines(), "link_present": LINK.exists()}
    if LINK.exists():
        alias = (LINK / "ifalias").read_text().strip()
        result["alias"] = "matches trial" if alias == name else ("different" if alias else "empty")
        result["ifindex"] = int((LINK / "ifindex").read_text())
        if DEVICE in cmd("wg", "show", "interfaces").split():
            with (STAGE / "server.key").open("rb") as key:
                expected = subprocess.check_output(["wg", "pubkey"], stdin=key, text=True).strip()
            result["server_key_matches"] = cmd("wg", "show", DEVICE, "public-key") == expected
            result["port_matches"] = cmd("wg", "show", DEVICE, "listen-port") == "51821"
            result["sole_peer_matches"] = cmd("wg", "show", DEVICE, "allowed-ips").split() == [
                cfg["key"], cfg["address"] + "/32"]
    log = cmd("journalctl", "-b", "-u", unit, "_COMM=systemd", "--no-pager", "-o", "short-iso", "-n", "15")
    result["systemd_journal"] = log.splitlines()
    current = base_view()
    result["protected_fields_differing"] = sorted(k for k in set(current) | set(baseline)
                                                 if current.get(k) != baseline.get(k))
    return result


def trial_firewall(name):
    api = runpy.run_path(str(STAGE / "interface.py"))
    cfg = json.loads((STAGE / "reference.json").read_text())
    rules = api["MAC"]["independent_rules"](api["ORIGINAL"], cfg, name)
    return api, rules


def enable_trial_forwarding(directory):
    require((LINK / "ifalias").read_text().strip() == directory.name and
            (LINK / "ifindex").read_text().strip() == (directory / "created-index").read_text().strip(),
            "Mac interface ownership changed before enabling forwarding")
    forwarding = Path("/proc/sys/net/ipv4/conf") / DEVICE / "forwarding"
    value = forwarding.read_text().strip()
    require(value in ("0", "1"), "Unexpected Mac device forwarding value")
    if value == "0":
        forwarding.write_text("1\n")
    require(forwarding.read_text().strip() == "1", "Mac device IPv4 forwarding unavailable")


def worker(action, directory):
    name = directory.name
    require(re.fullmatch(r"rn-independent-(?:probe|full)-[0-9a-f]{16}", name), "Invalid worker directory")
    temporary = "rnp" + name[-12:]
    pending = LINK.parent / temporary
    full = name.startswith("rn-independent-full-")
    if action == "down":
        if LINK.exists():
            require((LINK / "ifalias").read_text().strip() == name,
                    "Probe interface ownership tag differs; retained for inspection")
            cmd("ip", "link", "del", "dev", DEVICE)
        if pending.exists():
            require((directory / "created-index").read_text().strip() == (pending / "ifindex").read_text().strip()
                    and (pending / "ifalias").read_text().strip() in ("", name),
                    "Unverified temporary device; retained for inspection")
            cmd("ip", "link", "del", "dev", temporary)
        if full:
            api, rules = trial_firewall(name)
            owned = api["owned_rules"](api["firewall_rules"](), rules)
            api["nft_batch"]([{"delete": {"rule": handle}} for handle in owned])
            require(not api["owned_rules"](api["firewall_rules"](), rules), "Trial firewall cleanup incomplete")
        return
    (directory / "started").touch(exist_ok=False)
    require(not LINK.exists() and not pending.exists(), "Interface already exists")
    baseline = json.loads((directory / "before.json").read_text())
    cfg = json.loads((STAGE / "reference.json").read_text())
    address = cfg["address"] + "/32"
    gateway = str(ipaddress.IPv4Address(cfg["address"]) + 1)
    start = int(time.time())
    require(base_view() == baseline, "Protected state changed before creating probe")
    # Set and read back the alias while the new device is still down and unconfigured.
    cmd("ip", "link", "add", "name", temporary, "type", "wireguard")
    (directory / "created-index").write_text((pending / "ifindex").read_text())
    cmd("ip", "link", "set", "dev", temporary, "alias", name)
    require((pending / "ifalias").read_text().strip() == name, "Could not label temporary probe")
    cmd("ip", "link", "set", "dev", temporary, "name", DEVICE)
    for argv in (
        ["wg", "set", DEVICE, "listen-port", "51821", "private-key", str(STAGE / "server.key"),
         "peer", cfg["key"], "allowed-ips", address],
        ["ip", "-4", "addr", "add", gateway + "/32", "dev", DEVICE],
        ["ip", "link", "set", "dev", DEVICE, "mtu", "1380", "up"],
        ["ip", "-4", "route", "add", address, "dev", DEVICE, "src", gateway],
    ):
        require((LINK / "ifalias").read_text().strip() == name, "Probe ownership changed")
        require(base_view() == baseline, "Protected state changed before " + argv[0])
        cmd(*argv)
        require((LINK / "ifalias").read_text().strip() == name, "Probe interface ownership tag missing or changed")
        require(base_view() == baseline, "Protected state changed after " + argv[0])
    require(cmd("wg", "show", DEVICE, "listen-port") == "51821" and
            cmd("wg", "show", DEVICE, "allowed-ips").split() == [cfg["key"], address],
            "Unexpected probe peer or port")
    if full:
        api, rules = trial_firewall(name)
        require(base_view() == baseline and not api["owned_rules"](api["firewall_rules"](), rules),
                "Gateway changed before trial firewall setup")
        api["nft_batch"]([{"add": {"rule": rule}} for rule in rules])
        require(len(api["owned_rules"](api["firewall_rules"](), rules)) == len(rules) and
                base_view(rules) == baseline, "Trial firewall verification failed")
        enable_trial_forwarding(directory)
        require(base_view(rules) == baseline, "Protected gateway changed after enabling Mac forwarding")
    (directory / "ready").write_text(str(start))
    time.sleep(240)


def remote(action, name, hashes, public_key, program):
    os.umask(0o077)
    os.environ.update(LC_ALL="C", PATH="/usr/sbin:/usr/bin:/sbin:/bin")
    require(re.fullmatch(r"rn-independent-(?:probe|full)-[0-9a-f]{16}", name), "Invalid trial name")
    folder = Path("/run") / name
    unit = name + ".service"
    script = folder / "worker.py"
    for filename, digest in hashes.items():
        require(hashlib.sha256((STAGE / filename).read_bytes()).hexdigest() == digest, "Staged source differs: " + filename)
    inspector = runpy.run_path(str(STAGE / "inspect-live.py"))
    addon = runpy.run_path(str(STAGE / "wg0-mac.py"))
    cfg = json.loads((STAGE / "reference.json").read_text())
    if action == "start":
        with (STAGE / "server.key").open("rb") as key:
            require(subprocess.check_output(["wg", "pubkey"], stdin=key, text=True).strip() == public_key,
                    "Server public key does not match imported profile")
        check = runpy.run_path(str(STAGE / "check-mac-interface.py"))
        check["inspect_candidate"](inspector, addon, cfg, str(ipaddress.IPv4Address(cfg["address"]) + 1))
        baseline = addon["projection"](inspector["inventory"]())
        require(addon["without_handles"](baseline) == cfg["base"], "Gateway drift before trial")
        folder.mkdir(mode=0o700)
        script.write_text(program)
        (folder / "before.json").write_text(json.dumps(baseline))
        # Exercise systemd's lifetime limit and post-stop callback before touching the link.
        marker = folder / "timer-tested"
        cmd("systemd-run", "--quiet", "--collect", "--unit=" + name + "-check",
            "-p", "Type=exec", "-p", "RuntimeMaxSec=1s", "-p", "ExecStopPost=/usr/bin/touch " + str(marker),
            "/usr/bin/sleep", "15")
        for _ in range(40):
            if marker.exists():
                break
            time.sleep(.25)
        require(marker.exists(), "VPS rollback timer rehearsal failed")
        cmd("systemd-run", "--quiet", "--collect", "--unit=" + name,
            "-p", "Type=exec", "-p", "RuntimeMaxSec=240s", "-p", "TimeoutStopSec=20s",
            "-p", "Requisite=racknerd-gateway.service wg-quick@wg0.service",
            "-p", "After=racknerd-gateway.service wg-quick@wg0.service",
            "-p", "ExecStopPost=/usr/bin/python3 -B " + str(script) + " down",
            "/usr/bin/python3", "-B", str(script), "up")
        for _ in range(180):
            if (folder / "ready").exists():
                return {"started": int((folder / "ready").read_text()), "protected_verified": True}
            require(active(unit), "Transient service exited; check journalctl -u " + unit)
            time.sleep(.5)
        raise RuntimeError("Timed out waiting for interface readiness")
    if action == "sample":
        require(active(unit), "Probe service is no longer active; inspect its journal")
        require(LINK.exists() and (LINK / "ifalias").read_text().strip() == name,
                "Probe interface missing or ownership tag differs")
        timestamp = dict(line.split() for line in cmd("wg", "show", DEVICE, "latest-handshakes").splitlines())[cfg["key"]]
        transfer = cmd("wg", "show", DEVICE, "transfer").split()
        require(len(transfer) == 3 and transfer[0] == cfg["key"], "Unexpected transfer record")
        rules = trial_firewall(name)[1] if name.startswith("rn-independent-full-") else []
        require(base_view(rules) == json.loads((folder / "before.json").read_text()), "Protected state changed")
        reverse = subprocess.run(["ping", "-n", "-I", DEVICE, "-c", "2", "-W", "1", cfg["address"]],
                                 stdout=subprocess.DEVNULL).returncode
        return {"handshake": int(timestamp), "server_now": int(time.time()),
                "traffic": [int(n) for n in transfer[1:]], "reverse_ping": reverse == 0}
    require(action == "finish", "Unknown operation")
    if not (folder / "before.json").exists():
        require(not LINK.exists(), "Unverified interface exists")
        return {"trial_started": False}
    state = cmd("systemctl", "show", "--property=ActiveState", "--value", unit) if active(unit) else ""
    if state == "active":
        cmd("systemctl", "stop", unit)
    baseline = json.loads((folder / "before.json").read_text())
    for _ in range(20):
        if not LINK.exists():
            break
        time.sleep(.25)
    require(not LINK.exists() and not (LINK.parent / ("rnp" + name[-12:])).exists()
            and not active(unit) and addon["projection"](snapshot()) == baseline,
            "Mac cleanup or protected gateway baseline unverified. Retain " + str(folder))
    for filename in ("worker.py", "before.json", "ready", "started", "timer-tested", "created-index"):
        (folder / filename).unlink(missing_ok=True)
    folder.rmdir()
    return {"mac_residue": False, "original_state_restored": True}


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--inspect-trial":
        print(json.dumps(inspect_trial(sys.argv[2]), indent=2))
        sys.exit(0)
    require(len(sys.argv) == 2 and sys.argv[1] in ("up", "down"), "Invalid worker action")
    worker(sys.argv[1], Path(__file__).resolve().parent)
