"""Install the reviewed independent service from the enrolled Mac. The Mac VPN stays disconnected."""
import configparser
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import runpy
import secrets
import stat
import subprocess
import sys
import tempfile

UNIT = "racknerd-mac-independent.service"
MODULES = ("interface.py", "wg0-mac.py", "inspect-live.py", "check-mac-interface.py")
LIB = Path("/usr/local/lib/racknerd-mac-independent")
CONF = Path("/etc/racknerd-mac-independent")
STAGE = Path("/var/lib/racknerd-mac-independent-staging/prepared")
UNIT_FILE = Path("/etc/systemd/system") / UNIT


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def command(*args):
    return subprocess.check_output(args, text=True, timeout=120).strip()


def install_file(path, data, mode):
    # Link a fully written file into its final name without replacing an existing file.
    if not path.exists() and not path.is_symlink():
        with tempfile.NamedTemporaryFile(dir=path.parent) as handle:
            os.fchmod(handle.fileno(), mode)
            handle.write(data)
            handle.flush()
            os.link(handle.name, path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == mode
            and path.read_bytes() == data, "Existing file differs: " + str(path))


def install(files, cfg, pub):
    os.umask(0o077)
    os.environ.update(PATH="/usr/sbin:/usr/bin:/sbin:/bin", LC_ALL="C")
    require(os.geteuid() == 0, "Requires VPS administration")
    manager = os.environ["SSH_CONNECTION"].split()[0]
    require(json.loads(command("ip", "-j", "route", "get", manager))[0]["dev"] == "eth0",
            "Management SSH does not use the original public interface")
    stagekey = STAGE / "server.key"
    for directory in (STAGE.parent, STAGE):
        info = directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077, "Unsafe staging directory")
    info = stagekey.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077, "Unsafe staged server key")
    with stagekey.open("rb") as key:
        require(subprocess.check_output(["wg", "pubkey"], stdin=key, text=True).strip() == pub, "Profile key mismatch")
    require(json.loads((STAGE / "reference.json").read_text()) == cfg, "Reference differs from successful trial")
    with os.fdopen(os.open(STAGE.parent / "lock", os.O_RDWR | os.O_NOFOLLOW), "r+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        deploy(files, cfg, pub, stagekey)


def deploy(files, cfg, pub, stagekey):
    require(set(files) == set(MODULES) | {UNIT}, "Unexpected installation payload")
    api = {}
    for name in ("inspect-live.py", "wg0-mac.py", "check-mac-interface.py"):
        scope = {"__name__": "review", "__file__": str(LIB / name)}
        exec(files[name], scope)
        api[name] = scope
    inspector, original, candidate = (api[n] for n in ("inspect-live.py", "wg0-mac.py", "check-mac-interface.py"))
    for path, digest in cfg["source_hashes"].items():
        require(hashlib.sha256(Path(path).read_bytes()).hexdigest() == digest, "Upstream source changed")
    for name in ("racknerd-gateway.service", "wg-quick@wg0.service", "racknerd-web-proxy.service"):
        require(command("systemctl", "show", "-p", "NeedDaemonReload", "--value", name) == "no",
                "Pending upstream unit edits: " + name)
    def prop(key):
        r = subprocess.run(["systemctl", "show", "-p", key, "--value", UNIT], text=True, capture_output=True, timeout=15)
        require(r.returncode == 0 or (key == "LoadState" and r.stdout.strip() == "not-found"), "Cannot inspect " + key)
        return r.stdout.strip()
    def verify_unit():
        require(prop("FragmentPath") == str(UNIT_FILE) and not prop("DropInPaths"), "Unexpected Mac unit definition")
        parents = {"racknerd-gateway.service", "wg-quick@wg0.service"}
        require(set(prop("PartOf").split()) == parents and set(prop("Requisite").split()) == parents
                and parents <= set(prop("After").split()), "Mac ordering or dependencies differ")
        for key in ("ConsistsOf", "BoundBy", "PropagatesStopTo", "RequiredBy", "RequisiteOf"):
            require(not prop(key), "Stopping Mac service could propagate through " + key)
    require(not command("systemctl", "list-units", "--state=active,activating", "--no-legend",
                        "--plain", "rn-mac-install-undo-*.timer", "rn-mac-install-undo-*.service",
                        "rn-independent-full-*.service", "rn-independent-probe-*.service"),
            "An earlier Mac trial or installation rollback is still running")
    load = prop("LoadState")
    require(load in ("not-found", "loaded"), "Unexpected unit state")
    if load == "loaded":
        verify_unit()
    # Existing files are accepted only when they match the reviewed installation.
    for folder, names in ((LIB, set(MODULES)), (CONF, {"reference.json", "server.key"})):
        if folder.exists() or folder.is_symlink():
            info = folder.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700 and
                    {p.name for p in folder.iterdir()} <= names, "Unexpected installation directory: " + str(folder))
    if UNIT_FILE.exists() or UNIT_FILE.is_symlink():
        require(not UNIT_FILE.is_symlink() and UNIT_FILE.read_text() == files[UNIT], "Existing Mac unit differs")
    active = load == "loaded" and prop("ActiveState") == "active"
    if not active:
        candidate["inspect_candidate"](inspector, original, cfg, str(ipaddress.IPv4Address(cfg["address"]) + 1), managed_install=True)
        baseline = original["projection"](inspector["inventory"]())
        require(original["without_handles"](baseline) == cfg["base"], "Baseline drift")
    for folder in (LIB, CONF):
        folder.mkdir(mode=0o700, exist_ok=True)
    for name in MODULES:
        install_file(LIB / name, files[name].encode(), 0o600)
    install_file(CONF / "reference.json", (STAGE / "reference.json").read_bytes(), 0o600)
    install_file(CONF / "server.key", stagekey.read_bytes(), 0o600)
    install_file(UNIT_FILE, files[UNIT].encode(), 0o644)
    command("systemd-analyze", "--man=no", "verify", str(UNIT_FILE))
    runtime = runpy.run_path(str(LIB / "interface.py"))
    def verify_live():
        token = json.loads((runtime["STATE"] / "owner").read_text())
        device = Path("/sys/class/net/rn-mac")
        require((device / "ifalias").read_text().strip() == "racknerd-mac-" + token and
                (device / "ifindex").read_text() == (runtime["STATE"] / "ifindex").read_text(), "Device owner differs")
        rules = candidate["independent_rules"](original, cfg, token)
        require(len(runtime["owned_rules"](runtime["firewall_rules"](), rules)) == 4, "Incomplete Mac firewall")
        require(command("wg", "show", "rn-mac", "public-key") == pub and
                command("wg", "show", "rn-mac", "listen-port") == "51821" and
                command("wg", "show", "rn-mac", "allowed-ips").split() == [cfg["key"], cfg["address"] + "/32"] and
                json.loads(command("ip", "-j", "route", "get", cfg["address"]))[0]["dev"] == "rn-mac" and
                Path("/proc/sys/net/ipv4/conf/rn-mac/forwarding").read_text().strip() == "1", "Mac endpoint differs")
        view = runtime["protected"](inspector["inventory"](), rules)
        require(original["without_handles"](view) == cfg["base"] and (active or view == baseline),
                "Protected gateway state differs")
    if active:
        require(prop("UnitFileState") == "enabled", "Mac unit already active without confirmed persistence")
        verify_live()
        print("Existing permanent Mac service verified.")
        return
    command("systemctl", "daemon-reload")
    verify_unit()
    require(prop("UnitFileState") == "disabled", "Unexpected Mac enablement")
    guard = "rn-mac-install-undo-" + secrets.token_hex(6)
    command("systemd-run", "--quiet", "--unit=" + guard, "--on-active=5min", "--timer-property=AccuracySec=1s",
            "/usr/bin/systemctl", "disable", "--now", UNIT)
    command("systemctl", "is-active", guard + ".timer")
    try:
        for rehearsal in (True, False):
            command("systemctl", "--job-mode=fail", "start", UNIT)
            verify_live()
            if rehearsal:
                command("systemctl", "stop", UNIT)
                require(original["projection"](inspector["inventory"]()) == baseline, "Mac-only rollback differs")
        command("systemctl", "enable", UNIT)
        require(prop("UnitFileState") == "enabled" and prop("ActiveState") == "active", "Enablement unverified")
        verify_live()
        command("systemctl", "is-active", guard + ".timer")
        command("systemctl", "stop", guard + ".timer")
        require(prop("UnitFileState") == "enabled" and prop("ActiveState") == "active", "Final unit check failed")
    except BaseException:
        command("systemctl", "disable", "--now", UNIT)
        require(original["projection"](inspector["inventory"]()) == baseline, "Inspect Mac rollback")
        command("systemctl", "stop", guard + ".timer")
        raise
    print("Permanent Mac service active and enabled. Mac-only stop/start and protected gateway verified.")


def main():
    root = Path(__file__).resolve().parents[1]
    local = root / ".local"
    reference = local / "reference"
    enroll = json.loads((local / "macos/enrollment.json").read_text())
    profile = configparser.ConfigParser(interpolation=None)
    profile.read(local / "macos/independent/RackNerd2.conf")
    pub = profile["Peer"]["PublicKey"]
    require(profile["Peer"]["Endpoint"] == enroll["endpoint"] + ":51821", "Unexpected profile endpoint")
    require(any(d.get("mac_recovered") and d.get("final_network_restored") and
                d.get("cleanup") == {"original_state_restored": True, "mac_residue": False} and
                d.get("active_connectivity", {}).get("public_exit_checks_passed") for d in
                (json.loads(p.read_text()) for p in local.glob("rn-independent-full-*/report.json"))), "Full trial required")
    original = runpy.run_path(str(root / "server/wg0-mac.py"))
    cfg = original["prepare"](json.loads((reference / "inventory.json").read_text()),
                              json.loads((reference / "source.json").read_text()), enroll)
    files = {name: (root / "server" / name).read_text() for name in (*MODULES, UNIT)}
    program = Path(__file__).read_text().rsplit('if __name__ == "__main__":', 1)[0]
    program += f"\ninstall({files!r}, {cfg!r}, {pub!r})\n"
    print("Installing only the dedicated Mac service. Enter SSH credentials in Terminal.", flush=True)
    subprocess.run(["ssh", "-T", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10",
                    "root@" + enroll["endpoint"], "python3 -B -"], input=program, text=True, check=True)


if __name__ == "__main__":
    main()
