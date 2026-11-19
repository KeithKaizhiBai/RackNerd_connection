"""Check candidate resources over the existing trusted SSH connection. Never activate a tunnel."""
import datetime
import argparse
import configparser
import ipaddress
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / ".local"


def mac_routes(targets):
    routes = {}
    for target in targets:
        value = subprocess.check_output(["/sbin/route", "-n", "get", target], text=True)
        routes[target] = dict(field.strip().split(": ", 1) for field in value.splitlines()
                              if field.strip().startswith(("destination: ", "interface: ", "gateway: ", "flags: ")))
    return routes


def check_mac(routes, endpoint):
    original = routes["default"]
    interface = original.get("interface", "")
    if not interface.startswith("en") or not original.get("gateway"):
        return (f"Mac default route: interface={interface or 'unknown'}, "
                f"gateway={original.get('gateway') or 'none'}. "
                f"Route to {endpoint}: interface={routes[endpoint].get('interface') or 'unknown'}. "
                "The probe needs the ordinary physical network. "
                "If another VPN is active, disconnect it for the trial and keep Wi-Fi or Ethernet connected.")
    for target, entry in routes.items():
        if (entry.get("interface"), entry.get("gateway")) != (original["interface"], original["gateway"]):
            return "A different interface or gateway handles " + target
        if target != endpoint and entry.get("destination") != "default" and not (
                entry.get("destination") == target and "WASCLONED" in entry.get("flags", "")):
            return "A specific existing route handles " + target
    client = runpy.run_path(str(ROOT / "macos/rn-mac"))
    client["inactive_proxy_settings"](client["checked"](client["SCUTIL"], "--proxy"))
    return None


def make_profiles(server_key, enrollment, gateway, port):
    import base64
    if len(base64.b64decode(server_key, validate=True)) != 32 or server_key == enrollment["server_public_key"]:
        raise ValueError("Unexpected independent server public key")
    dest = LOCAL / "macos"
    root = dest / "independent"
    root.mkdir(mode=0o700, exist_ok=True)
    for old, new, probe in (("RackNerd-Mac-Probe", "RackNerd2-Probe", True),
                            ("RackNerd-Mac", "RackNerd2", False)):
        profile = configparser.ConfigParser(interpolation=None)
        profile.optionxform = str
        profile.read(dest / (old + ".conf"))
        if profile["Peer"]["PublicKey"] != enrollment["server_public_key"]:
            raise ValueError("Unexpected source profile")
        profile["Peer"]["PublicKey"] = server_key
        profile["Peer"]["Endpoint"] = enrollment["endpoint"] + ":" + str(port)
        if probe:
            profile["Peer"]["AllowedIPs"] = gateway + "/32"
        path = root / (new + ".conf")
        import io
        buf = io.StringIO()
        profile.write(buf)
        if path.exists():
            if path.read_text() != buf.getvalue():
                raise ValueError("Existing independent profile differs: " + str(path))
        else:
            with path.open("x") as stream:
                stream.write(buf.getvalue())
    print("Profiles ready for import (keep inactive):", root)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mac-only", action="store_true", help="Check the current Mac network without SSH")
    parser.add_argument("--prepare", action="store_true", help="Stage Mac-specific files and generate the two inactive profiles")
    args = parser.parse_args()
    os.umask(0o077)
    ref = LOCAL / "reference"
    addon = runpy.run_path(str(ROOT / "server/wg0-mac.py"))
    enrollment = json.loads((LOCAL / "macos/enrollment.json").read_text())
    config = addon["prepare"](json.loads((ref / "inventory.json").read_text()),
                              json.loads((ref / "source.json").read_text()), enrollment)
    gateway = str(ipaddress.IPv4Address(config["address"]) + 1)
    endpoint = enrollment["endpoint"]
    routes = mac_routes(("default", config["address"], gateway, endpoint))
    if args.mac_only or args.prepare:
        for target, entry in routes.items():
            print(target, entry.get("interface"), "destination", entry.get("destination"), flush=True)
        problem = check_mac(routes, endpoint)
        if problem:
            sys.exit(problem)
        print("Mac physical routes and system proxy check passed. No tunnel activated.")
        if args.mac_only:
            return
    remote = "import json,os\nos.environ.update(LC_ALL='C', PATH='/usr/sbin:/usr/bin:/sbin:/bin')\n"
    for variable, filename in (("inspector", "inspect-live.py"), ("addon", "wg0-mac.py"),
                               ("candidate", "check-mac-interface.py")):
        source = (ROOT / "server" / filename).read_text()
        remote += f"{variable} = {{'__name__': 'inspection'}}\nexec({source!r}, {variable})\n"
    remote += f"report = candidate['inspect_candidate'](inspector, addon, {config!r}, {gateway!r})\n"
    if args.prepare:
        files = {name: (ROOT / "server" / name).read_text() for name in
                 ("check-mac-interface.py", "wg0-mac.py", "inspect-live.py", "interface.py",
                  "racknerd-mac-independent.service")}
        stage = (ROOT / "server/stage-independent.py").read_text()
        remote += f"stage = {{'__name__': 'staging'}}\nexec({stage!r}, stage)\n"
        remote += f"report['public_key'] = stage['prepare']({files!r}, {config!r})\n"
    remote += "print(json.dumps(report))\n"
    print("Checking VPS" + (" and staging inactive Mac files" if args.prepare else " (read-only)") +
          ". Enter the SSH password only in Terminal.", flush=True)
    result = subprocess.check_output(["ssh", "-T", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10",
                                      "root@" + enrollment["endpoint"], "python3 -"], input=remote, text=True)
    report = json.loads(result)
    report["mac_routes"] = routes
    report["checked_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with tempfile.NamedTemporaryFile(dir=LOCAL, prefix="independent-check-", suffix=".json",
                                     mode="w", delete=False) as f:
        json.dump(report, f, indent=2)
    print("VPS candidate checks passed. No tunnel or service activated.")
    print("Report:", f.name)
    problem = check_mac(routes, endpoint)
    if problem:
        sys.exit("Mac trial pending: " + problem)
    if args.prepare:
        make_profiles(report["public_key"], enrollment, gateway, report["port"])


if __name__ == "__main__":
    if sys.platform != "darwin":
        sys.exit("Run from Terminal on the enrolled MacBook")
    main()
