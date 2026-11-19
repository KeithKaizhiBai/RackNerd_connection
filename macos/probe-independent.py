"""Bounded WireGuard trial on the dedicated Mac port."""
import argparse
import configparser
import hashlib
import ipaddress
import json
import os
import re
from pathlib import Path
import runpy
import secrets
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / ".local"
NAME = "RackNerd2-Probe"


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Only check local profiles and route prerequisites")
    parser.add_argument("--full", action="store_true", help="Test the dedicated IPv4 Internet gateway with automatic rollback")
    args = parser.parse_args()
    full = args.full
    profile_name = "RackNerd2" if full else NAME
    os.umask(0o077)
    client = runpy.run_path(str(ROOT / "macos/rn-mac"))
    preflight = runpy.run_path(str(ROOT / "macos/check-independent.py"))
    enroll = json.loads((LOCAL / "macos/enrollment.json").read_text())
    gateway = str(ipaddress.IPv4Address(enroll["address"]) + 1)
    endpoint = enroll["endpoint"]
    client["snapshot"].__globals__["ENDPOINT"] = endpoint
    names = client["checked"](client["SCUTIL"], "--nc", "list")
    for name in (NAME, "RackNerd2"):
        if '"' + name + '"' not in names:
            raise RuntimeError("macOS cannot see " + name + ". Open WireGuard > File > Import Tunnel(s) from File and select " +
                               str(LOCAL / "macos/independent" / (name + ".conf")))
    tunnel = client["resolve_tunnel"](profile_name)
    require(all(client["tunnel_status"](client["resolve_tunnel"](name)) == "Disconnected"
                for name in (NAME, "RackNerd2", "RackNerd-Mac", "RackNerd-Mac-Probe") if '"' + name + '"' in names),
            "Start with the RackNerd profiles disconnected")
    profile = configparser.ConfigParser(interpolation=None)
    profile.read(LOCAL / "macos/independent" / (profile_name + ".conf"))
    peer = profile["Peer"]
    require(peer["Endpoint"] == endpoint + ":51821", "Unexpected trial endpoint")
    if full:
        require(peer["AllowedIPs"].replace(" ", "") == "0.0.0.0/0,::/1,8000::/1" and
                profile["Interface"]["Address"].replace(" ", "") == enroll["address"] + "/32," + str(ipaddress.IPv6Address(enroll["ipv6_sink"])) + "/128" and
                profile["Interface"]["DNS"].replace(" ", "") == "1.1.1.1,9.9.9.9", "Unexpected full profile")
        require(not any(k.lower() in ("http_proxy","https_proxy","all_proxy") and v for k,v in os.environ.items()),
                "A proxy is configured in the terminal environment")
        passed = False
        for receipt in LOCAL.glob("rn-independent-probe-*/report.json"):
            data = json.loads(receipt.read_text())
            if (data.get("mac_recovered") and data.get("cleanup") == {"mac_residue": False, "original_state_restored": True}
                    and data.get("stage", {}).get("protected_verified") and data.get("sample", {}).get("handshake")):
                passed = True
                break
        require(passed, "Complete the dedicated probe and recovery first")
    else:
        require(peer["AllowedIPs"] == gateway + "/32" and profile["Interface"]["Address"] == enroll["address"] + "/32"
                and "DNS" not in profile["Interface"], "Unexpected probe profile")
    problem = preflight["check_mac"](preflight["mac_routes"](("default", enroll["address"], gateway, endpoint)), endpoint)
    require(not problem, problem)
    if args.check:
        print("Independent profiles and physical routes verified.")
        return

    client["recovery_test"](profile_name)
    baseline = client["recovery_baseline"]()
    before = client["network_identity"](baseline)
    sites = ("https://www.apple.com.cn/", "https://example.com")
    def pages():
        return {url: client["run"]("/usr/bin/curl", "--disable", "--noproxy", "*", "-4fsS", "--max-time", "8",
                                   "-o", "/dev/null", url)["ok"] for url in sites}
    ordinary = pages()
    require(any(ordinary.values()), "No ordinary HTTPS connectivity before the probe")
    name = ("rn-independent-full-" if full else "rn-independent-probe-") + secrets.token_hex(8)
    path = LOCAL / name
    path.mkdir(mode=0o700)
    report = {"trial": name, "ordinary_before": ordinary}
    if full:
        report["before_connectivity"] = client["verify"](expect=None)
        report["endpoint_ping"] = client["run"]("/sbin/ping","-n","-c","4","-W","1000",endpoint)
    program = (ROOT / "server/probe-independent.py").read_text()
    hashes = {p: hashlib.sha256((ROOT / "server" / p).read_bytes()).hexdigest() for p in
              ("interface.py", "wg0-mac.py", "inspect-live.py", "check-mac-interface.py",
               "racknerd-mac-independent.service")}
    ref = LOCAL / "reference"
    old = runpy.run_path(str(ROOT / "server/wg0-mac.py"))
    cfg = old["prepare"](json.loads((ref / "inventory.json").read_text()),
                         json.loads((ref / "source.json").read_text()), enroll)
    hashes["reference.json"] = hashlib.sha256(json.dumps(cfg, sort_keys=True).encode()).hexdigest()
    host = "root@" + endpoint
    with tempfile.TemporaryDirectory(dir="/tmp", prefix="rn-mac-ssh-") as tmp:
        ssh = ["ssh", "-S", tmp + "/master", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=8",
               "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=2"]
        print("Trial:", name, "— enter SSH credentials only in Terminal.", flush=True)
        subprocess.run(ssh + ["-MNf", host], check=True)
        def remote(action):
            source = "unit_context={'__name__':'probe'}\n"
            source += f"exec({program!r},unit_context)\n"
            source += f"print(unit_context['json'].dumps(unit_context['remote']({action!r},{name!r},{hashes!r},{peer['PublicKey']!r},{program!r})))\n"
            connection = ssh + ["-o", "BatchMode=yes", "-o", "ProxyCommand=false"]
            if full and action in ("sample", "finish") and subprocess.run(ssh + ["-O", "check", host], capture_output=True).returncode:
                connection = ["ssh", "-S", "none", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=8"]
            result = subprocess.check_output(connection + [host, "python3 -"],
                                             input=source, text=True, timeout=180)
            return json.loads(result)
        attempted = activated = False
        try:
            require(subprocess.check_output(ssh + ["-o", "BatchMode=yes", "-o", "ProxyCommand=false", host, "id -u"],
                                            text=True).strip() == "0", "Management SSH unavailable")
            attempted = True
            report["stage"] = remote("start")
            require(client["network_identity"](client["recovery_baseline"]()) == before,
                    "Mac network changed during VPS setup")
            record = client["arm_recovery"](tunnel, 150 if full else 75)
            activated = True
            client["checked"](client["SCUTIL"], "--nc", "start", tunnel)
            for _ in range(50):
                if client["tunnel_status"](tunnel) == "Connected":
                    break
                time.sleep(.25)
            require(client["tunnel_status"](tunnel) == "Connected", "Probe did not activate")
            route = client["route_identity"](client["run"]("/sbin/route", "-n", "get", gateway))
            require(route["interface"].startswith("utun"), "Probe gateway route missing")
            if not full:
                require(client["network_identity"](client["recovery_baseline"]()) == before, "Ordinary network changed")
            report["ping"] = client["run"]("/sbin/ping", "-n", "-c", "4", "-W", "1000", gateway)
            require(report["ping"]["ok"], "Independent gateway ping failed")
            if full:
                active = client["recovery_baseline"]()
                addresses = client["checked"]("/sbin/ifconfig", route["interface"])
                require(re.search(r"(?m)^\s*inet\s+" + re.escape(enroll["address"]) + r"\s", addresses),
                        "Selected tunnel does not own the enrolled Mac address")
                v6_routes = {}
                for ip in ("2606:4700:4700::1111", "9000::1"):
                    v6 = client["run"]("/sbin/route", "-n", "get", "-inet6", ip)
                    v6_routes[ip] = client["route_identity"](v6) if v6["ok"] else {"unreachable": True}
                report["ipv6_routes"] = v6_routes
                require(all(item.get("unreachable") or item.get("interface") == route["interface"]
                            for item in v6_routes.values()), "IPv6 route outside trial tunnel")
                report["physical_endpoint_route"] = client["check_endpoint_path"](
                    endpoint, baseline["routes"][endpoint], active["routes"][endpoint], route["interface"])
                require(client["inactive_proxy_settings"](active["proxies"]) == client["inactive_proxy_settings"](baseline["proxies"]),
                        "Unexpected active system proxy")
                require(all(active["routes"][ip]["interface"] == route["interface"] for ip in ("1.1.1.1","9.9.9.9","208.67.222.222")),
                        "Public IPv4 routed outside trial interface")
                dns = client["checked"](client["SCUTIL"], "--dns")
                primary = re.search(r"(?ms)^resolver #1\s*\n(.*?)(?:\n\s*\n|\Z)", dns)
                servers = re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", primary[1]) if primary else []
                require(servers and set(servers) <= {"1.1.1.1", "9.9.9.9"}, "Unexpected primary DNS")
                report["active_resolvers"] = servers
                print("Full tunnel active. Test Safari, Chrome, ChatGPT and Codex now.", flush=True)
                checks = report["active_connectivity"] = client["verify"](expect=endpoint)
                status = report["status_after_requests"] = client["tunnel_status"](tunnel)
                failed = [label for label, passed in (
                    ("tunnel status " + status, status == "Connected"),
                    ("native DNS", checks["native_dns"]["ok"]),
                    ("Python HTTPS", checks["python"]["ok"])) if not passed]
                if not checks["public_exit_checks_passed"]:
                    for url, result in checks["exit_requests"].items():
                        if result.get("ipv4") != endpoint:
                            detail = result.get("ipv4") or result["stderr"] or "no valid IPv4 response"
                            failed.append(f"public IPv4 {url} ({detail})")
                failed.extend(f"{url} ({r['stderr']})" for url, r in checks["https"].items() if not r["ok"])
                require(not failed, "Full tunnel checks failed: " + ", ".join(failed))
                require(not checks["ipv6_numeric_tcp_probe"]["reachable"], "External IPv6 reachable")
            else:
                sample = report["sample"] = remote("sample")
                require(report["stage"]["started"] <= sample["handshake"] <= sample["server_now"] and
                        all(n > 0 for n in sample["traffic"]), "Independent handshake or bidirectional traffic missing")
                report["ordinary_during"] = pages()
                require(all(not ok or report["ordinary_during"][u] for u, ok in ordinary.items()), "Ordinary HTTPS regression")
            print("Waiting for automatic disconnect.", flush=True)
            for _ in range(175 if full else 100):
                if json.loads(record.read_text()).get("recovered"):
                    break
                time.sleep(1)
            require(json.loads(record.read_text()).get("recovered") and client["tunnel_status"](tunnel) == "Disconnected",
                    "Automatic Mac recovery unverified")
            require(client["network_identity"](client["recovery_baseline"]()) == before, "Mac baseline not restored")
            report["ordinary_after"] = pages()
            require(all(not ok or report["ordinary_after"][u] for u, ok in ordinary.items()), "Restored HTTPS regression")
            report["mac_recovered"] = True
            if full:
                sample = report["sample"] = remote("sample")
                require(report["stage"]["started"] <= sample["handshake"] <= sample["server_now"] and
                        all(n > 0 for n in sample["traffic"]), "Independent handshake or bidirectional traffic missing")
        finally:
            try:
                try:
                    if activated and client["tunnel_status"](tunnel) != "Disconnected":
                        client["stop_tunnel"](tunnel)
                    if activated:
                        report["final_mac_disconnected"] = client["tunnel_status"](tunnel) == "Disconnected"
                        report["final_network_restored"] = client["network_identity"](client["recovery_baseline"]()) == before
                finally:
                    if attempted:
                        report["cleanup"] = remote("finish")
            finally:
                (path / "report.json").write_text(json.dumps(report, indent=2))
                subprocess.run(ssh + ["-O", "exit", host], capture_output=True)
        require(report.get("final_mac_disconnected") and report.get("final_network_restored"), "Final Mac recovery unverified")
        require(report.get("cleanup", {}).get("original_state_restored"), "VPS recovery unverified")
    print("Independent full trial and cleanup verified:" if full else "Independent probe and cleanup verified:", path / "report.json")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        sys.exit(str(error))
