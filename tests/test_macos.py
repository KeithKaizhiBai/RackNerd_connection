#!/usr/bin/env python3
"""Offline regression tests. No SSH, network changes or system services."""

import base64
import contextlib
import datetime
import hashlib
import importlib.machinery
import importlib.util
import io
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent.parent


def module(name, relative):
    loader = importlib.machinery.SourceFileLoader(name, str(ROOT / relative))
    spec = importlib.util.spec_from_loader(name, loader)
    result = importlib.util.module_from_spec(spec)
    loader.exec_module(result)
    return result


gateway = module("rn_gateway", "server/rn-gateway")
mac = module("rn_mac", "macos/rn-mac")
inspector = module("rn_inspector", "server/inspect-live.py")
WINDOWS = base64.b64encode(b"W" * 32).decode()
MAC = base64.b64encode(b"M" * 32).decode()
SERVER = base64.b64encode(b"S" * 32).decode()
RECORD = {"peer": MAC, "address": "10.203.84.3"}


def good(value):
    return {"ok": True, "value": value}


def live_inventory():
    return {
        "schema": "racknerd-live-inventory/1",
        "captured_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "wireguard": {"rn-public": {"public-key": good(SERVER), "listen-port": good("51820"),
                                     "peers": good(WINDOWS),
                                     "allowed-ips": good(WINDOWS + "\t10.203.84.2/32")}},
        "ipv4_addresses": good([
            {"ifname": "eth0", "addr_info": [{"family": "inet", "local": mac.ENDPOINT, "prefixlen": 24}]},
            {"ifname": "rn-public", "addr_info": [{"family": "inet", "local": "10.203.84.1", "prefixlen": 32}]}]),
        "ipv4_routes": good([{"dst": "default", "dev": "eth0"},
                              {"dst": "10.203.84.2/32", "dev": "rn-public"}]),
    }


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        for name, path in (("ACTIVE", root / "active.json"), ("APPLIED", root / "applied.json"),
                           ("PEERS", root / "peers.json"), ("PEER_TRIAL", root / "peer-trial.json"),
                           ("TRIAL", root / "trial.json")):
            p = patch.object(gateway, name, path)
            p.start()
            self.addCleanup(p.stop)
        self.cfg = {"peer": WINDOWS, "port": 51820, "token": "owner"}
        gateway.save(gateway.ACTIVE, self.cfg)
        gateway.save(gateway.APPLIED, {"token": "owner", "wan": "eth0"})
        self.output = contextlib.redirect_stdout(io.StringIO())
        self.output.__enter__()
        self.addCleanup(self.output.__exit__, None, None, None)

    def test_single_client_rules_match_upstream(self):
        rules = gateway.nft_rules({"wan": "eth0", "excluded": ["0.0.0.0/8", "10.0.0.0/8"]}, "audit")
        self.assertEqual(hashlib.sha256(rules.encode()).hexdigest(),
                         "9a00a847f884750ed24bedb9a3b482055ecb75db45c89cc46761ad7f1275efcc")

    def test_new_peer_cannot_reuse_windows_or_server_addresses(self):
        for address in ("10.203.84.1", "10.203.84.2", "10.203.84.0", "10.203.84.255", "10.77.0.3"):
            with self.subTest(address=address), self.assertRaises(RuntimeError):
                gateway.extra_peer("macbook", {"peer": MAC, "address": address})

    def test_peer_name_cannot_inject_nft_commands(self):
        for name in ("windows", "mac;flush ruleset", 'mac"', "../mac", "MAC"):
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                gateway.extra_peer(name, RECORD)

    def test_extra_rules_preserve_private_network_isolation(self):
        rules = gateway.extra_nft_rules({"wan": "eth0"}, "macbook", RECORD)
        lines = rules.splitlines()
        self.assertEqual(len(lines), 4)
        self.assertTrue(all('comment "rn-peer:macbook"' in line for line in lines))
        self.assertTrue(all("10.203.84.3" in line for line in lines))
        outgoing = next(line for line in lines if 'forward iifname "rn-public"' in line)
        self.assertIn('oifname "eth0"', outgoing)
        self.assertIn("ip daddr != @non_internet", outgoing)
        incoming = next(line for line in lines if 'forward iifname "eth0"' in line)
        self.assertIn("ct state { established, related }", incoming)
        self.assertNotIn("new,", incoming)

    def test_startup_adds_new_rules_after_unchanged_primary_rules(self):
        net = {"wan": "eth0", "excluded": ["10.0.0.0/8"]}
        original = gateway.nft_rules(net, "owner")
        expanded = gateway.nft_rules(net, "owner", {"macbook": RECORD})
        self.assertTrue(expanded.startswith(original))
        self.assertIn("insert rule", expanded[len(original):])

    def test_duplicate_keys_or_addresses_are_rejected(self):
        for second in ({"peer": MAC, "address": "10.203.84.4"},
                       {"peer": SERVER, "address": "10.203.84.3"},
                       {"peer": WINDOWS, "address": "10.203.84.4"}):
            gateway.save(gateway.PEERS, {"macbook": RECORD, "other": second})
            with self.assertRaises(RuntimeError):
                gateway.additional_peers(self.cfg)

    def pending(self):
        value = {"name": "macbook", "record": RECORD, "token": "trial",
                 "deadline": time.monotonic() + 300}
        gateway.save(gateway.PEER_TRIAL, value)
        return value

    def test_uncommitted_peer_disappears_after_runtime_loss(self):
        self.pending()
        self.assertIn("macbook", gateway.additional_peers(self.cfg))
        gateway.PEER_TRIAL.unlink()
        self.assertEqual(gateway.additional_peers(self.cfg), {})

    def test_committed_peer_survives_runtime_loss(self):
        self.pending()
        gateway.save(gateway.PEERS, {"macbook": RECORD})
        gateway.PEER_TRIAL.unlink()
        self.assertEqual(gateway.additional_peers(self.cfg), {"macbook": RECORD})

    def test_partial_commit_is_not_rolled_back_by_timer(self):
        self.pending()
        gateway.save(gateway.PEERS, {"macbook": RECORD})
        with patch.object(gateway, "remove_live_peer") as remove:
            gateway.cancel_peer_trial(stop_timer=False)
        remove.assert_not_called()
        self.assertFalse(gateway.PEER_TRIAL.exists())

    def test_timer_cancels_only_pending_peer(self):
        self.pending()
        with patch.object(gateway, "remove_live_peer") as remove:
            gateway.cancel_peer_trial(stop_timer=False)
        remove.assert_called_once_with("macbook", RECORD)
        self.assertEqual(gateway.read(gateway.ACTIVE), self.cfg)

    def stage_patches(self, runner, routes=None):
        stack = contextlib.ExitStack()
        stack.enter_context(patch.object(gateway, "ensure_installed"))
        stack.enter_context(patch.object(gateway, "verify_live"))
        stack.enter_context(patch.object(gateway, "server_public", return_value=SERVER))
        stack.enter_context(patch.object(gateway, "extra_rule_handles", return_value=[]))
        stack.enter_context(patch.object(gateway, "systemd_property", return_value="active"))
        stack.enter_context(patch.object(gateway, "run", side_effect=runner))
        stack.enter_context(patch.object(gateway, "jrun", return_value=routes or []))
        self.addCleanup(stack.close)
        return stack

    def test_stage_arms_rollback_before_live_changes_without_restart(self):
        calls = []
        def runner(*args, **kwargs):
            calls.append(args)
            return ""
        self.stage_patches(runner)
        gateway.add_peer("macbook", MAC, "10.203.84.3", 300)
        timer_index = next(i for i, c in enumerate(calls) if c[0] == "systemd-run")
        nft_index = next(i for i, c in enumerate(calls) if c[:3] == ("nft", "-f", "-"))
        self.assertLess(timer_index, nft_index)
        self.assertEqual([c for c in calls if c[:2] == ("wg", "set")],
                         [("wg", "set", "rn-public", "peer", MAC, "allowed-ips", "10.203.84.3/32")])
        self.assertFalse(any(c[:2] == ("systemctl", "restart") or c[:3] == ("ip", "link", "delete")
                             for c in calls))
        self.assertFalse(gateway.PEERS.exists())
        self.assertEqual(gateway.read(gateway.ACTIVE), self.cfg)

    def test_stage_rejects_conflicting_routes_before_mutation(self):
        calls = []
        self.stage_patches(lambda *a, **k: calls.append(a) or "", [{"dst": "10.203.84.0/24", "dev": "other"}])
        with self.assertRaises(RuntimeError):
            gateway.add_peer("macbook", MAC, "10.203.84.3", 300)
        self.assertFalse(any(c[0] == "systemd-run" for c in calls))
        self.assertFalse(gateway.PEER_TRIAL.exists())

    def test_failed_live_add_cleans_up_only_the_mac_candidate(self):
        def runner(*args, **kwargs):
            if args[:2] == ("wg", "set"):
                raise RuntimeError("simulated wg failure")
            return ""
        self.stage_patches(runner)
        with patch.object(gateway, "remove_live_peer") as remove:
            with self.assertRaisesRegex(RuntimeError, "simulated wg failure"):
                gateway.add_peer("macbook", MAC, "10.203.84.3", 300)
        remove.assert_called_once_with("macbook", RECORD)
        self.assertFalse(gateway.PEER_TRIAL.exists())
        self.assertEqual(gateway.read(gateway.ACTIVE), self.cfg)

    def test_expired_peer_trial_cannot_be_committed(self):
        pending = self.pending()
        pending["deadline"] = time.monotonic() - 1
        gateway.save(gateway.PEER_TRIAL, pending)
        with self.assertRaises(RuntimeError):
            gateway.commit_peer()
        self.assertFalse(gateway.PEERS.exists())

    def test_commit_requires_recent_handshake(self):
        self.pending()
        with patch.object(gateway, "systemd_property", return_value="active"), \
                patch.object(gateway, "verify_live"), \
                patch.object(gateway, "run", return_value=MAC + "\t0"):
            with self.assertRaises(RuntimeError):
                gateway.commit_peer()
        self.assertFalse(gateway.PEERS.exists())

    def test_commit_persists_only_after_live_verification(self):
        self.pending()
        with patch.object(gateway, "systemd_property", return_value="active"), \
                patch.object(gateway, "verify_live"), \
                patch.object(gateway, "run", return_value=MAC + "\t" + str(int(time.time()))):
            gateway.commit_peer()
        self.assertEqual(gateway.read(gateway.PEERS), {"macbook": RECORD})
        self.assertFalse(gateway.PEER_TRIAL.exists())
        self.assertEqual(gateway.read(gateway.ACTIVE), self.cfg)

    def test_removal_never_deletes_the_windows_peer_or_whole_interface(self):
        calls = []
        def runner(*args, **kwargs):
            calls.append((args, kwargs))
            if args[:2] == ("wg", "show"):
                return WINDOWS + "\t10.203.84.2/32\n" + MAC + "\t10.203.84.3/32"
            return ""
        with patch.object(gateway, "link_details", return_value={"rn-public": {"ifalias": "rn-public-gateway:owner"}}), \
                patch.object(gateway, "owned_table", return_value=True), \
                patch.object(gateway, "extra_rule_handles", return_value=[("input", 101), ("forward", 102)]), \
                patch.object(gateway, "jrun", return_value=[{"dst": "10.203.84.3", "dev": "rn-public"}]), \
                patch.object(gateway, "run", side_effect=runner):
            gateway.remove_live_peer("macbook", RECORD)
        mutations = [a for a, _ in calls if a[:2] == ("wg", "set")]
        self.assertEqual(mutations, [("wg", "set", "rn-public", "peer", MAC, "remove")])
        self.assertFalse(any("delete" in a or "restart" in a for a, _ in calls))
        self.assertEqual(gateway.read(gateway.ACTIVE), self.cfg)

    def test_foreign_interface_cannot_be_removed(self):
        with patch.object(gateway, "link_details", return_value={"rn-public": {"ifalias": "foreign"}}), \
                patch.object(gateway, "run") as run:
            with self.assertRaises(RuntimeError):
                gateway.remove_live_peer("macbook", RECORD)
        run.assert_not_called()

    def test_primary_peer_has_no_peer_remove_name(self):
        with patch.object(gateway, "verify_live"), patch.object(gateway, "remove_live_peer") as remove:
            with self.assertRaises(RuntimeError):
                gateway.remove_peer("windows")
        remove.assert_not_called()

    def test_multi_peer_startup_rebuilds_windows_and_mac(self):
        gateway.APPLIED.unlink()
        gateway.save(gateway.PEERS, {"macbook": RECORD})
        calls = []
        with patch.object(gateway, "preflight", return_value={"wan": "eth0", "index": 2, "excluded": ["10.0.0.0/8"]}), \
                patch.object(gateway, "link_details", return_value={"eth0": {"mtu": 1500}}), \
                patch.object(gateway, "forwarding"), \
                patch.object(gateway, "run", side_effect=lambda *a, **k: calls.append(a) or ""):
            gateway.up()
        self.assertIn(("ip", "-4", "route", "add", "10.203.84.2/32", "dev", "rn-public"), calls)
        self.assertIn(("ip", "-4", "route", "add", "10.203.84.3/32", "dev", "rn-public"), calls)
        peers = [c for c in calls if c[:2] == ("wg", "set")]
        self.assertTrue(any(WINDOWS in c and "10.203.84.2/32" in c for c in peers))
        self.assertTrue(any(MAC in c and "10.203.84.3/32" in c for c in peers))

    def verify_patches(self, allowed, route_device="rn-public"):
        stack = contextlib.ExitStack()
        path = Path(self.tmp.name) / "forwarding"
        for name in ("eth0", "rn-public"):
            (path / name).mkdir(parents=True)
            (path / name / "forwarding").write_text("1\n")
        stack.enter_context(patch.object(gateway, "IPV4_CONF", path))
        stack.enter_context(patch.object(gateway, "systemd_property", return_value="active"))
        stack.enter_context(patch.object(gateway, "owned_table", return_value=True))
        stack.enter_context(patch.object(gateway, "link_details", return_value={"rn-public": {"ifalias": "rn-public-gateway:owner"}}))
        stack.enter_context(patch.object(gateway, "server_public", return_value=SERVER))
        def runner(*args, **kwargs):
            return {"allowed-ips": allowed, "listen-port": "51820", "public-key": SERVER}[args[-1]]
        stack.enter_context(patch.object(gateway, "run", side_effect=runner))
        stack.enter_context(patch.object(gateway, "jrun", return_value=[{"dev": route_device}]))
        stack.enter_context(patch.object(gateway, "extra_rule_handles", return_value=[
            ("input", 1), ("forward", 2), ("forward", 3), ("wan_masquerade", 4)]))
        self.addCleanup(stack.close)

    def test_live_verification_accepts_peer_order_without_changing_primary_identity(self):
        gateway.save(gateway.PEERS, {"macbook": RECORD})
        self.verify_patches(MAC + "\t10.203.84.3/32\n" + WINDOWS + "\t10.203.84.2/32")
        gateway.verify_live(self.cfg)

    def test_live_verification_detects_windows_address_change(self):
        gateway.save(gateway.PEERS, {"macbook": RECORD})
        self.verify_patches(WINDOWS + "\t10.203.84.4/32\n" + MAC + "\t10.203.84.3/32")
        with self.assertRaises(RuntimeError):
            gateway.verify_live(self.cfg)

    def test_live_verification_detects_windows_route_change(self):
        self.verify_patches(WINDOWS + "\t10.203.84.2/32", route_device="eth0")
        with self.assertRaises(RuntimeError):
            gateway.verify_live(self.cfg)


class ClientTests(unittest.TestCase):
    def test_exit_queries_keep_two_witnesses_on_timeout_and_reject_wrong_addresses(self):
        expected = "192.0.2.1"
        other = "192.0.2.2"
        for primary, backup, passed, use_backup in (
            (28, expected, True, True), (7, 28, False, True), (28, other, False, True),
            (other, expected, False, False), (60, expected, False, False),
            ("invalid", expected, False, False), (expected, other, True, False)):
            calls = []
            def fetch(url, connect_timeout):
                calls.append((url, connect_timeout))
                answer = {"https://api.ipify.org": primary, "https://ipv4.icanhazip.com": expected,
                          "https://checkip.amazonaws.com": backup}[url]
                code = answer if isinstance(answer, int) else 0
                return {"exit_code": code, "ok": code == 0, "stdout": f"{answer}\nRN_METRICS 0", "stderr": ""}
            with self.subTest(primary=primary, backup=backup), patch.object(mac, "https", side_effect=fetch):
                exits, observed, ok = mac.public_exits(expected)
                self.assertEqual(ok, passed)
                self.assertEqual("https://checkip.amazonaws.com" in exits, use_backup)
                self.assertEqual(observed["https://ipv4.icanhazip.com"], expected)
                self.assertEqual(("https://api.ipify.org", 10) in calls, primary in (7, 28))

    def test_site_timeout_retries_once_and_retains_both_timings(self):
        for second_code in (0, 28):
            with self.subTest(second_code=second_code):
                results = [{"ok": code == 0, "exit_code": code, "stdout": "body\nRN_METRICS " + str(i),
                            "stderr": "timeout" if code else ""} for i, code in enumerate((28, second_code))]
                with patch.object(mac, "https", side_effect=results) as fetch:
                    result = mac.check_site("https://example.com")
                self.assertEqual([call.kwargs["connect_timeout"] for call in fetch.call_args_list], [4, 10])
                self.assertEqual(result["ok"], second_code == 0)
                self.assertEqual([r["stdout"] for r in result["attempts"]], ["RN_METRICS 0", "RN_METRICS 1"])

    def test_site_certificate_failure_is_reported_immediately(self):
        with patch.object(mac, "https", return_value={"ok": False, "exit_code": 60, "stdout": "", "stderr": "TLS"}) as fetch:
            result = mac.check_site("https://example.com")
        fetch.assert_called_once()
        self.assertFalse(result["ok"])

    def test_full_trial_accepts_omitted_disabled_proxy_fields(self):
        active = "<dictionary> {\n  FTPPassive : 1\n}"
        before = active.replace("  FTPPassive", "  ExceptionsList : <array> {\n    0 : *.example\n  }\n  HTTPEnable : 0\n  HTTPSEnable : 0\n  SOCKSEnable : 0\n  FTPPassive")
        self.assertEqual(mac.inactive_proxy_settings(before), mac.inactive_proxy_settings(active))
        self.assertNotEqual(mac.inactive_proxy_settings(active.replace("FTPPassive : 1", "FTPPassive : 0")),
                            mac.inactive_proxy_settings(before))
        for flag in ("HTTPEnable", "HTTPSEnable", "SOCKSEnable", "ProxyAutoConfigEnable", "ProxyAutoDiscoveryEnable"):
            scoped = active.replace("  FTPPassive", f"  __SCOPED__ : <dictionary> {{\n    en0 : <dictionary> {{\n      {flag} : 1\n    }}\n  }}\n  FTPPassive")
            with self.subTest(flag=flag), self.assertRaisesRegex(RuntimeError, flag):
                mac.inactive_proxy_settings(scoped)
        with self.assertRaises(RuntimeError):
            mac.inactive_proxy_settings("")

    def test_full_endpoint_uses_original_scoped_gateway(self):
        physical = {"interface": "en0", "gateway": "198.51.100.1"}
        ordinary = {"interface": "utun7", "destination": "default"}
        def lookup(interface, gateway, flags="UP,GATEWAY"):
            return {"ok": True, "stdout": f"interface: {interface}\ngateway: {gateway}\nflags: <{flags}>"}
        with patch.object(mac, "run", return_value=lookup("en0", "198.51.100.1")) as run:
            scoped = mac.check_endpoint_path("192.0.2.47", physical, ordinary, "utun7")
            self.assertEqual(scoped["interface"], "en0")
            run.assert_called_once_with("/sbin/route", "-n", "get", "-ifscope", "en0", "192.0.2.47")
            for wrong in ({"interface": "utun8"}, {"interface": "en0", "gateway": "198.51.100.2"}):
                with self.assertRaises(RuntimeError):
                    mac.check_endpoint_path("192.0.2.47", physical, wrong, "utun7")
        for result in (lookup("utun7", "198.51.100.1"), lookup("en0", "198.51.100.2"),
                       lookup("en0", "198.51.100.1", "UP,BLACKHOLE"), {"ok": False}):
            with patch.object(mac, "run", return_value=result), self.assertRaises(RuntimeError):
                mac.check_endpoint_path("192.0.2.47", physical, ordinary, "utun7")

    def test_physical_default_route_and_matching_host_clone(self):
        ip = "1.1.1.1"
        parent = dict(destination="default", gateway="192.0.2.1", interface="en0",
                      flags="<UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>")
        clone = dict(parent, destination=ip, flags="<UP,GATEWAY,HOST,DONE,WASCLONED,IFSCOPE,IFREF,GLOBAL>")
        def state(route):
            return {"routes": {"default": parent, ip: route}, "dns": ["192.0.2.53"], "proxies": ""}

        before = state(parent)
        self.assertEqual(mac.network_identity(state(clone)), before)
        for change in ({"interface": "utun4"}, {"gateway": "192.0.2.2"}, {"destination": "1.0.0.0"},
                       {"flags": clone["flags"].replace("WASCLONED", "REJECT")}):
            with self.subTest(change=change):
                self.assertNotEqual(mac.network_identity(state(dict(clone, **change))), before)
        for field in ("dns", "proxies"):
            self.assertNotEqual(mac.network_identity(dict(state(clone), **{field: "changed"})), before)
        self.assertNotEqual(mac.network_identity({"routes": {"default": clone, ip: clone}})["routes"], before["routes"])

    def setUp(self):
        endpoint = patch.object(mac, "ENDPOINT", "203.0.113.10")
        endpoint.start()
        self.addCleanup(endpoint.stop)

    def test_live_inventory_accepts_an_unused_independent_peer(self):
        self.assertEqual(mac.validate_profile_inventory(live_inventory(), "rn-public", "10.203.84.3", MAC),
                         (SERVER, "10.203.84.1"))

    def test_actual_legacy_interface_is_used_without_renaming(self):
        value = live_inventory()
        value["wireguard"]["wg0"] = value["wireguard"].pop("rn-public")
        value["wireguard"]["wg0"]["allowed-ips"] = good(WINDOWS + "\t10.77.0.2/32")
        value["ipv4_addresses"]["value"][1] = {
            "ifname": "wg0", "addr_info": [{"family": "inet", "local": "10.77.0.1", "prefixlen": 24}]}
        value["ipv4_routes"] = good([{"dst": "10.77.0.0/24", "dev": "wg0"}])
        self.assertEqual(mac.validate_profile_inventory(value, "wg0", "10.77.0.3", MAC), (SERVER, "10.77.0.1"))

    def test_inventory_conflicts_are_rejected(self):
        for address in ("10.203.84.1", "10.203.84.2", mac.ENDPOINT):
            with self.subTest(address=address), self.assertRaises(ValueError):
                mac.validate_profile_inventory(live_inventory(), "rn-public", address, MAC)

    def test_shared_cryptographic_identity_is_rejected(self):
        for key in (WINDOWS, SERVER):
            with self.subTest(key=key), self.assertRaises(ValueError):
                mac.validate_profile_inventory(live_inventory(), "rn-public", "10.203.84.3", key)

    def test_wide_existing_allowedips_prevents_address_theft(self):
        value = live_inventory()
        value["wireguard"]["rn-public"]["allowed-ips"] = good(WINDOWS + "\t10.203.84.0/24")
        with self.assertRaises(ValueError):
            mac.validate_profile_inventory(value, "rn-public", "10.203.84.3", MAC)

    def test_stale_or_incomplete_inventory_is_rejected(self):
        value = live_inventory()
        value["captured_at_utc"] = "2000-01-01T00:00:00+00:00"
        with self.assertRaises(ValueError):
            mac.validate_profile_inventory(value, "rn-public", "10.203.84.3", MAC)
        value = live_inventory()
        value["ipv4_routes"]["ok"] = False
        with self.assertRaises(ValueError):
            mac.validate_profile_inventory(value, "rn-public", "10.203.84.3", MAC)

    def test_unavailable_route_queries_do_not_pass_as_empty_state(self):
        with self.assertRaises(RuntimeError):
            mac.route_identity({"ok": False, "stdout": ""})

    def test_profile_sets_native_ipv4_default_and_captures_ipv6(self):
        with tempfile.TemporaryDirectory() as root:
            local = Path(root)
            (local / "macbook.key").write_text(MAC + "\n")
            (local / "macbook.pub").write_text(MAC + "\n")
            for p in local.iterdir():
                p.chmod(0o600)
            inv = local / "inventory.json"
            inv.write_text(json.dumps(live_inventory()))
            args = type("Args", (), {"inventory": str(inv), "interface": "rn-public", "address": "10.203.84.3"})
            with patch.object(mac, "LOCAL", local), contextlib.redirect_stdout(io.StringIO()):
                mac.profile(args)
            text = (local / "RackNerd-Mac.conf").read_text()
            routes = [ipaddress.ip_network(s.strip()) for s in
                      re.search(r"^AllowedIPs = (.+)$", text, re.M)[1].split(",")]
            ipv4 = [n for n in routes if n.version == 4]
            self.assertEqual(ipv4, [ipaddress.ip_network("0.0.0.0/0")])
            self.assertIn(ipaddress.ip_network("::/1"), routes)
            self.assertIn(ipaddress.ip_network("8000::/1"), routes)
            self.assertEqual((local / "RackNerd-Mac.conf").stat().st_mode & 0o777, 0o600)
            probe = (local / "RackNerd-Mac-Probe.conf").read_text()
            self.assertIn("AllowedIPs = 10.203.84.1/32", probe)
            self.assertNotIn("DNS =", probe)

    def test_rfc7748_known_x25519_vector_with_installed_openssl(self):
        openssl = next((str(p) for p in (Path("/opt/homebrew/opt/openssl@3/bin/openssl"),
                                        Path("/usr/local/opt/openssl@3/bin/openssl"),
                                        Path("/usr/bin/openssl")) if p.is_file()), None)
        if openssl is None:
            self.skipTest("OpenSSL unavailable")
        raw = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        expected = bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        try:
            public = mac.derive_public(openssl, raw)
        except RuntimeError:
            self.skipTest("Installed OpenSSL lacks X25519")
        self.assertEqual(base64.b64decode(public), expected)

    def test_trial_cannot_start_without_a_recovery_test(self):
        with tempfile.TemporaryDirectory() as root, patch.object(mac, "LOCAL", Path(root)), \
                patch.object(mac, "resolve_tunnel", return_value="uuid"), \
                patch.object(mac, "checked") as mutate:
            with self.assertRaises(FileNotFoundError):
                mac.trial("RackNerd-Mac", 90)
        mutate.assert_not_called()

    def test_competing_full_tunnel_blocks_activation(self):
        with tempfile.TemporaryDirectory() as root:
            local = Path(root)
            (local / "recovery-tested.json").write_text(json.dumps({"tunnel": "uuid", "time": time.time()}))
            with patch.object(mac, "LOCAL", local), \
                    patch.object(mac, "resolve_tunnel", return_value="uuid"), \
                    patch.object(mac, "tunnel_status", return_value="Disconnected"), \
                    patch.object(mac, "snapshot", return_value={"ipv4_routes": {"ok": True, "stdout": "default link#20 UCSg utun5"}}), \
                    patch.object(mac, "checked") as mutate:
                with self.assertRaisesRegex(RuntimeError, "Another VPN"):
                    mac.trial("RackNerd-Mac", 90)
            mutate.assert_not_called()

    def test_recovery_worker_can_stop_tunnel_without_network_requests(self):
        with tempfile.TemporaryDirectory() as root:
            record = Path(root) / "job.json"
            mac.save(record, {"tunnel": "uuid", "seconds": 2})
            with patch.object(mac.time, "sleep"), patch.object(mac, "stop_tunnel") as stop:
                mac.recover(record)
            stop.assert_called_once_with("uuid")
            self.assertTrue(json.loads(record.read_text())["recovered"])

    def test_recovery_can_be_prepared_while_existing_proxy_is_unchanged(self):
        with tempfile.TemporaryDirectory() as root:
            local = Path(root)
            record = local / "record.json"
            mac.save(record, {"recovered": True})
            with patch.object(mac, "LOCAL", local), \
                    patch.object(mac, "resolve_tunnel", return_value="uuid"), \
                    patch.object(mac, "tunnel_status", return_value="Disconnected"), \
                    patch.object(mac, "recovery_baseline", return_value={"proxies": "HTTPEnable : 1"}), \
                    patch.object(mac, "arm_recovery", return_value=record), \
                    contextlib.redirect_stdout(io.StringIO()):
                mac.recovery_test("RackNerd-Mac")
            self.assertEqual(json.loads((local / "recovery-tested.json").read_text())["tunnel"], "uuid")

    def test_proxy_configuration_prevents_trial_without_modifying_it(self):
        for env, flags in ((["HTTPS_PROXY"], ""), ([], "ProxyAutoConfigEnable : 1")):
            with self.subTest(env=env, flags=flags), tempfile.TemporaryDirectory() as root:
                local = Path(root)
                (local / "recovery-tested.json").write_text(json.dumps({"tunnel": "uuid", "time": time.time()}))
                with patch.object(mac, "LOCAL", local), \
                        patch.object(mac, "resolve_tunnel", return_value="uuid"), \
                        patch.object(mac, "tunnel_status", return_value="Disconnected"), \
                        patch.object(mac, "snapshot", return_value={"ipv4_routes": {"ok": True, "stdout": "default 192.168.1.1 en0"}, "proxy_environment_names": env}), \
                        patch.object(mac, "recovery_baseline", return_value={"proxies": flags}), \
                        patch.object(mac, "arm_recovery") as arm, patch.object(mac, "checked") as mutate:
                    with self.assertRaisesRegex(RuntimeError, "proxy is enabled"):
                        mac.trial("RackNerd-Mac", 90)
                arm.assert_not_called()
                mutate.assert_not_called()

    def test_full_trial_requires_real_probe_recovery(self):
        with tempfile.TemporaryDirectory() as root, contextlib.ExitStack() as stack:
            local = Path(root)
            mac.save(local / "recovery-tested.json", {"tunnel": "full", "time": time.time()})
            stack.enter_context(patch.object(mac, "LOCAL", local))
            stack.enter_context(patch.object(mac, "resolve_tunnel", side_effect=["full", "probe"]))
            stack.enter_context(patch.object(mac, "tunnel_status", return_value="Disconnected"))
            stack.enter_context(patch.object(mac, "snapshot", return_value={
                "ipv4_routes": {"stdout": ""}, "proxy_environment_names": []}))
            stack.enter_context(patch.object(mac, "recovery_baseline", return_value={"proxies": ""}))
            arm = stack.enter_context(patch.object(mac, "arm_recovery"))
            with self.assertRaisesRegex(RuntimeError, "active Probe"):
                mac.trial("RackNerd-Mac", 90)
            arm.assert_not_called()

    def test_only_active_probe_with_restored_baseline_records_recovery(self):
        for status, after, success in (("Connected", "original", True), ("Disconnected", "original", False),
                                       ("Connected", "changed", False)):
            with self.subTest(status=status, after=after), tempfile.TemporaryDirectory() as root:
                local = Path(root)
                record = local / "job.json"
                mac.save(record, {"tunnel": "probe", "seconds": 30, "probe_baseline": {"dns": "original"},
                                  "endpoint": mac.ENDPOINT})
                with patch.object(mac, "LOCAL", local), patch.object(mac.time, "sleep"), \
                        patch.object(mac, "tunnel_status", return_value=status), \
                        patch.object(mac, "stop_tunnel") as stop, \
                        patch.object(mac, "recovery_baseline", return_value={"dns": after}):
                    mac.recover(record)
                stop.assert_called_once_with("probe")
                self.assertEqual((local / "probe-restored.json").exists(), success)

    def test_git_ignores_private_profiles_and_includes_only_source(self):
        with tempfile.TemporaryDirectory() as root:
            local = Path(root)
            (local / ".gitignore").write_bytes((ROOT / ".gitignore").read_bytes())
            subprocess.run(["git", "init", "-q", str(local)], check=True, capture_output=True)
            names = [".local/macos/macbook.key", ".local/macos/RackNerd-Mac.conf",
                     "macos/accidental.key", "macos/live.conf", "macos/test.log",
                     "macos/rn-mac", "macos/README.md", "macos/RackNerd-Mac.conf.example",
                     "server/inspect-live.py", "tests/test_macos.py"]
            result = subprocess.run(["git", "-C", str(local), "check-ignore", "--no-index", "--stdin"],
                                    input="\n".join(names) + "\n", text=True, capture_output=True, check=True)
            self.assertEqual(set(result.stdout.splitlines()), set(names[:5]))


class InspectionTests(unittest.TestCase):
    def test_private_and_preshared_keys_and_hook_bodies_never_leave_inspector(self):
        value = inspector.public_profile("""[Interface]
PrivateKey = SUPER_SECRET_PRIVATE_KEY
Address = 10.77.0.1/24
PostUp = secret-command --password TOP_SECRET
[Peer]
PublicKey = PUBLIC
PresharedKey = SUPER_SECRET_PSK
AllowedIPs = 10.77.0.2/32
""")
        output = json.dumps(value)
        self.assertNotIn("SUPER_SECRET", output)
        self.assertNotIn("TOP_SECRET", output)
        self.assertNotIn("secret-command", output)
        self.assertIn("10.77.0.2/32", output)
        self.assertEqual(value["hook_directives_present"], ["PostUp"])

    def test_unknown_gateway_metadata_fields_are_not_exported(self):
        value = inspector.gateway_metadata(json.dumps({"peer": WINDOWS, "port": 51820,
                                                       "private_key": "SECRET", "token": "OWNER_TOKEN"}))
        self.assertEqual(value, {"peer": WINDOWS, "port": 51820})


if __name__ == "__main__":
    unittest.main(verbosity=2)
