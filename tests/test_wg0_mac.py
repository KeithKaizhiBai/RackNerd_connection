"""Offline wg0 lifecycle tests. Every network mutation targets an in-memory model."""
import base64
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("addon", ROOT / "server/wg0-mac.py")
addon = importlib.util.module_from_spec(spec)
spec.loader.exec_module(addon)


class Lifecycle(unittest.TestCase):
    def setUp(self):
        self.inv = json.loads((ROOT / "tests/wg0-fixture.json").read_text())
        self.enrollment = {"mac_public_key": base64.b64encode(b"M" * 32).decode(),
                           "address": "10.77.0.4", "gateway": "10.77.0.1", "interface": "wg0",
                           "endpoint": "192.0.2.5",
                           "server_public_key": self.inv["wireguard"]["wg0"]["public-key"]["value"]}
        self.source = {"schema": "racknerd-gateway-source/1",
                       "files": {p: {"sha256": "0" * 64} for p in addon.SOURCE_FILES}}
        self.cfg = addon.prepare(self.inv, self.source, self.enrollment)
        self.state = addon.projection(self.inv)
        self.journal = {"token": "test", "base": copy.deepcopy(self.state), "claimed": []}
        self.calls = []
        self.observations = []

    def read(self):
        self.observations.append(len(self.calls))
        return copy.deepcopy(self.state)

    def execute(self, args, payload):
        rules = self.state["rules"]
        key = self.enrollment["mac_public_key"]
        ip = self.enrollment["address"]
        if args[:2] == ["nft", "-j"]:
            batch = json.loads(payload)["nftables"]
            if "-c" in args:
                return
            for command in batch:
                if "add" in command:
                    rule = command["add"]["rule"]
                    rules.append({"rule": dict(rule, handle=100 + len(rules))})
                else:
                    remove = command["delete"]["rule"]
                    self.assertEqual(set(remove), {"family", "table", "chain", "handle"})
                    matches = [obj for obj in rules if "rule" in obj and
                               all(obj["rule"].get(k) == v for k, v in remove.items())]
                    self.assertEqual(len(matches), 1)
                    self.assertTrue(matches[0]["rule"]["comment"].startswith("rn-mac:test:"))
                    rules.remove(matches[0])
        elif args[:3] == ["ip", "-4", "route"]:
            self.assertEqual(args[4:], [ip + "/32", "dev", "wg0", "proto", "static", "metric", "45404"])
            r = {"dst": ip, "dev": "wg0", "protocol": "static", "metric": 45404,
                 "scope": "link", "flags": []}
            if args[3] == "add":
                self.state["routes"].append(r)
            else:
                self.assertEqual(args[3], "del")
                self.state["routes"].remove(r)
        else:
            self.assertEqual(args[:5], ["wg", "set", "wg0", "peer", key])
            if args[5:] == ["remove"]:
                del self.state["peers"][key]
                del self.state["keepalive"][key]
            else:
                self.assertEqual(args[5:], ["allowed-ips", ip + "/32"])
                self.state["peers"][key] = ip + "/32"
                self.state["keepalive"][key] = "off"
        self.calls.append(args)

    def run_update(self, add=True, executor=None):
        addon.update(self.cfg, self.journal, self.read, executor or self.execute, add)

    def test_add_remove_roundtrip_and_repeat(self):
        self.run_update()
        self.run_update()
        self.run_update(False)
        self.run_update(False)
        self.assertEqual(self.state, self.journal["base"])
        self.assertEqual([c[0] for c in self.calls], ["nft", "ip", "wg", "wg", "ip", "nft"])
        self.assertTrue(all(i in self.observations for i in range(7)))

    def test_probe_add_and_rollback_never_write_firewall(self):
        self.cfg["probe_only"] = True
        self.run_update()
        self.assertEqual(self.state["rules"], self.journal["base"]["rules"])
        self.run_update(False)
        self.assertEqual(self.state, self.journal["base"])
        self.assertEqual([cmd[0] for cmd in self.calls], ["ip", "wg", "wg", "ip"])

    def test_original_rules_keep_handles_order_and_counters(self):
        self.run_update()
        base = self.journal["base"]["rules"]
        self.assertEqual(self.state["rules"][:len(base)], base)
        mac = [x["rule"] for x in self.state["rules"][len(base):]]
        self.assertEqual([list(r["expr"][-1])[0] for r in mac], ["drop", "accept", "accept", "masquerade"])
        self.assertEqual(mac[0]["expr"][3], next(x["rule"] for x in base if "rule" in x)["expr"][3])
        for r in mac:
            expr = r["expr"]
            self.assertEqual({e["match"]["right"] for e in expr[:2]}, {"wg0", "eth0"})
            self.assertEqual(expr[2]["match"]["right"], self.enrollment["address"])
            self.assertFalse(any("counter" in e for e in expr))

    def test_partial_failure_recovered_by_stop_post(self):
        for cutoff in (1, 2, 3):
            with self.subTest(cutoff=cutoff):
                self.calls.clear()

                def interrupted(args, payload):
                    self.execute(args, payload)
                    if len(self.calls) == cutoff:
                        raise RuntimeError("interrupted after command")

                with self.assertRaises(RuntimeError):
                    self.run_update(executor=interrupted)
                self.run_update(False)
                self.assertEqual(self.state, self.journal["base"])

    def test_refuses_foreign_route(self):
        self.state["routes"].append({"dst": "10.77.0.4", "dev": "eth0"})
        with self.assertRaisesRegex(ValueError, "ownership mismatch"):
            self.run_update()
        self.assertFalse(self.calls)

    def test_recovery_refuses_an_unclaimed_mac_key(self):
        self.state["peers"][self.cfg["key"]] = self.cfg["address"] + "/32"
        self.state["keepalive"][self.cfg["key"]] = "off"
        with self.assertRaisesRegex(ValueError, "without journal entry"):
            self.run_update(False)
        self.assertFalse(self.calls)

    def test_refuses_changed_windows_peer_between_steps(self):
        def race(args, payload):
            self.execute(args, payload)
            if self.calls:
                self.state["peers"][next(iter(self.state["peers"]))] = "10.77.0.2/31"
        with self.assertRaisesRegex(ValueError, "Protected"):
            self.run_update(executor=race)
        self.assertEqual(len(self.calls), 1)

    def test_refuses_foreign_change_or_reordered_mac_rules_on_removal(self):
        self.run_update()
        initial = copy.deepcopy(self.state)
        for kind in ("handle", "expr", "position", "duplicate", "route", "service", "peer"):
            with self.subTest(kind=kind):
                self.state = copy.deepcopy(initial)
                if kind == "handle":
                    next(x["rule"] for x in self.state["rules"] if "rule" in x)["handle"] += 1
                elif kind == "expr":
                    self.state["rules"][-1]["rule"]["expr"].pop(0)
                elif kind == "position":
                    self.state["rules"].insert(0, self.state["rules"].pop(-3))
                elif kind == "duplicate":
                    self.state["rules"].append(copy.deepcopy(self.state["rules"][-1]))
                elif kind == "route":
                    self.state["routes"][-1]["metric"] += 1
                elif kind == "service":
                    self.state["services"][addon.BASE]["ActiveState"] = "inactive"
                else:
                    self.state["peers"][self.cfg["key"]] = "10.77.0.4/31"
                with self.assertRaises(ValueError):
                    self.run_update(False)
                self.assertEqual(len(self.calls), 3)

    def test_rollback_after_partial_loss_of_mac_firewall_rules(self):
        self.run_update()
        active = copy.deepcopy(self.state)
        original = self.journal["base"]
        for mask in range(16):
            with self.subTest(surviving_rules=mask):
                self.state = copy.deepcopy(active)
                self.state["rules"] = self.state["rules"][:len(original["rules"])] + [
                    r for i, r in enumerate(self.state["rules"][len(original["rules"]):]) if mask & (1 << i)]
                self.run_update(False)
                self.assertEqual(self.state, original)

    def test_counter_changes_are_traffic_not_config_changes(self):
        counter = next(x["counter"] for x in self.inv["firewall"]["nftables"]["value"]["nftables"]
                       if "counter" in x)
        counter["bytes"] += 10000
        self.assertEqual(addon.projection(self.inv), self.state)

    def test_rejects_boot_peer_in_base_profile(self):
        profile = self.inv["persistence"]["wireguard_profiles"]["/etc/wireguard/wg0.conf"]
        profile["public_fields"]["sections"].append({"section": "Peer", "fields": {}})
        with self.assertRaisesRegex(ValueError, "boot peer"):
            addon.prepare(self.inv, self.source, self.enrollment)

    def test_refuses_wg_quick_saveconfig(self):
        profile = self.inv["persistence"]["wireguard_profiles"]["/etc/wireguard/wg0.conf"]
        profile["public_fields"]["sections"][0]["fields"]["saveconfig"] = ["true"]
        with self.assertRaisesRegex(ValueError, "persistent interface"):
            addon.prepare(self.inv, self.source, self.enrollment)

    def test_conflicting_address_and_identity_refused(self):
        for overrides in ({"address": "10.77.0.3"}, {"mac_public_key": self.cfg["base"]["interface"]["public-key"]},
                          {"mac_public_key": next(iter(self.cfg["base"]["peers"]))}):
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                addon.prepare(self.inv, self.source, dict(self.enrollment, **overrides))

    def test_dependency_graph_does_not_pull_upstream_units_in(self):
        unit = (ROOT / "server/racknerd-mac.service").read_text().splitlines()
        for prefix in ("Requires=", "Wants=", "BindsTo=", "Conflicts=", "RequiredBy="):
            self.assertFalse(any(line.startswith(prefix) for line in unit))
        self.assertIn("Requisite=racknerd-gateway.service wg-quick@wg0.service", unit)
        self.assertIn("PartOf=racknerd-gateway.service wg-quick@wg0.service", unit)
        self.assertIn("WantedBy=multi-user.target", unit)


if __name__ == "__main__":
    unittest.main()
