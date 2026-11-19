"""Exercise recovery decisions without running network commands."""
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest
from unittest.mock import patch


module = runpy.run_path(str(Path(__file__).resolve().parents[1] / "server/probe-independent.py"))
trial = "rn-independent-probe-0123456789abcdef"


class Recovery(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / trial).mkdir()
        self.link = root / "rn-mac"
        self.link.mkdir()
        (self.link / "ifalias").write_text("")
        (self.link / "ifindex").write_text("4")

    def test_forwarding_is_scoped_to_trial_device(self):
        root = self.link.parent
        directory = root / "rn-independent-full-0123456789abcdef"
        directory.mkdir()
        (directory / "created-index").write_text("4")
        (self.link / "ifalias").write_text(directory.name)
        settings = root / "conf"
        for device in ("rn-mac", "wg0", "eth0", "default", "all"):
            (settings / device).mkdir(parents=True)
            (settings / device / "forwarding").write_text("0")
        setting = settings / "rn-mac" / "forwarding"
        enable = module["enable_trial_forwarding"]
        with patch.dict(enable.__globals__, LINK=self.link, Path={ "/proc/sys/net/ipv4/conf": settings }.__getitem__):
            for field, wrong in (("ifalias", "another-trial"), ("ifindex", "8")):
                original = (self.link / field).read_text()
                (self.link / field).write_text(wrong)
                with self.assertRaises(RuntimeError):
                    enable(directory)
                self.assertEqual(setting.read_text(), "0")
                (self.link / field).write_text(original)
            enable(directory)
            self.assertEqual(setting.read_text(), "1\n")
            with patch.object(Path, "write_text", side_effect=AssertionError("unnecessary write")):
                enable(directory)
        for other in ("wg0", "eth0", "default", "all"):
            self.assertEqual((settings / other / "forwarding").read_text(), "0")

    def test_label_before_rename(self):
        root = self.link.parent
        directory = root / trial
        self.link.rename(root / "unused")
        (directory / "before.json").write_text("{}")
        (root / "reference.json").write_text('{"address":"10.77.0.4","key":"peer"}')
        pending = root / ("rnp" + trial[-12:])
        worker = module["worker"]
        def simulate(*args):
            if "add" in args:
                pending.mkdir()
                (pending / "ifindex").write_text("8")
                (pending / "ifalias").write_text("")
            elif "alias" in args:
                self.assertEqual(args[-1], trial)
                # Simulate a kernel which leaves the alias empty.
            elif "del" in args:
                self.assertEqual(args[-1], pending.name)
                pending.rename(root / "removed-temp")
            else:
                self.fail(args)
        with patch.dict(worker.__globals__, STAGE=root, LINK=self.link, cmd=simulate, base_view=dict):
            with self.assertRaisesRegex(RuntimeError, "Could not label"):
                worker("up", directory)
            worker("down", directory)
        self.assertFalse(self.link.exists())
        self.assertFalse(pending.exists())

class PermanentCleanup(unittest.TestCase):
    def test_only_delete_interface_with_recorded_alias_and_index(self):
        real_root = Path(__file__).resolve().parents[1]
        api = runpy.run_path(str(real_root / "server/interface.py"))
        control = api["control"]
        for alias, index, remove in (("racknerd-mac-0123", "19", True),
                                     ("racknerd-mac-0123", "20", False), ("", "19", False)):
            with self.subTest(alias=alias, index=index), tempfile.TemporaryDirectory() as d:
                root = Path(d)
                dev = root / "rn-mac"
                dev.mkdir()
                (dev / "ifalias").write_text(alias)
                (dev / "ifindex").write_text(index)
                (root / "ifindex").write_text("19")
                (root / "owner").write_text('"0123"')
                (root / "reference.json").write_text("{}")
                calls = []
                def cmd(*args):
                    calls.append(args)
                    dev.rename(root / "removed")
                with patch.dict(control.__globals__, STATE=root, CONF=root, Path=lambda _: root,
                                command=cmd, MAC={"independent_rules": lambda *args: []}, firewall_rules=list), \
                        patch.object(os, "geteuid", return_value=0), \
                        patch.dict(os.environ, RUNTIME_DIRECTORY=str(root)):
                    if remove:
                        control("down")
                    else:
                        with self.assertRaisesRegex(RuntimeError, "Foreign interface"):
                            control("down")
                self.assertEqual(calls, [("ip", "link", "del", "dev", "rn-mac")] if remove else [])
                self.assertEqual((root / "owner").exists(), not remove)
