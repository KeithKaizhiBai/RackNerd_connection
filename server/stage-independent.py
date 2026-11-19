"""Stage the prospective unit and a dedicated key. No installed unit or network writes."""
import fcntl
import json
import os
from pathlib import Path
import subprocess
import tempfile


def prepare(files, reference):
    os.umask(0o077)
    parent = Path("/var/lib/racknerd-mac-independent-staging")
    parent.mkdir(mode=0o700, exist_ok=True)
    if parent.is_symlink() or parent.stat().st_uid != 0 or parent.stat().st_mode & 0o077:
        raise ValueError("Staging directory ownership mismatch")
    with (parent / "lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        stage = parent / "prepared"
        payload = dict(files, **{"reference.json": json.dumps(reference, sort_keys=True)})
        if not stage.exists():
            with tempfile.TemporaryDirectory(dir=parent) as tmp:
                new = Path(tmp) / "prepared"
                new.mkdir(mode=0o700)
                for name, contents in payload.items():
                    (new / name).write_text(contents)
                with (new / "server.key").open("xb") as key:
                    subprocess.run(["wg", "genkey"], stdout=key, check=True)
                subprocess.run(["systemd-analyze", "--man=no", "verify", str(new / "racknerd-mac-independent.service")],
                               check=True, timeout=60)
                new.rename(stage)
        for name, contents in payload.items():
            if (stage / name).read_bytes() != contents.encode():
                raise ValueError("Staged file differs; inspect before replacing: " + name)
        with (stage / "server.key").open("rb") as key:
            return subprocess.check_output(["wg", "pubkey"], stdin=key, text=True).strip()
