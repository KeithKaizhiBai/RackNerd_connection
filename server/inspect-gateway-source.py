"""Read-only source inventory for the live custom gateway. No network changes."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import sys


def redact(text):
    result = []
    for line in text.splitlines():
        if re.search(r"private.?key|preshared.?key|password|passwd|secret|token|authorization", line, re.I):
            result.append("# [sensitive line omitted]")
        else:
            result.append(re.sub(r"[A-Za-z0-9+/]{43}=", "[key omitted]", line))
    return "\n".join(result) + "\n"


if __name__ == "__main__":
    if sys.platform != "linux" or os.geteuid() != 0:
        raise SystemExit("Run with root read access on the VPS")
    files = {}
    for name in ("/etc/racknerd-gateway/gateway.sh",
                 "/etc/systemd/system/racknerd-gateway.service",
                 "/etc/systemd/system/racknerd-web-proxy.service",
                 "/etc/nftables.conf"):
        path = Path(name)
        try:
            raw = path.read_bytes()
            files[name] = {"sha256": hashlib.sha256(raw).hexdigest(),
                           "source_redacted": redact(raw.decode())}
        except (OSError, ValueError) as error:
            files[name] = {"error": str(error)}
    directory = Path("/etc/racknerd-gateway")
    print(json.dumps({"schema": "racknerd-gateway-source/1",
                      "captured_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      "files": files,
                      "gateway_directory_names": sorted(p.name for p in directory.iterdir())
                          if directory.is_dir() else []}, indent=2))
