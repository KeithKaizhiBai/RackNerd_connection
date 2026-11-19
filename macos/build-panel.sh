#!/bin/sh
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
dest=${1:-"$root/RackNerd.app"}
if [ -e "$dest" ] || [ -L "$dest" ]; then
    echo "Destination already exists: $dest" >&2
    exit 1
fi
parent=$(dirname "$dest")
tmp=$(mktemp -d "$parent/.racknerd-panel.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
app="$tmp/RackNerd.app"
/usr/bin/osacompile -o "$app" "$root/macos/RackNerd.applescript"
python3 - "$root/.local/macos/settings.json" "$app/Contents/Resources/endpoint.txt" <<'PY'
import ipaddress
import json
import sys
from pathlib import Path

endpoint = ipaddress.IPv4Address(json.loads(Path(sys.argv[1]).read_text())["endpoint"])
Path(sys.argv[2]).write_text(str(endpoint) + "\n")
PY
/usr/bin/codesign --force --sign - "$app"
/usr/bin/codesign --verify --strict "$app"
mv "$app" "$dest"
echo "$dest"
