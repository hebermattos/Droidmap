#!/usr/bin/env bash
set -euo pipefail
# Package the source-built release, including matching NSE libraries and data.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d "${RUNNER_TEMP:-/tmp}/droidmap-nmap-package.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
: "${GITHUB_REPOSITORY:=hebermattos/Droidmap}"
gh release download nmap-android-arm64 --repo "$GITHUB_REPOSITORY" --dir "$WORK" \
  --pattern nmap-arm64.tar.gz --pattern nmap-arm64.tar.gz.sha256
# Accept one exact SHA-256 record for the expected archive, never arbitrary paths.
EXPECTED="$(python3 - "$WORK/nmap-arm64.tar.gz.sha256" <<'PY'
from pathlib import Path
import re,sys
record=Path(sys.argv[1]).read_text().strip()
match=re.fullmatch(r'([0-9a-fA-F]{64})\s+\*?nmap-arm64\.tar\.gz',record)
if not match: raise SystemExit('Invalid Nmap archive checksum record')
print(match.group(1))
PY
)"
python3 "$ROOT/native-tools/install-nmap-runtime.py" "$WORK/nmap-arm64.tar.gz" --sha256 "$EXPECTED"
python3 "$ROOT/tests/verify-nmap-data.py" --assets "$ROOT/app/src/main/assets/nmap-data" --nmap-version 7.992
