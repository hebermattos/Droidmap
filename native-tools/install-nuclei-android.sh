#!/usr/bin/env bash
set -euo pipefail
# Usage: bash native-tools/install-nuclei-android.sh /path/to/nuclei-arm64
SOURCE="${1:-}"
if [[ -z "$SOURCE" || ! -f "$SOURCE" ]]; then
  echo "Usage: $0 /path/to/Android-arm64-nuclei" >&2
  exit 2
fi
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="$ROOT/app/src/main/jniLibs/arm64-v8a/libnuclei.so"
MAGIC="$(od -An -tx1 -N4 "$SOURCE" | tr -d ' \n')"
if [[ "$MAGIC" != "7f454c46" ]]; then
  echo "Expected an ELF executable" >&2; exit 1
fi
MACHINE="$(od -An -tu1 -j18 -N1 "$SOURCE" | tr -d ' \n')"
if [[ "$MACHINE" != "183" ]]; then
  echo "Expected AArch64 ELF (e_machine=183), got $MACHINE" >&2; exit 1
fi
if ! LC_ALL=C grep -aq '/system/bin/linker64' "$SOURCE"; then
  echo "Expected Android linker64; ordinary Linux ARM64 executables are unsupported" >&2; exit 1
fi
mkdir -p "$(dirname "$TARGET")"
cp "$SOURCE" "$TARGET"
chmod 755 "$TARGET"
echo "Installed $(du -h "$TARGET" | cut -f1) at $TARGET"
echo "Verify on a physical Android device; compile success does not establish runtime compatibility."
