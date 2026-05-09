#!/usr/bin/env bash
# Build AnyPhraseRecovery into dist/AnyPhraseRecovery-<version>.mds.zip
# Reads the version from dapp.conf so this is the single source of truth.
set -euo pipefail

cd "$(dirname "$0")"

if ! command -v jq >/dev/null 2>&1; then
  VERSION=$(python3 -c "import json; print(json.load(open('dapp.conf'))['version'])")
else
  VERSION=$(jq -r .version dapp.conf)
fi
NAME=$(python3 -c "import json; print(json.load(open('dapp.conf'))['name'])")

if [ -z "$VERSION" ] || [ -z "$NAME" ]; then
  echo "ERROR: could not read name/version from dapp.conf" >&2
  exit 1
fi

OUT_DIR=dist
OUT_FILE="${OUT_DIR}/${NAME}-${VERSION}.mds.zip"

mkdir -p "$OUT_DIR"
rm -f "$OUT_FILE"

# Pack only the runtime files. Anything else (README, LICENSE, build.sh,
# .gitignore, dist/ itself) stays out of the .mds.zip — the dapp must be
# self-contained and minimal.
zip -q -r "$OUT_FILE" \
  dapp.conf \
  favicon.svg \
  index.html \
  mds.js \
  styles.css \
  app.js \
  -x ".*"

echo "Built: $OUT_FILE  ($(du -h "$OUT_FILE" | cut -f1))"
unzip -l "$OUT_FILE"
