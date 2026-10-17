#!/usr/bin/env bash
# Build dist/ConfigTool.exe: Go launcher + embedded payload (portable Python, xray, sing-box, app/).
# Needs: bash, curl, tar, unzip, zip, go 1.22, windres (binutils-mingw-w64-x86-64), python3.
# Every download is pinned and verified by SHA-256.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)

PY_TAG=20261013
PY_FILE="cpython-3.12.15+${PY_TAG}-x86_64-pc-windows-msvc-install_only_stripped.tar.gz"
PY_SHA=7a2aef48e5ee569e310b29b32681debbc5d888e92790d85331a47736c6b06aad   # matches the official SHA256SUMS of that release
XRAY_TAG=v26.3.27
XRAY_SHA=d004c39288ce9ada487c6f398c7c545f7d749e44bdfdd59dbc9f865afba4e1ad  # matches the official .dgst file
SB_TAG=v1.14.2
SB_SHA=c2d8bfff918755808781dfdeeb8581b6c91eb3a243d9a7b55483cfc0c0684d32    # pinned on first download (no official checksum file)

DL=build/dl
PAY=build/payload
rm -rf "$PAY" launcher/payload.zip launcher/*.syso
mkdir -p "$DL" "$PAY/xray" "$PAY/singbox" "$PAY/app" dist

get() { # url sha out
  [ -f "$3" ] || curl -fL --retry 3 -o "$3" "$1"
  echo "$2  $3" | sha256sum -c - >/dev/null || { echo "checksum mismatch: $1" >&2; rm -f "$3"; exit 1; }
}

get "https://github.com/astral-sh/python-build-standalone/releases/download/${PY_TAG}/${PY_FILE//+/%2B}" "$PY_SHA" "$DL/python.tar.gz"
get "https://github.com/XTLS/Xray-core/releases/download/${XRAY_TAG}/Xray-windows-64.zip" "$XRAY_SHA" "$DL/xray.zip"
get "https://github.com/SagerNet/sing-box/releases/download/${SB_TAG}/sing-box-${SB_TAG#v}-windows-amd64.zip" "$SB_SHA" "$DL/sing-box.zip"

tar -xzf "$DL/python.tar.gz" -C "$PAY"
[ -f "$PAY/python/pythonw.exe" ] || { echo "python/pythonw.exe missing" >&2; exit 1; }
unzip -oq "$DL/xray.zip" xray.exe geoip.dat geosite.dat LICENSE -d "$PAY/xray"
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
unzip -oq "$DL/sing-box.zip" -d "$T"
cp "$T"/sing-box-*/sing-box.exe "$T"/sing-box-*/libcronet.dll "$T"/sing-box-*/LICENSE "$PAY/singbox/"

cp app/*.py app/*.html "$PAY/app/"
for f in snapshot.txt blocklist.txt; do
  if [ -f "app/$f" ]; then cp "app/$f" "$PAY/app/"; fi
done

# Bundled IP blocklist: generated from the public lists when not provided.
if [ ! -f "$PAY/app/blocklist.txt" ]; then
  PAYLOAD_APP="$PAY/app" python3 scripts/make_blocklist.py \
    || echo "warning: bundled blocklist not generated; the app downloads it at runtime"
fi

(cd "$PAY" && zip -qr9X "$ROOT/launcher/payload.zip" python xray singbox app)

WINDRES=$(command -v windres || command -v x86_64-w64-mingw32-windres || true)
[ -n "$WINDRES" ] || { echo "windres not found (install binutils-mingw-w64-x86-64)" >&2; exit 1; }

chmod +x launcher/cppcat.sh   # uploads through the GitHub web UI drop the executable bit
cd launcher
"$WINDRES" --preprocessor="$ROOT/launcher/cppcat.sh" -O coff -i res.rc -o resource_windows_amd64.syso
VER=$(sha256sum payload.zip | cut -c1-16)
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -mod=mod -trimpath \
  -ldflags "-s -w -H=windowsgui -buildid= -X main.ver=$VER" -o ../dist/ConfigTool.exe .
cd ..
(cd dist && sha256sum ConfigTool.exe > ConfigTool.exe.sha256)
ls -l dist
