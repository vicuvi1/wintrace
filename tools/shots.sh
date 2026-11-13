#!/usr/bin/env bash
# README / CV screenshots with headless Chrome. Needs: node tools/serve.js 5190
set -euo pipefail
CHROME="${CHROME:-/c/Program Files/Google/Chrome/Application/chrome.exe}"
BASE="${BASE:-http://localhost:5190/}"
OUT="$(cd "$(dirname "$0")/.." && pwd -W 2>/dev/null || pwd)/docs"
P="$(mktemp -d)"
shot() { "$CHROME" --headless=new --disable-gpu --use-angle=swiftshader --hide-scrollbars --no-first-run --user-data-dir="$P" \
  --window-size="$3" --force-device-scale-factor=1 --virtual-time-budget=8000 --screenshot="$OUT/$1.png" "${BASE}?static$2" >/dev/null 2>&1; echo "docs/$1.png"; }
shot landing "" 1440,1080
shot story "#sample=01" 1440,1150
shot detections "#sample=03&tab=detections" 1440,1300
shot timeline "#sample=04&tab=timeline" 1440,1100
shot mitre "#sample=03&tab=mitre" 1440,1050
shot entities "#sample=06&tab=entities" 1440,950
shot kerberoast "#sample=02" 1440,1000
shot dcsync "#sample=05&tab=detections" 1440,1100
shot clean "#sample=07" 1440,900
shot light "&theme=light#sample=04" 1440,1100
shot og "#sample=01" 1200,630
