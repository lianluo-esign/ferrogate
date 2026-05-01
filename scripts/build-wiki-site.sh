#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WIKI_DIR="${WIKI_DIR:-$ROOT_DIR/wiki}"
SITE_DIR="${SITE_DIR:-$ROOT_DIR/wiki-site}"
OUTPUT_DIR="${OUTPUT_DIR:-$SITE_DIR/public}"
MODE="${1:-build}"

if [[ ! -d "$WIKI_DIR" ]]; then
  echo "wiki directory not found: $WIKI_DIR" >&2
  exit 1
fi

if [[ ! -f "$SITE_DIR/package.json" ]]; then
  echo "Quartz site package.json not found: $SITE_DIR/package.json" >&2
  exit 1
fi

cd "$SITE_DIR"

if [[ ! -d node_modules ]]; then
  npm ci
fi

case "$MODE" in
  build)
    npx quartz build -d "$WIKI_DIR" -o "$OUTPUT_DIR"
    ;;
  serve)
    npx quartz build --serve --watch -d "$WIKI_DIR" -o "$OUTPUT_DIR"
    ;;
  clean)
    rm -rf "$OUTPUT_DIR"
    ;;
  *)
    echo "Usage: $0 [build|serve|clean]" >&2
    exit 1
    ;;
esac
