#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

PYTHON_BIN="python3"
if [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
  PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
fi

case "${1:-}" in
  --install)
    echo "[*] Preparing ORFX Python environment..."
    if ! command -v python3 >/dev/null 2>&1; then
      echo "[-] python3 was not found. Install Python 3.10+ first."
      exit 1
    fi
    python3 -m venv .venv 2>/dev/null || {
      echo "[-] Could not create .venv. On Kali/Debian install: python3-venv"
      exit 1
    }
    .venv/bin/python -m pip install --upgrade pip
    if [[ -s requirements.txt ]]; then
      .venv/bin/python -m pip install -r requirements.txt
    fi
    echo "[+] Installation complete. ORFX will use .venv automatically."
    ;;
  --check)
    "$PYTHON_BIN" orfx.py --check
    ;;
  *)
    "$PYTHON_BIN" orfx.py "$@"
    ;;
esac
