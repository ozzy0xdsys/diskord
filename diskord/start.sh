#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

# Create venv if missing
if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi

# Activate venv
source .venv/bin/activate

python -m pip install --upgrade pip
pip install -r requirements.txt

# Optional: set a strong secret for session signing (recommended)
# export PYCORD_SECRET="$(python -c 'import secrets;print(secrets.token_urlsafe(48))')"

# Run
python main.py
