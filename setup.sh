#!/usr/bin/env bash
# One-click setup for Kali / Linux / macOS
set -e
python3 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python main.py --doctor
echo; echo "Setup done. Run:  source .venv/bin/activate && python main.py 192.168.1.0/24"
