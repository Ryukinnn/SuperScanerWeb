#!/usr/bin/env bash
set -euo pipefail

echo "[+] Installing SuperScanerWeb..."

if ! command -v python3 >/dev/null 2>&1; then
  echo "[!] python3 belum tersedia. Install dulu: sudo apt install python3 python3-venv"
  exit 1
fi

python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
chmod +x superscanerweb.py

cat <<'MSG'

[+] Instalasi Python selesai.

Opsional untuk memaksimalkan tool bawaan Kali:
  sudo apt update
  sudo apt install -y whois dnsutils whatweb wafw00f nikto nmap sslscan

Contoh pemakaian:
  source .venv/bin/activate
  python3 superscanerweb.py --target https://example.com --yes-authorized
  python3 superscanerweb.py --target https://example.com --yes-authorized --use-kali
  python3 superscanerweb.py --target https://example.com --yes-authorized --use-kali --active

MSG
