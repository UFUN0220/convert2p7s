#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "[1/6] Checking Python..."
python3 --version >/dev/null

echo "[2/6] Creating build virtual environment..."
if [ ! -d ".venv-build-macos" ]; then
  python3 -m venv .venv-build-macos
fi

source ".venv-build-macos/bin/activate"

echo "[3/6] Installing dependencies..."
python -m pip install --upgrade pip
python -m pip install -r requirements.txt -r requirements-build.txt

echo "[4/6] Running regression tests..."
python test_signing_service.py

echo "[5/6] Building macOS app..."
pyinstaller --clean --noconfirm p7s_signer_macos.spec

echo "[6/6] Applying ad-hoc codesign if available..."
if command -v codesign >/dev/null 2>&1; then
  codesign --force --deep --sign - "dist/P7S离线文件数字签名工具.app" || true
fi

echo
echo "Build finished."
echo "APP path: $(pwd)/dist/P7S离线文件数字签名工具.app"
