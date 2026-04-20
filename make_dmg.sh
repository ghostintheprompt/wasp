#!/bin/bash

# WASN DMG Creation Script
# Requires pyinstaller

APP_NAME="WASP"
VERSION="1.0.0"
DIST_DIR="dist"
BUILD_DIR="build"
DMG_NAME="WASP_${VERSION}.dmg"

echo "[+] Starting build process for ${APP_NAME} v${VERSION}..."

# Clean previous builds
rm -rf "${DIST_DIR}" "${BUILD_DIR}" *.spec "${DMG_NAME}"

# Install pyinstaller if missing
if ! python3 -m PyInstaller --version &> /dev/null; then
    echo "[*] Installing PyInstaller..."
    python3 -m pip install pyinstaller
fi

# Create standalone binary
echo "[+] Creating binary..."
python3 -m PyInstaller --onefile --name "${APP_NAME}" \
            --add-data "signatures.json:." \
            --add-data "assets:assets" \
            wasp.py

if [ $? -ne 0 ]; then
    echo "[-] Build failed"
    exit 1
fi

# Create DMG
echo "[+] Creating DMG..."
mkdir -p "${BUILD_DIR}/dmg"
cp "${DIST_DIR}/${APP_NAME}" "${BUILD_DIR}/dmg/"
cp README.md "${BUILD_DIR}/dmg/"
cp LICENSE "${BUILD_DIR}/dmg/"

hdiutil create -volname "${APP_NAME}" -srcfolder "${BUILD_DIR}/dmg" -ov -format UDZO "${DMG_NAME}"

if [ $? -eq 0 ]; then
    echo "[+] Successfully created ${DMG_NAME}"
else
    echo "[-] DMG creation failed"
    exit 1
fi

# Cleanup
rm -rf "${BUILD_DIR}"
echo "[+] Done."
