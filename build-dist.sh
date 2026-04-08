#!/usr/bin/env bash
# build-dist.sh — Build a distributable zip for ZPA Status Mini-SIEM
#
# Downloads Python wheels for RHEL (x86_64) and packages everything into
# a self-contained zip file. Supports Python 3.9+ on the target.
#
# Usage:
#   bash build-dist.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_NAME="zpa-siem-$(date +%Y%m%d)"
DIST_DIR="$SCRIPT_DIR/dist/$DIST_NAME"

# Minimum Python version on target (used for wheel download)
TARGET_PYVER=39

# Conditional dependencies not resolved by pip when building on a newer Python.
# These are required on Python <3.10/3.11 but pip evaluates markers using the
# build machine's Python, so they get silently skipped.
PY39_EXTRAS=(
    "importlib-metadata>=3.6.0"   # Flask/Werkzeug need this on Python <3.10
    "zipp>=3.20"                  # importlib-metadata needs this on Python <3.12
    "tomli>=1"                    # pytest needs this on Python <3.11
    "exceptiongroup>=1.0.0rc8"   # pytest needs this on Python <3.11
)

echo "=== Building distribution: $DIST_NAME ==="

# Clean previous build
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR/vendor"

# Vendor dependencies
echo ">>> Downloading Python wheels for RHEL x86_64 (Python ${TARGET_PYVER})..."
pip download -r "$SCRIPT_DIR/requirements.txt" "${PY39_EXTRAS[@]}" \
    -d "$DIST_DIR/vendor" \
    --platform manylinux2014_x86_64 \
    --python-version "$TARGET_PYVER" \
    --only-binary=:all: 2>/dev/null || {
    echo "    Note: some packages may not have binary wheels."
    echo "    Falling back to source downloads..."
    pip download -r "$SCRIPT_DIR/requirements.txt" "${PY39_EXTRAS[@]}" \
        -d "$DIST_DIR/vendor" 2>/dev/null
}
echo "    $(ls "$DIST_DIR/vendor" | wc -l) packages downloaded."

# Copy application files
echo ">>> Copying application files..."
cp -r "$SCRIPT_DIR/src" "$DIST_DIR/src"
cp -r "$SCRIPT_DIR/config" "$DIST_DIR/config"
cp "$SCRIPT_DIR/install.sh" "$DIST_DIR/"
cp "$SCRIPT_DIR/requirements.txt" "$DIST_DIR/"
cp "$SCRIPT_DIR/README.md" "$DIST_DIR/"

# Remove dev-only files
find "$DIST_DIR" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
find "$DIST_DIR" -name "*.pyc" -delete 2>/dev/null || true

# Create zip
echo ">>> Creating zip archive..."
cd "$SCRIPT_DIR/dist"
zip -r "$DIST_NAME.zip" "$DIST_NAME" -x "*.pyc" "*__pycache__*" > /dev/null

echo ""
echo "=== Distribution built ==="
echo "  File: dist/$DIST_NAME.zip"
echo "  Size: $(du -h "$DIST_NAME.zip" | cut -f1)"
echo ""
echo "  To install on RHEL:"
echo "    scp dist/$DIST_NAME.zip admin@server:/tmp/"
echo "    ssh admin@server 'cd /tmp && unzip $DIST_NAME.zip && cd $DIST_NAME && sudo bash install.sh'"
