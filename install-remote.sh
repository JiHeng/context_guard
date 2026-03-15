#!/usr/bin/env bash
# context guard remote installer — pipe-friendly bootstrap
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/JiHeng/context_guard/main/install-remote.sh | bash
#   VERSION=0.0.1 curl -fsSL ... | bash

set -e

REPO_OWNER="JiHeng"
REPO_NAME="context_guard"

# --- Resolve version ---
if [ -n "$VERSION" ]; then
    TAG="v${VERSION#v}"
else
    echo "[context_guard] Fetching latest release ..."
    TAG=$(curl -fsSL "https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest" \
        | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"//;s/".*//')
    if [ -z "$TAG" ]; then
        echo "[context_guard] Error: could not determine latest release."
        echo "  Check https://github.com/${REPO_OWNER}/${REPO_NAME}/releases"
        exit 1
    fi
fi

ASSET_NAME="context-guard-${TAG}.tar.gz"
ASSET_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download/${TAG}/${ASSET_NAME}"

# --- Check dependencies ---
for cmd in python3 curl; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "[context_guard] Error: '$cmd' is required but not found. Please install it first."
        exit 1
    fi
done

# --- Download and extract ---
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

echo "[context_guard] Downloading ${ASSET_NAME} ..."
HTTP_CODE=$(curl -fsSL -w "%{http_code}" "$ASSET_URL" -o "$TMPDIR/release.tar.gz" 2>/dev/null) || true
if [ ! -s "$TMPDIR/release.tar.gz" ] || [ "$HTTP_CODE" = "404" ]; then
    echo "[context_guard] Error: release asset not found at ${ASSET_URL}"
    echo "  Available releases: https://github.com/${REPO_OWNER}/${REPO_NAME}/releases"
    exit 1
fi

echo "[context_guard] Extracting ..."
tar -xzf "$TMPDIR/release.tar.gz" -C "$TMPDIR"

# The tarball extracts to context-guard-vX.Y.Z/
REPO_DIR="$TMPDIR/context-guard-${TAG}"

if [ ! -f "$REPO_DIR/install.sh" ]; then
    echo "[context_guard] Error: install.sh not found in archive."
    exit 1
fi

# --- Run the real installer ---
echo "[context_guard] Running installer ..."
bash "$REPO_DIR/install.sh"

echo "[context_guard] Temporary files cleaned up."
