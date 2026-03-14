#!/usr/bin/env bash
# context guard remote installer — pipe-friendly bootstrap
# Usage: curl -fsSL https://raw.githubusercontent.com/REPO_OWNER/REPO_NAME/main/install-remote.sh | bash

set -e

REPO_OWNER="REPO_OWNER"
REPO_NAME="REPO_NAME"
BRANCH="main"
TARBALL_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/archive/refs/heads/${BRANCH}.tar.gz"

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

echo "[context_guard] Downloading from ${TARBALL_URL} ..."
curl -fsSL "$TARBALL_URL" -o "$TMPDIR/repo.tar.gz"

echo "[context_guard] Extracting ..."
tar -xzf "$TMPDIR/repo.tar.gz" -C "$TMPDIR"

# GitHub tarballs extract to <repo>-<branch>/
REPO_DIR="$TMPDIR/${REPO_NAME}-${BRANCH}"

if [ ! -f "$REPO_DIR/install.sh" ]; then
    echo "[context_guard] Error: install.sh not found in archive. Check REPO_OWNER/REPO_NAME."
    exit 1
fi

# --- Run the real installer ---
echo "[context_guard] Running installer ..."
bash "$REPO_DIR/install.sh"

echo "[context_guard] Temporary files cleaned up."
