#!/usr/bin/env bash
# Builds Bastion in release mode and installs it for the current user (~/.local).
# Uninstall: ./install.sh --uninstall
set -euo pipefail
cd "$(dirname "$0")"
PREFIX="${PREFIX:-$HOME/.local}"
BIN="$PREFIX/bin"; APPS="$PREFIX/share/applications"; ICONS="$PREFIX/share/icons/hicolor/scalable/apps"; MIME="$PREFIX/share/mime"

if [[ "${1:-}" == "--uninstall" ]]; then
  rm -f "$BIN/bastion" "$APPS/bastion.desktop" "$ICONS/bastion.svg" "$MIME/packages/bastion-rdp.xml"
  update-mime-database "$MIME" 2>/dev/null || true
  update-desktop-database "$APPS" 2>/dev/null || true
  echo "Bastion uninstalled (your connections in ~/.config/bastion and keyring passwords were kept)."
  exit 0
fi

cargo build --release -p bastion
# Cargo does not always build into ./target (CARGO_TARGET_DIR, build.target-dir): ask it where
# the binary went, so an old ./target/release/bastion is never installed in its place.
TARGET_DIR="$(cargo metadata --format-version 1 --no-deps | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')"
BUILT="$TARGET_DIR/release/bastion"
if [[ -z "$TARGET_DIR" || "$TARGET_DIR" == *\\* || ! -x "$BUILT" ]]; then
  echo "install.sh: cannot find the binary cargo just built (looked for '$BUILT'); nothing was installed." >&2
  exit 1
fi
install -Dm755 "$BUILT" "$BIN/bastion"
install -Dm644 packaging/bastion.desktop "$APPS/bastion.desktop"
install -Dm644 packaging/bastion.svg "$ICONS/bastion.svg"
install -Dm644 packaging/bastion-rdp.xml "$MIME/packages/bastion-rdp.xml"
update-mime-database "$MIME" 2>/dev/null || true
update-desktop-database "$APPS" 2>/dev/null || true
xdg-mime default bastion.desktop application/x-rdp 2>/dev/null || true
command -v kbuildsycoca6 >/dev/null && kbuildsycoca6 --noincremental >/dev/null 2>&1 || true
echo "Installed to $BIN/bastion. Find 'Bastion' in your app launcher; .rdp files now open with Bastion."
