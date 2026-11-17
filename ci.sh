#!/usr/bin/env bash
# Bastion CI: formatting, lints and the full test suite (unit, integration, loopback RDP, UI snapshots).
# Usage: ./ci.sh            run everything
#        UPDATE_SNAPSHOTS=1 ./ci.sh   accept intentional UI changes
set -euo pipefail
cd "$(dirname "$0")"

step() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }

step "Formatting"
cargo fmt --all -- --check

step "Clippy (deny warnings)"
cargo clippy --workspace --all-targets -- -D warnings

step "Loopback test server"
cargo build --quiet --manifest-path tools/test-server/Cargo.toml

step "Tests"
cargo test --workspace

printf '\n\033[1;32mAll checks passed.\033[0m\n'
