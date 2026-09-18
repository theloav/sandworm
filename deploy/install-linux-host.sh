#!/usr/bin/env bash
# Run on a dedicated Ubuntu/Debian host. Does not launch samples.
set -euo pipefail
if [[ $EUID -ne 0 ]]; then
  echo "Run with sudo on the dedicated sandbox host." >&2
  exit 1
fi
apt-get update
apt-get install -y qemu-system-x86 qemu-utils genisoimage python3-venv
echo 'Host dependencies installed. Run sandworm sandbox-build as an unprivileged user.'
