#!/usr/bin/env bash
# Prepare the official CAPE installer at a reviewable, pinned revision.
# Installer execution is explicit because it reconfigures the dedicated host.
set -euo pipefail
if [[ $# -lt 2 || ! $1 =~ ^[0-9a-f]{40}$ ]]; then
  echo 'Usage: install-cape-host.sh FULL_COMMIT_SHA NEW_CHECKOUT_DIR [--install]' >&2
  exit 1
fi
cape_revision=$1
cape_checkout=$2
if [[ -e $cape_checkout ]]; then
  echo 'Checkout directory must not already exist.' >&2
  exit 1
fi
git clone --no-checkout https://github.com/kevoreilly/CAPEv2.git "$cape_checkout"
git -C "$cape_checkout" checkout --detach "$cape_revision"
echo "Pinned CAPE checkout prepared: $cape_checkout"
if [[ ${3:-} == --install ]]; then
  cd "$cape_checkout"
  sudo bash installer/cape2.sh base cape
else
  echo 'Review installer/cape2.sh and the CAPE deployment guide before running its base installer.'
fi
