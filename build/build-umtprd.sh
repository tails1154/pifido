#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BUILDROOT_DIR=${BUILDROOT_DIR:-"$ROOT/.buildroot-2025.11"}
CC=${CC:-"$BUILDROOT_DIR/output/host/bin/arm-linux-gcc"}

[ -x "$CC" ] || { echo "missing cross compiler: $CC" >&2; exit 1; }

make -C "$ROOT/vendor/uMTP-Responder" \
    CC="$CC" CFLAGS='-I./inc -Wall -O3' LDFLAGS='-lpthread -lrt'
install -D -m 0755 "$ROOT/vendor/uMTP-Responder/umtprd" \
    "$ROOT/build/rootfs-overlay/usr/bin/umtprd"

echo "installed ARM uMTP responder"
