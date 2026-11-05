#!/bin/sh
set -eu

PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
IMAGE=${PIFIDO_IMAGE:-"$PROJECT_ROOT/output/images/sdcard.img"}
TARGET=${1:-}

[ "$(id -u)" -eq 0 ] || { echo 'run as root (sudo)' >&2; exit 2; }
[ -n "$TARGET" ] || { echo "usage: $0 /dev/disk/by-id/removable-card" >&2; exit 2; }
[ -f "$IMAGE" ] || { echo "image not found: $IMAGE" >&2; exit 2; }
[ -e "$TARGET" ] || { echo "device not found: $TARGET" >&2; exit 2; }

DEV=$(readlink -f -- "$TARGET")
TYPE=$(lsblk -dnro TYPE -- "$DEV")
RM=$(lsblk -dnro RM -- "$DEV")
TRAN=$(lsblk -dnro TRAN -- "$DEV")
SIZE=$(lsblk -dnro SIZE -- "$DEV")
MODEL=$(lsblk -dnro MODEL -- "$DEV")
SERIAL=$(lsblk -dnro SERIAL -- "$DEV")
[ "$TYPE" = disk ] || { echo "refusing non-disk target: $DEV" >&2; exit 3; }
[ "$RM" = 1 ] || { echo "refusing non-removable target: $DEV" >&2; exit 3; }
[ "$TRAN" = usb ] || { echo "refusing non-USB target: $DEV" >&2; exit 3; }

ROOT=$(findmnt -no SOURCE / 2>/dev/null || true)
ROOTDISK=$(lsblk -ndo PKNAME -- "$ROOT" 2>/dev/null || true)
[ "$ROOTDISK" != "$(basename -- "$DEV")" ] || { echo 'refusing the running system disk' >&2; exit 3; }

echo "Target: $DEV"
echo "Model:  $MODEL"
echo "Serial: $SERIAL"
echo "Size:   $SIZE"
echo "Image:  $IMAGE ($(stat -c '%s bytes' "$IMAGE"))"

for part in $(lsblk -lnpo NAME,TYPE -- "$DEV" | awk '$2 == "part" {print $1}'); do
    if findmnt -rn -S "$part" >/dev/null 2>&1; then
        echo "refusing mounted partition: $part" >&2
        exit 4
    fi
done

sync
dd if="$IMAGE" of="$DEV" bs=4M status=progress conv=fsync
sync

IMAGE_HASH=$(sha256sum "$IMAGE" | awk '{print $1}')
IMAGE_BYTES=$(stat -c '%s' "$IMAGE")
[ $((IMAGE_BYTES % 512)) -eq 0 ] || { echo 'image size is not sector aligned' >&2; exit 5; }
DEVICE_HASH=$(dd if="$DEV" bs=512 count=$((IMAGE_BYTES / 512)) status=none | sha256sum | awk '{print $1}')
[ "$IMAGE_HASH" = "$DEVICE_HASH" ] || {
    echo "verification failed: image=$IMAGE_HASH device=$DEVICE_HASH" >&2
    exit 5
}
echo "flash verified: $IMAGE_HASH"
