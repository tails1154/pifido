#!/bin/sh
set -eu

# Update selected boot files without reformatting or rewriting the SD image.
# Usage: ./build/update-card-files.sh [file ...]

TARGET=${PIFIDO_BOOT_DEVICE:-/dev/disk/by-id/usb-Generic_MassStorageClass_000000001539-0:1-part1}
MOUNT=/mnt/piannaple-boot-update

if [ "$#" -eq 0 ]; then
    set -- /tmp/piannaple-mtp-rootfs.cpio.gz
fi

sudo mkdir -p "$MOUNT"
sudo mount -o rw -- "$TARGET" "$MOUNT"
trap 'sudo umount "$MOUNT"' EXIT

for source in "$@"; do
    case "$source" in
        */pifido-full.cpio.gz|*/piannaple-mtp-rootfs.cpio.gz) destination="$MOUNT/pifido-full.cpio.gz" ;;
        */config.txt|*/rpi-config.txt) destination="$MOUNT/config.txt" ;;
        */cmdline.txt) destination="$MOUNT/cmdline.txt" ;;
        */zImage) destination="$MOUNT/kernel.img" ;;
        */bcm2708-rpi-zero-w.dtb) destination="$MOUNT/bcm2708-rpi-zero-w.dtb" ;;
        *) echo "refusing unlisted boot file: $source" >&2; exit 2 ;;
    esac
    sudo install -m 0644 "$source" "$destination"
done
sync
