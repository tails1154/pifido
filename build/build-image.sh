#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILDROOT_DIR=${BUILDROOT_DIR:-$PROJECT_ROOT/.buildroot-2025.11}
OUTPUT_DIR=${OUTPUT_DIR:-"$PROJECT_ROOT/output"}
if [ ! -d "$BUILDROOT_DIR" ]; then
    git clone --depth 1 --branch 2025.11 https://gitlab.com/buildroot.org/buildroot.git "$BUILDROOT_DIR"
fi

mkdir -p "$BUILDROOT_DIR/board/pifido-overlay/usr/lib/pifido"
# The build directory may have been used by the former Java image.  Remove
# only those known generated artifacts so they cannot survive into a native
# rebuild; no host or persistent credential data is touched.
rm -rf "$BUILDROOT_DIR/board/pifido-overlay/usr/lib/zulu"
rm -f "$BUILDROOT_DIR/board/pifido-overlay/usr/lib/pifido/pifido.jar"
cp -a "$PROJECT_ROOT/build/rootfs-overlay/." "$BUILDROOT_DIR/board/pifido-overlay/"
mkdir -p "$BUILDROOT_DIR/package/pifido-native"
cp -a "$PROJECT_ROOT/buildroot-package/pifido-native/." "$BUILDROOT_DIR/package/pifido-native/"
if ! grep -q 'source "package/pifido-native/Config.in"' "$BUILDROOT_DIR/package/Config.in"; then
    printf '\nsource "package/pifido-native/Config.in"\n' >> "$BUILDROOT_DIR/package/Config.in"
fi
chmod 0755 "$BUILDROOT_DIR/board/pifido-overlay/etc/init.d/S01pifido"
chmod 0755 "$BUILDROOT_DIR/board/pifido-overlay/usr/lib/pifido/setup-hid-gadget"
chmod 0755 "$BUILDROOT_DIR/board/pifido-overlay/init"
# The firmware package can retain an older config.txt between incremental
# builds. Seed the image-side copy before Buildroot's post-image hook runs so
# it contains exactly one kernel selector.
mkdir -p "$BUILDROOT_DIR/output/images/rpi-firmware"
install -D -m 0644 "$PROJECT_ROOT/build/rpi-config.txt" \
    "$BUILDROOT_DIR/output/images/rpi-firmware/config.txt"
sed -i '/^kernel=/d' "$BUILDROOT_DIR/output/images/rpi-firmware/config.txt"
printf '%s\n' 'kernel=kernel.img' >>"$BUILDROOT_DIR/output/images/rpi-firmware/config.txt"
# A previous image generation may have cached a config referring to
# kernel.img. Keep the generated boot layout aligned with Buildroot's zImage.
if [ -f "$BUILDROOT_DIR/output/images/genimage.cfg" ]; then
    sed -i 's/"kernel.img"/"zImage"/g' "$BUILDROOT_DIR/output/images/genimage.cfg"
    sed -i '/^[[:space:]]*"",[[:space:]]*$/d' "$BUILDROOT_DIR/output/images/genimage.cfg"
fi
# Buildroot's firmware helper may append its default kernel=kernel.img line;
# keep that name as a symlink so post-image generation always sees the current
# zImage without duplicating the kernel.
ln -sfn zImage "$BUILDROOT_DIR/output/images/kernel.img"

make -C "$BUILDROOT_DIR" raspberrypi0w_defconfig
cat >> "$BUILDROOT_DIR/.config" <<EOF
BR2_TARGET_ROOTFS_CPIO_GZIP=y
BR2_TARGET_ROOTFS_CPIO=y
BR2_TARGET_ROOTFS_EXT2_SIZE="512M"
BR2_ROOTFS_OVERLAY="$BUILDROOT_DIR/board/pifido-overlay"
BR2_ROOTFS_POST_BUILD_SCRIPT="$PROJECT_ROOT/build/rootfs-post-build.sh"
BR2_PACKAGE_RPI_FIRMWARE_CONFIG_FILE="$PROJECT_ROOT/build/rpi-config.txt"
BR2_PACKAGE_OPENJDK=n
BR2_PACKAGE_PYTHON3=n
BR2_PACKAGE_MBEDTLS=y
BR2_PACKAGE_TINYCBOR=y
BR2_PACKAGE_OPENSSL=y
BR2_PACKAGE_PIFIDO_NATIVE=y
BR2_TARGET_GENERIC_GETTY=n
BR2_TARGET_GENERIC_ISSUE="PiFIDO"
BR2_LINUX_KERNEL_CONFIG_FRAGMENT_FILES="$PROJECT_ROOT/build/kernel-minimal.fragment"
EOF
make -C "$BUILDROOT_DIR" olddefconfig
# Buildroot's local-package stamp does not notice edits to the source tree.
# Explicitly rebuild only the native authenticator so incremental image
# builds cannot silently embed a stale binary; kernel and toolchain objects
# remain cached.
make -C "$BUILDROOT_DIR" pifido-native-rebuild
make -C "$BUILDROOT_DIR" -j"$(nproc)"

# Buildroot may retain its stock firmware configuration when the source file
# changes without invalidating the firmware package stamp.  Install the exact
# boot files used by this image explicitly so the Pi firmware loads the
# external initramfs from the SD card.
install -D -m 0644 "$PROJECT_ROOT/build/rpi-config.txt" \
    "$BUILDROOT_DIR/output/images/rpi-firmware/config.txt"
install -D -m 0644 "$PROJECT_ROOT/build/cmdline-fast.txt" \
    "$BUILDROOT_DIR/output/images/rpi-firmware/cmdline.txt"
# The firmware config is installed again after Buildroot's post-image step;
# ensure the Raspberry Pi firmware still selects the kernel image. Without
# this line board/raspberrypi/post-image.sh emits an empty genimage entry and
# tries to copy the entire input directory into boot.vfat.
sed -i '/^kernel=/d' "$BUILDROOT_DIR/output/images/rpi-firmware/config.txt"
printf '%s\n' 'kernel=kernel.img' >>"$BUILDROOT_DIR/output/images/rpi-firmware/config.txt"

# Keep the kernel small: the complete native runtime is supplied as one
# external initramfs. Do not append the historical Java update archive: a
# second CPIO archive can override /init and S01pifido during unpacking.
cp "$BUILDROOT_DIR/output/images/rootfs.cpio.gz" \
    "$BUILDROOT_DIR/output/images/pifido-full.cpio.gz"
GENIMAGE_CFG="$BUILDROOT_DIR/output/images/genimage.cfg"
# Older generated configs can retain an empty boot-file entry. genimage treats
# it as the entire input directory, exhausts the FAT image, and fails with a
# misleading "Disk full" error. Remove only that invalid entry.
sed -i '/^[[:space:]]*"",[[:space:]]*$/d' "$GENIMAGE_CFG"
if ! grep -q 'pifido-full.cpio.gz' "$GENIMAGE_CFG"; then
    sed -i '/"zImage",/a\			"pifido-full.cpio.gz",' "$GENIMAGE_CFG"
fi
GENIMAGE_TMP=$(mktemp -d -p "$BUILDROOT_DIR" pifido-genimage.XXXXXX)
mkdir -p "$GENIMAGE_TMP/root" "$GENIMAGE_TMP/tmp"
"$BUILDROOT_DIR/output/host/bin/genimage" \
    --rootpath "$GENIMAGE_TMP/root" \
    --tmppath "$GENIMAGE_TMP/tmp" \
    --inputpath "$BUILDROOT_DIR/output/images" \
    --outputpath "$BUILDROOT_DIR/output/images" \
    --config "$GENIMAGE_CFG"

mkdir -p "$OUTPUT_DIR/images"
cp "$BUILDROOT_DIR/output/images/sdcard.img" "$OUTPUT_DIR/images/sdcard.img"
sha256sum "$OUTPUT_DIR/images/sdcard.img" | tee "$OUTPUT_DIR/images/sdcard.img.sha256"
