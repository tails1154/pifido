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
make -C "$BUILDROOT_DIR" -j"$(nproc)"

# Keep the kernel small: the complete runtime is supplied as an external
# initramfs. The overlay archive is appended after the base rootfs so its
# current authenticator JAR and startup files override the base copies.
cat "$BUILDROOT_DIR/output/images/rootfs.cpio.gz" "$PROJECT_ROOT/pifido-update.cpio.gz" \
    > "$BUILDROOT_DIR/output/images/pifido-full.cpio.gz"
GENIMAGE_CFG="$BUILDROOT_DIR/output/images/genimage.cfg"
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
