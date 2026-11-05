#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILDROOT_DIR=${BUILDROOT_DIR:-$PROJECT_ROOT/.buildroot-2025.11}
OUTPUT_DIR=${OUTPUT_DIR:-"$PROJECT_ROOT/output"}
export GRADLE_USER_HOME=${GRADLE_USER_HOME:-$PROJECT_ROOT/.gradle-home}
export JAVA_TOOL_OPTIONS="${JAVA_TOOL_OPTIONS:-} -Djava.io.tmpdir=$PROJECT_ROOT/.java-tmp"
mkdir -p "$GRADLE_USER_HOME" "$PROJECT_ROOT/.java-tmp"

if [ ! -d "$BUILDROOT_DIR" ]; then
    git clone --depth 1 --branch 2025.11 https://gitlab.com/buildroot.org/buildroot.git "$BUILDROOT_DIR"
fi

JAVA_HOME=${JAVA_HOME:-/usr/lib/jvm/java-8-openjdk}
JAVA_HOME="$JAVA_HOME" "$PROJECT_ROOT/vendor/pi-zero-security-key/gradlew" -p "$PROJECT_ROOT/vendor/pi-zero-security-key" shadowJar --no-daemon

mkdir -p "$BUILDROOT_DIR/board/pifido-overlay/usr/lib/pifido"
cp -a "$PROJECT_ROOT/build/rootfs-overlay/." "$BUILDROOT_DIR/board/pifido-overlay/"
cp "$PROJECT_ROOT/vendor/pi-zero-security-key/build/libs/pi-zero-security-key-0.1.0.jar" \
   "$BUILDROOT_DIR/board/pifido-overlay/usr/lib/pifido/pifido.jar"

# Prebuilt Azul Zulu 11 ARM32 hard-float runtime with ARMv6 support.
JAVA_URL=${JAVA_URL:-https://cdn.azul.com/zulu/bin/zulu11.90.19-ca-jdk11.0.32-linux_aarch32hf.tar.gz}
JAVA_CACHE="$BUILDROOT_DIR/dl/zulu11-armv6.tar.gz"
mkdir -p "$(dirname "$JAVA_CACHE")"
[ -s "$JAVA_CACHE" ] || curl --fail --location --retry 3 --output "$JAVA_CACHE" "$JAVA_URL"
JAVA_TMP=$(mktemp -d -p "$BUILDROOT_DIR" pifido-zulu.XXXXXX)
tar -xf "$JAVA_CACHE" -C "$JAVA_TMP"
JAVA_DIR=$(find "$JAVA_TMP" -mindepth 1 -maxdepth 1 -type d | head -n 1)
mkdir -p "$BUILDROOT_DIR/board/pifido-overlay/usr/lib/zulu"
chmod -R u+rwX "$BUILDROOT_DIR/board/pifido-overlay/usr/lib/zulu" 2>/dev/null || true
cp -a "$JAVA_DIR/." "$BUILDROOT_DIR/board/pifido-overlay/usr/lib/zulu/"
rm -rf "$BUILDROOT_DIR/board/pifido-overlay/usr/lib/zulu/include" "$BUILDROOT_DIR/board/pifido-overlay/usr/lib/zulu/jmods" "$BUILDROOT_DIR/board/pifido-overlay/usr/lib/zulu/demo" "$BUILDROOT_DIR/board/pifido-overlay/usr/lib/zulu/man" "$BUILDROOT_DIR/board/pifido-overlay/usr/lib/zulu/lib/src.zip"
rm -f "$BUILDROOT_DIR/board/pifido-overlay/usr/lib/zulu/bin/javac" "$BUILDROOT_DIR/board/pifido-overlay/usr/lib/zulu/bin/javadoc" "$BUILDROOT_DIR/board/pifido-overlay/usr/lib/zulu/bin/javap" "$BUILDROOT_DIR/board/pifido-overlay/usr/lib/zulu/bin/jar"
rm -rf "$JAVA_TMP"
chmod 0755 "$BUILDROOT_DIR/board/pifido-overlay/etc/init.d/S01pifido"
chmod 0755 "$BUILDROOT_DIR/board/pifido-overlay/init"

make -C "$BUILDROOT_DIR" raspberrypi0w_defconfig
cat >> "$BUILDROOT_DIR/.config" <<EOF
BR2_TARGET_ROOTFS_CPIO_GZIP=y
BR2_TARGET_ROOTFS_CPIO=y
BR2_TARGET_ROOTFS_EXT2_SIZE="512M"
BR2_ROOTFS_OVERLAY="$BUILDROOT_DIR/board/pifido-overlay"
BR2_PACKAGE_RPI_FIRMWARE_CONFIG_FILE="$PROJECT_ROOT/build/rpi-config.txt"
BR2_PACKAGE_OPENJDK=n
BR2_PACKAGE_PYTHON3=n
BR2_PACKAGE_MBEDTLS=y
BR2_PACKAGE_TINYCBOR=y
BR2_PACKAGE_OPENSSL=y
BR2_TARGET_GENERIC_GETTY=n
BR2_TARGET_GENERIC_ISSUE="PiFIDO"
BR2_LINUX_KERNEL_CONFIG_FRAGMENT_FILES="$PROJECT_ROOT/build/kernel.fragment"
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
