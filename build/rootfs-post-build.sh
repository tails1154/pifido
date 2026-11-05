#!/bin/sh
set -eu

# PiFIDO is USB-only.  Buildroot's default BusyBox startup helpers would
# otherwise probe networking, start daemons, and attempt module loading before
# the authenticator.  Keep the generated init/rc scripts and entropy seeding,
# but remove only these unrelated services.
rm -f "$TARGET_DIR/etc/init.d/S01syslogd"
rm -f "$TARGET_DIR/etc/init.d/S02klogd"
rm -f "$TARGET_DIR/etc/init.d/S11modules"
rm -f "$TARGET_DIR/etc/init.d/S40network"
rm -f "$TARGET_DIR/etc/init.d/S50crond"
# The USB-key image has a single CTAPHID interface. Do not carry the former
# MTP responder or composite-console artifacts into the initramfs.
rm -f "$TARGET_DIR/etc/init.d/S01mtp" "$TARGET_DIR/usr/bin/umtprd"
rm -rf "$TARGET_DIR/etc/umtprd"
# The native C authenticator is the only runtime. Remove artifacts left by
# earlier Java-image builds even when Buildroot is reused incrementally.
rm -f "$TARGET_DIR/usr/lib/pifido/pi-zero-security-key.jar"
rm -f "$TARGET_DIR/opt-pifido.jar" "$TARGET_DIR/pifido-java.log"
rm -rf "$TARGET_DIR/usr/lib/zulu" "$TARGET_DIR/usr/lib/jvm"
# Keep the Raspberry Pi Zero W kernel modules supplied by the overlay.  The
# runtime kernel is the matching Raspberry Pi firmware kernel, so removing
# these modules prevents dwc2/libcomposite from creating a UDC and makes MTP
# fail with ENODEV (-19).
