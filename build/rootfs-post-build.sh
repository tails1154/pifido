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
rm -rf "$TARGET_DIR/lib/modules"
