# Pi Zero W image build

This build uses Buildroot's `raspberrypi0w_defconfig`, BusyBox init, the
Raspberry Pi boot firmware, the ARM1176 kernel, ConfigFS USB HID, and the
audited Java CTAP2 implementation. The Java runtime is a prebuilt Azul Zulu 11
ARM32 hard-float archive with ARMv6 support; the image build does not compile
OpenJDK or Python for the target.

The runtime mounts `/dev/mmcblk0p2` at `/data`, uses `commit=1,data=journal`,
and the authenticator synchronously fsyncs a temporary credential file before
atomic replacement and directory fsync. This is designed for abrupt USB power
loss, but no filesystem can guarantee recovery after physical media failure.

Run `./build-image.sh`. The result is `output/images/sdcard.img`.
