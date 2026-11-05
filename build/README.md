# Pi Zero W image build

This build uses Buildroot's `raspberrypi0w_defconfig`, BusyBox init, the
Raspberry Pi boot firmware, a reduced ARM1176 kernel, ConfigFS USB HID, and the
native ARM C CTAP2 implementation. No JVM, desktop, network, or Python runtime
is included.

The runtime mounts `/dev/mmcblk0p2` at `/data`, uses `commit=1,data=journal`,
and the authenticator synchronously fsyncs a temporary credential file before
atomic replacement and directory fsync. This is designed for abrupt USB power
loss, but no filesystem can guarantee recovery after physical media failure.

Run `./build-image.sh`. The result is `output/images/sdcard.img`. The image
contains the native daemon at `/usr/bin/pifido-native` and creates only one
FIDO HID gadget (`0x1209:0xf1d0`) at boot.

To flash a removable card, use the stable `/dev/disk/by-id` path and inspect it
beforehand:

```sh
sudo ./build/flash-sd.sh /dev/disk/by-id/usb-Generic_MassStorageClass_000000001539-0:1
```

The script refuses non-removable disks, mounted partitions, and devices without
the expected removable-disk properties.
