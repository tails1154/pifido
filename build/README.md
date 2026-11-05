# Pi Zero W image build

This build uses Buildroot's `raspberrypi0w_defconfig`, BusyBox init, the
Raspberry Pi boot firmware, a reduced ARM1176 kernel, ConfigFS USB HID, and the
native ARM C CTAP2 implementation. No JVM, desktop, network, or Python runtime
is included.

The runtime mounts `/dev/mmcblk0p2` at `/data`, uses `commit=1,data=journal`,
and the authenticator synchronously fsyncs a temporary credential file before
atomic replacement and directory fsync. This is designed for abrupt USB power
loss, but no filesystem can guarantee recovery after physical media failure.

Transport diagnostics append to `/data/log.log` with mode `0600` and a
synchronous write per event. They record CTAPHID command names, framing headers,
lengths, and CTAP status codes. Request and response payload bytes are redacted
because they can contain PIN material, credential IDs, and authentication
hashes. If `/data` failed to mount, the log warns that it is volatile.

The native daemon provisions PIN `1154` on first boot if `/data/pifido/pin.bin`
does not exist. Only the CTAP PIN verifier and retry counter are persisted, in a
mode-`0600` crash-consistent file. CTAP PIN protocol 1 supports PIN verification
and PIN changes; eight failed attempts permanently block PIN use until the
administrator manually resets the local PIN state. CTAP authenticator reset is
not implemented. Removing `pin.bin` reinitializes the default PIN. The four-digit
PIN is weak, and the Pi SD card does not provide a secure element against
offline PIN guessing after physical theft.

The PIN protocol unit test can be built and run on the build computer with
`make -C native pin-test && ./native/pin-test`. It covers PIN verification,
retry persistence, token authorization, and PIN change using a temporary file.

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
