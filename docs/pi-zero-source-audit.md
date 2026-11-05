# Pi Zero W FIDO2 source audit

Audited on 2026-11-04 before adopting code.

## `mphi-rc/pi-zero-security-key`

- Commit: `483b0055eb7165e8d94f94e92e1af1ada0bf4aaa` (2020-04-07), Apache-2.0.
- It contains a CTAPHID packet implementation, CTAP2 `getInfo`, `makeCredential`, `getAssertion`, ES256 credential signing, PIN protocol code, and seven Java unit-test files. Its ConfigFS gadget descriptor uses FIDO usage page `0xF1D0` and 64-byte reports.
- The source defaults to `AlwaysAllowUserVerifier`, advertises user presence as available, and does not implement CTAP reset or `getNextAssertion`. It reports resident keys as unsupported. Its credential/config JSON is written asynchronously without an atomic replace or restrictive file mode.
- The optional physical UI targets an Adafruit OLED bonnet, not an ordinary GPIO button. The Gradle wrapper is 5.6.2; its test task fails on the build host's Java 27 because the bundled Groovy cannot initialize.
- This is the most complete licensed base, but it needs a fail-closed GPIO verifier, durable credential writes, a minimal-runtime build path, and CTAP coverage fixes before use.

## `AdityaMitra5102/RPi-FIDO2-Security-Key`

- Commit: `5f332e39a22bad2042c787c904a41f0643e18eba` (2025-02-22). The repository has no license file, so its code is not being copied into this project.
- It has Python USB gadget setup and handlers for basic CTAP2 operations, but it reports `uv=true` and sets UP/UV flags without actual verification, has no CTAP `clientPIN` handler, stores keys in cleartext with ordinary writes, logs raw HID/CBOR bytes, and its CTAPHID error path calls a function with a missing argument. Its configfs HID report length is 8 while the report descriptor specifies 64-byte reports.
- The installer performs a full OS upgrade, appends boot configuration without backup, installs systemd units, and reboots; it does not meet the requested minimal initramfs architecture.

## Build host / removable media

- Host: Arch Linux x86_64. Buildroot 2026.08 supports `raspberrypi0w_defconfig`, ARM1176, and the requested BusyBox-based image path. The checked-out Buildroot revision is `d5180309b1b66ef3b8eaccca70ad69be8e0729a1`.
- `lsblk` found a 29.1 GiB removable card-reader medium at `/dev/sdd`, with a single FAT partition labeled `PS4`. It is not positively identifiable as the old Raspberry Pi installation, so it is not an authorized flash target. `/dev/sdc` is the same reader's empty LUN.

## Design consequences

The Pi has no secure element. Credential keys will persist on a dedicated ext4 SD partition with root-only permissions, synchronous writes, and crash-consistent replacement. They are necessarily exposed if an attacker removes and reads the card. The production image uses a two-wire GPIO26-to-GND presence contact with debounce and release-before-next-request; automatic user presence is disabled. WebUSB management will require a management PIN and an explicit confirmation for deletion. Reset and private-key export remain disabled.
