# Repository Guidelines

## Project Structure

- `native/` contains the userspace C CTAP2/CTAPHID daemon, CBOR handling,
  credential store, cryptography, and host tests.
- `build/` contains the Buildroot image script, minimal kernel fragments,
  BusyBox init scripts, USB gadget setup, and safe SD-card flashing tools.
- `buildroot-package/` defines the custom Buildroot package that cross-compiles
  and installs `pifido-native`.
- `docs/` contains source audits, wiring notes, and WebUSB design material.
- `vendor/` contains audited upstream source; avoid changing it unless the
  change is explicitly required and documented.
- Generated Buildroot output lives under `.buildroot-2025.11/` and final images
  under `output/images/`; do not commit generated artifacts or credentials.

## Build, Test, and Development Commands

```sh
make -C native clean test                 # host self-tests and store tests
make -C native pifido-native             # build the host daemon
./build/build-image.sh                    # build the bootable SD image
qemu-arm -L .buildroot-2025.11/output/target \
  .buildroot-2025.11/output/target/usr/bin/pifido-native --self-test
```

The image script builds the ARM kernel, native package, initramfs, firmware,
and `output/images/sdcard.img`. Flash only a positively identified removable
device with `sudo ./build/flash-sd.sh /dev/disk/by-id/...`.

## Coding Style and Naming

Use C11, four-space indentation, `snake_case` for functions and variables, and
descriptive `PIFIDO_`-prefixed public interfaces. Keep protocol parsing and
cryptography separate from transport code. Shell scripts use POSIX `sh`,
`set -eu`, quoted paths, and explicit safety checks. Run `git diff --check`
before committing.

## Testing Guidelines

Add deterministic unit coverage to `native/store_test.c` or a focused test
binary. Test credential persistence, counter updates, CBOR framing, and crypto
verification without printing secrets. Hardware USB enumeration and Chrome
WebAuthn tests must be clearly reported as hardware tests and must not be
claimed as passed from host or QEMU results.

## Commits and Pull Requests

Use short imperative commit subjects, for example `Fix HID descriptor setup`.
Keep commits focused. Pull requests should describe the runtime or image
impact, list commands and hardware tests run, include image hashes when an
image changes, and explicitly call out anything not verified on a real Pi or
Chromebook. Never include private keys, credential stores, or SD-card dumps.

## Security and Flashing

Credential writes must remain crash-consistent and restrictive. Do not log
private keys, PINs, HID payloads, or authentication secrets. Never use a raw
`dd` target guessed from `/dev/sdX`; use the guarded flashing script and stable
device identifiers.
