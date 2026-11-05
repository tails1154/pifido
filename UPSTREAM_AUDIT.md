# Upstream audit: `joostd/fido-hybrid-transport`

Audited 2026-11-04 at commit `a890158` (shallow clone at `/tmp/fido-hybrid-transport`).

## What it implements

- `authenticator/main.py` acts as a caBLE/FIDO hybrid responder: it decodes a `FIDO:/...` URI, derives BLE service data and a Noise PSK, advertises through BlueZ D-Bus, registers/connects a WebSocket tunnel, and dispatches CTAP `getInfo`, `makeCredential`, `getAssertion`, and `selection` commands.
- The built-in software authenticator creates P-256 credentials with Python `secrets` and `cryptography`, then signs assertions. It stores credentials in a JSON file.
- `client/main.py` is a command-line test client for those commands and a relay for USB keys. It is not the Chromebook browser.
- `tunnel/main.py` is an optional WebSocket relay. The default authenticator mode registers with Google's undocumented caBLE tunnel service; `self` requires a public TLS endpoint and certificate.
- The authenticator README describes Raspberry Pi OS/BlueZ BLE advertising as supported, but does not establish Chrome compatibility for this particular build.

## Dependencies and setup stated upstream

Python 3.13+ in the authenticator's `pyproject.toml`; `cbor2`, `cryptography`, `fido2`, and `websockets`, plus OS packages `libdbus-1-dev`, `libglib2.0-dev`, `python3-gi`, `python3-dbus`, and `python3-cairo`. The BLE code depends on BlueZ's `LEAdvertisingManager1` D-Bus API. Upstream suggests a venv with system site packages.

## Gaps that block deployment as requested

- There is no physical-presence/approval callback. `handle_make_credential` and `handle_get_assertion` return success without waiting for a person's action; assertion flags are set to UP and UV in code. This violates the requested explicit approval requirement.
- The credential JSON stores unencrypted PKCS#8 private keys. Its write path does not set restrictive permissions or use an atomic replacement.
- Debug logging explicitly includes raw CTAP messages and key/session material. Debug mode is unsafe for ordinary operation and logging must be redesigned before use.
- The code reports UV in `getInfo` based on a comment's hybrid convention, not an implemented local user-verification step. This project has not been proven to match browser expectations or the requested physical approval semantics.
- The authenticator expects a decoded URI on its command line. It has no camera scanner, Kivy interface, request queue, timeout UI, or display power management.
- The default tunnel depends on undocumented Google infrastructure. The alternative self-hosted options require a reachable endpoint and TLS setup. Wi-Fi presence alone does not provide public reachability.
- The project has no installation/uninstallation flow for this device and no Chrome/webauthn.io end-to-end evidence.

## Alternative checked

`lachlan-ibm/soft-fido2` implements a software CTAP2/WebAuthn authenticator and has a Linux UHID system-authenticator path, with optional TPM support. Its documented transport is local Linux/USB-style integration; it does not supply caBLE hybrid transport for a Chromebook. It therefore does not resolve the missing hybrid/browser transport and is not a drop-in replacement.

## Verification actually performed

- Upstream authenticator source passed `python -m py_compile` on this workstation.
- SSH works as `tails1154` with `/home/tails1154/.ssh/id_ecdsa_mc` (the default `id_ed25519` key is not authorized).
- The Pi reports Raspberry Pi OS 13 / Python 3.13.5 on armv7l. Bluetooth and NetworkManager are active; the controller supports BLE advertising. A temporary valid caBLE advertisement was accepted by BlueZ (`ActiveInstances=1`).
- `rpicam-hello --list-cameras` detects the CSI IMX219 sensor. Kivy 2.3.1 is installed, but Picamera2 and the upstream CTAP Python packages are absent. The DSI backlight is exposed as `/sys/class/backlight/10-0045` at brightness 255/255. No `/sys/class/power_supply` device reports battery telemetry.
- A temporary Python test environment was created under `/tmp` without system package changes. The upstream client and authenticator did not complete a hybrid handshake: when both ran on the Pi, the client scanner did not discover the Pi's active advertisement. The session was stopped and temporary session material/logs were deleted. This does not determine whether a separate Chromebook can discover it.
- CTAP `getInfo` over a completed hybrid handshake, credential creation/assertion, Chrome registration/login on `webauthn.io`, persistence after reboot, and physical approval/denial remain untested. Browser and human presence are necessary for the latter tests.

No authenticator code has been deployed or represented as working. The next milestone needs a separate browser/client to exercise caBLE and a safe physical-approval callback before CTAP credential operations can be used. The Chromebook's WebAuthn test flow also requires an on-device QR scan and explicit physical approval.
