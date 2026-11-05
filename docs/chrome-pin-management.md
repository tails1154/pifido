# Chrome PIN management

The native authenticator exposes CTAP2 clientPIN protocol 1. Chromium first
sends a credential-management touch probe (`makeCredential` with an empty
`pinAuth`). The authenticator must answer this probe with
`CTAP2_ERR_PIN_AUTH_INVALID` (`0x33`); `0x14` (`missing parameter`) leaves
Chromium waiting and prevents the PIN UI from opening.

After the probe, Chrome's **Manage security keys → Change PIN** flow uses:

1. `clientPIN` subcommand 1 (`getRetries`)
2. `clientPIN` subcommand 2 (`getKeyAgreement`)
3. `clientPIN` subcommand 4 (`changePIN`), authenticated with the current PIN
4. A credential-management probe or test request

Expected diagnostic lines are:

```text
CTAP makeCredential PIN/UV status=0x33
CTAP clientPIN status=0x00 response_bytes=...
```

The device must be rebooted after replacing `pifido-full.cpio.gz`. A
`configured=yes` startup line means a PIN already exists; changing it requires
the current PIN. The default for a fresh state is `1154`.
