# WebUSB management

The companion manager will use a vendor-specific WebUSB interface separate
from the FIDO HID interface. It will provide credential metadata, deletion,
diagnostics, and user-presence mode.

`requirePhysicalPresence` is enabled by default. Disabling it requires the
management PIN and a typed confirmation. The page must display a persistent
warning while automatic user presence is enabled. Re-enabling physical
presence does not require the GPIO contact, so a lost cable can be recovered
from the manager. Private keys are never sent to the browser, and reset,
credential export, and arbitrary private-key import are disabled.
