# Optional two-wire presence contact

The device can use a simple momentary contact instead of automatic user
presence. Connect one wire to physical pin 37 (BCM GPIO26) and the other to a
nearby ground pin such as physical pin 39. Leave the contact open normally;
briefly connect the wires when Chrome asks for the key.

GPIO26 is configured as an input with the Raspberry Pi's internal pull-up. The
contact therefore carries only a small input current. Do not connect GPIO26 to
5 V and do not connect two GPIO outputs together. The software requires the
line to return high before accepting a later press, debounces it for 40 ms,
and times out after 8 seconds.

The production image enables the physical-contact verifier with
`-Dpifido.requireButton=true`. Automatic presence is disabled.
