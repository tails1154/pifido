# Piannaple network sensor

The Pi 3B+ remains the touchscreen controller. A second Pi can run Kali as a
headless, authorized network-auditing sensor. `piannaple-sensor-bootstrap.sh`
installs a dedicated SSH key, Avahi/mDNS, and lightweight network tools after
Kali has booted and SSH is reachable.

The private key is kept at `~/.ssh/piannaple-sensor_ed25519` by default and is
never stored in this repository.

```sh
./network/piannaple-sensor-bootstrap.sh kali@192.168.1.50 netsensor
ssh -i ~/.ssh/piannaple-sensor_ed25519 kali@netsensor.local
```

Use scanning and capture only on networks and devices you own or have explicit
permission to assess.
