# Piannaple touchscreen home screen

This is the Piannaple Kivy `ScreenManager` application for the Pi 3B+ touchscreen.
It shows Wi-Fi, Bluetooth, system load, clock, refresh, settings, and a guarded
shutdown control. It does not start or expose the old FIDO2 authenticator.

On Raspberry Pi OS Lite/Desktop with Kivy installed:

```sh
sudo install -d /opt/piannaple
sudo install -m 0755 home_screen.py /opt/piannaple/home_screen.py
sudo install -m 0644 piannaple.service /etc/systemd/system/piannaple.service
sudo systemctl daemon-reload
sudo systemctl enable --now piannaple.service
```

Shutdown is intentionally disabled unless `PIFIDO_ALLOW_SHUTDOWN=1` is added
to the service environment.
