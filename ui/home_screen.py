#!/usr/bin/env python3
"""Lightweight touchscreen home screen for the Raspberry Pi 3B+."""

from __future__ import annotations

import os
import glob
import subprocess
import threading
import time
from datetime import datetime

from kivy.app import App
from kivy.clock import Clock
from kivy.core.window import Window
from kivy.lang import Builder
from kivy.properties import StringProperty
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.screenmanager import Screen, ScreenManager

from modules import discover


def discover_sensor_host():
    """Return the first Piannaple sensor advertised by Avahi."""
    try:
        result = subprocess.run(
            ("avahi-browse", "-rtp", "_piannaple-sensor._tcp"),
            check=False, capture_output=True, text=True, timeout=4,
        )
        for line in result.stdout.splitlines():
            fields = line.split(";")
            if len(fields) >= 8 and fields[0] == "=" and fields[7]:
                return fields[7]
    except (OSError, subprocess.SubprocessError):
        pass
    return os.environ.get("PIANNAPLE_SENSOR", "netsensor.local")


KV = r"""
<Button>:
    background_normal: ""
    background_down: ""
    background_color: (.10, .16, .23, 1) if self.state == "normal" else (.16, .28, .39, 1)
    color: .90, .95, 1, 1
    border: 0, 0, 0, 0
    padding: "12dp"

<TextInput>:
    background_normal: ""
    background_active: ""
    background_color: .08, .11, .16, 1
    foreground_color: .92, .95, 1, 1
    cursor_color: .35, .78, 1, 1
    padding: "14dp", "10dp"

<Label>:
    font_name: "Roboto"

<HomeScreen>:
    BoxLayout:
        orientation: "vertical"
        padding: "24dp"
        spacing: "18dp"
        canvas.before:
            Color:
                rgba: .035, .045, .065, 1
            Rectangle:
                pos: self.pos
                size: self.size
        Label:
            text: "PIANNAPLE"
            color: .35, .78, 1, 1
            font_size: "26sp"
            bold: True
            outline_color: .02, .08, .13, 1
            outline_width: 1
            size_hint_y: None
            height: "42dp"
        Label:
            text: "AUTHORIZED NETWORK AUDITING CONSOLE"
            color: .65, .7, .78, 1
            font_size: "16sp"
            size_hint_y: None
            height: "30dp"
        GridLayout:
            cols: 4
            spacing: "10dp"
            size_hint_y: None
            height: "82dp"
            StatusCard:
                title: "WI-FI"
                value: root.wifi_status
            StatusCard:
                title: "BLUETOOTH"
                value: root.bluetooth_status
            StatusCard:
                title: "SYSTEM"
                value: root.system_status
            StatusCard:
                title: "TIME"
                value: root.clock_status
        Label:
            text: "NETWORK TOOLS"
            color: .45, .55, .68, 1
            font_size: "14sp"
            bold: True
            size_hint_y: None
            height: "24dp"
        GridLayout:
            cols: 2
            spacing: "12dp"
            size_hint_y: None
            height: "132dp"
            Button:
                text: "NMAP\nQUICK SCAN"
                font_size: "18sp"
                on_release: root.open_tool("nmap")
            Button:
                text: "WI-FI\nKISMET STATUS"
                font_size: "18sp"
                on_release: root.open_tool("kismet")
            Button:
                text: "ARP\nDISCOVERY"
                font_size: "18sp"
                on_release: root.open_tool("arp")
            Button:
                text: "PACKET\nCAPTURE"
                font_size: "18sp"
                on_release: root.open_tool("tcpdump")
        GridLayout:
            cols: 3
            spacing: "10dp"
            size_hint_y: None
            height: "58dp"
            Button:
                text: "REFRESH"
                on_release: root.refresh()
            Button:
                text: "SETTINGS"
                on_release: root.manager.current = "settings"
            Button:
                text: "SHUT DOWN"
                background_color: .65, .12, .14, 1
                on_release: root.request_shutdown()
        Label:
            text: root.message
            color: .7, .75, .82, 1
            font_size: "15sp"
            text_size: self.width, None
            halign: "center"
            size_hint_y: None
            height: "38dp"

<SplashScreen>:
    BoxLayout:
        orientation: "vertical"
        padding: "36dp"
        spacing: "12dp"
        canvas.before:
            Color:
                rgba: .025, .035, .055, 1
            Rectangle:
                pos: self.pos
                size: self.size
        Widget:
        Label:
            text: "PIANNAPLE"
            color: .35, .78, 1, 1
            font_size: "38sp"
            bold: True
            size_hint_y: None
            height: "62dp"
        Label:
            text: "NETWORK AUDITING CONSOLE"
            color: .72, .78, .88, 1
            font_size: "17sp"
            size_hint_y: None
            height: "34dp"
        Label:
            text: root.status
            color: .45, .85, .65, 1
            font_size: "15sp"
            size_hint_y: None
            height: "30dp"
        Widget:

<StatusCard>:
    orientation: "vertical"
    padding: "12dp"
    canvas.before:
        Color:
            rgba: .09, .12, .17, 1
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [8]
        Color:
            rgba: .16, .25, .34, 1
        Line:
            rounded_rectangle: (self.x, self.y, self.width, self.height, 8)
            width: 1
    Label:
        text: root.title
        color: .45, .55, .68, 1
        font_size: "13sp"
        halign: "left"
    Label:
        text: root.value
        color: .9, .94, 1, 1
        font_size: "17sp"
        halign: "left"

<ToolsScreen>:
    BoxLayout:
        orientation: "vertical"
        padding: "20dp"
        spacing: "12dp"
        canvas.before:
            Color:
                rgba: .035, .045, .065, 1
            Rectangle:
                pos: self.pos
                size: self.size
        Label:
            text: "NETWORK AUDITING TOOLS"
            color: .35, .78, 1, 1
            font_size: "23sp"
            bold: True
            size_hint_y: None
            height: "38dp"
        Label:
            text: "Only scan networks and systems you are authorized to test."
            color: .8, .65, .35, 1
            font_size: "14sp"
            size_hint_y: None
            height: "28dp"
        TextInput:
            id: target
            hint_text: "Target (example: 192.168.1.0/24)"
            multiline: False
            font_size: "18sp"
            size_hint_y: None
            height: "52dp"
        GridLayout:
            cols: 2
            spacing: "10dp"
            Button:
                text: "NMAP QUICK SCAN"
                on_release: root.run_tool("nmap", target.text)
            Button:
                text: "ARP DISCOVERY"
                on_release: root.run_tool("arp", target.text)
            Button:
                text: "KISMET STATUS"
                on_release: root.run_tool("kismet", "")
            Button:
                text: "TCPDUMP SAMPLE"
                on_release: root.run_tool("tcpdump", "")
        Label:
            text: root.output
            color: .82, .87, .94, 1
            font_size: "14sp"
            text_size: self.width, self.height
            halign: "left"
            valign: "top"
        Button:
            text: "BACK"
            font_size: "18sp"
            size_hint_y: None
            height: "62dp"
            on_release: root.manager.current = "home"

<SettingsScreen>:
    BoxLayout:
        orientation: "vertical"
        padding: "22dp"
        spacing: "12dp"
        canvas.before:
            Color:
                rgba: .035, .045, .065, 1
            Rectangle:
                pos: self.pos
                size: self.size
        Label:
            text: "SETTINGS"
            color: .35, .78, 1, 1
            font_size: "25sp"
            bold: True
            size_hint_y: None
            height: "40dp"
        StatusCard:
            title: "REMOTE SENSOR"
            value: root.sensor_host
        StatusCard:
            title: "DISPLAY POWER"
            value: root.display_policy
        StatusCard:
            title: "AUTO POWER-OFF"
            value: root.power_policy
        Widget:
        Button:
            text: "REFRESH SENSOR CONNECTION"
            size_hint_y: None
            height: "62dp"
            on_release: root.refresh_sensor()
        Button:
            text: "BACK TO TOOLS"
            size_hint_y: None
            height: "62dp"
            on_release: root.manager.current = "home"
"""


class StatusCard(BoxLayout):
    title = StringProperty("")
    value = StringProperty("")


class SplashScreen(Screen):
    status = StringProperty("Starting network tools…")


class SettingsScreen(Screen):
    sensor_host = StringProperty(os.environ.get("PIANNAPLE_SENSOR", "netsensor.local"))
    display_policy = StringProperty("Backlight off after 60 seconds")
    power_policy = StringProperty("Power off after 1 hour idle")

    def refresh_sensor(self):
        self.sensor_host = "checking…"
        Clock.schedule_once(lambda _dt: setattr(self, "sensor_host", os.environ.get("PIANNAPLE_SENSOR", "netsensor.local")), .5)


class ToolsScreen(Screen):
    output = StringProperty("I can't find the other Pi.")

    def run_tool(self, tool, target):
        target = target.strip()
        if tool in ("nmap", "arp") and not target:
            self.output = "Enter an authorized target first."
            return
        self.output = "Running " + tool + " on the sensor…"
        threading.Thread(target=self._run_remote, args=(tool, target), daemon=True).start()

    def _run_remote(self, tool, target):
        key = os.path.expanduser("~/.ssh/piannaple-sensor_ed25519")
        host = discover_sensor_host()
        commands = {
            "nmap": ("nmap", "-T3", "-F", target),
            "arp": ("sudo", "arp-scan", "--interface=eth0", target),
            "kismet": ("systemctl", "--no-pager", "--full", "status", "kismet"),
            "tcpdump": ("sudo", "timeout", "8", "tcpdump", "-c", "20", "-nn", "-i", "any"),
        }
        command = commands[tool]
        try:
            result = subprocess.run(
                ("ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "-i", key, host, "--", *command),
                check=False, capture_output=True, text=True, timeout=30,
            )
            text = (result.stdout + result.stderr).strip()
            if len(text) > 1800:
                text = text[-1800:]
            Clock.schedule_once(lambda _dt: setattr(self, "output", text or "Command returned no output."))
        except (OSError, subprocess.SubprocessError) as exc:
            Clock.schedule_once(lambda _dt: setattr(self, "output", "I can't find the other Pi."))


class HomeScreen(Screen):
    wifi_status = StringProperty("checking…")
    bluetooth_status = StringProperty("checking…")
    system_status = StringProperty("starting")
    clock_status = StringProperty("")
    subtitle = StringProperty("Touchscreen home screen")
    message = StringProperty("Ready")

    def on_pre_enter(self, *_args):
        self.refresh()
        Clock.schedule_interval(self._update_clock, 1)

    def _update_clock(self, *_args):
        self.clock_status = datetime.now().strftime("%H:%M:%S")

    def refresh(self):
        self.message = "Refreshing system status…"
        threading.Thread(target=self._read_status, daemon=True).start()

    def _read_status(self):
        key = os.path.expanduser("~/.ssh/piannaple-sensor_ed25519")
        host = discover_sensor_host()
        probe = "printf 'wifi=%s\\n' \"$(cat /sys/class/net/wlan0/operstate 2>/dev/null || echo unavailable)\"; printf 'bt=%s\\n' \"$(hciconfig hci0 2>/dev/null | grep -q RUNNING && echo ready || echo unavailable)\"; printf 'load=%s\\n' \"$(awk '{print $1}' /proc/loadavg 2>/dev/null || echo n/a)\""
        try:
            result = subprocess.run(
                ("ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "-i", key, host, "--", "sh", "-c", probe),
                check=False, capture_output=True, text=True, timeout=10,
            )
            values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
            if result.returncode != 0:
                raise OSError(result.stderr.strip() or "sensor unavailable")
            Clock.schedule_once(lambda _dt: self._apply_status(values.get("wifi", "unknown"), values.get("bt", "unknown"), values.get("load", "n/a")))
        except (OSError, subprocess.SubprocessError) as exc:
            Clock.schedule_once(lambda _dt: self._apply_status("offline", "offline", "sensor unavailable"))

    def _apply_status(self, wifi, bt, load):
        self.wifi_status = wifi
        self.bluetooth_status = bt
        self.system_status = "load " + load
        self.message = "Sensor status updated" if wifi != "offline" else "I can't find the other Pi."

    @staticmethod
    def _command(*command):
        try:
            result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=2)
            return result.stdout.strip() or "unavailable"
        except (OSError, subprocess.SubprocessError):
            return "unavailable"

    def show_message(self, text):
        self.message = text

    def open_tool(self, tool):
        tools = self.manager.get_screen("tools")
        tools.output = "Select a target on the Network Tools screen." if tool in ("nmap", "arp") else "Ready."
        self.manager.current = "tools"

    def request_shutdown(self):
        self.message = "Shutdown requested"
        if os.environ.get("PIFIDO_ALLOW_SHUTDOWN") == "1":
            subprocess.Popen(("systemctl", "poweroff"))
        else:
            self.message = "Shutdown disabled in development mode"


class HomeApp(App):
    display_idle_seconds = int(os.environ.get("PIANNAPLE_DISPLAY_IDLE_SECONDS", "60"))
    poweroff_seconds = int(os.environ.get("PIANNAPLE_POWEROFF_SECONDS", "3600"))

    def build(self):
        self.title = "Piannaple"
        self.fullscreen = "auto"
        self._last_activity = time.monotonic()
        self._display_off = False
        self._backlight = self._find_backlight()
        self._backlight_level = self._read_backlight()
        Window.bind(on_touch_down=self._activity)
        Clock.schedule_interval(self._idle_tick, 5)
        Builder.load_string(KV)
        manager = ScreenManager()
        manager.add_widget(SplashScreen(name="splash"))
        manager.add_widget(HomeScreen(name="home"))
        manager.add_widget(ToolsScreen(name="tools"))
        manager.add_widget(SettingsScreen(name="settings"))
        discover(manager)
        manager.current = "splash"
        Clock.schedule_once(lambda _dt: setattr(manager, "current", "home"), 1.5)
        return manager

    @staticmethod
    def _find_backlight():
        devices = sorted(glob.glob("/sys/class/backlight/*/brightness"))
        return devices[0] if devices else None

    def _read_backlight(self):
        if not self._backlight:
            return None
        try:
            with open(self._backlight, encoding="ascii") as stream:
                return stream.read().strip()
        except OSError:
            return None

    def _set_backlight(self, value):
        if not self._backlight:
            return
        try:
            with open(self._backlight, "w", encoding="ascii") as stream:
                stream.write(str(value))
        except OSError as exc:
            print(f"Piannaple backlight control unavailable: {exc}")

    def _activity(self, *_args):
        self._last_activity = time.monotonic()
        if self._display_off:
            self._set_backlight(self._backlight_level or "1")
            self._display_off = False

    def _idle_tick(self, *_args):
        idle = time.monotonic() - self._last_activity
        if self._backlight and not self._display_off and idle >= self.display_idle_seconds:
            self._backlight_level = self._backlight_level or self._read_backlight() or "1"
            self._set_backlight("0")
            self._display_off = True
        if idle >= self.poweroff_seconds and os.environ.get("PIANNAPLE_AUTO_POWEROFF", "1") == "1":
            subprocess.Popen(("systemctl", "poweroff"))


if __name__ == "__main__":
    HomeApp().run()
