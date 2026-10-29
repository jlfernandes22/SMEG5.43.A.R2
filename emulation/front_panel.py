#!/usr/bin/env python3
"""Laptop buttons for the emulator's original MCU and simulated ECU inputs."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import subprocess
import sys

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import GLib, Gtk

ROOT = Path(__file__).resolve().parent.parent


class FrontPanel(Gtk.Window):
    def __init__(self, qmp_socket, parent_pid=None, asr_demo=False, car_fmux=False):
        super().__init__(title=('SMEG+ Grip Control demo buttons' if asr_demo
                               else 'SMEG+ virtual buttons'))
        self.set_default_size(380, 740)
        self.set_border_width(16)
        self.qmp_socket = qmp_socket
        self.parent_pid = parent_pid
        self.car_fmux = car_fmux
        self.worker = ThreadPoolExecutor(max_workers=1)
        self.pending = None
        self.closed = False
        self.buttons = []
        self.menu_buttons = {}
        self.connect('destroy', self.close)
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.add(outer)
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        outer.pack_start(scroll, True, True, 0)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        scroll.add(box)
        heading = Gtk.Label(label='Virtual front panel')
        heading.set_xalign(0)
        box.pack_start(heading, False, False, 0)
        subtitle = Gtk.Label(label='QEMU only · simulated vehicle')
        subtitle.set_xalign(0)
        box.pack_start(subtitle, False, False, 0)
        physical = Gtk.Grid(column_spacing=8, row_spacing=8)
        box.pack_start(physical, False, False, 0)
        for i, name in enumerate(('menu', 'src')):
            button = self.button(name.upper(), ['--panel', name])
            button.set_tooltip_text('Native MENU key' if name == 'menu'
                                    else 'Native SRC source cycling')
            physical.attach(button, i, 0, 1, 1)
            self.menu_buttons[name] = button
        menus = Gtk.Grid(column_spacing=8, row_spacing=8)
        box.pack_start(menus, False, False, 0)
        for i, (name, title) in enumerate([
                ('media', 'Media'), ('drive', 'Driving'),
                ('config', 'Settings'), ('web', 'Connect Apps'),
                ('nav', 'Navigation'), ('telephone', 'Phone')]):
            button = self.button(title, ['--panel', name])
            menus.attach(button, i % 2, i // 2, 1, 1)
            self.menu_buttons[name] = button
        service = Gtk.Grid(column_spacing=8, row_spacing=8)
        box.pack_start(service, False, False, 0)
        for i, (name, title, tip) in enumerate([
                ('cheat', 'Cheat menu', 'Original SMEG cheat-code entry screen'),
                ('versions', 'System versions',
                 'Original system, Bluetooth, map and display version viewer')]):
            button = self.button(title, ['--panel', name])
            button.set_tooltip_text(tip)
            service.attach(button, i, 0, 1, 1)
            self.menu_buttons[name] = button
        box.pack_start(Gtk.Separator(), False, False, 0)
        label = Gtk.Label(label='Simulated vehicle inputs')
        label.set_xalign(0)
        box.pack_start(label, False, False, 0)
        fixtures = Gtk.Grid(column_spacing=8, row_spacing=8)
        box.pack_start(fixtures, False, False, 0)
        for i, (title, args) in enumerate([
                ('Set Eco OFF', ['--eco', 'off', '--notify']),
                ('Set Eco ON', ['--eco', 'on', '--notify']),
                ('Traction OFF', ['--esp', 'off']),
                ('Traction ON', ['--esp', 'on']),
                ('Sensors OFF', ['--parking', 'off']),
                ('Sensors ON', ['--parking', 'standby']),
                ('Show obstacles', ['--parking', 'active']),
                ('Hide obstacles', ['--parking', 'standby'])]):
            fixtures.attach(self.button(title, args), i % 2, i // 2, 1, 1)
        environment = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        box.pack_start(environment, False, False, 0)
        environment.pack_start(Gtk.Label(label='Outside °C (simulated)'), False, False, 0)
        self.temperature = Gtk.SpinButton.new_with_range(-40, 85, .5)
        self.temperature.set_digits(1)
        self.temperature.set_value(20)
        environment.pack_start(self.temperature, False, False, 0)
        apply_temperature = Gtk.Button(label='Set')
        apply_temperature.connect('clicked', lambda unused: self.send(
            'Simulated temperature', ['--temperature', str(self.temperature.get_value())]))
        self.buttons.append(apply_temperature)
        environment.pack_start(apply_temperature, True, True, 0)
        box.pack_start(self.button('Sync clock to laptop', ['--clock-live']), False, False, 0)
        if asr_demo:
            # Only the isolated compatible-theme profile launcher opts in: some
            # original themes contain a DOTE placeholder for this popup.
            label = Gtk.Label(label='Grip Control display demo')
            label.set_xalign(0)
            box.pack_start(label, False, False, 0)
            modes = Gtk.Grid(column_spacing=8, row_spacing=8)
            box.pack_start(modes, False, False, 0)
            for i, mode in enumerate(('normal', 'snow', 'mud', 'sand', 'off')):
                modes.attach(self.button(mode.title(), ['--traction', mode]),
                             i % 2, i // 2, 1, 1)
        self.status = Gtk.Label(label='Wait for the SMEG screen before using these buttons.')
        self.status.set_xalign(0)
        self.status.set_line_wrap(True)
        outer.pack_end(self.status, False, False, 0)
        if parent_pid:
            GLib.timeout_add_seconds(2, self.check_parent)

    def button(self, title, args):
        button = Gtk.Button(label=title)
        button.set_hexpand(True)
        button.set_size_request(140, 44)
        button.connect('clicked', lambda unused: self.send(title, args))
        self.buttons.append(button)
        return button

    def send(self, title, args):
        if self.pending is not None:
            return
        for button in self.buttons:
            button.set_sensitive(False)
        self.status.set_text('Sending: ' + title)
        command = [sys.executable, str(ROOT / 'emulation/ui_control.py'),
                   '--socket', str(self.qmp_socket),
                   *(['--car-fmux'] if self.car_fmux else []), *args]
        self.pending = self.worker.submit(subprocess.run, command,
                                         capture_output=True, text=True, timeout=8)
        GLib.timeout_add(30, self.finish, title)

    def finish(self, title):
        if self.closed:
            return False
        if not self.pending.done():
            return True
        try:
            result = self.pending.result()
            self.status.set_text((title + ' sent to emulator.') if result.returncode == 0
                                 else 'Emulator unavailable. Start launch_features.sh.')
        except (OSError, subprocess.TimeoutExpired):
            self.status.set_text('Emulator did not respond. Try again when it is running.')
        self.pending = None
        for button in self.buttons:
            button.set_sensitive(True)
        return False

    def check_parent(self):
        if os.getppid() != self.parent_pid:
            self.destroy()
            return False
        try:
            os.kill(self.parent_pid, 0)
        except ProcessLookupError:
            self.destroy()
            return False
        except PermissionError:
            pass
        return not self.closed

    def close(self, unused):
        self.closed = True
        self.worker.shutdown(wait=False, cancel_futures=True)
        Gtk.main_quit()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--socket', type=Path,
                   default=ROOT / 'artifacts/phase4/runs/features/control.qmp')
    p.add_argument('--parent-pid', type=int)
    p.add_argument('--asr-demo', action='store_true',
                   help='Mode inputs for the isolated SQUARE/WARMLIGHT profile')
    p.add_argument('--car-fmux', action='store_true',
                   help='Navigate using the captured car keyboard mapping and native menu tiles')
    args = p.parse_args()
    window = FrontPanel(args.socket, args.parent_pid, args.asr_demo, args.car_fmux)
    window.show_all()
    Gtk.main()


if __name__ == '__main__':
    main()
