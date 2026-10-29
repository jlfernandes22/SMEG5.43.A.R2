"""Load private device settings from the environment or ignored local JSON.

Optional keys in the project-root .smeg-local.json are usb_device, usb_serial,
usb_capacity_bytes, usb_model, usb_mount and bluetooth_address. Environment
variables take precedence. No physical device is selected by default.
"""
import json
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOCAL_CONFIG = ROOT / '.smeg-local.json'
ENVIRONMENT_KEYS = {
    'usb_device': 'SMEG_USB_DEVICE',
    'usb_serial': 'SMEG_USB_SERIAL',
    'usb_capacity_bytes': 'SMEG_USB_CAPACITY_BYTES',
    'usb_model': 'SMEG_USB_MODEL',
    'usb_mount': 'SMEG_USB_MOUNT',
    'bluetooth_address': 'SMEG_BLUETOOTH_ADDRESS',
}


def load_local_device_config():
    """Read explicit local settings; never include their values in errors."""
    if LOCAL_CONFIG.exists():
        try:
            config = json.loads(LOCAL_CONFIG.read_text())
        except (OSError, ValueError):
            raise ValueError('Cannot read valid local device configuration') from None
        if not isinstance(config, dict):
            raise ValueError('Local device configuration must be a JSON object')
    else:
        config = {}
    selected = {}
    for key, environment_key in ENVIRONMENT_KEYS.items():
        value = os.environ.get(environment_key, config.get(key))
        if value is None:
            continue
        if key == 'usb_capacity_bytes':
            if isinstance(value, bool) or not str(value).isdigit() or int(value) <= 0:
                raise ValueError('Configured USB capacity must be a positive byte count')
            value = int(value)
        elif not isinstance(value, str) or not value.strip():
            raise ValueError('Configured ' + key + ' must be a nonempty string')
        selected[key] = value
    return selected
