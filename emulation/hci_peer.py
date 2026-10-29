"""Validate explicitly selected Bluetooth peers without opening a controller."""
import argparse
import re


def bluetooth_peer(value):
    if not re.fullmatch(r'[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}', value):
        raise argparse.ArgumentTypeError('Bluetooth peer must be six colon-separated hexadecimal octets')
    return value.upper()


def peer_bytes(value):
    """Return the little-endian BD_ADDR used in HCI packets."""
    return bytes.fromhex(bluetooth_peer(value).replace(':', ''))[::-1]
