#!/usr/bin/env python3
"""Bounded artifact-only diagnostic: appended MENU with animations disabled.

Isolates animation-ID incompatibility before copying shared resources. It is
not an installation package or evidence of cross-theme compatibility.
"""
import struct
import prepare_theme_menu_experiment as experiment

original = experiment.append_selector


def append_without_animation(raw, donor):
    assert struct.unpack_from('>4I', donor, 0x40) == (20, 0, 1, 1)
    changed = bytearray(donor)
    struct.pack_into('>I', changed, 0x4c, 0)
    result, audit = original(raw, bytes(changed))
    audit['diagnostic_root_MENU_animations_disabled'] = True
    audit['shared_dependencies_still_unverified'] = True
    return result, audit


if __name__ == '__main__':
    experiment.append_selector = append_without_animation
    experiment.main()
