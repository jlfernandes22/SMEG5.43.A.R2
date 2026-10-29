#!/usr/bin/env python3
"""Offline tests for native resource pool preservation; no QEMU/device access."""
import struct
import unittest
from prepare_theme_menu_dependencies_experiment import add_images, image_records, add_colors, add_fonts, font_data, u32


def make_images(records):
    # Exact native count includes an intentionally overlapping dummy sentinel.
    count = len(records) + 1
    start = 4 + count * 32
    directory, payload = bytearray(), bytearray()
    for id_, blob, width, height in records:
        directory.extend(struct.pack('>8I', id_, start + len(payload), len(blob), 0, 0, width, height, 1))
        payload.extend(blob)
    assert len(payload) >= 12
    return struct.pack('>4I', start + len(payload), count, start, 0) + directory + b'\0' * 20 + payload


def make_fonts(records, families):
    base = 16 + len(records) * 28
    cursor = base + len(families) * 12
    directory, payload = bytearray(), bytearray()
    for key, text in families.items():
        blob = (text + '\0').encode('utf-16-be')
        directory.extend(struct.pack('>3I', key, cursor, len(blob)))
        payload.extend(blob)
        cursor += len(blob)
    return struct.pack('>4I', cursor, len(records), base, len(families)) + b''.join(struct.pack('>7I', *r) for r in records) + directory + payload


class PoolTests(unittest.TestCase):
    def test_native_overlap_and_original_pixel_bytes_survive(self):
        old = make_images([(0, bytes(range(32)), 1, 1), (17, b'original-image' * 7, 12, 9)])
        donor = make_images([(0, b'donor-data----' * 4, 5, 6), (17, b'another-donor' * 4, 7, 8)])
        result, mapping, audit = add_images(old, donor, {0, 17})
        old_count, old_start, old_records = image_records(old)
        count, start, records = image_records(result)
        self.assertEqual(count, old_count + 2)
        self.assertEqual(start, old_start + 64)
        self.assertEqual(result[start:start + len(old) - old_start], old[old_start:])
        for original, relocated in zip(old_records, records):
            self.assertEqual(original[:4], relocated[:4])
            self.assertEqual(original[8:], relocated[8:])
            self.assertEqual(u32(relocated, 4), u32(original, 4) + 64)
        # Original IDs are never replaced even when donor IDs collide.
        self.assertEqual(mapping, {0: 18, 17: 19})
        for donor_id, new_id in mapping.items():
            record = next(r for r in records if u32(r) == new_id)
            source = next(r for r in image_records(donor)[2] if u32(r) == donor_id)
            offset, length = struct.unpack_from('>II', record, 4)
            source_offset, source_length = struct.unpack_from('>II', source, 4)
            self.assertEqual(result[offset:offset + length], donor[source_offset:source_offset + source_length])
        self.assertTrue(audit['original_pixel_payload_preserved'])

    def test_missing_donor_image_fails_instead_of_aliasing(self):
        data = make_images([(0, b'0' * 20, 1, 1)])
        with self.assertRaises(KeyError):
            add_images(data, data, {99})

    def test_color_collisions_get_private_ids(self):
        old = struct.pack('>6I', 24, 2, 1, 0xff000000, 7, 0xff00ff00)
        donor = struct.pack('>4I', 16, 1, 1, 0xffff0000)
        result, mapping = add_colors(old, donor, {1})
        self.assertEqual(mapping, {1: 8})
        self.assertEqual(result[8:24], old[8:])
        self.assertEqual(struct.unpack_from('>II', result, 24), (8, 0xffff0000))

    def test_font_family_collision_preserves_original_and_appends_exact_family(self):
        old = make_fonts([(4, 1, 22, 4, 0, 0, 0)], {0: 'Common', 1: 'Old slider'})
        donor = make_fonts([(4, 1, 31, 4, 0, 0, 0)], {0: 'Common', 1: 'New slider'})
        result, mapping = add_fonts(old, donor, {4})
        records, families = font_data(result)
        self.assertEqual(mapping, {4: 5})
        self.assertEqual(records[0], font_data(old)[0][0])
        self.assertEqual(families[1], ('Old slider\0').encode('utf-16-be'))
        self.assertEqual(families[2], ('New slider\0').encode('utf-16-be'))
        self.assertEqual(struct.unpack('>7I', records[1]), (5, 2, 31, 4, 0, 0, 0))

if __name__ == '__main__':
    unittest.main()
