"""Native BigHarmony preheader conversion independent of source filename."""
import struct
import zlib


def native_bank(data, sidecar):
    assert data.startswith(b'BIGHARMONY')
    fields = dict(line.split(':', 1) for line in sidecar.decode('ascii').splitlines() if ':' in line)
    size, crc = int(fields['HEADER_SIZE']), int(fields['HEADER_CRC32']) & 0xffffffff
    assert zlib.crc32(data[2048:2048+size]) == crc
    pre = bytearray(168)
    for offset, value in [(0, 'BIGHARMONY'), (32, '0.540.0'),
                          (64, fields['VERSION_BIGHARMONY_STRUCT']),
                          (96, fields['DATE']), (128, fields['VERSION'])]:
        value = value.encode('ascii')
        assert len(value) < 32
        pre[offset:offset+len(value)] = value
    struct.pack_into('>II', pre, 160, size, crc)
    return bytes(pre) + b'\xff' * (2048-168) + data[2048:]
