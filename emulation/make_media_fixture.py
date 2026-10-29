#!/usr/bin/env python3
"""Create a host-only FAT16 USB disk with generated playback test assets."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import wave


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    if a.output.exists():
        p.error('output exists; refusing to overwrite a previous test disk')
    for tool in ('mkfs.vfat', 'mcopy', 'ffmpeg'):
        if not shutil.which(tool):
            p.error('missing dependency: ' + tool)
    a.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='smeg-media-') as d:
        root = Path(d)
        wav = root / 'Bench.wav'
        with wave.open(str(wav), 'wb') as f:
            f.setnchannels(2)
            f.setsampwidth(2)
            f.setframerate(44100)
            # A quiet generated tone, never a copied commercial recording.
            f.writeframes(b''.join(struct.pack('<hh', value, value)
                for i in range(44100 * 3)
                for value in [int(1200 * math.sin(2 * math.pi * 440 * i / 44100))]))
        subprocess.run(['ffmpeg', '-v', 'error', '-i', str(wav),
                        '-metadata', 'title=SMEG emulator bench tone',
                        '-metadata', 'artist=Generated test fixture',
                        '-codec:a', 'libmp3lame', '-b:a', '128k',
                        str(root / 'Bench.mp3')], check=True)
        pattern = root / 'Pattern.ppm'
        pattern.write_bytes(b'P6\n800 480\n255\n' + bytes(
            v for y in range(480) for x in range(800)
            for v in (x * 255 // 799, y * 255 // 479, 80)))
        subprocess.run(['ffmpeg', '-v', 'error', '-i', str(pattern),
                        '-frames:v', '1', str(root / 'Pattern.jpg')], check=True)
        files = [wav, root / 'Bench.mp3', root / 'Pattern.jpg']
        image = a.output.resolve()
        with image.open('xb') as f:
            f.truncate(32 * 1024 * 1024)
        try:
            subprocess.run(['mkfs.vfat', '-F', '16', '-n', 'SMEG_BENCH', str(image)],
                           check=True, capture_output=True)
            env = dict(os.environ, MTOOLS_SKIP_CHECK='1')
            for file in files:
                subprocess.run(['mcopy', '-i', str(image), str(file), '::/'],
                               check=True, capture_output=True, env=env)
                readback = root / ('readback-' + file.name)
                subprocess.run(['mcopy', '-i', str(image), '::/' + file.name,
                                str(readback)], check=True, capture_output=True, env=env)
                if readback.read_bytes() != file.read_bytes():
                    raise RuntimeError('USB fixture readback mismatch: ' + file.name)
            report = {'physical_device_access': False, 'format': 'FAT16 superfloppy',
                      'bytes': image.stat().st_size, 'files': [
                          {'name': f.name, 'bytes': f.stat().st_size,
                           'sha256': hashlib.sha256(f.read_bytes()).hexdigest()}
                          for f in files]}
            image.with_suffix('.json').write_text(json.dumps(report, indent=2) + '\n')
            print(json.dumps(report))
        except BaseException:
            image.unlink(missing_ok=True)
            raise


if __name__ == '__main__':
    main()
