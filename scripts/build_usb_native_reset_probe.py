#!/usr/bin/env python3
"""Build a local-only native BSP reset probe into a new Phase23 virtual USB.

Never accepts a physical device. This requests the original BSP reset after
verified USB removal; it does not restore resources, databases, or firmware.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile

from elftools.elf.elffile import ELFFile
from ensure_smeg_fat_lfn import Fat32
from smeg_db_inf import crc16

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'emulation'))
from make_usb_probe import OFFSET, SIZE, run

SOURCE = ROOT / 'emulation/usb_native_reset_probe.c'
BSP = ROOT / 'artifacts/phase2/package/SMEG_PLUS_UPG/BSP/SMEG_PLUS_256/vxWorks.bin'
BSP_SHA256 = 'e8aff17981ae5ba8c1574fba70ed747d32ae08badec932bfae38b7f6a4694110'
CHECKS = [
    ('EmergencyReboot', 0x296438, 60, 0xb5071dd1),
    ('sysToMonitor', 0x20e3d0, 120, 0xd28c382e),
    ('gpioIoctl', 0x21bb98, 5356, 0x5818a431),
    ('iosDevFind', 0x49119c, 200, 0x3334db73),
]
SENTINEL = b'SMEG_NATIVE_RESET_PROBE_V1\n'
IMPORTS = {'fopen', 'fread', 'fwrite', 'fclose', 'fflush', 'ferror', 'mkdir',
           'printf', 'taskDelay', 'sysClkRateGet', 'iosDevFind'}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def fnv(data):
    result = 2166136261
    for byte in data:
        result = ((result ^ byte) * 16777619) & 0xffffffff
    return result


def contract(wait_seconds):
    data = BSP.read_bytes()
    require(hashlib.sha256(data).hexdigest() == BSP_SHA256,
            'Original local BSP256 input changed; this is not a physical BSP dump')
    rows = []
    for name, address, size, expected in CHECKS:
        raw = data[address-0x200000:address-0x200000+size]
        require(len(raw) == size and fnv(raw) == expected, 'BSP function mismatch: '+name)
        rows.append(dict(name=name, address=hex(address), bytes=size,
                         fnv1a32=f'{expected:08x}', sha256=hashlib.sha256(raw).hexdigest()))
    text = [
        '/* Original local BSP256 fingerprints; not a physical-car identity claim. */',
        'struct NativeResetCheck {unsigned long address; unsigned bytes,hash;};',
        'static const struct NativeResetCheck native_reset_checks[] = {',
        *[f'{{0x{a:x}ul,{n}u,0x{h:08x}u}},' for _, a, n, h in CHECKS],
        '};', '#define NATIVE_RESET_ENTRY_ADDRESS 0x296438ul',
        f'#define NATIVE_RESET_WAIT_SECONDS {wait_seconds}u',
        '#define NATIVE_RESET_ABSENT_CHECKS 5u', '',
    ]
    return '\n'.join(text), rows


HOST_HARNESS = r'''
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct {int id, open; unsigned position;} MockFile;
unsigned char test_code[4][16];
static MockFile handles[2];
static char sentinel_data[192], status_data[192];
static unsigned sentinel_bytes, status_bytes;
static const char *mode;
static int seconds, armed, writes, resets, queries_at_seven;
static int present(void) {
    if (!strcmp(mode,"no_usb") || !strcmp(mode,"default_device") ||
        !strcmp(mode,"partial_device")) return 0;
    if (!strcmp(mode,"timeout") || !strcmp(mode,"io_failure")) return 1;
    if (!strcmp(mode,"transient")) return seconds<3 || seconds==5;
    if (!strcmp(mode,"returned_device") && seconds==7) return ++queries_at_seven>1;
    return seconds<3;
}
static void *mock_find(const char *path,const char **tail) {
    assert(!strcmp(path,"/bd0"));
    if (!strcmp(mode,"default_device")) {*tail=path;return handles;}
    if (!strcmp(mode,"partial_device")) {*tail=path+3;return handles;}
    if (!present()) {*tail=path;return NULL;}
    *tail=path+4;return handles;
}
static MockFile *mock_open(const char *path,const char *access) {
    int id;
    assert(!strncmp(path,"/bd0/RESET_PROBE/",17));
    if (!strcmp(path,"/bd0/RESET_PROBE/SENTINEL.TXT")) {
        assert(!strcmp(access,"rb"));id=0;
        if (!strcmp(mode,"missing_sentinel") || seconds>=3) {
            if (strcmp(mode,"timeout") && (strcmp(mode,"transient") || seconds!=5)) return NULL;
        }
    } else {
        assert(!strcmp(path,"/bd0/RESET_PROBE/ARMED/STATUS.TXT"));id=1;
        assert(armed && (!strcmp(access,"rb") || !strcmp(access,"wb")));
        if (!strcmp(access,"wb")) status_bytes=0;
        if (!strcmp(mode,"status_readback") && !strcmp(access,"rb")) return NULL;
    }
    assert(!handles[id].open);
    handles[id]=(MockFile){id,1,0};return &handles[id];
}
static size_t mock_read(void *out,size_t size,size_t count,MockFile *f) {
    unsigned available=f->id?status_bytes:sentinel_bytes;
    const char *data=f->id?status_data:sentinel_data;
    size_t bytes=size*count;
    assert(f->open && size==1);
    if (bytes>available-f->position) bytes=available-f->position;
    memcpy(out,data+f->position,bytes);f->position+=(unsigned)bytes;return bytes;
}
static size_t mock_write(const void *in,size_t size,size_t count,MockFile *f) {
    assert(f->open && f->id==1 && size==1 && count<sizeof(status_data));
    ++writes;memcpy(status_data,in,count);status_bytes=(unsigned)count;
    return !strcmp(mode,"write_failure")?count-1:count;
}
static int mock_close(MockFile *f) {
    int bad=(!strcmp(mode,"close_failure") && f->id==1) ||
            (!strcmp(mode,"poll_close_failure") && f->id==0 && seconds==1);
    assert(f->open);f->open=0;return bad?-1:0;
}
static int mock_flush(MockFile *f) {assert(f->open);return !strcmp(mode,"flush_failure")?-1:0;}
static int mock_error(MockFile *f) {assert(f->open);return 0;}
static int mock_mkdir(const char *path,int permissions) {
    assert(!strcmp(path,"/bd0/RESET_PROBE/ARMED") && permissions==0777);
    if (!strcmp(mode,"duplicate")) return -1;
    assert(!armed);armed=1;return 0;
}
static int mock_delay(int ticks) {assert(ticks==100);++seconds;return !strcmp(mode,"delay_failure")?-1:0;}
static int mock_rate(void) {return !strcmp(mode,"bad_clock")?0:100;}
static int mock_printf(const char *format,...) {(void)format;return 0;}
static void mock_reset(void) {assert(!handles[0].open && !handles[1].open && armed);++resets;}
#define SMEG_NATIVE_RESET_HOST_TEST 1
#define FILE MockFile
#define fopen mock_open
#define fread mock_read
#define fwrite mock_write
#define fclose mock_close
#define fflush mock_flush
#define ferror mock_error
#define mkdir mock_mkdir
#define printf mock_printf
#define taskDelay mock_delay
#define sysClkRateGet mock_rate
#define iosDevFind mock_find
#define NATIVE_RESET_INVOKE() mock_reset()
#include "usb_native_reset_probe.c"
#undef printf
int main(int argc,char **argv) {
    int result;
    assert(argc==2);mode=argv[1];
    for(unsigned i=0;i<4;++i) {
        memset(test_code[i],0x31+(int)i,16);
        native_reset_checks[i].hash=reset_hash(test_code[i],16);
    }
    if(!strcmp(mode,"wrong_fingerprint"))test_code[0][0]^=1;
    if(!strcmp(mode,"wrong_last_fingerprint"))test_code[3][15]^=1;
    memcpy(sentinel_data,RESET_SENTINEL_TEXT,sizeof(RESET_SENTINEL_TEXT)-1);
    sentinel_bytes=sizeof(RESET_SENTINEL_TEXT)-1;
    if(!strcmp(mode,"bad_sentinel"))sentinel_data[0]^=1;
    result=smeg_native_reset_probe();
    assert(!handles[0].open && !handles[1].open);
    printf("{\"case\":\"%s\",\"status\":%d,\"reset_calls\":%d,\"seconds\":%d,\"armed\":%d,\"USB_status_writes\":%d,\"all_streams_closed\":true}\n",
           mode,result,resets,seconds,armed,writes);
    return 0;
}
'''


def host_tests():
    cases = [
        ('removed', -11, 1, 7), ('transient', -11, 1, 10),
        ('wrong_fingerprint', -1, 0, 0), ('wrong_last_fingerprint', -1, 0, 0),
        ('no_usb', -2, 0, 0), ('default_device', -2, 0, 0), ('partial_device', -2, 0, 0),
        ('bad_sentinel', -3, 0, 0), ('missing_sentinel', -3, 0, 0),
        ('bad_clock', -4, 0, 0), ('duplicate', -6, 0, 0),
        ('write_failure', -7, 0, 0), ('flush_failure', -7, 0, 0),
        ('close_failure', -7, 0, 0), ('status_readback', -7, 0, 0),
        ('delay_failure', -8, 0, 1), ('poll_close_failure', -9, 0, 1),
        ('returned_device', -10, 0, 7), ('timeout', -12, 0, 12),
        ('io_failure', -12, 0, 12),
    ]
    results = []
    with tempfile.TemporaryDirectory(prefix='smeg-reset-host-') as directory:
        temp = Path(directory)
        (temp/'native_reset_contract.h').write_text(
            'struct NativeResetCheck {unsigned long address;unsigned bytes,hash;};\n'
            'static struct NativeResetCheck native_reset_checks[]={\n'+
            ''.join(f'{{(unsigned long)test_code[{i}],16,0}},\n' for i in range(4))+
            '};\n#define NATIVE_RESET_WAIT_SECONDS 12u\n#define NATIVE_RESET_ABSENT_CHECKS 5u\n')
        (temp/'test.c').write_text(HOST_HARNESS)
        executable = temp/'test'
        command = ['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-fsanitize=undefined',
                   '-I', str(temp), '-I', str(SOURCE.parent), str(temp/'test.c'), '-o', str(executable)]
        subprocess.run(command, check=True, capture_output=True)
        for name, status, resets, seconds in cases:
            executed = subprocess.run([str(executable), name], check=True, capture_output=True, text=True)
            row = json.loads(executed.stdout)
            require((row['status'], row['reset_calls'], row['seconds']) == (status, resets, seconds),
                    'Native reset host case failed: '+json.dumps(row))
            if name in {'wrong_fingerprint', 'wrong_last_fingerprint', 'no_usb', 'default_device',
                        'partial_device', 'bad_sentinel', 'missing_sentinel', 'bad_clock', 'duplicate'}:
                require(row['USB_status_writes'] == 0, 'Unexpected write before one-use guard')
            results.append(row)
    return dict(production_C_control_flow_tested=True, firmware_apis_mocked=True,
                physical_reset_proven=False, direct_NAND_operations_mocked_or_used=False, cases=results)


def create_image(image, files):
    """Use the existing regular-file FAT32 probe layout and mtools helper."""
    with tempfile.TemporaryDirectory(prefix='smeg-reset-fat-') as directory:
        temp = Path(directory)
        partition = temp/'partition.raw'
        with partition.open('xb') as stream:
            stream.truncate(SIZE)
        run('mkfs.vfat', '-F', '32', '-n', 'RESET_QEMU', str(partition))
        mbr = bytearray(512)
        mbr[446:462] = struct.pack('<B3sB3sII', 0, b'\xfe\xff\xff', 12,
                                  b'\xfe\xff\xff', OFFSET//512, SIZE//512)
        mbr[510:] = b'\x55\xaa'
        with image.open('xb') as target, partition.open('rb') as source:
            target.write(mbr)
            target.seek(OFFSET)
            shutil.copyfileobj(source, target)
        spec = str(image)+'@@'+str(OFFSET)
        for name in ('FLYING', 'RESET_PROBE'):
            run('mmd', '-i', spec, '::/'+name)
        for i, (name, data) in enumerate(files.items()):
            source = temp/str(i)
            source.write_bytes(data)
            run('mcopy', '-i', spec, str(source), '::/'+name)
            require(run('mtype', '-i', spec, '::/'+name).stdout == data, 'FAT member readback failed')
    with image.open('rb') as stream:
        fat = Fat32(stream, image.stat().st_size)
        actual = {}
        def walk(cluster, prefix=''):
            for item in fat.entries(cluster):
                name = item['lfn'] or item['short']
                if name in ('.', '..') or item['attr'] & 8:
                    continue
                path = prefix+name
                if item['attr'] & 0x10:
                    walk(item['cluster'], path+'/')
                else:
                    actual[path] = item['bytes']
        walk(fat.root)
        require(actual == {n:len(d) for n,d in files.items()},
                'Unexpected virtual USB files/guard: '+repr(actual))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='New directory under artifacts/phase23')
    parser.add_argument('--wait-seconds', type=int, default=180)
    args = parser.parse_args()
    out = args.output.resolve()
    require(out.is_relative_to(ROOT/'artifacts/phase23') and out != ROOT/'artifacts/phase23'
            and not out.exists() and not args.output.is_symlink(), 'New Phase23 artifact directory required')
    require(15 <= args.wait_seconds <= 600, 'Removal timeout must be 15..600 seconds')
    header, checks = contract(args.wait_seconds)
    tests = host_tests()
    out.mkdir(parents=True)
    (out/'native_reset_contract.h').write_text(header)
    shutil.copyfile(SOURCE, out/SOURCE.name)
    module = out/'native_reset.out'
    command = ['clang', '--target=powerpc-unknown-linux-gnu', '-mbig-endian', '-m32', '-mlongcall',
               '-ffreestanding', '-fno-pic', '-fno-stack-protector', '-fno-unwind-tables',
               '-fno-asynchronous-unwind-tables', '-msoft-float', '-O2', '-Wall', '-Wextra', '-Werror',
               '-I', str(out), '-c', str(out/SOURCE.name), '-o', str(module)]
    subprocess.run(command, check=True)
    with module.open('rb') as stream:
        elf = ELFFile(stream)
        require(elf.elfclass == 32 and not elf.little_endian and elf['e_type'] == 'ET_REL'
                and elf['e_machine'] == 'EM_PPC', 'Wrong native ELF format')
        symbols = list(elf.get_section_by_name('.symtab').iter_symbols())
        entry = next(s for s in symbols if s.name == 'smeg_native_reset_probe')
        require(entry['st_value'] == 0 and elf.get_section(entry['st_shndx']).name == '.text',
                'Native module entry must be .text offset zero')
        imports = sorted(s.name for s in symbols if s.name and s['st_shndx'] == 'SHN_UNDEF')
        require(set(imports) <= IMPORTS and 'iosDevFind' in imports, 'Unexpected module imports: '+repr(imports))
    payload = module.read_bytes()
    body = (f'{crc16(payload):04x}\r\nVER:SMEG5.43.A.R2\r\nTYPE:RELOCABLE\r\nID:0\r\n'
            f'COMPRESSED:NO\r\nSIZE:{len(payload)}\r\nENTRY:YES\r\n').encode()
    doctor = b'0000\r\nACTION:TemporaryBootRom\r\nLOAD_AND_EXECUTE:/bd0/FLYING/native_reset.out\r\n'
    files = {'FLYING/native_reset.out': payload,
             'FLYING/native_reset.out.inf': f'{crc16(body):04x}'.encode()+body,
             'FLYING/doctor_smeg_plus_i.inf': f'{crc16(doctor):04x}'.encode()+doctor,
             'RESET_PROBE/SENTINEL.TXT': SENTINEL}
    for name in ('FLYING/native_reset.out.inf', 'FLYING/doctor_smeg_plus_i.inf'):
        inf = files[name]
        require(int(inf[:4],16) == crc16(inf[4:]), 'INF metadata CRC failed')
    require(int(files['FLYING/native_reset.out.inf'][4:8],16) == crc16(payload), 'Module CRC failed')
    image = out/'usb.raw'
    create_image(image, files)
    report = dict(
        scope='Local QEMU native BSP reset after USB removal; not a resource/firmware restore',
        emulator_only=True, physical_device_access=False, physical_car_approved=False,
        native_USB_test_completed=False, physical_reset_proven=False,
        resources_or_databases_restored=False, direct_NAND_write_API_included=False,
        internal_filesystem_writes_requested=False, application_or_MMI_API_dependency=False,
        USER_DATA_dependency=False, USB_descriptor_self_disarmed=False,
        removal_protocol='Five one-second consecutive failed sentinel opens AND absent native /bd0 device; fail closed on timeout/errors',
        one_use_guard='/bd0/RESET_PROBE/ARMED exclusive mkdir; retained on timeout/failure',
        reset_entry='Original BSP256 EmergencyReboot() at 0x296438, calls sysToMonitor(1)',
        reset_limit='Electrical reset behavior is modeled in QEMU; physical unit not tested. Normal reboot bookkeeping may write internally.',
        wait_seconds=args.wait_seconds, absent_checks=5,
        original_local_BSP=str(BSP), original_local_BSP_sha256=BSP_SHA256,
        physical_BSP_byte_identity_claimed=False, native_fingerprints=checks,
        source_sha256=sha(SOURCE), frozen_source_sha256=sha(out/SOURCE.name),
        contract_sha256=sha(out/'native_reset_contract.h'), compile_command=command,
        ELF_entry_offset=0, module_imports=imports, module_sha256=sha(module),
        image=str(image), image_sha256=sha(image), image_bytes=image.stat().st_size,
        partition_offset_bytes=OFFSET, host_tests=tests,
        files=[dict(path=n, bytes=len(d), sha256=hashlib.sha256(d).hexdigest()) for n,d in files.items()])
    (out/'usb.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(dict(image=str(image), image_sha256=report['image_sha256'],
                          files=len(files), host_cases=len(tests['cases']), module_imports=imports)))


if __name__ == '__main__':
    main()
