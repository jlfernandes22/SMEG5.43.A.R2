#!/usr/bin/env python3
"""Mock-only USB preparation guard tests; never probes or opens a device."""
from contextlib import ExitStack, contextmanager, redirect_stdout
import io
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import prepare_verified_theme_usb as usb


HASH = 'ab' * 32
IMAGE = usb.PHASE / 'guard-test/usb.raw'
PROOF = usb.PHASE / 'guard-test/proof.json'
THEMES = ['GRAPHIC','ELLIPTIC','CUBIC','REFLEX','ESSENTIEL','REDLINE','SQUARE','WARMLIGHT']


def setUpModule():
    global _identity_patch
    _identity_patch = patch.multiple(
        usb, DEVICE=Path('/dev/disk/by-id/usb-SMEG_TEST_DEVICE'),
        SERIAL='SMEG_TEST_SERIAL', CAPACITY=64 * 1024**3, MODEL='SMEG TEST USB',
    )
    _identity_patch.start()


def tearDownModule():
    _identity_patch.stop()


def drive():
    return {'name':'sdb','path':'/dev/sdb','type':'disk','maj:min':'8:16',
            'size':usb.CAPACITY,'model':usb.MODEL,'serial':usb.SERIAL,
            'tran':'usb','rm':True,'ro':False,'mountpoints':[None],
            'children':[{'path':'/dev/sdb1','type':'part','mountpoints':[None]}]}


@contextmanager
def device_mocks(disks, mode=stat.S_IFBLK, rdev=os.makedev(8,16), alias='/dev/sdb'):
    with ExitStack() as stack:
        command=stack.enter_context(patch.object(usb.subprocess,'check_output',return_value=json.dumps({'blockdevices':disks}).encode()))
        stack.enter_context(patch.object(Path,'exists',return_value=True))
        stack.enter_context(patch.object(Path,'resolve',return_value=Path(alias)))
        stack.enter_context(patch.object(Path,'stat',return_value=SimpleNamespace(st_mode=mode,st_rdev=rdev)))
        yield command


def receipts():
    validation={'virtual_USB':{'sha256':HASH}}
    independent={'virtual_USB_sha256':HASH,'all12_asset_files_match_manifest':True,
                 'exact_SQL_change_count':20,'all_other_SQL_rows_columns_and_schema_preserved':True,
                 'audit_sources_and_original_backups_unchanged':True,
                 'virtual_USB_readback':{'all_hashes_match':True,'all_package_members_readback_verified':151},
                 'all_package_file_sha256':{str(i):{'sha256':HASH}for i in range(151)}}
    proof={'candidate_USB_sha256':HASH,'exact_native_USB_install_and_cold_boot_verified':True,
           'all_eight_theme_switches_visually_verified':True,'verified_theme_names':THEMES.copy(),
           'all_eight_themes_Internet_menu_verified':True,'unresolved_compatibility_issues':[],
           'fatal_guest_exceptions':[]}
    manifest={'files':[{'path':f'SMEG_BACKUP/file-{i}','sha256':HASH}for i in range(34)]}
    return validation,independent,proof,manifest


@contextmanager
def receipt_mocks(values, bad_backup=False):
    validation,independent,proof,manifest=values
    def read_text(path,*args,**kwargs):
        mapping={'candidate-validation.json':validation,'candidate-independent-audit.json':independent,
                 'proof.json':proof,'copy-manifest.json':manifest}
        if path.name not in mapping:
            raise AssertionError('Unexpected file read: '+str(path))
        return json.dumps(mapping[path.name])
    def checksum(path):
        if bad_backup and str(path).endswith('file-33'):
            return 'cd'*32
        return HASH
    with ExitStack()as stack:
        stack.enter_context(patch.object(Path,'is_file',return_value=True))
        stack.enter_context(patch.object(Path,'is_symlink',return_value=False))
        stack.enter_context(patch.object(Path,'stat',return_value=SimpleNamespace(st_mode=stat.S_IFREG,st_size=2*1024**3)))
        stack.enter_context(patch.object(Path,'read_text',read_text))
        stack.enter_context(patch.object(usb,'sha',side_effect=checksum))
        yield


class DeviceIdentity(unittest.TestCase):
    def test_unconfigured_identity_fails_before_inventory(self):
        with patch.multiple(usb, SERIAL='', CAPACITY=0, MODEL=''),\
             patch.object(usb.subprocess, 'check_output') as inventory,\
             self.assertRaisesRegex(ValueError, 'Configure an explicit USB identity'):
            usb.device_state()
        inventory.assert_not_called()

    def test_exact_device_preflight_reads_only(self):
        with device_mocks([drive()])as command:
            node,mounted=usb.device_state()
            self.assertEqual(node['serial'],usb.SERIAL)
            self.assertEqual(mounted,[])
            self.assertIn('TYPE',command.call_args.args[0][-1])

    def test_wrong_identity_transport_capacity_removability_and_readonly(self):
        for key,value in [('serial','wrong'),('tran','sata'),('size',usb.CAPACITY-512),
                          ('model','OTHER'),('rm',False),('ro',True),('type','part')]:
            node=drive();node[key]=value
            with self.subTest(key=key),device_mocks([node]),self.assertRaises(ValueError):
                usb.device_state()

    def test_wrong_alias_or_kernel_number_or_regular_file(self):
        cases=[{'alias':'/dev/sda'},{'rdev':os.makedev(8,0)},{'mode':stat.S_IFREG}]
        for values in cases:
            with self.subTest(values=values),device_mocks([drive()],**values),self.assertRaises(ValueError):
                usb.device_state()

    def test_missing_and_ambiguous_drive(self):
        for nodes in [[],[drive(),drive()]]:
            with self.subTest(count=len(nodes)),device_mocks(nodes),self.assertRaises(ValueError):
                usb.device_state()

    def test_recursive_mounted_child_and_nullable_mountpoints(self):
        node=drive();node['mountpoints']=None
        node['children'][0]['children']=[{'path':'/dev/mapper/child','mountpoints':['/media/test']}]
        with device_mocks([node]):
            self.assertEqual(usb.device_state()[1],['/media/test'])

    def test_nested_matching_drive_can_be_found(self):
        with device_mocks([{'serial':None,'children':[drive()]}]):
            self.assertEqual(usb.device_state()[0]['path'],'/dev/sdb')


class ReceiptGuards(unittest.TestCase):
    def test_full_matching_receipts(self):
        values=receipts()
        with receipt_mocks(values):
            self.assertEqual(usb.validate_receipts(IMAGE,PROOF),values[2])

    def test_every_theme_and_exact_native_proof_required(self):
        for mutation in ['native','visual','missing_theme','wrong_theme','exception','sha']:
            values=receipts();proof=values[2]
            if mutation=='native':proof['exact_native_USB_install_and_cold_boot_verified']=False
            elif mutation=='visual':proof['all_eight_theme_switches_visually_verified']=False
            elif mutation=='missing_theme':proof['verified_theme_names'].pop()
            elif mutation=='wrong_theme':proof['verified_theme_names'][0]='FICTITIOUS'
            elif mutation=='exception':proof['fatal_guest_exceptions']=['Data access exception']
            else:proof['candidate_USB_sha256']='cd'*32
            with self.subTest(mutation=mutation),receipt_mocks(values),self.assertRaises(ValueError):
                usb.validate_receipts(IMAGE,PROOF)

    def test_independent_receipt_must_be_complete_and_same_image(self):
        for mutation in ['truthy_only','sha','assets','sql','preservation','sources','readback','member_count']:
            values=list(receipts());independent=values[1]
            if mutation=='truthy_only':values[1]={'arbitrary':True}
            elif mutation=='sha':independent['virtual_USB_sha256']='cd'*32
            elif mutation=='assets':independent['all12_asset_files_match_manifest']=False
            elif mutation=='sql':independent['exact_SQL_change_count']=19
            elif mutation=='preservation':independent['all_other_SQL_rows_columns_and_schema_preserved']=False
            elif mutation=='sources':independent['audit_sources_and_original_backups_unchanged']=False
            elif mutation=='readback':independent['virtual_USB_readback']['all_hashes_match']=False
            else:independent['all_package_file_sha256'].pop('150')
            with self.subTest(mutation=mutation),receipt_mocks(values),self.assertRaises(ValueError):
                usb.validate_receipts(IMAGE,PROOF)

    def test_nonfatal_menu_incompatibility_or_missing_Internet_proof_blocks_preparation(self):
        for mutation in ['missing_Internet','false_Internet','missing_issues','DOTE_issue']:
            values=receipts();proof=values[2]
            if mutation=='missing_Internet':proof.pop('all_eight_themes_Internet_menu_verified')
            elif mutation=='false_Internet':proof['all_eight_themes_Internet_menu_verified']=False
            elif mutation=='missing_issues':proof.pop('unresolved_compatibility_issues')
            else:proof['unresolved_compatibility_issues']=['GRAPHIC main menu renders DOTE placeholder']
            with self.subTest(mutation=mutation),receipt_mocks(values),self.assertRaises(ValueError):
                usb.validate_receipts(IMAGE,PROOF)

    def test_original_exports_must_be_backed_up_exactly(self):
        with receipt_mocks(receipts(),bad_backup=True),self.assertRaises(ValueError):
            usb.validate_receipts(IMAGE,PROOF)


class ExclusiveOpenGuards(unittest.TestCase):
    def test_verified_open_descriptor(self):
        with patch.object(usb.os,'fstat',return_value=SimpleNamespace(st_mode=stat.S_IFBLK,st_rdev=os.makedev(8,16))),\
             patch.object(usb.fcntl,'ioctl',return_value=struct.pack('=Q',usb.CAPACITY)):
            usb.validate_open_device(99,drive())

    def test_wrong_open_device_type_number_or_capacity(self):
        for mode,rdev,size in [(stat.S_IFREG,os.makedev(8,16),usb.CAPACITY),
                               (stat.S_IFBLK,os.makedev(8,0),usb.CAPACITY),
                               (stat.S_IFBLK,os.makedev(8,16),usb.CAPACITY-512)]:
            with self.subTest(mode=mode,rdev=rdev,size=size),\
                 patch.object(usb.os,'fstat',return_value=SimpleNamespace(st_mode=mode,st_rdev=rdev)),\
                 patch.object(usb.fcntl,'ioctl',return_value=struct.pack('=Q',size)),self.assertRaises(ValueError):
                usb.validate_open_device(99,drive())

    def run_main(self,arguments,mounted):
        stack=ExitStack()
        stack.enter_context(patch.object(sys,'argv',['prepare_verified_theme_usb.py','--image',str(IMAGE),'--verification',str(PROOF)]+arguments))
        stack.enter_context(patch.object(Path,'is_symlink',return_value=False))
        stack.enter_context(patch.object(Path,'is_file',return_value=True))
        stack.enter_context(patch.object(Path,'exists',return_value=False))
        stack.enter_context(patch.object(Path,'resolve',lambda x,*a,**k:x))
        stack.enter_context(patch.object(usb,'validate_receipts',return_value=receipts()[2]))
        stack.enter_context(patch.object(usb,'device_state',return_value=(drive(),mounted)))
        stack.enter_context(patch.object(usb,'sha',return_value=HASH))
        stack.enter_context(patch.object(usb.os,'geteuid',return_value=0))
        opened=stack.enter_context(patch.object(usb.os,'open',side_effect=AssertionError('No physical opens allowed in mock tests')))
        return stack,opened

    def test_default_preflight_never_opens_for_write(self):
        stack,opened=self.run_main([],['/media/read-only-usb'])
        with stack,redirect_stdout(io.StringIO())as output:
            usb.main()
        self.assertFalse(json.loads(output.getvalue())['USB_written'])
        opened.assert_not_called()

    def test_write_rejects_mounted_child_before_open(self):
        stack,opened=self.run_main(['--write'],['/media/child'])
        with stack,self.assertRaisesRegex(ValueError,'Unmount'):
            usb.main()
        opened.assert_not_called()

    def test_failed_receipt_never_probes_device(self):
        stack,opened=self.run_main(['--write'],[])
        with stack,patch.object(usb,'validate_receipts',side_effect=ValueError('Theme verification incomplete')),\
             patch.object(usb,'device_state')as probe,self.assertRaisesRegex(ValueError,'Theme verification'):
            usb.main()
        probe.assert_not_called()
        opened.assert_not_called()

    def test_new_mount_at_second_identity_check_prevents_open(self):
        stack,opened=self.run_main(['--write'],[])
        with stack,patch.object(usb,'device_state',side_effect=[(drive(),[]),(drive(),['/media/newmount'])]),\
             patch.object(usb.os,'open',return_value=99) as source_open,\
             patch.object(usb.os,'fdopen',return_value=io.BytesIO(b'checked source')),\
             patch.object(usb,'validate_open_source'),\
             self.assertRaisesRegex(ValueError,'became mounted'):
            usb.main()
        source_open.assert_called_once_with(IMAGE,os.O_RDONLY|os.O_NOFOLLOW)
        opened.assert_not_called()


class SourceProofBinding(unittest.TestCase):
    def test_original_regular_source_is_accepted_and_rewound(self):
        original=b'original exact tested image A\x00\xff'
        with tempfile.TemporaryFile('w+b') as source:
            source.write(original);source.seek(7)
            usb.validate_open_source(source,hashlib.sha256(original).hexdigest(),len(original))
            self.assertEqual(source.tell(),0)
            self.assertEqual(source.read(),original)

    def test_same_length_changed_source_cannot_use_original_proof(self):
        original=b'original image A'
        with tempfile.TemporaryFile('w+b') as source:
            source.write(original[:-1]+b'B')
            source.flush()
            with self.assertRaisesRegex(ValueError,'differs from the exact tested image'):
                usb.validate_open_source(source,hashlib.sha256(original).hexdigest(),len(original))

    def test_open_source_geometry_checked_before_hash(self):
        for size in [7,9]:
            with self.subTest(size=size),tempfile.TemporaryFile('w+b') as source:
                source.write(b'x'*size)
                source.flush()
                with patch.object(usb.hashlib,'file_digest') as digest,\
                     self.assertRaisesRegex(ValueError,'regular image geometry'):
                    usb.validate_open_source(source,HASH,8)
                digest.assert_not_called()

    def test_changed_image_after_proof_fails_before_target_open_original_reaches_guarded_open(self):
        # Real temporary source bytes/FD; all receipt and disk inventory data are
        # mocked. The only permitted os.open is this temporary regular file.
        # Use small geometry only for the source validator so the regression
        # exercises the real hash check without hashing a 2 GiB test fixture.
        original=b'exact tested image A'
        changed=b'new untested image B'
        expected=hashlib.sha256(original).hexdigest()
        real_open=os.open
        real_validate=usb.validate_open_source
        for payload in [changed,original]:
            with self.subTest(original=payload==original),tempfile.TemporaryDirectory() as directory:
                source_path=Path(directory)/'usb.raw';source_path.write_bytes(payload)
                proof=receipts()[2];proof['candidate_USB_sha256']=expected
                calls=[]
                def guarded_open(path,flags,*args,**kwargs):
                    calls.append((Path(path),flags))
                    if Path(path)==source_path:
                        self.assertEqual(flags,os.O_RDONLY|os.O_NOFOLLOW)
                        return real_open(path,flags,*args,**kwargs)
                    self.assertEqual(Path(path),usb.DEVICE)
                    raise RuntimeError('Mock target open reached; no device accessed')
                stack,_=ExclusiveOpenGuards().run_main(['--write'],[])
                with stack,\
                     patch.object(sys,'argv',['prepare_verified_theme_usb.py','--image',str(source_path),'--verification',str(PROOF),'--write']),\
                     patch.object(usb,'validate_receipts',return_value=proof),\
                     patch.object(usb.os,'open',side_effect=guarded_open),\
                     patch.object(usb,'validate_open_source',side_effect=lambda source,sha:real_validate(source,sha,len(original))),\
                     patch.object(usb.os,'write') as target_write,\
                     patch.object(usb,'sha',side_effect=AssertionError('Main must retain the proof hash, not recompute it')):
                    if payload==changed:
                        with self.assertRaisesRegex(ValueError,'USB was not opened'):
                            usb.main()
                        self.assertEqual(calls,[(source_path,os.O_RDONLY|os.O_NOFOLLOW)])
                    else:
                        with self.assertRaisesRegex(RuntimeError,'Mock target open reached'):
                            usb.main()
                        self.assertEqual(calls[-1],(usb.DEVICE,os.O_RDWR|os.O_EXCL))
                    target_write.assert_not_called()


if __name__=='__main__':
    unittest.main()
