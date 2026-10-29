"""Exact original AUDIO_BT UI entry points for temporary progress dialogs."""
from pathlib import Path
import hashlib
ADDRESSES=[0x0288b97c,0x028acd98,0x028a8e8c,0x011334e8,0x01958d74,
    0x028a91d0,0x0288bee4,0x027360dc,0x02733578,0x027348c8,
    0x020615a0,0x028ad890,0x02063394,0x0206162c,0x0205fa84,0x020606c8,
    0x028ad7d4,0x028a924c,0x02734a80,0x02884c40,0x026883e8,
    0x028ceb54,0x028ceba8,0x02734bc4]
def write_contract(root:Path,out:Path):
    original=root/'artifacts/phase2/applications/AUDIO_BT_256/app.bin'
    app=original.read_bytes()
    def fnv(data):
        h=2166136261
        for x in data:h=((h^x)*16777619)&0xffffffff
        return h
    checks=[dict(address=a,hash=fnv(app[a-0x1000000:a-0x1000000+64]))for a in ADDRESSES]
    (out/'theme_progress_contract.h').write_text('struct ProgressCheck {unsigned address,hash;};\nstatic const struct ProgressCheck progress_checks[]={'+','.join('{0x%xu,0x%xu}'%(r['address'],r['hash'])for r in checks)+'};\n')
    return dict(app_sha256=hashlib.sha256(app).hexdigest(),checks=checks,
        busy_popup=9010,busy_resource=[9,41],completion_popup=9014,completion_resource=[9,39],
        transient_generic_wstring_offset='0x70',native_text_getter='0x028ad890',
        completion_numeric_text_control=500,native_update_text='0x027348c8',
        completion_success_logical_id='0x0033e334',completion_failure_logical_id='0x0033e336',
        progress_control=1000,progress_numeric_format=2,progress_range=[0,100],
        native_update_numeric='0x02734a80',native_progress_getter='0x026883e8',
        native_progress_client_getter='0x02884c40',BCM_progress_setters_called=False,
        percent_callback_file_IO=False,detail_callback_file_IO=False,
        original_range_callsite='0x028ceb54',original_percent_callsite='0x028ceba8')
