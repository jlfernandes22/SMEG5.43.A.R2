#!/usr/bin/env python3
"""Check the ABI cases that otherwise silently corrupt software GL calls."""
import json
from pathlib import Path
m=json.loads((Path(__file__).parent/'gles_symbols.json').read_text())
r={x['name']:x for x in m['exports']}
assert len(r)==len(m['exports'])==186
assert len({x['address'] for x in r.values()})==186
assert r['glSampleCoverage']['signature']=='vfu'
assert r['glSampleCoverage']['arguments'][0]['abi']=={'bank':'FPR','register':1}
assert r['glSampleCoverage']['arguments'][1]['abi']=={'bank':'GPR','register':3}
assert r['glTexImage2D']['arguments'][8]['abi']['offset_from_r1']==8
assert r['glTexImage2DMM']['signature']=='vuiiiiiuup'
assert r['glTexImage2DMM']['arguments'][8]['pointer_role']=='output_guest_pointer_to_writable_texture_staging_memory'
assert r['glGetTexImageMM']['signature']=='vuiuup'
assert r['glCompressedTexImage2DMM']['signature']=='vuiuiiiip'
assert r['glCompressedTexImage2DMMDirect']['signature']=='vuuiiiip'
assert r['glOrthof']['signature']=='vffffff'
assert r['glGetString']['return']['code']=='p'
assert r['glGetString']['return']['abi']=='r3'
assert r['eglSwapBuffers']['signature']=='upp'
assert r['eglSwapBuffers']['arguments'][0]['pointer_role']=='opaque_native_EGL_handle_not_memory'
assert sum(x['signature'] is not None for x in r.values())==177
print('GLES metadata: 186 exports, 177 verified signatures; mixed FP/GPR, overflow stack and MM pointer roles pass')
