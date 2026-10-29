#!/usr/bin/env python3
"""Join original SMEG exports with official Khronos prototypes; no guessed APIs."""
import gzip
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SYMBOLS = ROOT/'artifacts/phase3/payloads/SYSTEM/Application/PKG/abs_symbols_base.txt.gz'
REGISTRIES = [ROOT/'sources/khronos/gl.xml', ROOT/'sources/khronos/egl.xml']
OUT = ROOT/'emulation/gles_symbols.json'
INC = ROOT/'emulation/smeg_gles_symbols.inc'
SCALARS = {'GLenum':'u', 'GLboolean':'u', 'GLbitfield':'u', 'GLuint':'u',
           'GLubyte':'u', 'GLushort':'u', 'GLint':'i', 'GLsizei':'i',
           'GLbyte':'i', 'GLshort':'i', 'GLintptr':'i', 'GLsizeiptr':'i',
           'GLfloat':'f', 'GLclampf':'f', 'GLfixed':'x', 'GLclampx':'x',
           'void':'v', 'EGLBoolean':'u', 'EGLDisplay':'p', 'EGLSurface':'p'}
CLIENT_ARRAYS = {'glVertexPointer', 'glColorPointer', 'glTexCoordPointer',
                 'glNormalPointer', 'glPointSizePointerOES',
                 'glWeightPointerOES', 'glMatrixIndexPointerOES'}

def plain(node):
    return ''.join(node.itertext()).strip()

def typecode(node):
    text = plain(node)
    if '*' in text:
        return 'p'
    return SCALARS[node.findtext('ptype') or text.split()[0]]

def main():
    commands = {}
    for path in REGISTRIES:
        for node in ET.parse(path).findall('commands/command'):
            proto = node.find('proto')
            if proto is not None:
                commands[proto.findtext('name')] = node
    # These two vendor prototypes are established by original native argument
    # use and Qt call sites, not inferred from their names or undocumented aliases.
    native_prototypes = {
        'glCompressedTexImage2DMM': ('void', [('GLenum','target'),('GLint','level'),
            ('GLenum','internalformat'),('GLsizei','width'),('GLsizei','height'),
            ('GLint','border'),('GLsizei','imageSize'),('void **','compressed_out')]),
        'glCompressedTexImage2DMMDirect': ('void', [('GLenum','target'),
            ('GLenum','internalformat'),('GLsizei','width'),('GLsizei','height'),
            ('GLint','border'),('GLsizei','imageSize'),('void **','compressed_out')]),
        'glTexImage2DMM': ('void', [('GLenum','target'),('GLint','level'),
            ('GLint','internalformat'),('GLsizei','width'),('GLsizei','height'),
            ('GLint','border'),('GLenum','format'),('GLenum','type'),('void **','pixels_out')]),
        'glGetTexImageMM': ('void', [('GLenum','target'),('GLint','level'),
            ('GLenum','format'),('GLenum','type'),('void *','pixels_out')]),
    }
    for name, (ret_type, params) in native_prototypes.items():
        node = ET.Element('command')
        proto = ET.SubElement(node,'proto');proto.text = ret_type+' '
        ET.SubElement(proto,'name').text = name
        for ctype, pname in params:
            param = ET.SubElement(node,'param')
            base = ctype.split()[0]
            pt = ET.SubElement(param,'ptype');pt.text = base
            pt.tail = ctype[len(base):]+' '
            ET.SubElement(param,'name').text = pname
        commands[name] = node
    exports = []
    for line in gzip.open(SYMBOLS, 'rt'):
        fields = line.split()
        if len(fields) == 3 and fields[1] == 'T' and (
                re.fullmatch(r'gl[A-Z]\w+', fields[2]) or fields[2] == 'eglSwapBuffers'):
            exports.append((int(fields[0], 16), fields[2]))
    records = []
    for address, name in exports:
        record = {'address':f'0x{address:08x}', 'name':name}
        command = commands.get(name)
        if command is None:
            record.update({'signature':None, 'intercept_safe':False,
                           'reason':'Vendor API absent from downloaded official registries; prototype unverified.'})
            records.append(record)
            continue
        proto = command.find('proto')
        ret = typecode(proto)
        gpr, fpr, stack = 3, 1, 8
        args = []
        for index, param in enumerate(command.findall('param')):
            code = typecode(param)
            declaration = plain(param)
            ptype = param.findtext('ptype') or 'void'
            argname = param.findtext('name')
            item = {'index':index, 'name':argname, 'ctype':declaration,
                    'base_type':ptype, 'code':code, 'guest_bits':32,
                    'registry_length':param.attrib.get('len')}
            if code == 'f':
                item['abi'] = {'bank':'FPR', 'register':fpr}
                fpr += 1
            elif gpr <= 10:
                item['abi'] = {'bank':'GPR', 'register':gpr}
                gpr += 1
            else:
                item['abi'] = {'bank':'stack', 'offset_from_r1':stack,
                               'endian':'big'}
                stack += 4
            if code == 'p':
                role = 'input' if 'const' in declaration else 'output'
                if ptype in ['EGLDisplay','EGLSurface']:
                    role = 'opaque_native_EGL_handle_not_memory'
                if name in ['glCompressedTexImage2DMM','glCompressedTexImage2DMMDirect']:
                    role = 'output_guest_pointer_to_writable_compressed_texture_memory'
                elif name == 'glTexImage2DMM':
                    role = 'output_guest_pointer_to_writable_texture_staging_memory'
                elif name == 'glGetTexImageMM':
                    role = 'output_texture_pixel_bytes'
                if name in CLIENT_ARRAYS:
                    role = 'client_array_pointer_or_bound_array_buffer_offset'
                elif name == 'glDrawElements':
                    role = 'indices_pointer_or_bound_element_array_buffer_offset'
                elif name == 'glGetPointerv':
                    role = 'output_guest_pointer_to_guest_pointer'
                item.update({'pointer_role':role, 'guest_pointer_bits':32,
                             'guest_pointee_byte_order':'big for numeric arrays; byte streams unchanged'})
            if ptype in ['GLboolean','GLubyte','GLbyte']:
                item['semantic_bits'] = 8
            elif ptype in ['GLshort','GLushort']:
                item['semantic_bits'] = 16
            if ptype in ['GLintptr','GLsizeiptr']:
                item['host_portability'] = 'Guest signed32; host pointer-sized signed scalar, explicitly widen for host call.'
            if code == 'x':
                item['fixed_point'] = 'signed16.16 in GPR for float-valued parameters; enum-valued Fog/TexEnv/TexParameter pnames use raw enum integer'
            args.append(item)
        record.update({'signature':ret+''.join(p['code'] for p in args),
                       'prototype':plain(proto)+'('+', '.join(p['ctype'] for p in args)+')',
                       'return':{'code':ret, 'ctype':plain(proto),
                                 'abi':'none' if ret == 'v' else ('f1' if ret == 'f' else 'r3'),
                                 'pointer_role':'host pointer requires stable guest-address copy' if ret == 'p' else None},
                       'arguments':args, 'intercept_safe':True,
                       'registry':('Original SMEG native code and Qt call sites' if name in native_prototypes else ('Khronos EGL XML' if name.startswith('egl') else 'Khronos OpenGL XML'))})
        records.append(record)
    provenance = []
    for path in REGISTRIES:
        provenance.append({'path':str(path.relative_to(ROOT)),
                           'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
    result = {'source_symbols':str(SYMBOLS.relative_to(ROOT)),
              'symbol_file_sha256':hashlib.sha256(SYMBOLS.read_bytes()).hexdigest(),
              'vendor_MM_evidence':{'glTexImage2DMM':{'native':'0x01fdc7c4','Qt_call':'0x01dfce08','return_capture':'0x01dfce0c','allocation':'TextureCreateLevel0x01ff40b4 calls nativeHostAlloc/ReallocUserModeMem only; TextureRemoveResident0x01ff2054 flags only','constraints':'internalformat=format=BGRA0x80e1, typeUNSIGNED_BYTE0x1401','output':'9thargvoid**; nativewritestextureCPUaddress','pixels':'Qt0x01dfce64..8c byteswapsARGBQImagewordstoBGRAbyte stream; do not swap again','row_stride':'4*MMwidth; Qtadds4*(MMwidth-QImagewidth) paddingaftereachrow'},'glGetTexImageMM':{'native':'0x01fdc318','Qt_call':'0x01e0dab4','pixels':'5tharg outputbytebuffer, QtglyphcacheformatLUMINANCE_ALPHA0x190a,typeUNSIGNED_BYTE0x1401'}},
              'registry_sources':['https://raw.githubusercontent.com/KhronosGroup/OpenGL-Registry/main/xml/gl.xml',
                                  'https://raw.githubusercontent.com/KhronosGroup/EGL-Registry/main/api/egl.xml'],
              'registry_files':provenance,
              'guest_abi':{'CPU':'PowerPC32 big endian, VxWorks EABI hard float',
                           'integer_pointer_arguments':'r3..r10 independently of floats; overflow stack begins r1+8',
                           'float_arguments':'f1 upward independently of GPR allocation',
                           'verified_mixed_argument_example':'glSampleCoverage01fcd41c saves GLfloatvaluefromf1 and subsequentGLbooleaninvertr3 at01fcd430',
                           'float_array_memory':'IEEE754 BE32; host must convert to native endian',
                           'pointer_lifetime':'Client arrays persist beyond setup calls; marshal at draw time or mirror stable storage',
                           'fixed_function_host_aliases':'glOrthof->glOrtho, glFrustumf->glFrustum, glClearDepthf->glClearDepth, glDepthRangef->glDepthRange require float-to-double conversion; x forms require16.16 conversion.'},
              'exports':records}
    OUT.write_text(json.dumps(result,indent=2)+'\n')
    lines = ['/* Generated by generate_gles_metadata.py; original addresses, Khronos prototypes.',
             ' * Signature: return then args; v void, u unsigned, i signed, f float, x fixed16.16, p pointer.',
             ' * GPR/FPR banks are independent. See gles_symbols.json for pointer roles/lengths.',
             ' * Four vendor MM APIs verified from original code/Qt calls; other unknowns excluded.',
             ' * EGL startup stays native. */']
    for record in records:
        if record['signature'] is not None:
            lines.append('{'+record['address']+', '+json.dumps(record['name'])+', '+json.dumps(record['signature'])+'},')
    INC.write_text('\n'.join(lines)+'\n')
    known = sum(r['signature'] is not None for r in records)
    print(json.dumps({'exports':len(records),'verified_signatures':known,'unverified_vendor':len(records)-known,
                      'json':str(OUT.relative_to(ROOT)),'include':str(INC.relative_to(ROOT))}))

if __name__ == '__main__':
    main()
