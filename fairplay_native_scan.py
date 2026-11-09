#!/usr/bin/env python3
"""Read-only whole-image static ARM64 transfer and pointer inventory."""
import bisect
import collections
import hashlib
import json
import struct
import uuid
from pathlib import Path
import capstone

ROOT = Path(__file__).resolve().parent
OUT = ROOT/'triage_evidence'
image = (ROOT/'com.apple.driver.FairPlayIOKit').read_bytes()
layout = json.loads((OUT/'native_function_layout.json').read_text())
chunks=[]
for f in layout['functions']:
    for a,b in f['chunks']: chunks.append((int(a,16),int(b,16),f['name'],f['start']))
chunks.sort();starts=[x[0] for x in chunks]
prefix_best=[]
for i,x in enumerate(chunks):
    prior=prefix_best[-1] if prefix_best else i
    prefix_best.append(i if x[1]>chunks[prior][1] else prior)
def owner(ea):
    i=bisect.bisect_right(starts,ea)-1
    if i>=0: i=prefix_best[i]
    if i>=0 and chunks[i][0]<=ea<chunks[i][1]: return chunks[i][2],chunks[i][3]
    return None,None
names={int(x['ea'],16):x['name'] for x in layout['names']}
segments=[];sections=[];symbols=[];commands=[];o=32;image_uuid=None
for _ in range(struct.unpack_from('<I',image,16)[0]):
    cmd,size=struct.unpack_from('<II',image,o);commands.append({'cmd':hex(cmd),'size':size})
    if cmd==0x19:
        name=image[o+8:o+24].split(b'\0')[0].decode();va,vs,fo,sz=struct.unpack_from('<4Q',image,o+24)
        segments.append({'name':name,'address':hex(va),'vm_size':vs,'file_offset':fo,'file_size':sz})
        for i in range(struct.unpack_from('<I',image,o+64)[0]):
            so=o+72+i*80;sn=image[so:so+16].split(b'\0')[0].decode()
            sa,ss,sf=struct.unpack_from('<QQI',image,so+32)
            sections.append({'segment':name,'section':sn,'address':hex(sa),'size':ss,'file_offset':sf})
    if cmd==2: _,_,symoff,nsyms,stroff,strsize=struct.unpack_from('<6I',image,o)
    if cmd==0x1b: image_uuid=str(uuid.UUID(bytes=image[o+8:o+24]))
    o+=size
for i in range(nsyms):
    sx,ty,se,de,va=struct.unpack_from('<IBBHQ',image,symoff+16*i)
    n=image[stroff+sx:image.index(0,stroff+sx)].decode(errors='replace') if sx else ''
    symbols.append({'name':n,'type':ty,'section':se,'description':de,'value':hex(va)})
cs=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN)
cs.skipdata=True
transfers=[];counts=collections.Counter();orphan_ranges=[];ipc=[];instruction_count=0
ipc_target=next((a for a,n in names.items() if n=='_mach_msg_rpc_from_kernel_proper'),None)
for sec in sections:
    if sec['section'] not in ['__text','__auth_stubs']: continue
    va=int(sec['address'],16);code=image[sec['file_offset']:sec['file_offset']+sec['size']]
    for ea,sz,mn,op in cs.disasm_lite(code,va):
        instruction_count+=1;counts[mn]+=1
        if mn in ['bl','b','blr','braa','brab','blraa','blrab','br','braaz','brabz','blraaz','blrabz']:
            fn,fa=owner(ea);target=None
            # Capstone versions differ in whether the leading '#' is included.
            if mn in ['bl','b']:
                try: target=int(op.lstrip('#'),16)
                except ValueError: pass
            row={'ea':hex(ea),'mnemonic':mn,'operands':op,'function':fn,'function_address':fa}
            if target is not None: row.update(target=hex(target),target_name=names.get(target),target_function=owner(target)[0])
            transfers.append(row)
            if target==ipc_target: ipc.append(row)
        if owner(ea)[0] is None:
            if orphan_ranges and int(orphan_ranges[-1]['end'],16)==ea: orphan_ranges[-1]['end']=hex(ea+sz)
            else: orphan_ranges.append({'start':hex(ea),'end':hex(ea+sz)})

# Values that look like canonical kernel pointers, outside all loaded real ranges.
# This is a pointer-shaped-data inventory, not proof of dereferencing each value.
real=[(int(s['start'],16),int(s['end'],16)) for s in layout['segments'] if s['name']!='UNDEF']
external=collections.defaultdict(list);local_refs=collections.defaultdict(list)
for sec in sections:
    if sec['section'] not in ['__const','__data','__auth_got','__got','__auth_ptr']: continue
    base=int(sec['address'],16);off=sec['file_offset'];end=min(sec['size'],len(image)-off)
    for j in range(0,end-7,8):
        v=struct.unpack_from('<Q',image,off+j)[0]
        if v>>40==0xfffffe:
            if not any(a<=v<b for a,b in real): external[hex(v)].append(hex(base+j))
            elif owner(v)[0] is not None: local_refs[hex(v)].append(hex(base+j))

summary={'binary_sha256':hashlib.sha256(image).hexdigest(),'uuid':image_uuid,
 'file_type':struct.unpack_from('<I',image,12)[0],'load_commands':commands,
 'segments':segments,'sections':sections,'nlist_symbols':len(symbols),
 'undefined_nlist_symbols':sum((s['type']&0xe)==0 and bool(s['type']&1) for s in symbols),
 'decoded_or_skipdata_units':instruction_count,'mnemonics':dict(counts),
 'transfers':len(transfers),'direct_rpc_calls':ipc,'orphan_code_ranges':orphan_ranges,
 'external_pointer_shaped_values':len(external),'interpretation':'Static scan only; indirect targets and reachability not exhaustively resolved. O(I log F + P*S) time, O(I + P + F) storage: I instructions, F function chunks, P pointer slots, S segments.'}
for name,obj in [('native_scan_summary.json',summary),('native_transfers.json',transfers),('macho_symbols.json',symbols),('external_pointer_values.json',dict(external)),('local_function_pointer_refs.json',dict(local_refs))]:
    (OUT/name).write_text(json.dumps(obj,indent=2)+'\n')
print(json.dumps({k:v for k,v in summary.items() if k not in ['mnemonics','sections','segments','load_commands','orphan_code_ranges']},indent=2))
