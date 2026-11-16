#!/usr/bin/env python3
"""Pinned collection traversal and module-pointer signing source/records.
O(collection + load commands + pointer bytes) time/space. No native execution.
"""
import json,struct,bisect,subprocess,re
from pathlib import Path
from hashlib import sha256
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import sha
from resolve_kernel_collection_interfaces import commands
P='kernel_initializer_pointer_signing'
WALK=0xfffffe000c47cce0;SIGN=0xfffffe000c656ca4;SIGN_END=0xfffffe000c657040;HEADER=0xfffffe0007004000
SCOPE='Original collection/fileset segment traversal and nonzero module initializer/terminator pointer re-signing, including FairPlayIOKit tables. Separate logical-PAC CPU cases; no module callback invocation, native signatures or replacement of the retained continuous startup.'
def logical(im,a,n):
 out=bytearray()
 while n:
  count=min(n,4096-(a&4095));out+=im.logical_page(a&~4095)[a&4095:(a&4095)+count];a+=count;n-=count
 return bytes(out)
def body(k,a,end=None):
 compiler_end=k.starts[bisect.bisect_right(k.starts,a)];end=compiler_end if end is None else end;raw=k.read(a,end-a)
 rows=[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str,'bytes_hex':bytes(i.bytes).hex()} for i in k.cs.disasm(raw,a)];assert len(rows)*4==len(raw)
 result={'start':hex(a),'end':hex(end),'compiler_recorded_end':hex(compiler_end),'bytes':raw.hex(),'sha256':sha256(raw).hexdigest(),'instructions':rows}
 if end<compiler_end:
  trailing=k.read(end,compiler_end-end);assert rows[-1]['mnemonic']=='ret' and not any(i['mnemonic']=='ret' for i in rows[:-1])
  for i in rows:
   if i['mnemonic'].startswith('b') and i['mnemonic']!='bti' or i['mnemonic'] in ['cbz','cbnz','tbz','tbnz']:
    target=int(i['operands'].rsplit('#',1)[1],16);assert a<=target<end
  result['excluded_trailing_bytes']={'size_bytes':len(trailing),'sha256':sha256(trailing).hexdigest(),'all_zero':not any(trailing),'nonzero_bytes':sum(bool(x) for x in trailing),'scope':'Compiler start metadata extends beyond the sole RET; every direct branch in the bounded closure stays within it. Excluded bytes are not asserted to be padding or another function.'}
 return result
def build():
 im=Image();k=im.k;headers=[];tables=[]
 for image in [k.root,*k.entries]:
  off=image['header_offset'];size=32+struct.unpack_from('<I',k.data,off+20)[0];raw=k.data[off:off+size];address=next(s['address']+off-s['file_offset'] for s in k.root['segments'] if s['file_offset']<=off< s['file_offset']+s['file_size']);assert logical(im,address,size)==raw
  headers.append({'image':image['name'],'address':hex(address),'bytes_hex':raw.hex()})
  for at,c,n in commands(k.data,off):
   if c!=0x19:continue
   for j in range(struct.unpack_from('<I',k.data,at+64)[0]):
    section=at+72+80*j;flags=struct.unpack_from('<I',k.data,section+64)[0]
    if flags&255 not in [9,10]:continue
    a,length=struct.unpack_from('<QQ',k.data,section+32);assert length%8==0;data=logical(im,a,length);pointers=[im.pointer(p) for p in range(a,a+length,8)];assert all(int(p['target'],16)==struct.unpack_from('<Q',data,8*j)[0] for j,p in enumerate(pointers))
    tables.append({'image':image['name'],'segment_command':hex(address+at-off),'section_index':j,'section_record_hex':k.data[section:section+80].hex(),'section':k.data[section:section+16].split(b'\0')[0].decode(),'segment':k.data[section+16:section+32].split(b'\0')[0].decode(),'flags':hex(flags),'address':hex(a),'size_bytes':length,'original_bytes_hex':k.read(a,length).hex(),'logical_bytes_hex':data.hex(),'pointers':pointers})
 fairplay=[t for t in tables if t['image']=='com.apple.driver.FairPlayIOKit'];targets=[int(p['target'],16) for t in fairplay for p in t['pointers']];callback_bodies=[]
 for j,a in enumerate(targets):
  size=84 if j<3 else 16;raw=k.read(a,size);rows=[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str,'bytes_hex':bytes(i.bytes).hex()} for i in k.cs.disasm(raw,a)];assert len(rows)*4==size and rows[-1]['mnemonic']==('retab' if j<3 else 'b');callback_bodies.append({'start':hex(a),'end':hex(a+size),'bytes':raw.hex(),'sha256':sha256(raw).hexdigest(),'instructions':rows,'scope':'Explicit bounded C++ initializer or destructor wrapper; not executed in the collection-walker CPU cases.'})
 classes=[]
 for a,name,meta,literal,parent,size,vtable in [(targets[0],'FPMemoryDescriptor',0xfffffe000ccc77f8,0xfffffe000790ae98,0xfffffe000847c5c8,48,0xfffffe000846a750),(targets[1],'com_apple_driver_FairPlayIOKitUserClient',0xfffffe000ccc7820,0xfffffe000790aeca,0xfffffe000847c5b8,248,0xfffffe000846b288),(targets[2],'com_apple_driver_FairPlayIOKit',0xfffffe000ccc7878,0xfffffe000790cc00,0xfffffe000847c5d8,136,0xfffffe000846c328)]:
  text=k.read(literal,128).split(b'\0')[0].decode();assert text==name;classes.append({'initializer':hex(a),'class_name':name,'class_name_address':hex(literal),'metaclass':hex(meta),'superclass_pointer':im.pointer(parent),'class_size_bytes':size,'constructor_call_PC':hex(a+44),'constructor_stub':hex(0xfffffe000a69f174),'metaclass_vtable_address_point':hex(vtable),'vtable_store_PC':hex(a+72),'vtable_data_discriminator':'0xcda1'})
 for c in classes:
  address=int(c['metaclass_vtable_address_point'],16);c['metaclass_vtable_symbol_base']=hex(address-16);c['first_vtable_entry_pointer']=im.pointer(address)
 stubs=[{'address':hex(a),'bytes_hex':k.read(a,16).hex(),'authenticated_target_pointer':im.pointer(slot)} for a,slot in [(0xfffffe000a69f174,0xfffffe000847c3e8),(0xfffffe000a69f184,0xfffffe000847c3f0)]];symbols=k.symbols(targets+[int(c['metaclass'],16) for c in classes]+[int(c['superclass_pointer']['target'],16) for c in classes]+[int(c['metaclass_vtable_symbol_base'],16) for c in classes]+[int(s['authenticated_target_pointer']['target'],16) for s in stubs])
 sdk=Path(subprocess.check_output(['xcrun','--show-sdk-path'],text=True).strip());loader=(sdk/'usr/include/mach-o/loader.h').read_bytes();names=['LC_SEGMENT_64','LC_FILESET_ENTRY','LC_REQ_DYLD','SECTION_TYPE','S_MOD_INIT_FUNC_POINTERS','S_MOD_TERM_FUNC_POINTERS'];defines=[line for line in loader.decode().splitlines() if re.match(r'^#define\s+('+('|'.join(names))+r')\s',line)];assert len(defines)==6
 functions=[body(k,WALK),body(k,SIGN,SIGN_END)]
 return {'generator_sha256':sha(__file__),'scope':SCOPE,'kernel_collection_sha256':k.sha256,'functions':functions,'headers':headers,'pointer_tables':tables,'fairplay_target_symbols':{hex(a):symbols[hex(a)] for a in targets},'fairplay_callback_bodies':callback_bodies,'fairplay_class_initializers':classes,'fairplay_OSMetaClass_stubs':stubs,'fairplay_original_symbols':symbols,'exact_helper_symbols':k.symbols([WALK,SIGN]),'SDK_definitions':{'source':'Apple SDK loader header','source_sha256':sha256(loader).hexdigest(),'defines':defines},'verified_counts':{'functions':2,'source_words':sum(len(f['instructions']) for f in functions),'source_bytes':sum(len(bytes.fromhex(f['bytes'])) for f in functions),'headers':len(headers),'fileset_images':len(k.entries),'pointer_tables':len(tables),'pointer_slots':sum(len(t['pointers']) for t in tables),'pointer_bytes':sum(t['size_bytes'] for t in tables),'fairplay_tables':len(fairplay),'fairplay_pointer_slots':len(targets),'fairplay_callback_source_words':sum(len(f['instructions']) for f in callback_bodies),'fairplay_class_initializers':len(classes)},'prior_continuous_startup_unchanged':True,'native_target_executed':False}
if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
