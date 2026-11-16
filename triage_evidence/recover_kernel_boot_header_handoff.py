#!/usr/bin/env python3
"""Original collection entry, early callbacks, header copies and root custody.
O(collection + fixups + source + records*log(records)) time;
O(collection + fixups + source + records) space. No native boot.
"""
import bisect,json,struct,re,subprocess
from pathlib import Path
from hashlib import sha256
from kext_port_tools import ROOT,SOURCE
from kernel_vm_mig_tools import Image
from resolve_kernel_collection_interfaces import commands
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_kernel_sptm_boot_inputs as B
P='kernel_boot_header_handoff';ENTRY=0xfffffe000c65c000;COMMON=ENTRY+0x34;COLD=ENTRY+0x50;SECONDARY=ENTRY+0xc4
PREINIT=0xfffffe000c66058c;DEVICE_INIT=0xfffffe000c660ad4;MAIN=0xfffffe000c639a40;COPY=0xfffffe000c647f10
RECORDS=0xfffffe000cbc4000;RECORD_END=0xfffffe000cbc50f0;CALLBACKS=0xfffffe000cbfebb8;CALLBACK_END=CALLBACKS+32
ARGS_DEST=0xfffffe0007e6d1e0;HEADER_DEST=0xfffffe0007e6d660;DEVICE_PTR=0xfffffe0007f8b5e0
CALLBACK_TARGETS=[0xfffffe000c660014,0xfffffe000c6613cc,0xfffffe000c6611e8,0xfffffe000c661fa4]
NEW=[ENTRY,COMMON,COLD,SECONDARY,PREINIT,DEVICE_INIT,MAIN,COPY,0xfffffe000c660058,0xfffffe000c660158,*CALLBACK_TARGETS]
FUNCTIONS=NEW+B.FUNCTIONS
SCOPE='Original LC_UNIXTHREAD entry and mode dispatch, cold-entry input custody, original early tagged-list linking and original header/SPTM publication, followed by a declared opaque-return continuation and original memcpy calls into kernel-owned boot-argument/header storage. Original bulk header copy supplies the previously unresolved pmap physical-root global and device-input pointer. Private exact state joins reach original converters/context/pool/CPU/mapping consumers. Self-relocator, CPU-feature callbacks, opaque transport and pre-copy registration leaves retain explicit private contracts; native caller, root/table ownership and a daemon transaction remain unknown.'
FALSE=B.FALSE+['native_entry_inputs_attested','native_self_relocation_executed','native_early_callbacks_executed','native_boot_header_ownership_established']

def logical(im,a,n):
 out=bytearray()
 while len(out)<n:
  at=a+len(out);pg=at&~4095;take=min(n-len(out),4096-(at-pg));out.extend(im.logical_page(pg)[at-pg:at-pg+take])
 return bytes(out)

def build():
 im=Image();k=im.k;functions=[];opaque=[];old=json.loads(read(ROOT/(B.P+'_checks.json')));matched=0
 for a in FUNCTIONS:
  j=bisect.bisect_left(k.starts,a);assert k.starts[j]==a;b=B.BOOT_END if a==B.BOOT else k.starts[j+1];raw=k.read(a,b-a);ii=[]
  for at in range(a,b,4):
   word=k.read(at,4);d=list(k.cs.disasm(word,at));assert len(d)<=1
   ii.append({'ea':hex(at),'mnemonic':d[0].mnemonic if d else '.word','operands':d[0].op_str if d else hex(int.from_bytes(word,'little'))})
   if not d:opaque.append({'pc':hex(at),'bytes_hex':word.hex(),'word_u32':hex(int.from_bytes(word,'little'))})
  f={'start':hex(a),'end':hex(b),'bytes':raw.hex(),'sha256':sha256(raw).hexdigest(),'instructions':ii};prior=next((f for f in old['functions'] if f['start']==hex(a)),None)
  if prior is not None:assert prior==f;matched+=1
  functions.append(f)
 thread=[]
 for off,cmd,n in commands(k.data,0):
  if cmd!=5:continue
  flavor,count=struct.unpack_from('<II',k.data,off+8);assert (flavor,count,n)==(6,68,288)
  values=struct.unpack_from('<33QII',k.data,off+16);assert values[32]==ENTRY
  thread.append({'LC':'LC_UNIXTHREAD','command_offset':hex(off),'bytes_hex':k.data[off:off+n].hex(),'flavor':flavor,'state_count_u32':count,
   'registers31':list(map(hex,values[:31])),'SP':hex(values[31]),'PC':hex(values[32]),'CPSR':hex(values[33]),'padding_u32':values[34]})
 assert len(thread)==1
 sdk=Path(subprocess.check_output(['xcrun','--show-sdk-path'],text=True).strip())/'usr/include';schema=[]
 for name in ['mach/arm/thread_status.h','mach/arm/_structs.h']:
  raw=(sdk/name).read_bytes()
  if name.endswith('thread_status.h'):assert re.search(rb'#define ARM_THREAD_STATE64\s+6\b',raw)
  else:
   for token in [b'__uint64_t __x[29]',b'__uint64_t __fp',b'__uint64_t __lr',b'__uint64_t __sp',b'__uint64_t __pc',b'__uint32_t __cpsr',b'__uint32_t __pad']:assert token in raw
  schema.append({'header':name,'sha256':sha256(raw).hexdigest(),'size_bytes':len(raw)})
 callbacks=[im.pointer(a) for a in range(CALLBACKS,CALLBACK_END,8)];assert [int(p['target'],16) for p in callbacks]==CALLBACK_TARGETS
 assert all((p['format'],p['auth'],p['diversity'],p['address_diversity'],p['key'])==(8,1,'0x2abe',0,0) for p in callbacks)
 records=[];owners={}
 for a in range(RECORDS,RECORD_END,16):
  p=im.pointer(a+8);target=int(p['target'],16);owner=target&~3
  records.append({'address':hex(a),'raw_hex':k.read(a,16).hex(),'logical_hex':logical(im,a,16).hex(),'tagged_owner_fixup':p,'owner':hex(owner),'tag_u2':target&3,
   'signed_code_delta32':struct.unpack('<i',k.read(a,4))[0],'raw_branch_delta32':struct.unpack('<I',k.read(a+4,4))[0]})
  owners[owner]={'address':hex(owner),'raw24_hex':k.read(owner,24).hex(),'logical24_hex':logical(im,owner,24).hex()}
 strings=[]
 for a in [0xfffffe000704b389,0xfffffe00070b1614,0xfffffe0007062b7e,0xfffffe0007062b89,0xfffffe00070ea71b,0xfffffe00070ea745]:
  raw=k.read(a,200).split(bytes(1))[0];strings.append({'address':hex(a),'bytes_hex':raw.hex(),'text':raw.decode('ascii')})
 counts={'captured_functions':len(functions),'captured_words':sum(len(f['instructions']) for f in functions),'captured_bytes':sum(len(bytes.fromhex(f['bytes'])) for f in functions),
  'matched_prior_functions':matched,'opaque_words_preserved':len(opaque),'collection_thread_commands':len(thread),'early_callback_fixups':len(callbacks),'tagged_link_records':len(records),'unique_link_owners':len(owners)}
 return {'generator_sha256':sha(__file__),'scope':SCOPE,'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,
  'dependencies':{n:sha(ROOT/n) for n in [B.P+'_checks.json','kernel_native_reader.py','kernel_vm_mig_tools.py','resolve_kernel_collection_interfaces.py']},
  'functions':functions,'opaque_words':opaque,'collection_initial_thread':thread[0],'Apple_SDK_schema_headers':schema,'early_callbacks':callbacks,'tagged_link_records':records,'link_owner_blocks':sorted(owners.values(),key=lambda p:p['address']),
  'strings':strings,'exact_symbols':k.symbols([*FUNCTIONS,B.C.BOOTROOT,ARGS_DEST,HEADER_DEST,DEVICE_PTR]),
  'original_bulk_copy_destination_hex':k.read(ARGS_DEST,0x7d8).hex(),'verified_counts':counts,
  'conditional_kernel_boot_header_handoff_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
