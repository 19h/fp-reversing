#!/usr/bin/env python3
"""Original collection-header publisher/getter and direct caller census.
O(collection bytes + scanned words + captured bytes); no target execution.
"""
import json,struct,bisect
from hashlib import sha256
from kernel_native_reader import Kernel
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import sha
from recover_kernel_boot_environment_publication import capture
P='kernel_collection_header_publication';SET=0xfffffe000c6626e4;GET=0xfffffe000c5e5600;BOOT=0xfffffe000c66058c
SLOT=0xfffffe0007f8b528;MAP=0xfffffe00070303b0;HEADER=0xfffffe0007004000;KHEADER=0xfffffe000700c000
SCOPE='Original kernel-collection header/slide/minimum-address publication, kind mapping, direct boot caller and logging consumer. Separate publisher CPU cases; no replacement of the retained poisoned startup state or native boot admission.'
def build():
 k=Kernel();segments=[];calls=[];loads=[]
 for s in k.kernel['segments']:
  if s['name'] not in ['__TEXT_EXEC','__TEXT_BOOT_EXEC','__KLD']:continue
  raw=k.read(s['address'],s['file_size']);words=[w for w, in struct.iter_unpack('<I',raw)];segments.append({'name':s['name'],'start':hex(s['address']),'size_bytes':len(raw),'sha256':sha256(raw).hexdigest(),'words':len(words)})
  for j,w in enumerate(words):
   pc=s['address']+4*j
   if w&0x7c000000==0x14000000:
    off=(w&0x3ffffff)<<2;off=off-0x10000000 if off&0x8000000 else off
    if (pc+off)&((1<<64)-1)==SET:calls.append({'PC':hex(pc),'target':hex(SET),'owner':hex(k.starts[bisect.bisect_right(k.starts,pc)-1]),'bytes_hex':k.read(pc,4).hex()})
   if w&0x9f000000!=0x90000000 or j+1==len(words):continue
   imm=((w>>5)&0x7ffff)<<2|((w>>29)&3);imm=imm-(1<<21) if imm&(1<<20) else imm;n=words[j+1]
   if ((pc&~4095)+(imm<<12))&((1<<64)-1)==SLOT&~4095 and n&0xffc00000==0xf9400000 and (n>>5)&31==w&31 and ((n>>10)&4095)*8==SLOT&4095:loads.append({'ADRP_PC':hex(pc),'load_PC':hex(pc+4),'owner':hex(k.starts[bisect.bisect_right(k.starts,pc+4)-1]),'bytes_hex':k.read(pc,8).hex()})
 functions=[capture(k,a) for a in [SET,GET,BOOT,0xfffffe000c47cce0,0xfffffe000c48f880]];command_bytes=32+struct.unpack_from('<I',k.data,20)[0]
 return {'generator_sha256':sha(__file__),'scope':SCOPE,'kernel_collection_sha256':k.sha256,'functions':functions,'kind_map':{'address':hex(MAP),'bytes_hex':k.read(MAP,24).hex()},'initial_banks':{'address':hex(SLOT),'bytes_hex':k.read(SLOT,96).hex()},'original_collection_header':{'address':hex(HEADER),'bytes_hex':k.read(HEADER,command_bytes).hex()},'kernel_first_segment_VM_address':{'address':hex(KHEADER+0x38),'bytes_hex':k.read(KHEADER+0x38,8).hex()},'panic_strings':[{'address':hex(a),'text':k.read(a,128).split(b'\0')[0].decode('ascii')} for a in [0xfffffe00070ea8a6,0xfffffe00070ea8bd]],'exact_symbols':k.symbols([SET,GET,BOOT,SLOT]),'direct_census':{'scope':'All aligned words in three named file-backed kernel executable segments; adjacent ADRP/LDR references and direct setter branches only. No indirect/aliased/external writer completeness.','segments':segments,'setter_calls':calls,'adjacent_slot_loads':loads},'verified_counts':{'functions':len(functions),'words':sum(len(f['instructions']) for f in functions),'source_bytes':sum(len(bytes.fromhex(f['bytes'])) for f in functions),'scanned_words':sum(s['words'] for s in segments),'direct_setter_calls':len(calls),'adjacent_slot_loads':len(loads),'collection_header_bytes':command_bytes}}
if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
