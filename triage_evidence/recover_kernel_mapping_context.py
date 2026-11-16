#!/usr/bin/env python3
"""Original pmap context, root-pair and per-CPU result-pointer producers.
O(collection + captured bytes + fixups + scanned words) time/space.
Static metadata and complete functions; no native boot/translation effects.
"""
import bisect,json,struct
from hashlib import sha256
from kext_port_tools import ROOT,SOURCE
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_kernel_mapping_transport as T
import recover_kernel_zone_boot_inputs as B
import recover_kernel_physical_zero as Z
P='kernel_mapping_context';INIT=0xfffffe000be608f4;CPUINIT=0xfffffe000be734f0
P2V=0xfffffe000c6201c0;V2P=0xfffffe000c64529c;IDENT=0xfffffe000c6211d0;RESULT=0xfffffe000c62120c
GEOM=0xfffffe0007e6cb78;ROWS=0xfffffe0007013328;BOOTROOT=0xfffffe0007e6d838
ROOTPAIR=0xfffffe0007e6daa8;BUMP=0xfffffe0007e6da98;ASID_BITS=0xfffffe0007e6cf98;ASID_COUNT=0xfffffe0007e6ce44
CONV_GLOBALS=0xfffffe0007f8c718;TOPOLOGY=0xfffffe0007ef8c08;SHARED=0xfffffe0007e6d0b8
FUNCTIONS=[B.ARM,INIT,CPUINIT,P2V,V2P,IDENT,RESULT,Z.BZERO,T.GATE,T.DESC,T.IMPL,T.CLASSIFY,T.PRE,T.POST,T.CHECK]
SCOPE='Original ARM root-pair source cut, complete pmap context initializer, complete per-CPU initializer, original bidirectional range converters and original admission/descriptor/backend consumers. Exact state transfers across declared call epochs carry source-initialized context/geometry and the result-pointer slot written from an explicit opaque return. Range ownership, opaque SPTM identifier/result-pointer returns, initialization leaves, complete boot/gateway and native translation or daemon transaction identity remain unknown.'
FALSE=T.FALSE+['native_boot_executed','native_result_pointer_production_established','native_range_ownership_established','continuous_native_initialization_epoch_established']

def build():
 im=Image();k=im.k;k.cs.detail=True;functions=[];unknown=[]
 for address in FUNCTIONS:
  j=bisect.bisect_right(k.starts,address)-1;a,b=k.starts[j:j+2];assert a==address;raw=k.read(a,b-a);ii=[]
  for at in range(a,b,4):
   word=k.read(at,4);dec=list(k.cs.disasm(word,at));assert len(dec)<=1
   row={'ea':hex(at),'mnemonic':dec[0].mnemonic if dec else '.word','operands':dec[0].op_str if dec else hex(int.from_bytes(word,'little'))}
   if not dec:unknown.append({'pc':hex(at),'bytes_hex':word.hex(),'word_u32':hex(int.from_bytes(word,'little'))})
   ii.append(row)
  functions.append({'start':hex(a),'end':hex(b),'bytes':raw.hex(),'sha256':sha256(raw).hexdigest(),'instructions':ii})
 prior=json.loads(read(ROOT/(T.P+'_checks.json')));boot=json.loads(read(ROOT/(B.P+'_checks.json')));zero=json.loads(read(ROOT/(Z.P+'_checks.json')));matched=0
 for f in functions:
  old=next((g for g in prior['functions']+boot['functions']+zero['functions'] if g['start']==f['start']),None)
  if old is not None:assert f==old;matched+=1
 assert len(unknown)==4
 geometry=bytearray(k.read(GEOM,120));fixups=[]
 for off in [0,8]:
  p=im.pointer(GEOM+off);fixups.append(p);geometry[off:off+8]=int(p['target'],16).to_bytes(8,'little')
 assert struct.unpack_from('<Q',geometry)[0]==ROWS
 rows=[{'index':j,'address':hex(ROWS+56*j),'bytes_hex':k.read(ROWS+56*j,56).hex(),'u64_fields':[hex(x) for x in struct.unpack('<7Q',k.read(ROWS+56*j,56))]} for j in range(4)]
 calls=[];sections=[];words=0
 for s in k.kernel['segments']:
  if s['name'] not in ['__TEXT_EXEC','__TEXT_BOOT_EXEC','__KLD']:continue
  raw=k.read(s['address'],s['file_size']);sections.append({'name':s['name'],'address':hex(s['address']),'bytes_scanned':len(raw),'sha256':sha256(raw).hexdigest()});words+=len(raw)//4
  for j,(w,) in enumerate(struct.iter_unpack('<I',raw)):
   if w&0xfc000000!=0x94000000:continue
   pc=s['address']+4*j;imm=w&0x3ffffff;imm-=((imm>>25)&1)<<26;target=(pc+(imm<<2))&((1<<64)-1)
   if target in [INIT,CPUINIT]:calls.append({'pc':hex(pc),'target':hex(target),'compiler_function':hex(k.starts[bisect.bisect_right(k.starts,pc)-1])})
 assert any(c['pc']=='0xfffffe000be75458' and c['target']==hex(INIT) for c in calls)
 strings=[]
 for a in [0xfffffe000705f991,0xfffffe00070601b8,0xfffffe00070601e7,0xfffffe000705f9d4,0xfffffe000705f9e3]:
  raw=k.read(a,256).split(bytes(1))[0];strings.append({'address':hex(a),'bytes_hex':raw.hex(),'text':raw.decode('ascii')})
 counts={'captured_functions':len(functions),'captured_words':sum(len(f['instructions']) for f in functions),'captured_bytes':sum(len(bytes.fromhex(f['bytes'])) for f in functions),
  'matched_prior_functions':matched,'undecoded_words_preserved':4,'geometry_rows':len(rows),'geometry_fixups':len(fixups),
  'direct_call_scan_sections':len(sections),'aligned_branch_words_scanned':words,'initializer_call_sites':len(calls)}
 return {'generator_sha256':sha(__file__),'scope':SCOPE,'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,
  'dependencies':{n:sha(ROOT/n) for n in ['kernel_native_reader.py','kernel_vm_mig_tools.py',T.P+'_checks.json',B.P+'_checks.json',Z.P+'_checks.json']},
  'functions':functions,'undecoded_words':unknown,'geometry':{'address':hex(GEOM),'raw_bytes_hex':k.read(GEOM,120).hex(),'logical_bytes_hex':geometry.hex(),'fixups':fixups,'rows':rows},
  'bounds_literal':{'address':'0xfffffe000700f340','bytes_hex':k.read(0xfffffe000700f340,16).hex()},
  'flags_literal':{'address':'0xfffffe000700df08','bytes_hex':k.read(0xfffffe000700df08,8).hex()},
  'direct_call_scan':{'sections':sections,'aligned_words_scanned':words,'calls':calls,'scope':'Aligned BL-immediate references in three kernel executable segments only; indirect/tail/other-fileset callers and native reachability are not closed.'},
  'diagnostics':strings,'exact_symbols':k.symbols([*FUNCTIONS,GEOM,ROOTPAIR,BOOTROOT,T.CTX,T.CPU_BASE,ASID_BITS,ASID_COUNT]),
  'file_initial_state':{'context128_hex':k.read(T.CTX,128).hex(),'CPU_blocks49152_zero':k.read(T.CPU_BASE,49152)==bytes(49152),'root_pair16_hex':k.read(ROOTPAIR,16).hex()},
  'verified_counts':counts,'conditional_kernel_mapping_context_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
