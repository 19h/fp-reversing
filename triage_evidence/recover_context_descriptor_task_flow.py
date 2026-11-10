#!/usr/bin/env python3
"""Pin typed-context consumers,task carriers and frame-epoch boundaries;static only."""
import json,re,struct
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from kext_port_tools import ROOT,SOURCE,IMAGE,POOL,TABLE,qword,selected,block
from kernel_native_reader import Kernel
from recover_kext_aes_handoff import function
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha
from recover_versioned_request_abi import FLAGS
P='context_descriptor_task_flow'
SCOPE='Source-bound typed UserClient context flow through selector26 into mode/head/task consumers,two task-bearing records and sample descriptor factories. Literal-frame census is bounded;three private SP deltas,interference,whole-path reachability,task references,native descriptor ownership and delivery remain unproved.'
FUNCTIONS={'UserClient26':0xfffffe000a504034,'provider26':0xfffffe000a505198,'core26':0xfffffe000a635208,'sample_coordinator':0xfffffe000a6247a4,'second_consumer':0xfffffe000a61c404,'sample_sizes_factory':0xfffffe000a509948,'samples_factory':0xfffffe000a509980}
SPANS={'user_ABI':(0xfffffe000a504050,0xfffffe000a50408c),'provider_entry':(0xfffffe000a5051b8,0xfffffe000a5051d4),'provider_core':(0xfffffe000a5052f0,0xfffffe000a5052fc),'core_save':(0xfffffe000a63524c,0xfffffe000a635258),'mode_variable':(0xfffffe000a63c810,0xfffffe000a63c858),'mode_one':(0xfffffe000a642e4c,0xfffffe000a642e80),'context_alias':(0xfffffe000a642c64,0xfffffe000a642c80),'task_save':(0xfffffe000a647d94,0xfffffe000a647da0),'task_relay':(0xfffffe000a64a07c,0xfffffe000a64a084),'sample_record':(0xfffffe000a64b348,0xfffffe000a64b438),'sample_call':(0xfffffe000a64b438,0xfffffe000a64b498),'second_record':(0xfffffe000a651568,0xfffffe000a6516ac),'second_call':(0xfffffe000a6516ac,0xfffffe000a651714),'head':(0xfffffe000a65ed54,0xfffffe000a65ed84),'second_task_call':(0xfffffe000a61c84c,0xfffffe000a61c8e4),'coordinator_task_save':(0xfffffe000a624900,0xfffffe000a624908),'coordinator_task_call':(0xfffffe000a624b38,0xfffffe000a624b44),'sample_sizes_publish':(0xfffffe000a509964,0xfffffe000a509978),'samples_publish':(0xfffffe000a50999c,0xfffffe000a5099b0),'sample_sizes_ABI':(0xfffffe000a509958,0xfffffe000a509960),'samples_ABI':(0xfffffe000a509990,0xfffffe000a509998),'delta0':(0xfffffe000a63cd4c,0xfffffe000a63cd5c),'delta1':(0xfffffe000a6439e8,0xfffffe000a6439f8),'delta2':(0xfffffe000a644078,0xfffffe000a644088),'root_TL':(0xfffffe000a635358,0xfffffe000a63535c),'root_TR':(0xfffffe000a63536c,0xfffffe000a635370),'root_FLFR':(0xfffffe000a63665c,0xfffffe000a636678),'save_TL':(0xfffffe000a6362f0,0xfffffe000a6362f4),'save_TR':(0xfffffe000a635450,0xfffffe000a635454),'save_FLFR':(0xfffffe000a636694,0xfffffe000a63669c)}
DEPS=['userclient_context_lifecycle_source.json','userclient_context_lifecycle_checks.json','sample_caller_contracts.json','sample_caller_proofs.json','sample_descriptor_contracts.json','sample_descriptor_proofs.json','sample_descriptor_task_type_bits.smt2','selector26_lifecycle_contract.json','kext_port_tools.py','kernel_native_reader.py','recover_kext_aes_handoff.py','recover_kext_cold_init.py','validate_userclient_context_lifecycle.py','validate_versioned_request_abi.py','daemon_word_round_tools.py','validate_daemon_list_output.py','validate_daemon_existing_scalar_reader.py','validate_daemon_reader_container_origins.py']
def census(f):
 a=int(f['start'],16);raw=bytes.fromhex(f['bytes']);dc=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);dc.detail=True;ins=list(dc.disasm(raw,a));roots=[];overlap=[];reuse=[];sp=[]
 def width(i):
  p=i.op_str.split(',')[0]
  if i.mnemonic in['ldrb','ldurb','ldrsb','ldursb','strb','sturb']:w=1
  elif i.mnemonic in['ldrh','ldurh','ldrsh','ldursh','strh','sturh']:w=2
  elif i.mnemonic in['ldrsw','ldursw']:w=4
  else:w=16 if p.startswith('q')else 4 if p.startswith(('w','s'))else 8
  return w*2 if i.mnemonic in['ldp','stp','ldnp','stnp']else w
 for j,i in enumerate(ins):
  if i.op_str.startswith('sp,')or re.search(r'\[sp[^\]]*\]!',i.op_str)or re.search(r'\[sp[^\]]*\],',i.op_str):sp.append({'site':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str})
  m=re.search(r'\[sp(?:, #(-?0x[0-9a-f]+|\d+))?\]',i.op_str)
  if m and i.mnemonic.startswith(('ld','st')):
   off=int(m[1],0)if m[1]else 0;n=width(i);row={'site':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str,'frame_offset':off,'width_bytes':n}
   if off<0x740 and off+n>0x738:overlap.append(row)
   if off<0x9d8 and off+n>0x9d0:reuse.append(row)
  w=struct.unpack_from('<I',raw,j*4)[0]
  if w&0xffc003e0!=0xf94003e0 or((w>>10)&4095)*8!=0x738:continue
  reg='x'+str(w&31);uses=[]
  for v in ins[j+1:j+65]:
   if re.search(r'\['+reg+r'(?:,|\])',v.op_str)and v.mnemonic.startswith(('ld','st')):uses.append({'site':hex(v.address),'mnemonic':v.mnemonic,'operands':v.op_str})
   mn=v.mnemonic
   if mn in['b','br','braa','brab','bl','blr','blraa','blrab','ret','retab','retaa','brk','svc']or mn.startswith(('b.','cb','tb')):break
   writes={v.reg_name(x)for x in v.regs_access()[1]}
   if mn in['cmp','cmn','tst','ccmp','ccmn']:writes={x for x in writes if not re.fullmatch(r'[xw]\d+',x)}
   if{reg,'w'+reg[1:]}&writes:break
  roots.append({'site':hex(i.address),'register':reg,'direct_memory_uses_before_clobber_or_branch':uses})
 assert len(roots)==11 and len([x for x in overlap if x['mnemonic'].startswith('st')])==1
 assert len([x for x in sp if x['mnemonic']=='mov'])==3
 return {'compiler_envelope_aligned_words':len(ins),'saved_context_offset':0x738,'raw_mask_reload_sites':roots,'literal_saved_context_overlaps':overlap,'literal_task_scratch_overlaps':reuse,'SP_writes_and_writebacks':sp,'scope':'Exact compiler envelope;unsigned-immediate64-bit SP+738 root loads and bounded64-instruction direct-register uses. Explicit SP load/store overlap widths include pairs. Aliases,computed addressing,interprocedural clobbers and actual frame epochs remain outside this census.'}
def build():
 assert sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c';k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');fs={}
 for n,a in FUNCTIONS.items():
  f=function(k,e,a);raw=bytes.fromhex(f.pop('bytes_hex'));assert IMAGE.read(a,len(raw))==raw;f['bytes']=raw.hex();fs[n]=f
 fr={}
 for n,(a,z)in SPANS.items():
  f=next(f for f in fs.values()if int(f['start'],16)<=a<z<=int(f['end'],16));ii=[i for i in f['instructions']if a<=int(i['ea'],16)<z];assert len(ii)*4==z-a;fr[n]={'start':hex(a),'end':hex(z),'bytes':k.read(a,z-a).hex(),'instructions':ii}
 pairs={'T':(qword(POOL+0x840),qword(POOL+0xbb8)),'F':(qword(POOL+0x458)-8,qword(POOL+0x638)-12),'D':(qword(0xfffffe00084723f0)-4,qword(0xfffffe0008472478)-4)};banks={n+side:{'address':hex(a),'bytes':IMAGE.read(a,256).hex()}for n,ab in pairs.items()for side,a in zip(['L','R'],ab)};rules=[]
 for n,pair,key,add,target,div in [('SAMPLE','T',0x73,0xf1c,0xfffffe000a6247a4,0x6353),('SECOND','F',0x47,0xf07,0xfffffe000a61c404,0x1e46),('FACTORY','D',0xac,0xfa5,0xfffffe000a509980,0x55db)]:
  r=selected(*pairs[pair],key,add,TABLE);p=pointer(k,int(r['slot'],16));assert int(r['target'],16)==target and int(p['diversity'],16)==div;r.update(name=n,pair=pair,original_pointer=p);rules.append(r)
 pr=[pointer(k,a)for a in[POOL+0x840,POOL+0xbb8,POOL+0x458,POOL+0x638,0xfffffe00084723f0,0xfffffe0008472478,0xfffffe000846c2f0,0xfffffe000847c420]];syms=k.symbols([int(p['target'],16)for p in pr]+list(FUNCTIONS.values()))
 for p in pr:p['exact_symbols']=syms[p['target']]
 branches=[]
 for ix in[0x8f3,0x8f3^0x1e5]:
  p=pointer(k,TABLE+ix*8);p['index']=ix;branches.append(p)
 stub=block(0xfffffe000a69f1e4,16);assert k.read(0xfffffe000a69f1e4,16).hex()==stub['bytes']
 cc=census(fs['core26']);cp=SOURCE.parent/(SOURCE.name+'.c');lines=cp.read_text().splitlines();cx=[{'input_name':cp.name,'input_sha256':sha(cp),'first_line':a,'last_line':z,'text':'\n'.join(lines[a-1:z])}for a,z in[(7471,7512),(15242,15279),(184937,184995)]]
 counts={'captured_kext_functions':len(fs),'captured_instructions':sum(len(f['instructions'])for f in fs.values()),'captured_code_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'core_aligned_words':50634,'source_fragments':len(fr),'literal_context_reloads':len(cc['raw_mask_reload_sites']),'literal_context_stores':1,'literal_scratch_overlaps':len(cc['literal_task_scratch_overlaps']),'SP_mutation_sites':len(cc['SP_writes_and_writebacks']),'private_SP_delta_sites':3,'literal_bank_arrays':6,'bank_rules':3,'bank_input_cases':768,'original_pointer_records':len(pr),'mode_branch_pointers':2,'factory_stub_bytes':16}
 return {'generator_sha256':sha(__file__),'static_scope':SCOPE,'kext_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'dependencies':{n:sha(ROOT/n)for n in DEPS},'functions':fs,'fragments':fr,'context_census':cc,'banks':banks,'bank_rules':rules,'pointer_records':pr,'exact_symbols':syms,'mode_one_branch_pointers':branches,'factory_import_stub':stub,'associated_C':cx,'new_IDA_access':False,'semantic_memory_claims_used':0,'verified_source_counts':counts,**{n:False for n in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
