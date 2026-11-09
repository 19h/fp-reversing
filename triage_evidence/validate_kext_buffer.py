#!/usr/bin/env python3
"""Fresh original-byte, slot, factory, getter, SDK and local SMT verification.

Distinct private getter replay; no provider/prepare/PAC/native API execution.
O(B + C*I + E) time/space plus fixed-word SMT and compile-only SDK work.
"""
import collections,hashlib,json,struct,subprocess
from pathlib import Path
import z3
from kernel_native_reader import Kernel
from kext_port_tools import SOURCE,IMAGE,CS,ROOT
from recover_kext_cold_init import pointer
from recover_kext_buffer import sdk_command
from probe_kext_buffer import Getter,cases,ENTRY,OBJ,TABLE
from probe_kext_buffer_cleanup import Cleanup,cases as cleanup_cases,OBJ as COBJ,PROV as CPROV,FLAG,SERVICE,DESC,BYTES
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 counts=collections.Counter();c=json.loads((ROOT/'kext_buffer_contracts.json').read_text());p=json.loads((ROOT/'kext_buffer_profiles.json').read_text());proof=json.loads((ROOT/'kext_buffer_proofs.json').read_text());deps=set()
 for obj,name in[(c,'recover_kext_buffer.py'),(p,'probe_kext_buffer.py'),(proof,'prove_kext_buffer.py')]:
  assert sha(ROOT/name)==obj['generator_sha256']and not obj['full_goal_complete'];deps.add(name)
  for n,h in obj.get('dependencies',{}).items():assert sha(ROOT/n)==h;deps.add(n)
 k=Kernel();assert k.sha256==c['kernel_collection_sha256']==p['kernel_collection_sha256'];assert sha(SOURCE)==c['source_sha256'];assert k.symbols([int(a,16)for a in c['exact_symbols']])==c['exact_symbols']
 for r in c['kernel_functions']:assert k.function(int(r['start'],16))==r;counts['kernel_functions']+=1
 for r in c['kext_ranges']:
  a,z=int(r['start'],16),int(r['end'],16);raw=IMAGE.read(a,z-a);assert raw.hex()==r['bytes_hex']and hashlib.sha256(raw).hexdigest()==r['sha256'];assert r['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(raw,a)];counts['kext_ranges']+=1
 expected={0x28:('__ZNK8OSObject7releaseEv',0x3a87),0x218:('__ZN25IOGeneralMemoryDescriptor7prepareEj',0xf5b3),0x220:('__ZN25IOGeneralMemoryDescriptor8completeEj',0x9285),0x268:('__ZN24IOBufferMemoryDescriptor20initWithPhysicalMaskEP4taskjyyy',0x1c03),0x308:('__ZN24IOBufferMemoryDescriptor14getBytesNoCopyEv',0xf4f4)}
 for e in c['nominal_slots']:
  actual=pointer(k,int(e['slot'],16));assert all(e[n]==v for n,v in actual.items());assert int(e['slot'],16)==int(e['vtable_symbol_address'],16)+16+e['offset_from_vptr'];syms=k.symbols([int(e['target'],16)])[e['target']];assert syms==e['exact_symbols'];names=[x['name']for x in syms]
  if e['kind']=='buffer':name,tag=expected[e['offset_from_vptr']];assert names==[name]and int(e['diversity'],16)==tag;counts['buffer_slots']+=1
  elif e['kind']=='buffer_metaclass':assert names==['__ZNK24IOBufferMemoryDescriptor9MetaClass5allocEv']and e['offset_from_vptr']==0xa8 and e['diversity']=='0x1601';counts['metaclass_slots']+=1
  elif e['kind']=='provider':assert names==['__ZNK8OSObject7releaseEv']and e['diversity']=='0x3a87';counts['provider_slots']+=1
  else:assert e['kind']=='base_negative_control'and names==(['___cxa_pure_virtual']if e['offset_from_vptr']==0x218 else['__ZN15OSMetaClassBase25_RESERVEDOSMetaClassBase1Ev']);counts['base_negative_controls']+=1
 funcs={int(r['start'],16):r for r in c['kernel_functions']};getter=funcs[ENTRY];ops=[(r['mnemonic'],r['operands'])for r in getter['instructions']];assert ops==[('bti','c'),('ldrb','w8, [x0, #0xe0]'),('tbnz','w8, #6, #0xfffffe000c524b90'),('ldr','w8, [x0, #0x20]'),('and','w8, w8, #0xf0'),('cmp','w8, #0x20'),('b.ne','#0xfffffe000c524b84'),('ldr','x0, [x0, #0xb8]'),('ret',''),('ldr','x8, [x0, #0x60]'),('ldr','x0, [x8]'),('ret',''),('mov','x0, #0'),('ret','')]
 # Constructor and metaclass allocator explicitly install the same original vptr.
 for a in[0xfffffe000c525694,0xfffffe000c525cd0,0xfffffe000c525d04,0xfffffe000c525f70,0xfffffe000c525fc0]:
  op=[(r['mnemonic'],r['operands'])for r in funcs[a]['instructions']];assert('adrp','x16, #0xfffffe0007f85000')in op and('add','x16, x16, #0xd70')in op and('add','x16, x16, #0x10')in op and('pacda','x16, x17')in op and('str','x16, [x0]')in op;counts['buffer_vptr_installers']+=1
 f=funcs[0xfffffe000c526070]['instructions'];by={int(r['ea'],16):(r['mnemonic'],r['operands'])for r in f}
 for a,v in{0xfffffe000c52609c:('add','x0, x0, #0xdb0'),0xfffffe000c5260b0:('ldr','x8, [x16, #0xa8]!'),0xfffffe000c5260d0:('mov','x17, #0x268'),0xfffffe000c5260f0:('mov','x5, #0'),0xfffffe000c5260fc:('tbz','w0, #0, #0xfffffe000c526108'),0xfffffe000c52611c:('ldr','x8, [x16, #0x28]!')}.items():assert by[a]==v;counts['factory_source_facts']+=1
 caller={int(i['ea'],16):(i['mnemonic'],i['operands'])for i in c['kext_ranges'][0]['instructions']}
 for a,v in{0xfffffe000a5080c8:('mov','w1, #0x13'),0xfffffe000a508100:('mov','w1, #0'),0xfffffe000a508104:('movk','x16, #0xf5b3, lsl #48'),0xfffffe000a50810c:('cbz','w0, #0xfffffe000a50814c'),0xfffffe000a50816c:('movk','x16, #0xf4f4, lsl #48'),0xfffffe000a508178:('str','x0, [x8, #0x848]'),0xfffffe000a50818c:('mov','w0, #0'),0xfffffe000a5081a8:('strb','w8, [x20, #0xb00]')}.items():assert caller[a]==v;counts['kext_caller_source_facts']+=1
 e=c['associated_decompilation'];source=Path(e['path']);assert sha(source)==e['sha256'];excerpt=''.join(source.read_text().splitlines(keepends=True)[e['line_start']-1:e['line_end']]);assert excerpt==e['excerpt']and hashlib.sha256(excerpt.encode()).hexdigest()==e['excerpt_sha256']
 sdk=c['SDK_probe'];assert sha(ROOT/'kext_buffer_sdk_probe.cpp')==sdk['source_sha256'];assert sdk_command()==sdk['command']
 for e in sdk['primary_headers']:assert sha(Path(e['path']))==e['sha256'];counts['SDK_primary_headers']+=1
 compiled=subprocess.run(sdk_command(),capture_output=True,text=True);assert compiled.returncode==sdk['compile_exit']==0;counts['SDK_compile_exit']=0
 assert proof['contracts_sha256']==sha(ROOT/'kext_buffer_contracts.json')
 for e in proof['proofs']:
  path=ROOT/e['file'];assert sha(path)==e['sha256'];s=z3.Solver();s.set(timeout=30000);s.from_string(path.read_text());assert str(s.check())==e['result']=='unsat';counts['proofs_unsat']+=1;deps.add(e['file'])
 listed=list(cases());assert len(listed)==len(p['cases'])==4111;assert [r['input']for r in p['cases']]==listed;g=Getter(k);fresh=[]
 for row in p['cases']:
  case=row['input'];new=g.run(case);assert new==row;fresh.append(new);counts['fresh_runs']+=1;counts['fresh_source_visits']+=len(new['source_visits']);f=case['flag8'];t=case['type32'];direct=(t&0xf0)==0x20;branch='null'if f&0x40 else'direct'if direct else'indirect';result=0 if branch=='null'else case['direct64']if branch=='direct'else case['indirect64'];assert int(new['return64'],16)==result;counts[branch+'_returns']+=1
  addresses=[(int(r['address'],16),r['size_bytes'])for r in new['data_reads']];want=[(OBJ+0xe0,1)]+([]if branch=='null'else[(OBJ+0x20,4)]+([(OBJ+0xb8,8)]if branch=='direct'else[(OBJ+0x60,8),(TABLE,8)]));assert addresses==want
  for e in new['data_reads']:
   a,n=int(e['address'],16),e['size_bytes'];v=case['flag8']if a==OBJ+0xe0 else case['type32']if a==OBJ+0x20 else case['direct64']if a==OBJ+0xb8 else TABLE if a==OBJ+0x60 else case['indirect64'];assert bytes.fromhex(e['bytes_hex'])==v.to_bytes(n,'little');counts['source_data_read_events']+=1;counts['source_data_read_bytes']+=n
  counts[case['family']+'_cases']+=1
 assert len({r['input']['flag8']for r in fresh if r['input']['family']=='decision_grid'})==256;assert len({(r['input']['type32']>>4)&15 for r in fresh if r['input']['family']=='decision_grid'})==16;counts['original_getter_instructions']=len(set(a for r in fresh for a in r['source_visits']));assert counts['original_getter_instructions']==14
 cleanup=json.loads((ROOT/'kext_buffer_cleanup_profiles.json').read_text());assert cleanup['generator_sha256']==sha(ROOT/'probe_kext_buffer_cleanup.py')and cleanup['source_sha256']==sha(SOURCE)
 for n,h in cleanup['dependencies'].items():assert sha(ROOT/n)==h;deps.add(n)
 assert [r['input']for r in cleanup['cases']]==list(cleanup_cases());cg=Cleanup();cr=[]
 for old in cleanup['cases']:
  new=cg.run(old['input']);assert new==old;cr.append(new);counts['cleanup_fresh_runs']+=1;counts['cleanup_fresh_source_visits']+=len(new['source_visits']);cse=new['input'];d,b,pv=cse['descriptor_present'],cse['bytes_present'],cse['provider_present'];expected_calls=([('complete',hex(COBJ))]if d and b else[])+([('release',hex(COBJ))]if d else[])+([('release',hex(CPROV))]if pv else[]);assert[(e['kind'],e['receiver'])for e in new['modeled_calls']]==expected_calls;assert int(new['return64'],16)==0
  expected_writes=([BYTES]if d and b else[])+([DESC]if d else[])+([SERVICE]if pv else[])+[FLAG];writes=[e for e in new['source_writes']if int(e['address'],16)in[BYTES,DESC,SERVICE,FLAG]];assert[int(e['address'],16)for e in writes]==expected_writes
  for e in writes:assert bytes.fromhex(e['after_hex'])==bytes(e['size_bytes']);counts['cleanup_global_write_events']+=1
  final=new['final_globals'];assert final[hex(FLAG)]=='00'and final[hex(DESC)]=='0000000000000000'and final[hex(SERVICE)]=='0000000000000000';assert int.from_bytes(bytes.fromhex(final[hex(BYTES)]),'little')==(0x123456789abcdef0 if b and not d else 0)
  for e in new['modeled_calls']:
   assert not e['native_API_executed'];counts['cleanup_'+e['kind']+'_requests']+=1
   if e['kind']=='complete':assert e['W1']=='0x0'and int(e['modeled_return64'],16)==cse['complete_return32']
  if b and not d:counts['cleanup_declared_orphan_pointer_states']+=1
  if cse['family']=='return_status':assert cse['complete_return32']!=0;counts['cleanup_nonzero_complete_return_cases']+=1
 (ROOT/'kext_buffer_cleanup_replays.json').write_text(json.dumps({'scope':'Distinct fresh original cleanup control flow with declared objects and modeled calls.','generator_sha256':sha(Path(__file__)),'cases':cr,'native_target_executed':False},indent=2)+'\n');deps.update(['probe_kext_buffer_cleanup.py','kext_buffer_cleanup_profiles.json'])
 replay={'scope':'Distinct fresh original getter executions on declared fields; native object reachability unproved.','generator_sha256':sha(Path(__file__)),'cases':fresh,'native_target_executed':False};(ROOT/'kext_buffer_replays.json').write_text(json.dumps(replay,indent=2)+'\n')
 deps.update(['kext_buffer_contracts.json','kext_buffer_profiles.json','kext_buffer_proofs.json','recover_kext_buffer.py','probe_kext_buffer.py']);out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'dependencies':{n:sha(ROOT/n)for n in sorted(deps)},'verified_counts':dict(counts),'fresh_replays_sha256':sha(ROOT/'kext_buffer_replays.json'),'fresh_cleanup_replays_sha256':sha(ROOT/'kext_buffer_cleanup_replays.json'),'native_target_executed':False,'native_prepare_executed':False,'constructor_reachability_proved':False,'complete_initialization_proved':False,'all_checks_pass':True,'full_goal_complete':False};(ROOT/'kext_buffer_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(dict(counts)),flush=True)
if __name__=='__main__':main()
