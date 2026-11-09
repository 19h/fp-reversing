#!/usr/bin/env python3
"""Fresh media-wrapper, factory range, original source and exact thunk checks.

No native task access, copy, provider, reference or mapping API operation.
O(B+N+C*I+E) time/space plus compile-only SDK and fixed-word solver work.
"""
import collections,hashlib,json,struct,subprocess
from pathlib import Path
import z3
from kext_port_tools import ROOT,SOURCE,IMAGE,qword
from kernel_native_reader import Kernel
from recover_kext_aes_handoff import function,definitions
from recover_kext_cold_init import pointer
from recover_sample_descriptor import GROUPS,sdk_command
from probe_sample_descriptor import Media,cases,entry_arguments,ACTORS,STACK,META
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 counts=collections.Counter();c=json.loads((ROOT/'sample_descriptor_contracts.json').read_text());p=json.loads((ROOT/'sample_descriptor_profiles.json').read_text());proof=json.loads((ROOT/'sample_descriptor_proofs.json').read_text());deps=set()
 for obj,name in[(c,'recover_sample_descriptor.py'),(p,'probe_sample_descriptor.py'),(proof,'prove_sample_descriptor.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete'];deps.add(name)
  for n,h in obj.get('dependencies',{}).items():assert sha(ROOT/n)==h;deps.add(n)
 k=Kernel();assert k.sha256==c['kernel_collection_sha256']and sha(SOURCE)==c['source_sha256']==p['source_sha256'];fp=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit')
 for r in c['functions']:
  actual=function(k,fp,int(r['start'],16));assert all(r[n]==v for n,v in actual.items());assert IMAGE.read(int(r['start'],16),int(r['end'],16)-int(r['start'],16)).hex()==r['bytes_hex'];counts['kext_functions']+=1
 for r in c['kernel_functions']:assert k.function(int(r['start'],16))==r;counts['kernel_functions']+=1
 assert definitions(k,c['exact_definitions'])==c['exact_definitions'];assert k.symbols([int(a,16)for a in c['exact_symbols']])==c['exact_symbols'];assert c['exact_symbols']['0xfffffe000cb53108'][0]['name']=='__ZN25IOGeneralMemoryDescriptor10gMetaClassE'
 expected={0x28:('__ZNK8OSObject7releaseEv',0x3a87),0x138:('__ZN25IOGeneralMemoryDescriptor15initWithOptionsEPvjjP4taskjP8IOMapper',0xfe46),0x218:('__ZN25IOGeneralMemoryDescriptor7prepareEj',0xf5b3),0x220:('__ZN25IOGeneralMemoryDescriptor8completeEj',0x9285),0xa8:('__ZNK25IOGeneralMemoryDescriptor9MetaClass5allocEv',0x1601)}
 for s in c['nominal_slots']:
  actual=pointer(k,int(s['slot'],16));assert all(s[n]==v for n,v in actual.items());off=s['offset_from_vptr'];assert int(s['slot'],16)==int(s['vtable_symbol_address'],16)+16+off;syms=k.symbols([int(s['target'],16)])[s['target']];assert syms==s['exact_symbols']
  if off in[0x208,0x210]:
   thunk=k.function(int(s['target'],16));assert[(i['mnemonic'],i['operands'])for i in thunk['instructions']]==[('bti','c'),('b','#'+s['tail_target'])];names=k.symbols([int(s['tail_target'],16)])[s['tail_target']];assert names==s['tail_target_exact_symbols'];assert names[0]['name']==('__ZN18IOMemoryDescriptor9readBytesEyPvy'if off==0x208 else'__ZN18IOMemoryDescriptor10writeBytesEyPKvy');assert int(s['diversity'],16)==(0xfc00 if off==0x208 else 0x507b);counts['exact_tail_method_bindings']+=1
  else:name,tag=expected[off];assert syms[0]['name']==name and int(s['diversity'],16)==tag;counts['exact_direct_method_bindings']+=1
  counts['nominal_slots']+=1
 b=c['factory_binding'];assert qword(int(b['slot'],16))==int(b['target'],16)==0xfffffe000c53a934;assert b['symbols']==k.symbols([int(b['target'],16)])[b['target']]and b['symbols'][0]['name']=='__ZN18IOMemoryDescriptor16withAddressRangeEyyjP4task'
 funcs={int(r['start'],16):r for r in c['kernel_functions']};op={int(i['ea'],16):(i['mnemonic'],i['operands'])for i in funcs[0xfffffe000c53a934]['instructions']}
 facts={0xfffffe000c53a950:('stp','x0, x1, [sp]'),0xfffffe000c53a958:('add','x0, x0, #0x108'),0xfffffe000c53a97c:('cmp','x19, #0'),0xfffffe000c53a980:('mov','w8, #0x10'),0xfffffe000c53a984:('mov','w9, #0x20'),0xfffffe000c53a988:('csel','w8, w9, w8, eq'),0xfffffe000c53a9a8:('mov','x1, sp'),0xfffffe000c53a9ac:('orr','w5, w8, w20'),0xfffffe000c53a9b4:('mov','w2, #1'),0xfffffe000c53a9b8:('mov','w3, #0'),0xfffffe000c53a9bc:('mov','x4, x19'),0xfffffe000c53a9c0:('mov','x6, #0'),0xfffffe000c53a9cc:('tbz','w0, #0, #0xfffffe000c53a9d8')}
 for a,v in facts.items():assert op[a]==v;counts['factory_source_facts']+=1
 alloc=funcs[0xfffffe000c538da4]['instructions'];ops=[(i['mnemonic'],i['operands'])for i in alloc]
 for v in[('add','x16, x16, #0x6b0'),('add','x16, x16, #0x10'),('str','x16, [x0]'),('mov','w1, #0xb0')]:assert v in ops;counts['concrete_class_source_facts']+=1
 adapter=c['partial_record_adapter'];raw=IMAGE.read(int(adapter['start'],16),int(adapter['prefix_end'],16)-int(adapter['start'],16));assert raw.hex()==adapter['bytes_hex']and hashlib.sha256(raw).hexdigest()==adapter['sha256'];from kext_port_tools import CS,POOL,TABLE
 assert adapter['instructions']==[{'ea':hex(v.address),'mnemonic':v.mnemonic,'operands':v.op_str}for v in CS.disasm(raw,int(adapter['start'],16))]
 for category,base in[('table_base_rule',POOL),('bounds_target_rule',TABLE)]:
  b=adapter[category];l=IMAGE.read(int(b['left'],16),256);rr=IMAGE.read(int(b['right'],16),256);key=int(b['key'],16);const=int(b['constant'],16);assert all(x^rr[l[x]^key]==const for x in range(256));assert base+int(b['index'],16)*8==int(b['slot'],16);assert(qword(int(b['slot'],16))+int(b['bias'],16))&((1<<64)-1)==int(b['target'],16);counts['adapter_bank_rules']+=1;counts['adapter_byte_inputs']+=256
 ao={int(v['ea'],16):(v['mnemonic'],v['operands'])for v in adapter['instructions']}
 for a,v in{0xfffffe000a5c23c4:('orr','w11, w0, w11'),0xfffffe000a5c23d0:('and','w12, w0, w12'),0xfffffe000a5c23d4:('sub','w11, w11, w0'),0xfffffe000a5c23d8:('add','w11, w11, w12'),0xfffffe000a5c23e4:('eor','w11, w11, w12'),0xfffffe000a5c23f4:('ldr','w12, [x0, #0x28]'),0xfffffe000a5c23f8:('eor','w22, w12, w11'),0xfffffe000a5c23fc:('mov','w11, #0x1580'),0xfffffe000a5c2400:('ldr','x1, [x0, #0x30]'),0xfffffe000a5c2404:('ldp','x14, x19, [x0, #8]'),0xfffffe000a5c24a4:('add','x0, x14, x11'),0xfffffe000a5c24b0:('cmp','x19, #0'),0xfffffe000a5c24b8:('mov','w9, #0xa3'),0xfffffe000a5c24c4:('eor','w8, w8, w22'),0xfffffe000a5c24c8:('ldr','x8, [x20, w8, sxtw #3]')}.items():assert ao[a]==v;counts['adapter_source_facts']+=1
 sdk=c['SDK_probe'];assert sha(Path(sdk['header_path']))==sdk['header_sha256']and sha(ROOT/sdk['assembly_path'])==sdk['assembly_sha256']and sdk_command()==sdk['command'];result=subprocess.run(sdk_command('-'),capture_output=True,text=True);assert result.returncode==sdk['compile_exit']==0 and result.stdout==(ROOT/sdk['assembly_path']).read_text();assert all(x in result.stdout for x in['#520','#528','#64512','#20603']);counts['SDK_compile_exit']=0
 assert proof['contracts_sha256']==sha(ROOT/'sample_descriptor_contracts.json')
 for row in proof['proofs']:
  path=ROOT/row['file'];assert sha(path)==row['sha256'];s=z3.Solver();s.set(timeout=30000);s.from_string(path.read_text());assert str(s.check())==row['result']=='unsat';counts['proofs_unsat']+=1;deps.add(row['file'])
 assert [r['input']for r in p['cases']]==list(cases());g=Media();fresh=[]
 for old in p['cases']:
  case=old['input'];r=g.run(case);assert r==old;fresh.append(r);counts['fresh_runs']+=1;counts['fresh_source_visits']+=len(r['source_visits']);assert not r['native_API_executed']and not r['native_mapping_proved'];args=[int(v,16)for v in r['entry_arguments8']];assert args==entry_arguments(case);calls=r['modeled_calls'];globwrites=[w for w in r['source_writes']if not STACK<=int(w['address'],16)<STACK+0x4000]
  if case['mode']=='factory':
   counts['factory_runs']+=1;state=case['allocator_or_init_result'];expected=['allocation_result']+([]if state=='alloc_null'else['init_result']+(['release_result']if int(state)&1==0 else[]));assert[e['kind']for e in calls]==expected;want=ACTORS[0]if state!='alloc_null'and int(state)&1 else 0;assert int(r['return_register64'],16)==want;assert not globwrites
   assert calls[0]['registers8'][0]==hex(META);counts['allocation_result_models']+=1
   for e in calls[1:]:
    regs=[int(v,16)for v in e['registers8']]
    if e['kind']=='release_result':assert regs[0]==ACTORS[0];counts['factory_release_requests']+=1;continue
    assert regs[0]==ACTORS[0]and regs[2:7]==[1,0,case['task'],case['options']|(0x20 if case['task']==0 else 0x10),0];raw=bytes.fromhex(e['range16_hex']);assert raw==struct.pack('<2Q',args[0],args[1]);ptr=int(e['range_pointer'],16);epoch={}
    for w in r['source_writes']:
     if w['source_visit_index']>=e['source_visit_index']:continue
     a=int(w['address'],16)
     for j,v in enumerate(bytes.fromhex(w['after_hex'])):
      if ptr<=a+j<ptr+16:epoch[a+j-ptr]=v
    assert bytes(epoch[j]for j in range(16))==raw;counts['factory_range_records']+=1;counts['factory_range_source_bytes']+=16;counts['factory_null_task_type_records'if case['task']==0 else'factory_nonnull_task_type_records']+=1
   assert r['final_globals']==r['initial_globals'];continue
  counts['wrapper_runs']+=1;kind=case['kind']
  if kind=='samples_bridge':
   obs=r['bridge_observation'];actor=ACTORS[1];assert obs['target']=='0xfffffe000a508534'and not obs['target_executed'];assert[int(v,16)for v in obs['registers8']]==[actor,actor,args[0],args[1],args[2],args[3],args[4],args[5]];assert not calls and not globwrites;counts['bridge_records']+=1;continue
  if kind=='pointer_equal':assert not calls and not globwrites and int(r['return_register64'],16)==int(case['pointer_pair'][0]==case['pointer_pair'][1]);counts['pointer_equality_cases']+=1;continue
  group=case['group'];ix=list(GROUPS).index(group);actor=ACTORS[ix];globaladdr=GROUPS[group]['global'];assert len(calls)==1;call=calls[0];regs=[int(v,16)for v in call['registers8']]
  if kind=='create':
   assert call['kind']=='factory_result'and regs[:4]==[args[0],args[1],GROUPS[group]['options'],case['task']];assert int(r['return_register64'],16)==(0 if case['nonnull_result']else 0xffff5bd4);assert len(globwrites)==1 and int(globwrites[0]['address'],16)==globaladdr;assert int(r['final_globals'][hex(globaladdr)],16)==(actor if case['nonnull_result']else 0);counts['creation_calls']+=1;counts['creation_prior_nonnull_cases']+=int(case['prior_global_nonnull']);counts['creation_global_write_bytes']+=8
  else:
   assert not globwrites and r['final_globals']==r['initial_globals']and regs[0]==actor
   if kind in['read','write']:assert regs[:4]==[actor,args[0],args[1],args[2]]and int(r['return_register64'],16)==case['api_return64'];counts[kind+'_forwarding_records']+=1
   elif kind=='prepare':assert regs[:2]==[actor,0]and int(r['return_register64'],16)==(0 if case['api_return64']&0xffffffff==0 else 0xffff5bd4);counts['prepare_status_records']+=1
   elif kind=='complete':assert regs[:2]==[actor,0]and call['tail_transfer']and int(r['return_register64'],16)==case['api_return64'];counts['completion_tail_records']+=1
   else:assert kind=='release'and call['tail_transfer'];counts['release_tail_records']+=1
 (ROOT/'sample_descriptor_replays.json').write_text(json.dumps({'scope':'Distinct fresh original wrapper/factory cases under declared API results.','generator_sha256':sha(Path(__file__)),'cases':fresh,'native_target_executed':False},indent=2)+'\n');deps.update(['sample_descriptor_contracts.json','sample_descriptor_profiles.json','sample_descriptor_proofs.json','sample_descriptor_sdk_probe.s']);out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'dependencies':{n:sha(ROOT/n)for n in sorted(deps)},'verified_counts':dict(counts),'fresh_replays_sha256':sha(ROOT/'sample_descriptor_replays.json'),'native_target_executed':False,'native_mapping_proved':False,'complete_lifecycle_proved':False,'all_checks_pass':True,'full_goal_complete':False};(ROOT/'sample_descriptor_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(dict(counts)),flush=True)
if __name__=='__main__':main()
