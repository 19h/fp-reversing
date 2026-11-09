#!/usr/bin/env python3
"""Fresh wrapper/stack/ownership, original-source, command and ABI checks.

Provider implementations, opaque key data and native APIs are not executed.
O(B+C*I+E+N) time/space plus fixed-word SMT and compile-only SDK work.
"""
import collections,hashlib,json,struct,subprocess
from pathlib import Path
import z3
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,qword
from recover_kext_cold_init import pointer
from recover_kext_aes_handoff import function,definitions,references,starts,sdk_command
from probe_kext_aes_handoff import Handoff,cases,inputs,LENGTHS,OPS,PROV,OBJ,SERVICE,DESC,FLAG,BYTES,STACK
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 counts=collections.Counter();c=json.loads((ROOT/'kext_aes_handoff_contracts.json').read_text());p=json.loads((ROOT/'kext_aes_handoff_profiles.json').read_text());proof=json.loads((ROOT/'kext_aes_handoff_proofs.json').read_text());deps=set()
 for obj,name in[(c,'recover_kext_aes_handoff.py'),(p,'probe_kext_aes_handoff.py'),(proof,'prove_kext_aes_handoff.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete'];deps.add(name)
  for n,h in obj.get('dependencies',{}).items():assert sha(ROOT/n)==h;deps.add(n)
 k=Kernel();assert k.sha256==c['kernel_collection_sha256']and sha(SOURCE)==c['source_sha256']==p['source_sha256'];entries={e['name']:e for e in k.entries};assert {n:len(starts(k,entries[n]))for n in c['fileset_function_counts']}==c['fileset_function_counts']=={'com.apple.driver.FairPlayIOKit':450,'com.apple.iokit.IOCryptoAcceleratorFamily':106}
 for r in c['functions']:
  assert function(k,entries[r['entry']],int(r['start'],16))==r;counts['fileset_functions']+=1
  if r['entry']=='com.apple.driver.FairPlayIOKit':assert IMAGE.read(int(r['start'],16),int(r['end'],16)-int(r['start'],16)).hex()==r['bytes_hex'];counts['matching_kext_functions']+=1
 for r in c['kernel_functions']:assert k.function(int(r['start'],16))==r;counts['kernel_functions']+=1
 assert definitions(k,c['exact_definitions'])==c['exact_definitions']
 expected={('aes',0x890):('performAES',0x17dc),('aes',0x8a0):('getSupportedOptions',0x191b),('aes',0x8b8):('performImmediateAES',0x50a4),('aes',0x8d0):('_queueLocked',0x1430),('aes',0x8d8):('_startCommand',0x3fd7),('candidate_hardware',0x890):('performAES',0x17dc),('command_pool',0x148):('getCommand',0x239e),('command_pool',0x150):('returnCommand',0x3cbb),('command_gate',0x1e8):('runAction',0xf9ff),('command_gate',0x200):('commandSleep',0x6db9),('command_gate',0x208):('commandWakeup',0xf36c),('buffer',0x208):(None,0xfc00),('buffer',0x218):('prepare',0xf5b3),('buffer',0x220):('complete',0x9285),('buffer',0x28):('release',0x3a87)}
 for e in c['nominal_slots']:
  actual=pointer(k,int(e['slot'],16));assert all(e[n]==v for n,v in actual.items());assert int(e['slot'],16)==int(e['vtable_symbol_address'],16)+16+e['offset_from_vptr'];syms=k.symbols([int(e['target'],16)])[e['target']];assert syms==e['exact_symbols'];name,tag=expected[(e['kind'],e['offset_from_vptr'])];assert int(e['diversity'],16)==tag
  if name is None:assert syms==[]and e['target']=='0xfffffe000c5361d4';counts['unnamed_buffer_targets']+=1
  else:assert len(syms)==1 and name in syms[0]['name'];counts['exact_named_slots']+=1
  counts['nominal_slots']+=1
 binding=c['withBytes_binding'];assert qword(int(binding['slot'],16))==int(binding['target'],16)==0xfffffe000c526570 and k.symbols([int(binding['target'],16)])[binding['target']]==binding['exact_symbols'];assert binding['exact_symbols'][0]['name']=='__ZN24IOBufferMemoryDescriptor9withBytesEPKvmjb'
 refs=references();ret=c['reference_scan'];assert {n:v for n,v in ret.items()if n!='ed6d_call_modifier_candidates'}=={n:v for n,v in refs.items()if n!='ed6d_call_modifier_candidates'};assert len(ret['direct_text_branches'])==1 and ret['direct_text_branches'][0]['pc']=='0xfffffe000a50a010'and ret['direct_text_branches'][0]['target']=='0xfffffe000a508534';counts['direct_text_refs']=1;counts['direct_text_scan_words']=ret['direct_text_scan_words'];counts['raw_pointer_candidates']=sum(e['classification']=='raw_pointer_candidate'for e in ret['aligned_u64_matches']);counts['metadata_word_matches']=sum(e['classification']=='metadata_word'for e in ret['aligned_u64_matches'])
 catalog=starts(k,entries['com.apple.driver.FairPlayIOKit'])
 for a,b in zip(ret['ed6d_call_modifier_candidates'],refs['ed6d_call_modifier_candidates'],strict=True):
  assert all(a[n]==v for n,v in b.items());assert int(a['enclosing_compiler_start'],16)<=int(a['pc'],16)<int(a['enclosing_compiler_end'],16)and int(a['enclosing_compiler_start'],16)in catalog ;counts['modifier_candidate_sites']+=1
  if a['indirect_target_resolved']:assert a['pc']=='0xfffffe000a6227b0'and a['resolved_target']=='0xfffffe000a5085e0'
  else:counts['unresolved_modifier_sites']+=1
 for e in c['tagged_ed6d_slots']:
  actual=pointer(k,int(e['slot'],16));assert all(e[n]==v for n,v in actual.items());assert actual['diversity']=='0xed6d';assert k.symbols([int(e['target'],16)])[e['target']]==e['exact_symbols'];counts['same_diversity_table_targets']+=1
 assert sum(e['target']=='0xfffffe000a5085e0'for e in c['tagged_ed6d_slots'])==1
 caller=c['one_resolved_cleanup_caller'];assert caller['cleanup_call']=='0xfffffe000a6227b4'and caller['resolved_target']=='0xfffffe000a5085e0'and not caller['native_reachability_proved'];assert c['one_cleanup_caller_resolved']and not c['all_cleanup_callers_resolved']
 for b in caller['bank_identities']:
  left=IMAGE.read(int(b['left'],16),256);right=IMAGE.read(int(b['right'],16),256);assert left.hex()==b['left256_hex']and right.hex()==b['right256_hex'];key=int(b['key'],16);constant=int(b['constant'],16)
  assert all(x^right[left[x]^key]==constant for x in range(256));assert int(b['index'],16)==int(b['additive'],16)+constant;assert qword(int(b['slot'],16))+int(b['bias'],16)&((1<<64)-1)==int(b['target'],16);counts['cleanup_caller_bank_identities']+=1;counts['cleanup_caller_byte_inputs']+=256
 source_caller=next(r for r in c['functions']if r['start']=='0xfffffe000a62259c');cf={int(x['ea'],16):(x['mnemonic'],x['operands'])for x in source_caller['instructions']}
 facts={0xfffffe000a622624:('adrp','x24, #0xfffffe0008471000'),0xfffffe000a622628:('add','x24, x24, #0xf00'),0xfffffe000a62272c:('add','x9, x9, #0xfd0'),0xfffffe000a622738:('mov','w25, #0xac'),0xfffffe000a622744:('add','x11, x11, #0xfc0'),0xfffffe000a622754:('add','w8, w8, #0x2d'),0xfffffe000a622758:('ldr','x8, [x24, w8, uxtw #3]'),0xfffffe000a62275c:('sub','x27, x8, #0xc'),0xfffffe000a62276c:('blraa','x8, x17'),0xfffffe000a622784:('ldr','x9, [x24, #0xb70]'),0xfffffe000a622790:('mov','w10, #0x32'),0xfffffe000a622794:('eor','w9, w9, w10'),0xfffffe000a622798:('ldr','x10, [x24, #0xa10]'),0xfffffe000a6227a8:('add','w8, w8, #0xe88'),0xfffffe000a6227ac:('ldr','x8, [x27, w8, uxtw #3]'),0xfffffe000a6227b0:('mov','x17, #0xed6d'),0xfffffe000a6227b4:('blraa','x8, x17')}
 for a,v in facts.items():assert cf[a]==v;counts['cleanup_caller_source_facts']+=1
 banks=caller['bank_identities'];assert banks[0]['slot']=='0xfffffe0008472098'and banks[0]['target']=='0xfffffe0008472f20'and banks[0]['bias']=='0xfffffffffffffff4';assert banks[1]['left']==hex(qword(0xfffffe0008471f00+0x840))and banks[1]['right']==hex(qword(0xfffffe0008471f00+0xbb8));assert banks[2]['left']==hex(qword(0xfffffe0008471f00+0xb70))and banks[2]['right']==hex(qword(0xfffffe0008471f00+0xa10));assert banks[1]['slot']=='0xfffffe000847a828'and banks[2]['slot']=='0xfffffe000847ab28'
 helper=caller['assertion_helper'];assert IMAGE.read(int(helper['start'],16),20).hex()==helper['bytes_hex'];assert[(x['mnemonic'],x['operands'])for x in helper['instructions']]==[('bti','c'),('cmp','x0, x1'),('b.hi','#0xfffffe000a687edc'),('ret',''),('brk','#1')]
 excerpt=caller['associated_C_excerpt'];assert sha(Path(excerpt['path']))==excerpt['sha256'];assert ''.join(Path(excerpt['path']).read_text().splitlines(keepends=True)[excerpt['line_start']-1:excerpt['line_end']])==excerpt['text']and'cleanupKernelAESHW();'in excerpt['text'];counts['resolved_cleanup_call_sites']=1
 funcs={int(r['start'],16):r for r in c['functions']};provider={int(i['ea'],16):(i['mnemonic'],i['operands'])for i in funcs[0xfffffe000abff358]['instructions']};facts={0xfffffe000abff3a0:('ldp','x27, x23, [x29, #0x18]'),0xfffffe000abff3a4:('ldr','x28, [x29, #0x10]'),0xfffffe000abff7e8:('mov','w1, #1'),0xfffffe000abff7f8:('stp','x22, x20, [x0, #0x20]'),0xfffffe000abff7fc:('stp','x24, x28, [x0, #0x50]'),0xfffffe000abff804:('stp','x25, x8, [x0, #0x30]'),0xfffffe000abff808:('str','w21, [x0, #0x40]'),0xfffffe000abff85c:('str','x8, [x2, #0x60]'),0xfffffe000abff860:('str','x26, [x2, #0x48]'),0xfffffe000abff874:('stp','x11, x10, [x2, #0x80]'),0xfffffe000abff878:('str','xzr, [x2, #0x68]'),0xfffffe000abff8b0:('mov','x3, #0'),0xfffffe000abff8b4:('mov','x4, #0'),0xfffffe000abff8b8:('mov','x5, #0')}
 for a,v in facts.items():assert provider[a]==v;counts['provider_handoff_source_facts']+=1
 complete={int(i['ea'],16):(i['mnemonic'],i['operands'])for i in funcs[0xfffffe000abfd598]['instructions']};queue={int(i['ea'],16):(i['mnemonic'],i['operands'])for i in funcs[0xfffffe000abfd2d8]['instructions']}
 for a,v in{0xfffffe000abfd628:('ldr','x16, [x19, #0x80]'),0xfffffe000abfd62c:('cbz','x16, #0xfffffe000abfd69c'),0xfffffe000abfd630:('ldr','w21, [x19, #0x78]'),0xfffffe000abfd634:('ldr','x22, [x19, #0x88]'),0xfffffe000abfd668:('mov','x0, x22'),0xfffffe000abfd66c:('mov','x1, x21'),0xfffffe000abfd694:('mov','x17, #0xd507'),0xfffffe000abfd6c4:('mov','x1, x19'),0xfffffe000abfd6c8:('mov','w2, #0')}.items():assert complete[a]==v;counts['completion_source_facts']+=1
 for a,v in{0xfffffe000abfd3b8:('ldr','x8, [x19, #0x80]'),0xfffffe000abfd3bc:('cbz','x8, #0xfffffe000abfd3c8'),0xfffffe000abfd3e8:('mov','x1, x19'),0xfffffe000abfd3ec:('mov','w2, #0'),0xfffffe000abfd3fc:('ldr','w21, [x19, #0x78]')}.items():assert queue[a]==v;counts['queue_source_facts']+=1
 sdk=c['SDK_probe'];assert sdk['compile_exit']==0 and sha(ROOT/sdk['assembly_path'])==sdk['assembly_sha256'];assert sdk_command()==sdk['command']
 for e in sdk['primary_headers']:assert sha(Path(e['path']))==e['sha256']
 command=sdk_command();command[-1]='-';r=subprocess.run(command,capture_output=True,text=True);assert r.returncode==0 and r.stdout==(ROOT/sdk['assembly_path']).read_text();assert 'ldr\tx5, [x16, #520]'in r.stdout and'movk\tx16, #64512, lsl #48'in r.stdout;counts['SDK_compile_exit']=0;counts['SDK_primary_headers']=len(sdk['primary_headers'])
 assert proof['contracts_sha256']==sha(ROOT/'kext_aes_handoff_contracts.json')
 for e in proof['proofs']:
  path=ROOT/e['file'];assert sha(path)==e['sha256'];s=z3.Solver();s.set(timeout=30000);s.from_string(path.read_text());assert str(s.check())==e['result']=='unsat';counts['proofs_unsat']+=1;deps.add(e['file'])
 assert [r['input']for r in p['cases']]==list(cases());g=Handoff();fresh=[]
 for old in p['cases']:
  cse=old['input'];new=g.run(cse);assert new==old;fresh.append(new);counts['fresh_runs']+=1;counts['fresh_source_visits']+=len(new['source_visits']);assert not new['native_API_executed']and not new['accepted_operation_proved'];assert new['entry_arguments8']==[hex(v)for v in inputs(cse)];calls=new['modeled_calls'];api=[e for e in calls if e['kind']!='log_result'];kind=cse['kind'];outcome=cse['outcome'];args=[int(v,16)for v in new['entry_arguments8']]
  if kind!='copied':expected_kinds=['provider_result'];expected_result=0 if cse['provider_return64']&0xffffffff==0 else 0xffffffea
  elif outcome=='init_failure':expected_kinds=['init_result'];expected_result=0xffffffd8
  elif outcome=='factory_null':expected_kinds=['withBytes_result'];expected_result=0xffffffd8
  else:
   expected_kinds=['withBytes_result','provider_result'];expected_result=0xffffffea if outcome in['provider_error','prepare_error','copy_mismatch','copy_high']else 0
   if outcome!='provider_error':
    expected_kinds+=['prepare_result']
    if outcome!='prepare_error':expected_kinds+=['readBytes_result','complete_result']
   expected_kinds+=['release_result']
  assert[e['kind']for e in api]==expected_kinds;assert int(new['return64'],16)==expected_result;counts['zero_returns'if expected_result==0 else'minus22_returns'if expected_result==0xffffffea else'minus40_returns']+=1
  provider_calls=[e for e in api if e['kind']=='provider_result']
  for e in provider_calls:
   reg=[int(v,16)for v in e['registers8']];stack=list(struct.unpack('<3Q',bytes.fromhex(e['stack24_hex'])))
   if kind=='copied':want=[PROV,OBJ,OBJ,args[4]&0xffffffff,args[1],args[5],args[0],0];wantstack=[0,0,0];counts['inplace_descriptor_records']+=1
   elif kind in['shared','global']:want=[PROV,OBJ,OBJ,args[2]&0xffffffff,args[1],(args[3]&0xffffffff)^1 if kind=='global'else args[3],args[0],0];wantstack=[0,0,0];counts['inplace_descriptor_records']+=1
   else:want=[PROV,args[0],args[1],args[2],args[3],args[4],args[5],args[6]];wantstack=[args[7],0,0];counts['separate_descriptor_records']+=1
   assert reg==want and stack==wantstack;sp=int(e['SP'],16);epoch={}
   for w in new['source_writes']:
    if w['source_visit_index']>=e['source_visit_index']:continue
    a=int(w['address'],16)
    for i,v in enumerate(bytes.fromhex(w['after_hex'])):
     if sp<=a+i<sp+24:epoch[a+i-sp]=v
   assert bytes(epoch[i]for i in range(24)).hex()==e['stack24_hex'];counts['provider_stack_source_bytes']+=24;counts['provider_call_records']+=1
   if cse['provider_return64']and cse['provider_return64']&0xffffffff==0:counts['nonzero_X0_zero_W0_cases']+=1
  for e in api:
   regs=[int(v,16)for v in e['registers8']]
   if e['kind']=='withBytes_result':assert regs[:4]==[args[2],args[4]&0xffffffff,3,0];counts['temporary_descriptor_requests']+=1
   if e['kind']=='readBytes_result':assert regs[:4]==[OBJ,0,args[3],args[4]&0xffffffff];counts['copyout_requests']+=1
   if e['kind']in['prepare_result','complete_result']:assert regs[:2]==[OBJ,0];counts[e['kind'].replace('_result','_requests')]+=1
   if e['kind']=='release_result':assert regs[0]==OBJ;counts['release_requests']+=1
  assert all(STACK<=int(w['address'],16)<STACK+4096 for w in new['source_writes']);assert not any(int(e['address'],16)==FLAG for e in new['source_reads']);assert new['final_globals'][hex(FLAG)]==bytes([cse['readiness8']]).hex()
  assert new['retired_in_model']==([hex(OBJ)]if'release_result'in expected_kinds else[]);counts['local_log_requests']+=sum(e['kind']=='log_result'for e in calls)
 (ROOT/'kext_aes_handoff_replays.json').write_text(json.dumps({'scope':'Distinct fresh original wrapper runs under explicit result models; no provider execution.','generator_sha256':sha(Path(__file__)),'cases':fresh,'native_target_executed':False},indent=2)+'\n');deps.update(['kext_aes_handoff_contracts.json','kext_aes_handoff_profiles.json','kext_aes_handoff_proofs.json','kext_aes_handoff_sdk_probe.s']);out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'dependencies':{n:sha(ROOT/n)for n in sorted(deps)},'verified_counts':dict(counts),'fresh_replays_sha256':sha(ROOT/'kext_aes_handoff_replays.json'),'native_target_executed':False,'provider_implementation_executed':False,'key_data_contents_recovered':False,'accepted_operation_proved':False,'one_cleanup_caller_resolved':True,'all_cleanup_callers_resolved':False,'all_checks_pass':True,'full_goal_complete':False};(ROOT/'kext_aes_handoff_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(dict(counts)),flush=True)
if __name__=='__main__':main()
