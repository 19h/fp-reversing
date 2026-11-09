#!/usr/bin/env python3
"""Fresh state/fill cases, source writes, opaque-copy models and allocator ABI.

O(Cs*(B+Vs)+Cf*(Vf+L)+I+E) work and O(B+retained cases/events) space plus
solver/compiler work. No native allocation, task, copy, crypto or IPC action.
"""
import collections,hashlib,json,struct,subprocess
from pathlib import Path
import z3
from kext_port_tools import ROOT,SOURCE,IMAGE,CS
from kernel_native_reader import Kernel
from recover_kext_aes_handoff import function
from recover_kext_cold_init import pointer
from recover_sample_state import sdk_command
from probe_sample_state import State,cases,ARENA,CLEAR,CLEAR_END,STACK
from probe_sample_fill import Fill,cases as fill_cases
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 counts=collections.Counter();deps=set();c=json.loads((ROOT/'sample_state_contracts.json').read_text());p=json.loads((ROOT/'sample_state_profiles.json').read_text());fp=json.loads((ROOT/'sample_state_fill_profiles.json').read_text());proof=json.loads((ROOT/'sample_state_proofs.json').read_text())
 for obj,name in[(c,'recover_sample_state.py'),(p,'probe_sample_state.py'),(fp,'probe_sample_fill.py'),(proof,'prove_sample_state.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete'];deps.add(name)
  for n,h in obj.get('dependencies',{}).items():assert sha(ROOT/n)==h,n;deps.add(n)
 k=Kernel();entry=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');assert k.sha256==c['kernel_collection_sha256']and sha(SOURCE)==c['source_sha256']==p['source_sha256']==fp['source_sha256']
 for f in c['functions']:
  actual=function(k,entry,int(f['start'],16));assert actual==f;assert IMAGE.read(int(f['start'],16),int(f['end'],16)-int(f['start'],16)).hex()==f['bytes_hex'];counts['original_kext_functions']+=1
 for f in c['kernel_functions']:assert k.function(int(f['start'],16))==f;counts['original_kernel_functions']+=1
 assert k.symbols([int(a,16)for a in c['exact_symbols']])==c['exact_symbols'];assert not any(c['exact_symbols'][a]for a in ['0xfffffe000bcfe5b8','0xfffffe000bcfec48','0xfffffe0007f8bfb0']);assert pointer(k,0xfffffe000847c4c8)==c['copy_import_pointer'];stub=c['copy_import_stub'];assert k.read(int(stub['start'],16),stub['size_bytes'])==IMAGE.read(int(stub['start'],16),stub['size_bytes'])==bytes.fromhex(stub['bytes_hex']);assert [(i['mnemonic'],i['operands'])for i in c['functions'][2]['instructions']]==[('bti','c'),('b','#0xfffffe000a69f334')];assert [(i['mnemonic'],i['operands'])for i in stub['instructions']]==[('adrp','x17, #0xfffffe000847c000'),('add','x17, x17, #0x4c8'),('ldr','x16, [x17]'),('braa','x16, x17')];counts['copy_thunk_and_stub_bindings']+=1
 for b in c['bank_rules']:
  l=IMAGE.read(int(b['left'],16),256);r=IMAGE.read(int(b['right'],16),256);assert l.hex()==b['left256_hex']and r.hex()==b['right256_hex'];v=int(b['constant'],16);assert all(x^r[l[x]^int(b['key'],16)]==v for x in range(256));assert int(b['index'],16)==v+int(b['additive'],16);assert pointer(k,int(b['slot'],16))==b['original_pointer'];counts['exhaustive_bank_rules']+=1;counts['bank_byte_inputs']+=256
 ops={int(i['ea'],16):(i['mnemonic'],i['operands'])for f in c['functions']+c['kernel_functions']for i in f['instructions']}
 facts={0xfffffe000a625288:('str','wzr, [x22, #0xc4]'),0xfffffe000a6252cc:('mov','x0, x21'),0xfffffe000a6252d0:('mov','w1, #0'),0xfffffe000a6252d4:('mov','w2, #0xa8'),0xfffffe000a6252e8:('str','w8, [x22]'),0xfffffe000a6252f0:('ldrb','w8, [x12, #1]'),0xfffffe000a62532c:('str','w9, [x11, #0x24]'),0xfffffe000a625348:('str','w9, [x11, #0x24]'),0xfffffe000a6253ec:('stp','w8, w9, [x21, #0x24]'),0xfffffe000a6254c0:('ldrb','w8, [x11, #0x38]'),0xfffffe000a625520:('stp','w8, w9, [x10, #0x24]'),0xfffffe000a6255dc:('mov','w0, #0x2000'),0xfffffe000a6255e8:('str','x0, [sp, #0x10]'),0xfffffe000a6256d8:('ldr','x0, [sp, #0x10]'),0xfffffe000a6256dc:('mov','w1, #0x2000'),0xfffffe000a625a3c:('add','x0, x3, #0xb0'),0xfffffe000a625c4c:('ubfiz','x0, x8, #2, #0x20'),0xfffffe000a625c60:('add','x1, x3, #0xc4'),0xfffffe000a625c64:('mov','w2, #4'),0xfffffe000a625c8c:('cmp','w0, w8'),0xfffffe000a687d68:('neg','w8, w0'),0xfffffe000a687de0:('mov','w9, w1'),0xfffffe000a687de8:('mul','x9, x9, x10'),0xfffffe000a687ec4:('strb','w1, [x0]'),0xfffffe000c4ba628:('mov','x1, x19'),0xfffffe000c4ba62c:('mov','w2, #0x1000'),0xfffffe000c4ba630:('movk','w2, #3, lsl #16'),0xfffffe000c4ba634:('mov','x3, #0'),0xfffffe000c4ba638:('bl','#0xfffffe000bcfe5b8'),0xfffffe000c4ba63c:('cbz','x0, #0xfffffe000c4ba690'),0xfffffe000c4ba648:('ldadd','x19, x8, [x8]'),0xfffffe000c4ba85c:('cbz','x0, #0xfffffe000c4ba8c8'),0xfffffe000c4ba864:('mov','x1, x0'),0xfffffe000c4ba870:('mov','x2, x19'),0xfffffe000c4ba874:('bl','#0xfffffe000bcfec48'),0xfffffe000c4ba884:('ldadd','x8, x8, [x9]')}
 for a,v in facts.items():assert ops[a]==v,(hex(a),ops[a],v);counts['source_instruction_facts']+=1
 sdk=c['SDK_probe'];assert sha(Path(sdk['header_path']))==sdk['header_sha256']and sha(ROOT/sdk['assembly_path'])==sdk['assembly_sha256'];res=subprocess.run(sdk_command('/tmp/sample_state_sdk_recheck.s'),capture_output=True,text=True);assert res.returncode==0 and sha(Path('/tmp/sample_state_sdk_recheck.s'))==sdk['assembly_sha256'];counts['SDK_compile_exit']=res.returncode
 assert proof['contracts_sha256']==sha(ROOT/'sample_state_contracts.json')
 for row in proof['proofs']:
  assert sha(ROOT/row['file'])==row['sha256'];s=z3.Solver();s.set(timeout=30000);s.add(z3.parse_smt2_file(str(ROOT/row['file'])));assert str(s.check())==row['result']=='unsat';counts['proofs_unsat']+=1
 assert[r['input']for r in fp['cases']]==list(fill_cases());fill=Fill();fresh_fill=[]
 for old in fp['cases']:
  r=fill.run(old['input']);assert r==old;fresh_fill.append(r);case=r['input'];d=int(r['destination64'],16);n=case['length64'];v=case['fill64'];prefix=min(n,(-d)&7);rem=n-prefix;q=rem//8;tail=rem&7;word=((v&0xffffffff)*0x0101010101010101)&((1<<64)-1);expected=bytes([v&255])*prefix+word.to_bytes(8,'little')*q+bytes([v&255])*tail;assert hashlib.sha256(expected).hexdigest()==r['final_data_sha256'];assert int(r['return_X0'],16)==d+n-int(tail!=0);epoch={}
  for pc,off,width,h in r['stores']:
   raw=bytes.fromhex(h);assert len(raw)==width and 0<=off<off+width<=n;assert ENTRY_IN_FILL(pc);counts['fill_store_events']+=1
   for j,b in enumerate(raw):assert off+j not in epoch;epoch[off+j]=b
  assert set(epoch)==set(range(n));assert bytes(epoch[i]for i in range(n))==expected;counts['fresh_fill_cases']+=1;counts['fresh_fill_source_visits']+=r['source_visits_count'];counts['fill_source_written_bytes']+=n
  if v<=255:assert expected==bytes([v])*n;counts['canonical_fill_cases']+=1
  elif q and expected!=bytes([v&255])*n:counts['nonuniform_width_stress_cases']+=1
 assert[r['input']for r in p['cases']]==list(cases());fresh=[]
 for old in p['cases']:
  r=State(old['input']).run();assert r==old;fresh.append(r);counts['fresh_state_cases']+=1;counts['fresh_state_source_visits']+=len(r['source_visits']);assert not r['undefined_private_reads']and not r['native_API_executed'];case=r['input'];obj=case['object64'];header=STACK+0x3000;N=case['element_count32'];code,flag=case['header_byte1'],case['header_byte38'];initial=bytes.fromhex(r['object_fixture_hex']);final=bytes.fromhex(r['final_object_hex']);h=bytes.fromhex(r['header_fixture_hex']);clear=[w for w in r['source_writes']if CLEAR<=int(w['pc'],16)<CLEAR_END];covered={}
  for w in clear:
   a=int(w['address'],16);raw=bytes.fromhex(w['after_hex']);assert obj+4<=a<a+len(raw)<=obj+0xac and raw==bytes(len(raw));counts['caller_clear_store_events']+=1
   for j,b in enumerate(raw):assert a+j not in covered;covered[a+j]=b
  assert set(covered)==set(range(obj+4,obj+0xac));assert len(r['pure_memory_calls'])==1 and r['pure_memory_calls'][0]['arguments3']==[hex(obj+4),'0x0','0xa8'];counts['caller_clear_source_bytes']+=168
  state=bytearray(initial);events=[(w['source_visit_index'],0,w)for w in r['source_writes']if obj<=int(w['address'],16)<obj+0x140]+[(e['source_visit_index'],1,e)for e in r['memory_models']if e['kind']=='opaque_copy_model']
  for idx,typ,e in sorted(events,key=lambda t:t[:2]):
   if typ==0:a=int(e['address'],16)-obj;raw=bytes.fromhex(e['after_hex'])
   else:a=int(e['arguments3'][0],16)-obj;raw=bytes.fromhex(e['after_destination_hex'])
   state[a:a+len(raw)]=raw
  assert bytes(state)==final;assert int.from_bytes(final[:4],'little')==128;expected_code=2201 if code==1 else 2204 if code==2 else 3100 if code==3 else 3000 if flag else 0;opaque32=code==3 or(code not in[1,2]and flag!=0);assert struct.unpack_from('<II',final,0x24)==(expected_code,32 if opaque32 else 0);assert final[0xac:0xb0]==initial[0xac:0xb0];counts['state_object_reconstructions']+=1
  copies=[e for e in r['memory_models']if e['kind']=='opaque_copy_model'];wanted=[]
  if code not in[1,2]:wanted.append((obj+4,header+2,16))
  if opaque32:wanted.append((obj+0x2c,header+0x39,32))
  if N==1 and case['workspace_result64']:wanted.append((obj+0xb0,header+0x12,16))
  assert[tuple(int(v,16)for v in e['arguments3'])for e in copies]==wanted
  for e in copies:
   dst,src,length=[int(v,16)for v in e['arguments3']];assert dst+length<=src or src+length<=dst;assert bytes.fromhex(e['source_hex'])==bytes.fromhex(e['after_destination_hex'])==h[src-header:src-header+length];counts['modeled_opaque_copy_calls']+=1;counts['modeled_opaque_copy_bytes']+=length
  alloc=[e for e in r['memory_models']if e['kind']=='workspace_allocation_model'];free=[e for e in r['memory_models']if e['kind']=='workspace_free_model'];assert len(alloc)==1 and alloc[0]['requested_bytes']==8192 and int(alloc[0]['result64'],16)==case['workspace_result64'];counts['workspace_allocation_models']+=1
  if case['workspace_result64']and N==0:assert len(free)==1 and free[0]['extent64']==8192 and free[0]['arguments3'][:2]==[hex(ARENA),'0x2000'];counts['workspace_free_models']+=1
  else:assert not free
  controls=[e for e in r['state_reads']if e['region']=='header'];assert any(e['offset']==1 and e['size_bytes']==1 and int(e['bytes_hex'],16)==code for e in controls);assert any(e['offset']==0x38 for e in controls)==(code not in[1,2,3]);counts['source_header_control_cases']+=1
  suffix=[(e.get('group'),e['kind'])for e in r['helper_observations'][-3:]]
  if r['stop_reason']=='wrapper_return':
   assert suffix==[('samples','release'),('sample_sizes','complete'),('sample_sizes','release')];assert not any(e.get('group')=='samples'and e['kind']=='complete'for e in r['helper_observations']);status=int.from_bytes(bytes.fromhex(r['final_record_hex'])[8:12],'little');assert status==(0xce515bb2 if case['workspace_result64']==0 else 0x31ae0066);counts['cleanup_return_paths']+=1;counts['source_output_status_bytes']+=4;counts['workspace_null_error_paths'if case['workspace_result64']==0 else'empty_loop_success_paths']+=1
  else:
   assert r['stop_reason']=='unmodeled_helper'and N==1 and case['workspace_result64'];e=r['helper_observations'][-1];assert e['target']=='0xfffffe000a509a60'and e['pc']=='0xfffffe000a625c6c'and e['registers8'][:3]==['0x0',hex(obj+0xc4),'0x4'];counts['sample_size_read_boundaries']+=1
  assert not any(e['region']=='workspace'for e in r['state_reads'])
 replays={'scope':'Distinct fresh original fill/state cases. Copy and descriptor/heap results remain declared models; native APIs never execute.','generator_sha256':sha(Path(__file__)),'fill_cases':fresh_fill,'state_cases':fresh,'native_target_executed':False};(ROOT/'sample_state_replays.json').write_text(json.dumps(replays,indent=2)+'\n');deps.update(['sample_state_contracts.json','sample_state_profiles.json','sample_state_fill_profiles.json','sample_state_proofs.json','sample_state_sdk_probe.s']);out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in sorted(deps)},'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'verified_counts':dict(counts),'fresh_replays_sha256':sha(ROOT/'sample_state_replays.json'),'all_checks_pass':True,'native_target_executed':False,'native_lifetime_proved':False,'full_goal_complete':False};(ROOT/'sample_state_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(dict(counts)),flush=True)
def ENTRY_IN_FILL(offset):return 0<=offset<360 and offset%4==0
if __name__=='__main__':main()
