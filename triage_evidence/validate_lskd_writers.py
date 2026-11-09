#!/usr/bin/env python3
"""Fresh entry-prefix and conditional bank replays, independent byte epochs/proofs.

O(B+C*(V+E)+I+256R) time/space plus solver cost30 s/query. The entry runs stop
before allocation; local bank cases supply no accepted context or table entry.
"""
import hashlib,json,struct,gc
from pathlib import Path
from collections import Counter
import z3
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,selected
from recover_carrier_control import span
from recover_kext_cold_init import pointer
from lskd_writers_symbolic import queries
from probe_lskd_writers import Prefix,cases as prefix_cases
from probe_lskd_writers_bank import Candidate,cases as bank_cases
from lskd_writers_audit import audit
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def main():
 c=read('lskd_writers_contracts.json');p=read('lskd_writers_profiles.json');bp=read('lskd_writers_bank_profiles.json');proof=read('lskd_writers_proofs.json');k=Kernel();counts=Counter()
 for obj,name in[(c,'recover_lskd_writers.py'),(p,'probe_lskd_writers.py'),(bp,'probe_lskd_writers_bank.py'),(proof,'prove_lskd_writers.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert k.sha256==c['kernel_collection_sha256']==p['kernel_collection_sha256']==bp['kernel_collection_sha256']and sha(SOURCE)==c['source_sha256']==p['source_sha256']==bp['source_sha256']
 for s in c['spans']:
  now=span(k,int(s['start'],16),int(s['end'],16));assert all(now[n]==s[n]for n in now)and IMAGE.read(int(s['start'],16),int(s['end'],16)-int(s['start'],16)).hex()==s['bytes_hex'];counts['bounded_source_windows']+=1
 for ptr in c['original_pointer_slots']:assert pointer(k,int(ptr['slot'],16))==ptr;counts['original_pointer_slots']+=1
 assert k.symbols([int(a,16)for a in c['exact_symbols']])==c['exact_symbols']
 desc=c['selector18'];a=int(desc['descriptor'],16);assert k.read(a,48).hex()==desc['original48_hex']and IMAGE.read(a,48).hex()==desc['normalized48_hex']and list(struct.unpack('<6Q',IMAGE.read(a,48)))==[0,0xfffffe000a503dc4,0,3,3096,3096];assert(desc['selector']-1)==17 and(int(desc['lookup_mask64'],16)>>17)&1;counts['selector18_descriptor_bytes_checked']=48
 for b in c['bank_rules']:
  l,r=int(b['left'],16),int(b['right'],16);assert IMAGE.read(l,256).hex()==b['left256_hex']and IMAGE.read(r,256).hex()==b['right256_hex'];now=selected(l,r,int(b['key'],16),int(b['additive'],16),base=int(b['base'],16),bias=int(b['bias'],16));assert all(now[n]==b[n]for n in now)and pointer(k,int(b['slot'],16))==b['original_pointer'];counts['exhaustive_bank_rules']+=1;counts['bank_byte_input_checks']+=256
 qs,lifts=queries(c);assert len(qs)==len(proof['proofs'])==13 and lifts==proof['source_lift_counts']and sum(lifts.values())==39
 for(name,q),row in zip(qs,proof['proofs']):
  assert name==row['name']and row['result']=='unsat';op,np=ROOT/row['original_file'],ROOT/row['file'];assert sha(op)==row['original_sha256']and sha(np)==row['sha256'];orig=z3.parse_smt2_string(op.read_text());assert len(orig)==1
  for f in[z3.simplify(q),z3.simplify(orig[0]),z3.Xor(z3.simplify(q),z3.simplify(orig[0])),*z3.parse_smt2_string(np.read_text())]:
   s=z3.Solver();s.set(timeout=30000);s.add(f);assert str(s.check())=='unsat',name
  counts['source_proof_pairs_unsat']+=1
 rows=[];cases=list(prefix_cases());assert len(cases)==36 and[r['input']for r in p['cases']]==cases
 for case,retained in zip(cases,p['cases']):
  f=Prefix(case);r=f.run();del f;assert r==retained;rows.append(r);counts['fresh_entry_prefix_cases']+=1;counts['entry_prefix_instruction_visits']+=len(r['source_visits']);audit(r,k,counts)
  F=int(r['frame_base_SP'],16);assert int(r['entry_SP'],16)-F==0x1460 and r['boundary']['kind']=='before_original_allocator_call'and r['boundary']['pc']=='0xfffffe000a5304c8'and r['boundary']['registers31'][:2]==['0x4000','0x40']and r['boundary']['registers31'][8]=='0xfffffe000c4b9a08'
  assert len(r['source_calls'])==1 and r['source_calls'][0]['pc']=='0xfffffe000a530324'and r['source_calls'][0]['target']=='0xfffffe000a5a1cc4'and r['source_calls'][0]['X9_probe_size_bytes']=='0x13c0';counts['original_stack_probe_calls']+=1
  for name,a,pc in[('saved_left_bank',0xfffffe0007920c10,'0xfffffe000a53043c'),('saved_right_bank',0xfffffe00079170c0,'0xfffffe000a530458')]:
   snap=r[name];assert snap['bytes_hex']==struct.pack('<Q',a).hex()and snap['known_mask_hex']=='01'*8 and snap['provenance_hex']=='01'*8;assert any(x['pc']==pc and x['address']==snap['address']and x['after_hex']==snap['bytes_hex']for x in r['source_writes']);counts['original_bank_pointer_frame_stores']+=1
  for j,off,n,pc in[(0,0xad8,8,0xfffffe000a530344),(1,0xae4,4,0xfffffe000a530340),(2,0x5d8,8,0xfffffe000a53033c),(3,0xd68,4,0xfffffe000a530338),(4,0xa58,8,0xfffffe000a530334),(5,0x610,8,0xfffffe000a530330)]:
   v=case['inputs8'][j]&((1<<(n*8))-1);raw=v.to_bytes(n,'little');assert any(x['pc']==hex(pc)and int(x['address'],16)==F+off and x['size_bytes']==n and x['after_hex']==raw.hex()for x in r['source_writes']);counts['source_argument_to_frame_stores']+=1
  if case['entry_kind']=='provider':assert[r['source_visits'][j]['pc']for j in range(8)]==[hex(a)for a in range(0xfffffe000a505828,0xfffffe000a505848,4)];counts['source_provider_to_core_prefixes']+=1
  assert not r['API_models']and not r['native_allocator_executed']and not r['native_target_executed']and r['model_memory_writes']==0 and not r['external_IPC_emission_proved'];assert not any(v['pc']=='0xfffffe000a5304c8'for v in r['source_visits'])
 bankrows=[];cases=list(bank_cases());assert len(cases)==1024 and[r['input']for r in bp['cases']]==cases
 for j,(case,retained)in enumerate(zip(cases,bp['cases'])):
  f=Candidate(case);r=f.run();del f;assert r==retained;bankrows.append(r);counts['fresh_conditional_bank_cases']+=1;counts['conditional_bank_instruction_visits']+=len(r['source_visits']);audit(r,k,counts,True)
  assert len(r['source_visits'])==13 and len(r['source_reads'])==4 and len(r['source_writes'])==1;F=int(r['frame_SP'],16);assert r['source_reads'][0]['address']==hex(F+0xc28)and r['source_reads'][1]['address']==hex(0xfffffe0007920c10+(case['input32']&255));byte=int(r['source_reads'][1]['bytes_hex'],16);assert r['source_reads'][2]['address']==hex(0xfffffe00079170c0+(byte^0x20));assert r['source_reads'][3]['address']=='0xfffffe0008471af8'and r['source_reads'][3]['bytes_hex']==struct.pack('<Q',0xfffffe000ccc7b10).hex()
  w=r['source_writes'][0];assert w['pc']=='0xfffffe000a589938'and w['address']==hex(F+0xd28)and w['after_hex']==struct.pack('<Q',0xfffffe000ccc7b08).hex();assert not r['original_parent_path_executed']and not r['tag_table_modified']and not r['native_target_executed']and r['model_memory_writes']==0
  if j%256==255:gc.collect();print(json.dumps({'fresh_bank_cases':j+1}),flush=True)
 assert counts['fresh_entry_prefix_cases']==36 and counts['entry_prefix_instruction_visits']==4968 and counts['fresh_conditional_bank_cases']==1024 and counts['conditional_bank_instruction_visits']==13312 and counts['source_argument_to_frame_stores']==216 and counts['source_provider_to_core_prefixes']==18 and counts['source_instruction_byte_checks']==73120
 deps={n:sha(ROOT/n)for n in['lskd_writers_contracts.json','lskd_writers_profiles.json','lskd_writers_bank_profiles.json','lskd_writers_proofs.json','lskd_writers_symbolic.py','lskd_writers_audit.py','probe_lskd_writers.py','probe_lskd_writers_bank.py','probe_legacy_stack.py','legacy_stack_contracts.json']}
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'entry_cases':rows,'conditional_bank_cases':bankrows,'full_goal_complete':False};(ROOT/'lskd_writers_replays.json').write_text(json.dumps(out,indent=2)+'\n')
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'verified_counts':dict(counts),'source_lift_counts':lifts,'fresh_replays_sha256':sha(ROOT/'lskd_writers_replays.json'),'kernel_collection_sha256':k.sha256,'source_sha256':sha(SOURCE),'all_checks_pass':True,'model_memory_writes':0,'native_allocator_executed':False,'complete_core_operation_executed':False,'same_frame_reaching_definition_proved':False,'actual_tag_table_writer_proved':False,'native_target_executed':False,'external_IPC_emission_proved':False,'full_goal_complete':False};(ROOT/'lskd_writers_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts),'source_lift_counts':lifts}),flush=True)
if __name__=='__main__':main()
