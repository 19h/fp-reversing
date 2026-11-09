#!/usr/bin/env python3
"""Fresh local ABI fixtures, source proof re-lift and independent load decoding.

O(B+C*I+8192C+256R) time, O(B+C) space plus solver cost,30 s/query.
No positive parent path, accepted context, tag mutation, native API or IDB edit.
"""
import hashlib,json,struct
from pathlib import Path
from collections import Counter
import z3
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,selected
from recover_carrier_control import span
from recover_kext_cold_init import pointer
from lskd_objects_symbolic import queries
from probe_lskd_objects import Fixture,P,SP,VECTOR,CELL,PREFIXES
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def main():
 c=read('lskd_objects_contracts.json');p=read('lskd_objects_profiles.json');proof=read('lskd_objects_proofs.json');state=read('lskd_state_contracts.json');k=Kernel();counts=Counter()
 for obj,name in[(c,'recover_lskd_objects.py'),(p,'probe_lskd_objects.py'),(proof,'prove_lskd_objects.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert k.sha256==c['kernel_collection_sha256']==p['kernel_collection_sha256']and sha(SOURCE)==c['source_sha256']==p['source_sha256']
 for s in c['spans']:
  now=span(k,int(s['start'],16),int(s['end'],16));assert all(now[n]==s[n]for n in now)and IMAGE.read(int(s['start'],16),int(s['end'],16)-int(s['start'],16)).hex()==s['bytes_hex'];counts['bounded_source_spans']+=1
 assert k.symbols([int(a,16)for a in c['exact_symbols']])==c['exact_symbols']and k.read(CELL,8).hex()==c['vector_root']['original8_hex']=='0000000000000000'
 for row in c['dispatch_slots']:assert pointer(k,int(row['pointer']['slot'],16))==row['pointer'];counts['original_dispatch_slots']+=1
 for b in state['bank_rules']:
  l,r=int(b['left'],16),int(b['right'],16);assert IMAGE.read(l,256).hex()==b['left256_hex']and IMAGE.read(r,256).hex()==b['right256_hex'];now=selected(l,r,int(b['key'],16),int(b['additive'],16),base=int(b['base'],16),bias=int(b['bias'],16));assert all(now[n]==b[n]for n in now)and int(b['target'],16)==CELL;counts['vector_root_bank_input_checks']+=256
 # Independent A64 load encodings, with no Capstone operand dependency.
 decoded=[]
 for root_pc,slot_pc in[(0xfffffe000a58b7e0,0xfffffe000a58b7e4),(0xfffffe000a57e29c,0xfffffe000a57e2a0)]:
  w=int.from_bytes(k.read(root_pc,4),'little');assert(w&0xffc00000)==0xf9400000 and(w&31)==10 and(w>>5)&31==10 and((w>>10)&0xfff)==0
  v=int.from_bytes(k.read(slot_pc,4),'little');assert(v&0xffe00c00)==0xf8600800 and(v&31)==12 and(v>>5)&31==10 and(v>>16)&31==13 and(v>>13)&7==3 and(v>>12)&1==1 and(v>>30)&3==3
  decoded.append({'root_load_PC':hex(root_pc),'root_load_word':hex(w),'root_load':'X10 = u64[X10]','slot_load_PC':hex(slot_pc),'slot_load_word':hex(v),'slot_load':'X12 = u64[X10 + (X13 << 3)]','size_bytes':8,'scale_bytes':8});counts['independently_decoded_load_pairs']+=1
 qs,lifts=queries(c,state);assert len(qs)==len(proof['proofs'])==16 and lifts==proof['source_lift_counts']and sum(lifts.values())==115
 for(name,q),row in zip(qs,proof['proofs']):
  assert name==row['name']and row['result']=='unsat';op,np=ROOT/row['original_file'],ROOT/row['file'];assert sha(op)==row['original_sha256']and sha(np)==row['sha256'];orig=z3.parse_smt2_string(op.read_text());assert len(orig)==1
  for f in[z3.simplify(q),z3.simplify(orig[0]),z3.Xor(z3.simplify(q),z3.simplify(orig[0])),*z3.parse_smt2_string(np.read_text())]:
   s=z3.Solver();s.set(timeout=30000);s.add(f);assert str(s.check())=='unsat',name
  counts['source_proof_pairs_unsat']+=1
 fresh=[];coverage=Counter();j=0
 for provider in PREFIXES:
  f=Fixture(provider);a,z=PREFIXES[provider];raw=k.read(a,z-a);start_n=len(raw)//4
  for index in range(1024):
   for null in[False,True]:
    r=f.run(index,null);assert r==p['cases'][j];fresh.append(r);j+=1;coverage[(provider,null)]+=1;counts['fresh_local_fixture_cases']+=1;counts['source_instruction_visits']+=start_n;counts['source_instruction_byte_checks']+=len(raw)
    value=0 if null else 0x8800000000000001+index*0x100000101;expected=(0x455 if null else 0x42b)if provider=='vault'else(0x515 if null else 0x502)
    assert int(r['fixture_slot_word64'],16)==value==int(r['loaded_slot_word64'],16)and int(r['selected_dispatch_index32'],16)==expected and r['source_visits']==start_n and r['source_bytes_sha256']==hashlib.sha256(raw).hexdigest()
    reads=r['source_reads'];assert len(reads)==2 and reads[0]['address']==hex(CELL)and reads[0]['bytes_hex']==struct.pack('<Q',VECTOR).hex()and reads[1]['address']==hex(VECTOR+index*8)and reads[1]['bytes_hex']==struct.pack('<Q',value).hex()and all(x['size_bytes']==8 for x in reads);counts['source_u64_read_epochs']+=2
    writes=r['source_writes'];assert len(writes)==1 and writes[0]['address']==hex(SP+(0x40 if provider=='vault'else 0x90))and writes[0]['size_bytes']==8 and writes[0]['value64']=='0x0';counts['source_frame_zero_write_epochs']+=1
    assert r['boundary_PC']==hex(z)and r['fixture_vector_unchanged_by_source']and not r['complete_handler_executed']and not r['native_reachability_proved']and r['model_memory_writes']==0
  print(json.dumps({'fresh_local_cases':j,'provider':provider}),flush=True)
 assert j==len(p['cases'])==4096 and counts['source_instruction_visits']==65536 and counts['source_instruction_byte_checks']==262144 and all(n==1024 for n in coverage.values())
 # Frozen, already byte-audited real source prefixes establish the shared call
 # sites on the first pass. This readback does not claim a positive retry ran.
 old=read('lskd_lookup_profiles.json');sites=Counter()
 for r in old['cases']:
  for x in r['source_calls']:
   if x['pc']in['0xfffffe000a57ee9c','0xfffffe000a5727e0']:
    assert x['target']=='0xfffffe000a54e220'and x['target_executed_in_private_guest'];sites[x['pc']]+=1
 assert sites==Counter({'0xfffffe000a57ee9c':19,'0xfffffe000a5727e0':19});counts['preceding_source_acquire_call_readbacks']=sum(sites.values())
 deps={n:sha(ROOT/n)for n in['lskd_objects_contracts.json','lskd_objects_profiles.json','lskd_objects_proofs.json','lskd_objects_symbolic.py','probe_lskd_objects.py','lskd_lookup_profiles.json','lskd_state_contracts.json','lskd_state_symbolic.py','lskd_values_symbolic.py']}
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'cases':fresh,'full_goal_complete':False};(ROOT/'lskd_objects_replays.json').write_text(json.dumps(out,indent=2)+'\n')
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'verified_counts':dict(counts),'source_lift_counts':lifts,'independent_load_decodings':decoded,'fixture_coverage':[{'provider':k[0],'null_slot':k[1],'indices':n}for k,n in coverage.items()],'source_acquire_call_readbacks':dict(sites),'fresh_replays_sha256':sha(ROOT/'lskd_objects_replays.json'),'kernel_collection_sha256':k.sha256,'source_sha256':sha(SOURCE),'all_checks_pass':True,'model_memory_writes':0,'accepted_context_fixture_supplied':False,'positive_parent_path_executed':False,'native_target_executed':False,'external_IPC_emission_proved':False,'full_goal_complete':False};(ROOT/'lskd_objects_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts)}),flush=True)
if __name__=='__main__':main()
