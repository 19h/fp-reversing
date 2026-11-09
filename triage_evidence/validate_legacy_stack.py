#!/usr/bin/env python3
"""Fresh legacy wrapper/bridge replay and independent records/byte epochs.

O(B+C*(V+E)+256R) time/retained space plus solver cost. Native inner operations,
relocated-frame validity, lock publication and IPC emission are not proved.
"""
import gc,hashlib,json,struct
from collections import Counter
from pathlib import Path
import z3
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,selected
from recover_kext_aes_handoff import function
from recover_kext_cold_init import pointer
from probe_legacy_stack import Bridge,cases,P,M64
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def key32(p):
 w=p&0xffffffff;t=(((w|0x976412f0)^0xfffffffe)-(0x689bed0f|(~w&0xffffffff)))&0xffffffff;return((t^0xd83db235)*0x4ca11177)&0xffffffff
def compact_record(row):
 c=row['input'];a=int(row['source_calls'][0]['record']['address'],16);x=c['inputs8'];b=bytearray(b'\xa5'*(32 if c['family']=='record32'else 64));mask=bytearray(len(b))
 def put(o,fmt,v):
  raw=struct.pack(fmt,v);b[o:o+len(raw)]=raw;mask[o:o+len(raw)]=b'\1'*len(raw)
 if c['family']=='record32':
  k=((a^0x2bf25469f26d6f2a)*0xeac8f755)&M64;put(0,'<Q',x[0]);put(8,'<I',(k+0xc83b1be7)&0xffffffff);put(12,'<H',(k+(x[1]&0xffffffff)*0x7e23+0x64ca)&0xffff);put(24,'<Q',k^((x[2]*0x0af36ba5d7ced8c7+0x23aeddd02b5fde50)&M64))
 else:
  k=key32(a)
  for o,v in[(0,k+x[7]),(4,k^0x6e3),(8,x[4]-k),(24,k^x[6]),(60,x[1]-k)]:put(o,'<I',v&0xffffffff)
  for o,j in[(16,3),(32,5),(40,2),(48,0)]:put(o,'<Q',x[j])
 s=row['source_calls'][0]['record'];assert s['bytes_hex']==b.hex()and s['known_mask_hex']==mask.hex()and s['provenance_hex']==mask.hex();return sum(mask)
def audit_epochs(r,c,counts):
 state={};known=set();provenance={};events={};snapshots={};inputs=r['input'];fixture=inputs['global_fixture'];global_initial={}
 for j,d in enumerate(c['mutable_globals']):
  a=int(d['address'],16);v=int.from_bytes(bytes.fromhex(d['original8_hex']),'little')if fixture=='original'else 0 if fixture=='zero'else(0x12345678a5a50000+j*0x111111111)&M64
  for n,b in enumerate(struct.pack('<Q',v)):global_initial[a+n]=b
 guard=int(c['guard']['address'],16);guardraw=bytes.fromhex(c['guard']['original8_hex'])
 def initial(a):
  if P<=a<P+0x20000:return 0xa5
  if a in global_initial:return global_initial[a]
  if guard<=a<guard+8:return guardraw[a-guard]
  return IMAGE.read(a,1)[0]
 def current(a,n):return bytes(state.get(x,initial(x))for x in range(a,a+n))
 def snapshot(s):
  a=int(s['address'],16);n=s['size_bytes'];assert current(a,n).hex()==s['bytes_hex'];assert bytes(int(x in known)for x in range(a,a+n)).hex()==s['known_mask_hex'];assert bytes(provenance.get(x,0)for x in range(a,a+n)).hex()==s['provenance_hex']
 for e in r['source_reads']:events.setdefault(e['source_visit_index'],[]).append(('read',e))
 for e in r['source_writes']:events.setdefault(e['source_visit_index'],[]).append(('write',e))
 for call in r['source_calls']:snapshots[call['source_visit_index']]=call['record']
 models={m['source_visit_index']:m for m in r['models']}
 for v in r['source_visits']:
  idx=v['source_visit_index'];assert IMAGE.read(int(v['pc'],16),4).hex()==v['bytes_hex'];counts['source_byte_checks']+=4
  if idx in snapshots:snapshot(snapshots[idx])
  for kind,e in events.get(idx,[]):
   assert e['pc']==v['pc'];a=int(e['address'],16);n=e['size_bytes']
   if kind=='read':
    assert current(a,n).hex()==e['bytes_hex'],(v['pc'],e)
    if P<=a<a+n<=P+0x20000 and not e['probe_only']:assert all(x in known for x in range(a,a+n))
    counts['read_epochs']+=1
   else:
    b=bytes.fromhex(e['after_hex']);assert len(b)==n
    if not P<=a<a+n<=P+0x20000:assert any(int(d['address'],16)<=a<a+n<=int(d['address'],16)+8 for d in c['mutable_globals'])
    for x,byte in enumerate(b,a):state[x]=byte;known.add(x);provenance[x]=1
    counts['source_write_epochs']+=1
  if idx in models:
   m=models[idx];assert not m['target_executed'];snapshot(m['record_before'])
   if 'local_state_before'in m:snapshot(m['local_state_before'])
   for w in m['modeled_writes']:
    a=int(w['address'],16);b=bytes.fromhex(w['bytes_hex']);assert len(b)==w['size_bytes']==4
    for x,byte in enumerate(b,a):state[x]=byte;known.add(x);provenance[x]=2
    counts['modeled_written_bytes']+=len(b)
   snapshot(m['record_after'])
 snapshot(r['outer_record_after'])
def main():
 c=read('legacy_stack_contracts.json');p=read('legacy_stack_profiles.json');proof=read('legacy_stack_proofs.json');k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');counts=Counter()
 for obj,name in[(c,'recover_legacy_stack.py'),(p,'probe_legacy_stack.py'),(proof,'prove_legacy_stack.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for n,h in obj.get('dependencies',{}).items():assert sha(ROOT/n)==h,n
 assert sha(SOURCE)==c['source_sha256']==p['source_sha256'];assert k.sha256==c['kernel_collection_sha256']==p['kernel_collection_sha256']
 for f in c['functions']:assert function(k,e,int(f['start'],16))==f;counts['original_functions']+=1
 assert k.symbols([int(a,16)for a in c['exact_symbols']])==c['exact_symbols']
 for b in c['bank_rules']:
  l=int(b['left'],16);r=int(b['right'],16);assert IMAGE.read(l,256).hex()==b['left256_hex']and IMAGE.read(r,256).hex()==b['right256_hex'];s=selected(l,r,int(b['key'],16),int(b['additive'],16),base=int(b['base'],16),bias=int(b['bias'],16));assert all(s[n]==b[n]for n in s);assert pointer(k,int(b['slot'],16))==b['original_pointer'];counts['exhaustive_banks']+=1;counts['bank_byte_inputs']+=256
 for b in c['original_bindings']:assert pointer(k,int(b['slot'],16))==b;counts['original_bindings']+=1
 for d in c['mutable_globals']:assert k.read(int(d['address'],16),8).hex()==d['original8_hex'];counts['original_mutable_globals']+=1
 assert k.read(int(c['guard']['address'],16),8).hex()==c['guard']['original8_hex'];assert proof['contracts_sha256']==sha(ROOT/'legacy_stack_contracts.json')
 for q in proof['proofs']:
  path=ROOT/q['file'];source=ROOT/q['original_file'];assert sha(path)==q['sha256']and sha(source)==q['original_sha256'];s=z3.Solver();s.set(timeout=30000);s.from_string(path.read_text());assert str(s.check())==q['result']=='unsat';original=z3.parse_smt2_string(source.read_text());assert len(original)==1;s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(original[0]));assert str(s.check())=='unsat';counts['proofs_unsat']+=1
 expected=list(cases());assert[r['input']for r in p['cases']]==expected;fresh=[];pairs={}
 for j,(case,old)in enumerate(zip(expected,p['cases'])):
  b=Bridge(case);r=b.run();del b;assert r==old,(j,case);fresh.append(r);counts['fresh_cases']+=1;counts['source_visits']+=len(r['source_visits']);assert not r['undefined_private_value_reads']and not r['native_API_executed']and not r['inner_record_operations_executed']and not r['native_reachability_proved'];assert[v['source_visit_index']for v in r['source_visits']]==list(range(len(r['source_visits'])));assert len(r['models'])==len(r['source_calls'])==1
  counts['outer_record_source_bytes']+=compact_record(r);audit_epochs(r,c,counts);outer=r['source_calls'][0];model=r['models'][0];sp=int(r['entry_SP'],16);a=int(outer['record']['address'],16);callidx=outer['source_visit_index'];modelidx=model['source_visit_index'];assert callidx<modelidx
  if case['family']=='record32':
   counts['record32_cases']+=1;assert a==sp-0x40+8 and outer['target']=='0xfffffe000a52fd18'and model['target']=='0xfffffe000a55e8b0';q=int(model['record_before']['address'],16);raw=bytes.fromhex(model['record_before']['bytes_hex']);assert q==a-0x50 and int.from_bytes(raw[:8],'little')==q-8 and int.from_bytes(raw[24:32],'little')==case['inputs8'][0];assert sum(bytes.fromhex(model['record_before']['known_mask_hex']))==24;counts['inner_record_source_bytes']+=24
   observation=next(v for v in r['source_visits']if v['pc']=='0xfffffe000a52fea4');assert int(observation['observed_registers31'][1],16)==(case['inputs8'][2]+0x442b0f63903f796e)&M64;counts['affine_operand_observations']+=1
   copied=[w for w in r['source_writes']if w['address']==hex(a+16)];assert len(copied)==1 and copied[0]['pc']=='0xfffffe000a5302b4'and copied[0]['source_visit_index']>modelidx and copied[0]['after_hex']==struct.pack('<I',case['status32']).hex();counts['forwarded_status_bytes']+=4;assert r['boundary']['kind']=='returned'and int(r['boundary']['SP'],16)==sp and int(r['boundary']['registers31'][0],16)==(case['status32']+0xa1a9e7b7)&0xffffffff
   if case['inputs8'][0]==0x1234567887654321:
    key=(case['global_fixture'],case['placement'],case['status32']);other=pairs.get(key)
    if other is None:pairs[key]=r
    else:
     aa={n:v for n,v in r.items()if n!='input'};bb={n:v for n,v in other.items()if n!='input'};assert aa==bb;counts['W1_period_trace_pairs']+=1
  else:
   counts['record64_cases']+=1;assert a==sp-0x90+0x18 and outer['target']=='0xfffffe000a570cf4'and model['target']=='0xfffffe000a561344'and int(model['record_before']['address'],16)==a;seed=int(r['initial_displacement_seed64'],16);local=int(model['local_state_before']['address'],16);assert model['local_state_before']['bytes_hex']==struct.pack('<Q',(seed-0x40)&M64).hex();allocation=((((seed*0x2ec5+1)&M64)>>56)&0xf0)+16;assert local==sp-0xd0-allocation and allocation in range(16,257,16)
   assert len(r['probe_only_reads'])==1 and int(r['probe_only_reads'][0]['address'],16)==local;counts['original_probe_reads']+=1
   delta=(case['delta_units32']&0xffff)<<4;cell=sp-0x90+8;ws=[w for w in r['source_writes']if w['pc']=='0xfffffe000a570ef4'];assert len(ws)==1 and ws[0]['address']==hex(cell)and ws[0]['after_hex']==struct.pack('<Q',delta).hex()and ws[0]['source_visit_index']>modelidx;rs=[x for x in r['source_reads']if x['pc']=='0xfffffe000a50e868'];assert len(rs)==1 and rs[0]['address']==hex(cell)and rs[0]['bytes_hex']==ws[0]['after_hex']and rs[0]['source_visit_index']>ws[0]['source_visit_index'];counts['source_stack_displacements']+=1
   if delta:assert r['boundary']['kind']=='before_relocated_output_read'and int(r['boundary']['SP'],16)==sp-0x90+delta;assert not any(v['pc']=='0xfffffe000a50e874'for v in r['source_visits']);counts['relocated_read_stops']+=1
   else:assert r['boundary']['kind']=='returned'and int(r['boundary']['SP'],16)==sp and int(r['boundary']['registers31'][0],16)==case['status32'];counts['zero_displacement_returns']+=1
  if j%12==0:gc.collect()
 assert counts['fresh_cases']==192 and counts['source_visits']==67968 and counts['outer_record_source_bytes']==8544 and counts['W1_period_trace_pairs']==12
 deps={n:sha(ROOT/n)for n in['recover_legacy_stack.py','probe_legacy_stack.py','prove_legacy_stack.py','legacy_stack_contracts.json','legacy_stack_profiles.json','legacy_stack_proofs.json','kernel_native_reader.py','kext_port_tools.py']};replays={'scope':'Distinct fresh private replay; complete equality with retained cases.','generator_sha256':sha(Path(__file__)),'dependencies':deps,'cases':fresh,'native_target_executed':False,'full_goal_complete':False};(ROOT/'legacy_stack_replays.json').write_text(json.dumps(replays,indent=2)+'\n');out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'kernel_collection_sha256':k.sha256,'source_sha256':sha(SOURCE),'verified_counts':dict(counts),'fresh_replays_sha256':sha(ROOT/'legacy_stack_replays.json'),'all_checks_pass':True,'relocated_frame_validity_proved':False,'cached_FairPlay_lock_publication_proved':False,'native_target_executed':False,'full_goal_complete':False};(ROOT/'legacy_stack_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts)}),flush=True)
if __name__=='__main__':main()
