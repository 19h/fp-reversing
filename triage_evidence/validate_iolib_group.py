#!/usr/bin/env python3
"""Fresh private source replay and independent group/epoch/ABI checks.

O(B + C*(V+E) + W) time and retained space, plus solver-dependent proofs;
B is pinned source bytes, C fixture count, V/E visits/events, W census words.
No native registry/startup/synchronization/heap operation or IDB mutation.
"""
import gc,hashlib,json,struct
from collections import Counter
from pathlib import Path
import z3
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE
from recover_iolib_group import reference_census
from probe_iolib_group import Group,cases,P,GROUP,CELL,READY,FACILITY,MUTEX_CELL,HEAD,MAP,MUTEX,RW_OBJECT,INPUT_PTR,INPUT_VECTOR
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def q(v):return struct.pack('<Q',v)
def regs(row,n):return[int(v,16)for v in row['registers8'][:n]]
def overlap(events,a,n):return[e for e in events if a<=int(e['address'],16)and int(e['address'],16)+e['size_bytes']<=a+n]
def word_model(c,late):
 b=bytearray(328);struct.pack_into('<I',b,0,1);b[24:30]=b'IOKit\0'
 if not late:struct.pack_into('<I',b,4,c['token32']|c['flags32'])
 for flag,offsets in[(0x10000,[0x60,0x78,0xa8,0xc0,0xf0,0x108,0x120,0x138]),(0x20000,[0x90,0xd8])]:
  if c['flags32']&flag:
   for o in offsets:struct.pack_into('<I',b,o,1)
 return bytes(b)
def reconstruct(stage,counts):
 spans=[('group328_hex',GROUP,328),('group_cell_hex',CELL,8),('ready32_hex',READY,32),('facility24_hex',FACILITY,24)]
 for key,a,n in spans:
  b=bytearray.fromhex(stage['before'][key]);written=set()
  for w in stage['source_writes']:
   x=int(w['address'],16);z=x+w['size_bytes']
   if x<a+n and a<z:
    assert a<=x<z<=a+n;v=bytes.fromhex(w['after_hex']);assert len(v)==w['size_bytes'];b[x-a:z-a]=v;written.update(range(x-a,z-a))
  assert b.hex()==stage['after'][key],(stage['stage'],key)
  if stage['stage']=='cold'and key=='group328_hex':assert len(written)==328;counts['group_source_written_bytes']+=len(written)
def main():
 c=read('iolib_group_contracts.json');p=read('iolib_group_profiles.json');proof=read('iolib_group_proofs.json');k=Kernel();counts=Counter()
 for obj,name in[(c,'recover_iolib_group.py'),(p,'probe_iolib_group.py'),(proof,'prove_iolib_group.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for name,h in obj.get('dependencies',{}).items():assert sha(ROOT/name)==h,name
 assert k.sha256==c['kernel_collection_sha256']==p['kernel_collection_sha256'];assert sha(SOURCE)==c['source_sha256']
 for f in c['functions']:assert k.function(int(f['start'],16))==f;counts['kernel_functions']+=1
 assert k.symbols([int(a,16)for a in c['exact_symbols']])==c['exact_symbols']
 for d in c['data']:assert k.read(int(d['address'],16),len(bytes.fromhex(d['bytes_hex']))).hex()==d['bytes_hex'];counts['original_data_spans']+=1
 census=reference_census(k);assert census==c['reference_census'];counts['census_words']=census['words_scanned'];counts['page_ADRP_candidates']=census['page_ADRP_candidates'];counts['bounded_references']=len(census['references']);counts['bounded_writers']=sum(r['direction']=='write'for r in census['references']);counts['direct_startup_callers']=len(census['direct_IOLibInit_callers'])
 startup=next(f for f in c['functions']if f['start']=='0xfffffe000c4bcc70');ins={r['ea']:r for r in startup['instructions']};assert ins['0xfffffe000c4bcca8']['operands']=='#0xfffffe000c4b91a8'and ins['0xfffffe000c4bccac']['operands']=='#0xfffffe000c47c364'
 assert proof['contracts_sha256']==sha(ROOT/'iolib_group_contracts.json')
 for row in proof['proofs']:
  path=ROOT/row['file'];assert sha(path)==row['sha256'];s=z3.Solver();s.from_string(path.read_text());assert str(s.check())==row['result']=='unsat';counts['proofs_unsat']+=1
 fresh=[];expected_cases=list(cases());assert[r['input']for r in p['cases']]==expected_cases
 for j,(case,old)in enumerate(zip(expected_cases,p['cases'])):
  g=Group(case);r=g.run();del g;assert r==old,(j,case);fresh.append(r);counts['fresh_initial_states']+=1;late=case['phase32']>=4;stages=r['stages'];assert[s['stage']for s in stages]==(['cold']if late else['cold','warm_repeat','RW_allocate','RW_free'])
  previous=None;last_index=-1;publication=None
  for s in stages:
   counts['fresh_source_stages']+=1;counts['source_visits']+=len(s['source_visits'])
   if previous is not None:assert s['before']==previous
   previous=s['after'];assert not s['private_undefined_reads']
   for key in['native_API_executed','registry_operation_executed','synchronization_executed','heap_backend_executed','entry_reachability_proved']:assert s[key]is False
   visits={v['source_visit_index']:v for v in s['source_visits']}
   assert list(visits)==list(range(last_index+1,last_index+1+len(visits)));last_index=max(visits)
   for v in visits.values():assert k.read(int(v['pc'],16),4).hex()==v['bytes_hex'];counts['source_byte_checks']+=4
   for event in s['source_reads']+s['source_writes']:
    assert event['pc']==visits[event['source_visit_index']]['pc']
    if 'after_hex'in event:assert len(bytes.fromhex(event['after_hex']))==event['size_bytes']
   reconstruct(s,counts)
   global_writes=[w for w in s['source_writes']if not P<=int(w['address'],16)<P+0x10000]
   if s['stage']=='cold':
    counts['late_phase_stops'if late else'completed_cold_wrappers']+=1
    assert s['after']['group328_hex']==word_model(case,late).hex()
    copied=overlap(s['source_writes'],GROUP+24,6);assert b''.join(bytes.fromhex(e['after_hex'])for e in copied)==b'IOKit\0';assert all(e['pc']=='0xfffffe000c647fd4'for e in copied);counts['original_helper_name_bytes']+=6
    if late:
     assert s['boundary']['kind']=='before_registry_lock_path'and s['boundary']['pc']=='0xfffffe000bd03900'and not s['models'];assert all(s['after'][key]==s['before'][key]for key in['group_cell_hex','ready32_hex','facility24_hex']);continue
    assert s['boundary']['kind']=='returned';assert s['after']['group_cell_hex']==q(GROUP).hex();assert s['after']['ready32_hex']==(b'\1'+bytes(7)+q(MUTEX)+q(HEAD)*2).hex();assert s['after']['facility24_hex']==(q(MAP)+bytes.fromhex(r['environment_vector16_hex'])).hex()
    models=s['models'];assert[m['kind']for m in models]==['registry','first_setup','second_setup','mutex_allocation']
    assert regs(models[0],3)==[0xfffffe000ca90368,0xffff,GROUP];assert regs(models[1],5)==[int(r['environment_pointer64'],16),int.from_bytes(bytes.fromhex(r['environment_vector16_hex'])[:8],'little'),0xc0000000,0x10,0x03004081];assert regs(models[2],2)==[MAP,0x60000000];assert regs(models[3],2)==[GROUP,0]
    for m in models:assert not m['target_executed']and visits[m['source_visit_index']]['target_modeled'];counts['modeled_call_boundaries']+=1;assert not any(v['pc']==m['target']for v in visits.values())
    checks=[(CELL,8,'0xfffffe000c4b91e8',q(GROUP)),(FACILITY,8,'0xfffffe000c4b921c',q(MAP)),(FACILITY+8,16,'0xfffffe000c4b922c',bytes.fromhex(r['environment_vector16_hex'])),(MUTEX_CELL,8,'0xfffffe000c4b9240',q(MUTEX)),(HEAD,16,'0xfffffe000c4b924c',q(HEAD)*2),(READY,1,'0xfffffe000c4b9254',b'\1')];epochs=[]
    for a,n,pc,wanted in checks:
     ws=overlap(s['source_writes'],a,n);assert ws and all(w['pc']==pc for w in ws);assert b''.join(bytes.fromhex(w['after_hex'])for w in ws)==wanted;assert len({w['source_visit_index']for w in ws})==1;epochs.append(ws[0]['source_visit_index'])
    publication=epochs[0];assert models[0]['source_visit_index']<epochs[0]<models[1]['source_visit_index']<epochs[1]<models[2]['source_visit_index']<epochs[2]<models[3]['source_visit_index']<epochs[3]<epochs[4]<epochs[5];counts['ordered_publication_sequences']+=1
   else:
    assert not global_writes and not s['models']and s['before']==s['after'];assert publication is not None
    if s['stage']=='warm_repeat':
     rs=overlap(s['source_reads'],READY,1);assert len(rs)==1 and rs[0]['bytes_hex']=='01';assert s['boundary']['kind']=='returned';counts['warm_repeats']+=1
    else:
     rs=overlap(s['source_reads'],CELL,8);assert len(rs)==1 and rs[0]['bytes_hex']==q(GROUP).hex()and rs[0]['source_visit_index']>publication
     expect=[GROUP,0]if s['stage']=='RW_allocate'else[RW_OBJECT,GROUP];assert[int(v,16)for v in s['boundary']['registers31'][:2]]==expect;assert s['boundary']['kind']=='before_RW_core';counts['composed_RW_prefixes']+=1
  if j%16==0:gc.collect()
 assert counts['fresh_initial_states']==144 and counts['fresh_source_stages']==528 and counts['source_visits']==32432 and counts['group_source_written_bytes']==47232
 deps={n:sha(ROOT/n)for n in['recover_iolib_group.py','probe_iolib_group.py','iolib_group_contracts.json','iolib_group_profiles.json','iolib_group_proofs.json','kernel_native_reader.py','kext_port_tools.py']}
 replay={'scope':'Distinct fresh private runs, compared in full with retained profiles.','generator_sha256':sha(Path(__file__)),'dependencies':deps,'cases':fresh,'native_target_executed':False,'full_goal_complete':False};(ROOT/'iolib_group_replays.json').write_text(json.dumps(replay,indent=2)+'\n')
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'kernel_collection_sha256':k.sha256,'source_sha256':sha(SOURCE),'verified_counts':dict(counts),'fresh_replays_sha256':sha(ROOT/'iolib_group_replays.json'),'all_checks_pass':True,'native_startup_proved':False,'registry_backend_executed':False,'synchronization_executed':False,'cached_FairPlay_lock_publication_proved':False,'full_goal_complete':False};(ROOT/'iolib_group_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts)}),flush=True)
if __name__=='__main__':main()
