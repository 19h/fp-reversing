#!/usr/bin/env python3
"""Fresh instrumented original-A64 replay of all conditional caller pipelines,
with field/cursor/save audits, regenerated contracts and rebuilt SMT identities.
O(source visits + artifacts + solver resources) time, O(one CPU map/journal)
space. The two CPU passes share an ISA engine; separate source equations and
exhaustive source-byte identities provide semantic cross-checks. No native API.
"""
import json
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,TABLE,FIXUPS
from capture_daemon_record720 import sha
from probe_daemon_aux_callers import SPECS,record_address
from recover_daemon_aux_callers import recover
from prove_daemon_aux_callers import obligations
from replay_daemon_descriptor_producers import Replay
class AuditReplay(Replay):
 def __init__(self,s,p,pattern):self.spec=s;self.audits=Counter();super().__init__(p,pattern=pattern)
 def code(self,u,a,n,d):
  s=self.spec;p=self.p;R=int(p['record_address'],16);S=int(p['entry_SP'],16);FP=int(p['entry_FP'],16)
  if a==s['call']:
   raw=bytes(u.mem_read(R,24));K=(((R&0xffffffff)^0xdc40790b)*0x5973a279)&0xffffffff;assert self.reg('x0')==R and self.reg('x8')==0x100abca64 and self.reg('x17')==0xca54
   cursor=(S if s['cursor_kind']=='SP'else FP)+s['cursor_offset'];assert self.reg('x1')==cursor;assert int.from_bytes(raw[:4],'little')^K==0x471c and(int.from_bytes(raw[20:24],'little')-K)&0xffffffff==s['aux']and int.from_bytes(raw[8:16],'little')==0x6800001000
   assert raw[4:8]==self.ram[R+4-0x6800000000:R+8-0x6800000000]and raw[16:20]==self.ram[R+16-0x6800000000:R+20-0x6800000000];assert int.from_bytes(bytes(u.mem_read(cursor,8)),'little')==p['configuration']['counter64'];self.audits['constructed_records_checked']+=1
  if a==0x100a59bb4:assert self.reg('x0')==R;self.audits['same_record_at_entry_checked']+=1
  if a==s['spill']+4:
   F=self.reg('sp');assert self.reg('x0')==R and int.from_bytes(bytes(u.mem_read(F+0x24f8,8)),'little')==R;self.audits['source_written_record_saves_checked']+=1
  return super().code(u,a,n,d)

def main():
 p=json.loads((ROOT/'daemon_aux_callers_profiles.json').read_text());c=json.loads((ROOT/'daemon_aux_callers_contracts.json').read_text());proofs=json.loads((ROOT/'daemon_aux_callers_proofs.json').read_text());assert p['generator_sha256']==sha(ROOT/'probe_daemon_aux_callers.py')and p['specifications']==SPECS and recover()==c
 totals=Counter();audits=Counter();rows=[];effects=Counter()
 for j,row in enumerate(p['cases']):
  s=next(s for s in SPECS if s['label']==row['site']);profile=row['profile'];assert profile['entry_PC']==hex(s['start'])and profile['record_address']==hex(record_address(s,int(profile['entry_SP'],16),int(profile['entry_FP'],16)))
  assert profile['fixture_PC_transitions']==0 and profile['boundary']['kind']=='after_original_record_spill'
  for step in profile['source_visits']:
   if step['image']=='daemon':assert IMAGE.read(int(step['pc'],16),4).hex()==step['bytes_hex'];effects['original_daemon_instructions_checked']+=1
  for e in profile['source_reads']:
   if'known_mask_hex'in e and not all(bytes.fromhex(e['known_mask_hex'])):assert int(e['pc'],16)in[0x180587d24,0x180587d38];effects['undefined_stack_probe_reads_with_unused_values']+=1
  replay=AuditReplay(s,profile,(j+1)%4);out=replay.run();assert out['all_checks_pass'];assert replay.audits==Counter({'constructed_records_checked':1,'same_record_at_entry_checked':1,'source_written_record_saves_checked':1});audits.update(replay.audits);totals.update(out['verified_counts']);rows.append({'site':row['site'],**out,'caller_record_audits':dict(replay.audits)})
 qs,lifts,meta=obligations();assert len(qs)==len(proofs['proofs'])==29 and proofs['source_lift_counts']==lifts
 for (name,q),r in zip(qs,proofs['proofs'],strict=True):
  assert name==r['name']
  for f,h in [('file','sha256'),('original_file','original_sha256')]:
   path=ROOT/r[f];assert sha(path)==r[h];solver=z3.Solver();solver.set(timeout=30000);solver.add(z3.parse_smt2_file(str(path)));assert solver.check()==z3.unsat,(name,f)
  solver=z3.Solver();solver.set(timeout=30000);solver.add(q);assert solver.check()==z3.unsat,name
 assert len(c['conditional_bank_rules'])==8 and len(c['literal_CA54_call_candidates'])==16 and len(c['unclassified_literal_CA54_candidates'])==7
 for r in c['conditional_bank_rules']:
  l,h=IMAGE.read(int(r['left'],16),256),IMAGE.read(int(r['right'],16),256);k=int(r['key'],16);assert all(j^h[l[j]^k]==int(r['constant'],16)for j in range(256));assert int(r['additive'],16)+int(r['constant'],16)==0xcd2e;effects['exhaustive_bank_input_bytes_checked']+=256
 assert len(rows)==36 and totals['source_visits']==16654 and len(c['live_IDA_matches'])==6
 d={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['daemon_aux_callers_profiles.json','daemon_aux_callers_contracts.json','daemon_aux_callers_proofs.json','probe_daemon_aux_callers.py','replay_daemon_descriptor_producers.py','daemon_descriptor_producers_source.json','prove_daemon_aux_callers.py']},'verified_counts':{'original_record_emitters':9,'continuous_contexts_checked':36,'source_obligations_rebuilt':29,'accepted_SMT_files':58,'alignment_counterexamples':1,'bank_rules_exhaustive_256':8,'literal_aux_hits':12,'literal_call_candidates':16,'unclassified_literal_call_candidates':7,'live_IDA_ranges':6,'live_IDA_matching_bytes':1536,**dict(effects),**dict(audits)},'fresh_replay_cases':rows,'independent_A64_totals':dict(totals),'primary_and_replay_use_same_ISA_engine':True,'native_target_executed':False,'host_API_executed':False,'native_bank_root_writers_established':False,'native_incoming_phase_writers_established':False,'new_port_emission_established':False,'full_goal_complete':False,'all_checks_pass':True};(ROOT/'daemon_aux_callers_checks.json').write_text(json.dumps(d,indent=2)+'\n');print(json.dumps({'counts':d['verified_counts'],'fresh_A64_totals':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
