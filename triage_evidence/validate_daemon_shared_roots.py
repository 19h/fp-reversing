#!/usr/bin/env python3
"""Fresh strict-prefix A64 replay, helper preservation, all tracked field values
and branch-slot audits plus original/rebuilt SMT readback. O(visits + artifacts
+ solver resources) time, O(one map/journal) space. CPU passes share Unicorn;
local source theorems are separate checks. No native API/process/port effects.
"""
import json
from collections import Counter
import z3
from daemon_receive_tools import ROOT,IMAGE,TABLE,FIXUPS
from capture_daemon_record720 import sha
from capture_daemon_shared_roots import capture
from prove_daemon_shared_roots import obligations
from probe_daemon_shared_roots import FIELDS,EXPECTED,END
from replay_daemon_descriptor_producers import Replay

class AuditReplay(Replay):
 def __init__(self,p,pattern):self.audits=Counter();super().__init__(p,pattern=pattern)
 def code(self,u,a,n,d):
  if a==0x10061a310:
   regs,sp=self.helper_entry;assert self.reg('sp')==sp
   for j,x in enumerate(regs):
    if j!=9:assert self.reg('x'+str(j))==x
   self.audits['original_helper_preservation_checks']+=1
  if a==END:
   F=self.reg('sp');P=int(self.p['record_address'],16);assert F==int(self.p['entry_SP'],16)-0x10dd0 and self.reg('x29')==F+0x10dc0
   for off in FIELDS:assert int.from_bytes(bytes(u.mem_read(F+off,8)),'little')==EXPECTED[off];self.audits['source_defined_fields_checked']+=1
   op=self.p['configuration']['operation32'];signed=lambda v:v-(1<<32)if v&0x80000000 else v;ix=0x80a4 if signed(op)<signed(0xad952088)else 0x8061;slot=TABLE+8*ix;word=int.from_bytes(IMAGE.read(slot,8),'little');assert int.from_bytes(bytes(u.mem_read(F+0x9a0,4)),'little')==ix and int.from_bytes(bytes(u.mem_read(F+0x9b8,4)),'little')==op
   assert FIXUPS[slot]['target']==self.reg('x8')and self.reg('x17')==0x8a50 and word>>63==1 and(word>>32)&65535==0x8a50;assert any(e['address']==hex(slot)and e['size_bytes']==8 for e in self.p['source_reads']);self.audits['original_next_branch_slots_checked']+=1
   initial=next(g for g in self.p['initial_private_fixtures']if g['address']==hex(P));assert bytes(u.mem_read(P,24))==bytes.fromhex(initial['bytes_hex']);self.audits['protected_input_records_preserved']+=1
  return super().code(u,a,n,d)

def main():
 p=json.loads((ROOT/'daemon_shared_roots_profiles.json').read_text());s=json.loads((ROOT/'daemon_shared_roots_source.json').read_text());proofs=json.loads((ROOT/'daemon_shared_roots_proofs.json').read_text());assert p['generator_sha256']==sha(ROOT/'probe_daemon_shared_roots.py')and capture()==s
 rows=[];totals=Counter();audits=Counter();defined=Counter();targets=Counter()
 for j,r in enumerate(p['cases']):
  assert r['fixture_PC_transitions']==0 and r['boundary']['kind']=='before_shared_setup_branch'
  for step in r['source_visits']:
   if step['image']=='daemon':assert IMAGE.read(int(step['pc'],16),4).hex()==step['bytes_hex'];defined['original_daemon_instructions_checked']+=1
  for e in r['source_reads']:
   if'known_mask_hex'in e and not all(bytes.fromhex(e['known_mask_hex'])):assert int(e['pc'],16)in[0x180587d24,0x180587d38];defined['unused_stack_probe_reads_with_unknown_bytes']+=1
  F=int(r['frame_base'],16);P=int(r['record_address'],16)
  for e in r['source_writes']:assert int(e['address'],16)>=P+24 or int(e['address'],16)+e['size_bytes']<=P
  replay=AuditReplay(r,(j+1)%4);out=replay.run();assert out['all_checks_pass']and replay.audits['original_helper_preservation_checks']==1 and replay.audits['source_defined_fields_checked']==10;totals.update(out['verified_counts']);audits.update(replay.audits);rows.append({**out,'field_audits':dict(replay.audits)});targets[r['boundary']['registers31'][8]]+=1
 qs,counts,meta=obligations();assert len(qs)==len(proofs['proofs'])==6 and counts==proofs['source_lift_counts']and meta==proofs['metadata']
 for (name,q),r in zip(qs,proofs['proofs'],strict=True):
  assert name==r['name']
  for f,h in [('file','sha256'),('original_file','original_sha256')]:
   path=ROOT/r[f];assert sha(path)==r[h];sol=z3.Solver();sol.set(timeout=30000);sol.add(z3.parse_smt2_file(str(path)));assert sol.check()==z3.unsat
  sol=z3.Solver();sol.set(timeout=30000);sol.add(q);assert sol.check()==z3.unsat
 assert totals['source_visits']==13056 and targets==Counter({'0x100610388':4,'0x1004d4aac':4})
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['daemon_shared_roots_profiles.json','daemon_shared_roots_source.json','daemon_shared_roots_proofs.json','probe_daemon_shared_roots.py','capture_daemon_shared_roots.py','prove_daemon_shared_roots.py','replay_daemon_descriptor_producers.py','daemon_descriptor_producers_source.json']},'verified_counts':{'continuous_prefix_cases':8,'source_defined_fields_per_case':10,'tracked_fields_total':80,'setup_stores_per_case':129,'key_projection_instructions':20,'source_obligations_rebuilt':6,'accepted_SMT_files':12,**dict(defined),**dict(audits)},'fresh_replay_cases':rows,'independent_A64_totals':dict(totals),'next_target_counts':dict(targets),'primary_and_replay_use_same_ISA_engine':True,'native_target_executed':False,'host_API_executed':False,'complete_prologue_all_state_invariance_proved':False,'later_emitter_epoch_join_established':False,'new_port_emission_established':False,'full_goal_complete':False,'all_checks_pass':True};(ROOT/'daemon_shared_roots_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':out['verified_counts'],'fresh_A64_totals':dict(totals),'targets':dict(targets),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
