#!/usr/bin/env python3
"""Fresh independent A64 replay of strict and explicitly modeled profiles,
rebuilt source/SDK/contracts/SMT and token/key/output ledgers. O(profile visits
+ source/artifact bytes + solver/compiler resources) time; O(one CPU map and
journal + DAGs) space. No native framework, target, port or IPC execution.
"""
import json
from collections import Counter
import z3
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,IMAGE,FIXUPS
from capture_daemon_record720 import sha
from replay_daemon_descriptor_producers import Replay
from recover_daemon_record40_consumer import recover
from prove_daemon_record40_consumer import obligations

class Fresh(Replay):
 def __init__(self,p,pattern):
  self.import_words={int(r['address'],16):bytes.fromhex(r['bytes_hex'])for r in p['initial_image_fixtures']if int(r['address'],16)<0x100000000};self.models={m['source_visit_index']:m for m in p['API_model_events']};super().__init__(p,pattern=pattern)
 def ensure(self,a,n=1):
  if a in self.import_words:
   pg=a&~4095
   if pg not in self.pages:self.u.mem_map(pg,4096);self.u.mem_write(pg,bytes([0xc7])*4096);self.pages.add(pg)
   for address,b in self.import_words.items():
    if address&~4095==pg:self.u.mem_write(address,b)
   return
  return super().ensure(a,n)
 def code(self,u,a,n,d):
  model=self.models.get(self.seq)
  if model is None:return super().code(u,a,n,d)
  self.finish();assert model['pc']==hex(a)and self.steps[self.seq]['pc']==hex(a);raw=bytes(u.mem_read(a,4));assert raw==IMAGE.read(a,4)and raw.hex()==self.steps[self.seq]['bytes_hex'];slot=int(model['slot'],16);word=int.from_bytes(IMAGE.read(slot,8),'little');assert FIXUPS[slot]['target']==model['symbol']and word>>63==1 and(word>>32)&65535==int(model['modifier'],16)and(word>>48)&7==0;assert self.reg('x8')==int(model['target'],16)and self.reg('x17')==int(model['modifier'],16)and self.reg('SP')==int(model['SP'],16)
  for j,value in enumerate(model['arguments8']):assert self.reg('x'+str(j))==int(value,16)
  assert not self.reads[self.seq]and not self.writes[self.seq];self.current=self.seq;self.seq+=1;self.rc=self.wc=0;self.counts['source_visits']+=1;self.counts['declared_API_models_checked']+=1
  for j,value in enumerate(model['after_registers31']):
   if j<18 or j==30:u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),int(value,16))
   else:assert self.reg('x'+str(j))==int(value,16),(hex(a),j)
  u.reg_write(ar.UC_ARM64_REG_NZCV,int(model['after_NZCV'],16));u.reg_write(ar.UC_ARM64_REG_PC,a+4)

def main():
 profiles=json.loads((ROOT/'daemon_record40_consumer_profiles.json').read_text());contract=json.loads((ROOT/'daemon_record40_consumer_contracts.json').read_text());proofs=json.loads((ROOT/'daemon_record40_consumer_proofs.json').read_text());assert profiles['generator_sha256']==sha(ROOT/'probe_daemon_record40_consumer.py')and recover()==contract;qs,counts,meta=obligations();assert counts==proofs['source_lift_counts']and meta==proofs['metadata']and len(qs)==len(proofs['proofs']);files=0
 for (name,q),row in zip(qs,proofs['proofs'],strict=True):
  assert name==row['name'];s=z3.Solver();s.set(timeout=30000);s.add(q);assert s.check()==z3.unsat,(name,s.reason_unknown())
  for field,hashkey in [('file','sha256'),('original_file','original_sha256')]:
   p=ROOT/row[field];assert sha(p)==row[hashkey];s=z3.Solver();s.set(timeout=30000);s.add(z3.parse_smt2_file(str(p)));assert s.check()==z3.unsat,(name,field,s.reason_unknown());files+=1
 rows=[];totals=Counter();modes=Counter();markers=0;audit=0;queries=0
 for j,profile in enumerate(profiles['cases']):
  mode=profile['configuration']['API_model_mode'];modes[mode]+=1;assert profile['fixture_PC_transitions']==0
  for read in profile['source_reads']:
   if'known_mask_hex'in read:assert all(bytes.fromhex(read['known_mask_hex']))
  replay=Fresh(profile,(j+1)%4);row=replay.run();assert row['all_checks_pass'];totals.update(row['verified_counts']);rows.append(row)
  if mode in ['string_null','task_null']:
   R=int(profile['record_address'],16);assert profile['boundary']['kind']=='returned_to_original_caller'and bytes(replay.u.mem_read(R+8,1))==b'\x5b'and bytes(replay.u.mem_read(0x6800051f2f,1))==b'\0';markers+=1
  for model in profile['API_model_events']:
   if'audit_argument'in model:assert model['audit_argument']['bytes_hex']==model['original_token']['bytes_hex']and all(bytes.fromhex(model['audit_argument']['known_mask_hex']));audit+=1
  if mode=='task_nonnull':
   assert profile['boundary']['detail']['symbol']=='Security/_SecTaskCopyValueForEntitlement';assert replay.reg('x0')==0x680000a000 and replay.reg('x1')==0x6800009000 and replay.reg('x2')==0x680004f1c0;assert bytes(replay.u.mem_read(replay.reg('x2'),8))==bytes(8);queries+=1
  print(mode,profile['source_index'],'fresh A64 pass',flush=True)
 assert modes==Counter({m:4 for m in ['strict','allocator_words','string_null','string_nonnull','task_null','task_nonnull']})and markers==8 and audit==8 and queries==4
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['daemon_record40_consumer_profiles.json','daemon_record40_consumer_contracts.json','daemon_record40_consumer_proofs.json','probe_daemon_record40_consumer.py','recover_daemon_record40_consumer.py','prove_daemon_record40_consumer.py','daemon_record40_consumer_sdk.c','daemon_record40_consumer_sdk.ll','replay_daemon_descriptor_producers.py']},'verified_counts':{'source_obligations_rebuilt':len(qs),'accepted_SMT_files':files,'profile_cases':len(rows),'profile_modes':len(modes),'known_key_bytes':30,'audit_token_bits':256,'audit_token_argument_instances':audit,'conditional_marker_returns':markers,'entitlement_query_frontiers':queries,'source_bank_byte_inputs':1024,'unique_visited_source_instructions':len(contract['unique_visited_source']),'SDK_compile_exit':0},'independent_A64_totals':dict(totals),'fresh_replay_cases':rows,'mode_counts':dict(modes),'native_framework_calls_executed':False,'native_entitlement_value_observed':False,'native_authorization_outcome_established':False,'hardware_PAC_executed':False,'idb_mutated':False,'new_port_emission_established':False,'full_goal_complete':False,'all_checks_pass':True};(ROOT/'daemon_record40_consumer_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':out['verified_counts'],'A64_totals':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
