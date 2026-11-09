#!/usr/bin/env python3
"""Rebuild certified local source proofs and independently audit complete cores.
O(all visits/effects+source+solver resources) time; space includes compressed
artifacts, one decoded/fresh journal, one private map and solver expressions.
"""
import json,hashlib,struct
from pathlib import Path
from collections import Counter
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,TABLE
from recover_daemon_object_creation import sha,span
from recover_daemon_cache36 import ida_matches
from recover_daemon_descriptor_producers import verify_used_fixups
from replay_daemon_descriptor_producers import unpack
from validate_daemon_object_clock import checked,logical_read
from daemon_sha1_core_model import reference,IV,pad,STATE_XOR,WORD_XOR,ROUND_MAPS,ROUND_STARTS,ROUND_ENDS
from recover_daemon_sha1_core import helper_abis,OUTPUT_MAPS,key
from prove_daemon_sha1_core import obligations,generalized
from probe_daemon_sha1_core import execute,cases
def norm(x):return z3.simplify(x,bv_sort_ac=True)
def main():
 c=checked('daemon_sha1_core_contracts.json','recover_daemon_sha1_core.py');p=checked('daemon_sha1_core_proofs.json','prove_daemon_sha1_core.py');r=checked('daemon_sha1_core_profiles.json','probe_daemon_sha1_core.py');counts=Counter();totals=Counter();assert c['source_sha256']==r['source_sha256']==sha(SOURCE)
 for s in c['spans']:assert span(s['label'],int(s['start'],16),int(s['end'],16))==s;counts['original_source_spans']+=1
 for a,b in c['source_pool'].items():assert IMAGE.read(int(a,16),4).hex()==b;counts['unique_original_instructions']+=1
 assert verify_used_fixups([int(x['address'],16)for x in c['original_fixups']['records']])==c['original_fixups'];counts['original_fixups_checked']=len(c['original_fixups']['records']);live=ida_matches('daemon_sha1_core_ida_bytes.json');assert live==c['live_IDB_matches'];counts['live_IDB_ranges']=len(live);counts['live_IDB_bytes']=sum(x['size_bytes']for x in live)
 qs,lifts,details=obligations(c);assert lifts==p['source_lift_counts']and details==p['proof_scope']
 for (name,pred),proof in zip(qs,p['proofs'],strict=True):
  assert name==proof['name'];g,cert=generalized(name,pred);assert cert==proof['certificate'];orig=ROOT/proof['original_file'];simp=ROOT/proof['file'];assert sha(orig)==proof['original_sha256']and sha(simp)==proof['sha256'];a=z3.parse_smt2_file(str(orig));b=z3.parse_smt2_file(str(simp));assert len(a)==len(b)==1 and z3.eq(norm(a[0]),norm(pred))and z3.eq(norm(b[0]),norm(g));s=z3.Solver();s.set(timeout=30000);s.add(b[0]);assert str(s.check())=='unsat',name;counts['certified_source_obligations_rebuilt_unsat']+=1;counts['original_normalized_SMT_artifacts_matched']+=2
  if '_certified_rewrite_'in name:counts['certified_source_register_rewrites']+=1
 for abi in c['helper_ABIs'].values():
  lo,hi=abi['counter_domain'];s=z3.Solver();j=z3.BitVec('sha1_helper_index32',32);s.add(z3.UGE(j,lo),z3.ULE(j,hi));assert str(s.check())=='sat';counts['nonempty_helper_index_domains']+=1
 counts['source_lift_visits']=sum(lifts.values());assert [x['configuration']for x in r['cases']]==list(cases())and len(r['cases'])==48;cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;instructions={int(a,16):next(cs.disasm(bytes.fromhex(b),int(a,16)))for a,b in c['source_pool'].items()}
 for row in r['cases']:
  t=unpack(row);cfg=row['configuration'];assert t['configuration']==cfg and t['source_pool']==c['source_pool'];F=int(t['SP'],16);C=int(t['context'],16);B=int(t['workspace'],16);assert B==F+0x39f0+cfg['cursor64'];assert helper_abis(t)==c['helper_ABIs'];counts['helper_ABI_configurations_checked']+=6
  expected_entry={'sp':hex(F),'x8':'0x471c','x15':'0x471c','x4':hex(C),'x12':hex(C),'x20':hex(cfg['return_index']),'x30':hex(TABLE)};assert t['entry_defined_GPRs']==expected_entry;known={key(n)for n in expected_entry};assert len(known)==7
  for pc,raw in t['steps']:
   i=instructions[pc];assert bytes(i.bytes).hex()==raw;reads,writes=i.regs_access();assert all(cs.reg_name(a)in ['wzr','xzr']or key(cs.reg_name(a))in known for a in reads),(hex(pc),i.mnemonic,i.op_str);known.update(key(cs.reg_name(a))for a in writes);counts['GPR_defined_source_visits_checked']+=1
  data={int(f['address'],16)+j:x for f in t['initial_fixtures']for j,x in enumerate(bytes.fromhex(f['bytes_hex']))};before=bytes(data[C+j]for j in range(100));assert before.hex()==t['context_before'];writes=[]
  for e in t['events']:
   a=e['address'];n=e['size'];raw=bytes.fromhex(e['hex']if e['kind']=='read'else e['after_hex']);assert e['pc']in instructions and len(raw)==n
   if e['kind']=='read':assert raw==(bytes(data[a+j]for j in range(n))if 0x6b00000000<=a<0x6b00100000 else logical_read(a,n));counts['ordered_reads_checked']+=1
   else:assert 0x6b00000000<=a<a+n<=0x6b00100000;data.update({a+j:x for j,x in enumerate(raw)});writes.append(e);counts['ordered_writes_checked']+=1
  for pc,target,slot,modifier in t['edges']:
   fix=FIXUPS[slot];assert instructions[pc].mnemonic=='braa'and fix['target']==target and f'div=0x{modifier:04X} 'in fix['annotation'];counts['modeled_BRAA_edges_checked']+=1
  m=reference(bytes.fromhex(cfg['block_hex']),cfg['initial_state5']);schedule_writes=[e for e in writes if B<=e['address']<B+320];assert len(schedule_writes)==80 and [e['address']for e in schedule_writes]==list(range(B,B+320,4))
  for j,e in enumerate(schedule_writes):assert e['size']==4 and (int.from_bytes(bytes.fromhex(e['after_hex']),'little')^WORD_XOR)==m['schedule80'][j];counts['encoded_schedule_words_checked']+=1
  assert len(t['round_entries'])==81 and len(t['round_exits'])==80
  for j,shot in enumerate(t['round_entries'][:-1]):
   assert int(shot['pc'],16)==ROUND_STARTS[j//20];assert [shot['registers31'][rr]^STATE_XOR for rr in ROUND_MAPS[j//20]]==m['working_states81'][j];counts['round_entry_states_checked']+=1
  for j,shot in enumerate(t['round_exits']):
   assert int(shot['pc'],16)==ROUND_ENDS[j//20]
   for word,regs in enumerate(OUTPUT_MAPS[j//20]):
    for rr in regs:assert shot['registers31'][rr]==(m['working_states81'][j+1][word]^STATE_XOR)
   counts['round_exit_states_checked']+=1
  expected=bytearray(before)
  for j,v in enumerate(m['final_state5']):struct.pack_into('<I',expected,0x48+4*j,v^STATE_XOR)
  assert bytes(data[C+j]for j in range(100))==bytes(expected)==bytes.fromhex(t['context_after']);assert t['decoded_state20']==b''.join(x.to_bytes(4,'big')for x in m['final_state5']).hex();assert len([e for e in writes if C<=e['address']<C+100])==5;counts['complete_encoded_context_results_checked']+=1
  if cfg['kind']=='padded_message':assert t['decoded_state20']==hashlib.sha1(bytes.fromhex(cfg['message_hex'])).hexdigest();counts['hashlib_message_oracles_checked']+=1
  elif cfg['initial_state5']==IV:
   tail=reference(pad(bytes.fromhex(cfg['block_hex']))[64:],m['final_state5']);assert b''.join(x.to_bytes(4,'big')for x in tail['final_state5']).hex()==hashlib.sha1(bytes.fromhex(cfg['block_hex'])).hexdigest();counts['hashlib_model_tail_oracles_checked']+=1
  assert t['boundary']=={'pc':'0x100bdfaf0','kind':'before_return_epilogue','detail':{}};assert json.loads(json.dumps(execute(cfg)))==t;counts['freshly_recomputed_core_cases']+=1;totals.update({'source_visits':len(t['steps']),'modeled_BRAA_visits':len(t['edges']),'A64_executed_instructions':len(t['steps'])-len(t['edges']),'read_effects':sum(e['kind']=='read'for e in t['events']),'write_effects':len(writes)})
 assert totals==Counter(source_visits=783984,modeled_BRAA_visits=7968,A64_executed_instructions=776016,read_effects=28224,write_effects=5040);deps=['daemon_sha1_core_contracts.json','daemon_sha1_core_proofs.json','daemon_sha1_core_profiles.json','daemon_sha1_core_model.py','daemon_sha1_core_rewrite_plan.json','prove_daemon_sha1_core.py','probe_daemon_sha1_core.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'verified_counts':dict(counts),'independent_A64_totals':dict(totals),'source_lift_counts':lifts,'all_checks_pass':True,'new_port_emission_established':False,'identity_digest_or_cache_publication_established':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_sha1_core_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'counts':dict(counts),'totals':dict(totals)}),flush=True)
if __name__=='__main__':main()
