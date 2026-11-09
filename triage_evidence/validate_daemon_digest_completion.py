#!/usr/bin/env python3
"""Independently check completion byte/GPR ledgers, source proofs and inputs.
O(source+new visits/effects+retained effects+solver resources) time;
O(compressed artifacts+largest decoded/fresh journal+map+SMT DAG) space.
"""
import json,hashlib,struct
from pathlib import Path
from collections import Counter
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from recover_daemon_object_creation import sha,span
from recover_daemon_descriptor_producers import verify_used_fixups
from recover_daemon_cache36 import ida_matches
from replay_daemon_descriptor_producers import unpack
from validate_daemon_object_clock import checked,logical_read
from daemon_digest_output_access import register_access,key
from daemon_digest_completion_model import pattern,overwrite_byte,seed,SAVED
from daemon_digest_completion_inputs import retained
from recover_daemon_digest_completion import census
from prove_daemon_digest_completion import obligations
from probe_daemon_digest_completion import execute,configurations
def norm(x):return z3.simplify(x,bv_sort_ac=True)
def trace(t,counts,instructions):
 cfg=t['configuration'];kind=cfg['kind'];F=int(t['SP'],16);C=int(t['context'],16);O=int(t['output'],16);D=int(t['destination'],16);Flag=int(t['completion_flag_address'],16)
 known={key(n)for n in t['entry_defined_GPRs']}
 if kind=='completion':assert set(t['entry_defined_GPRs'])=={'sp','x30','w27','w11','w2','x8','w9','x13'}and int(t['entry_defined_GPRs']['x13'],16)==seed(F)
 for pc,raw in t['steps']:
  if pc not in instructions:
   cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;instructions[pc]=next(cs.disasm(IMAGE.read(pc,4),pc))
  i=instructions[pc];assert bytes(i.bytes).hex()==raw;reads,writes=register_access(i);assert all(i.reg_name(r)in ['wzr','xzr']or key(i.reg_name(r))in known for r in reads),(hex(pc),i.mnemonic);known.update(key(i.reg_name(r))for r in writes);counts[kind+'_defined_source_visits']+=1
 data={int(f['address'],16)+j:b for f in t['initial_fixtures']for j,b in enumerate(bytes.fromhex(f['bytes_hex']))};context_writes=[];destination_writes=[];flag_writes=[];read_footprint=set()
 if kind=='completion':assert t['context_input_mask100']==[False]*92+[True]*8
 for e in t['events']:
  a=e['address'];n=e['size'];b=bytes.fromhex(e['hex']if e['kind']=='read'else e['after_hex']);assert len(b)==n
  if e['kind']=='read':
   private=0x6b00000000<=a<a+n<=0x6b00100000
   assert b==(bytes(data[a+j]for j in range(n))if private or all(a+j in data for j in range(n))else logical_read(a,n))
   if C<=a<C+100:assert a==C+92 and n==4;read_footprint.update(range(a,a+n))
   counts[kind+'_ordered_reads']+=1
  else:
   assert (a==F+0x2ba0 and n==8)or(C<=a<a+n<=C+92 and n==1)or(kind=='completion'and((D<=a<a+n<=D+cfg['output_size']and n==1)or(a==Flag and n==1)or(a==F+0x3620 and n==8))),e
   data.update({a+j:v for j,v in enumerate(b)});counts[kind+'_ordered_writes']+=1
   if C<=a<C+92:context_writes.append(e)
   if D<=a<D+64:destination_writes.append(e)
   if a==Flag:flag_writes.append(e)
 for pc,target,slot,modifier in t['edges']:
  r=FIXUPS[slot];assert r['target']==target and f'div=0x{modifier:04X} 'in r['annotation'];counts[kind+'_modeled_BRAA_edges']+=1
 if kind=='completion':
  n=cfg['output_size'];expected=bytes(x^0x98 for x in bytes.fromhex(cfg['encoded_output_hex']));assert len(expected)==n
  assert bytes.fromhex(t['context_after'])[:92]==pattern(F);assert t['context_defined_mask100']==[True]*100
  assert bytes(data[C+j]for j in range(92))==pattern(F);assert bytes.fromhex(t['context_after'])[92:]==struct.pack('<II',n,cfg['selector'])
  assert [e['address']for e in context_writes]==list(range(C+91,C-1,-1));assert len(context_writes)==92
  assert bytes.fromhex(t['destination_hex64'])[:n]==expected;assert t['destination_defined_mask64']==[True]*n+[False]*(64-n)
  assert [e['address']for e in destination_writes]==list(range(D+n-1,D-1,-1))
  assert bytes(data[D+j]for j in range(n))==expected;assert len(flag_writes)==1 and flag_writes[0]['pc']==0x100a53644
  assert t['completion_flag_defined']and t['completion_flag_byte']=='01'and data[Flag]==1
  assert int.from_bytes(bytes(data[F+0x3620+j]for j in range(8)),'little')==cfg['cursor64']-32==0x2f0
  assert t['boundary']=={'pc':'0x100b687f4','kind':'before_unknown_saved_owner','detail':{'address':hex(F+0x3650),'size_bytes':8}}
  assert t['output_defined_mask32']==[True]*n+[False]*(32-n)and bytes.fromhex(t['output_hex32'])[:n]==bytes.fromhex(cfg['encoded_output_hex'])
  assert read_footprint==set(range(C+92,C+96));counts['complete_context_overwrites']+=1;counts['decoded_destination_bytes']+=n;counts['completion_byte_stores']+=1
  if 'message_hex'in cfg:assert expected==hashlib.sha1(bytes.fromhex(cfg['message_hex'])).digest();counts['conditional_canonical_SHA1_matches']+=1
 else:
  n=cfg['count64'];s=cfg['seed64'];assert len(context_writes)==1 and context_writes[0]['address']==C+n-1;assert data[C+n-1]==overwrite_byte(s)
  assert t['context_defined_mask100']==[j==n-1 for j in range(100)]and not destination_writes and not flag_writes and not read_footprint
  assert int(t['registers']['x11'],16)==(s+1)&((1<<64)-1)and int(t['registers']['x1'],16)==n-1
  want=0x100abd000 if n==1 else 0x100a1bf1c;assert t['boundary']=={'pc':hex(want),'kind':'after_one_source_iteration','detail':{'target':hex(want)}};counts['single_overwrite_iterations']+=1
def main():
 c=checked('daemon_digest_completion_contracts.json','recover_daemon_digest_completion.py');p=checked('daemon_digest_completion_proofs.json','prove_daemon_digest_completion.py');r=checked('daemon_digest_completion_profiles.json','probe_daemon_digest_completion.py');counts=Counter();assert c['source_sha256']==r['source_sha256']==sha(SOURCE)
 for s in c['spans']:assert span(s['label'],int(s['start'],16),int(s['end'],16))==s;counts['original_source_spans']+=1
 for a,b in c['source_pool'].items():assert IMAGE.read(int(a,16),4).hex()==b;counts['unique_observed_instructions']+=1
 assert verify_used_fixups([int(x['address'],16)for x in c['original_fixups']['records']])==c['original_fixups'];counts['original_fixups_checked']=len(c['original_fixups']['records'])
 live=ida_matches('daemon_digest_completion_ida_bytes.json');assert live==c['live_IDB_matches'];counts['live_IDB_ranges']=len(live);counts['live_IDB_bytes']=sum(x['size_bytes']for x in live)
 assert census()==c['saved_field_writer_census'];counts['bounded_scalar_writer_sites']=len(c['saved_field_writer_census']['records']);assert bytes(overwrite_byte(s)for s in range(256)).hex()==c['overwrite_byte_table256_hex'];counts['byte_function_inputs']=256
 qs,lifts=obligations(c);assert lifts==p['source_lift_counts']
 for(name,pred),proof in zip(qs,p['proofs'],strict=True):
  assert name==proof['name'];a=ROOT/proof['original_file'];b=ROOT/proof['file'];assert sha(a)==proof['original_sha256']and sha(b)==proof['sha256'];aa=z3.parse_smt2_file(str(a));bb=z3.parse_smt2_file(str(b))
  assert len(aa)==len(bb)==1 and z3.eq(norm(aa[0]),norm(pred)),name
  s=z3.Solver();s.set(timeout=30000);s.add(aa[0]!=bb[0]);assert str(s.check())=='unsat',name;counts['normalized_SMT_equivalences_unsat']+=1
  s=z3.Solver();s.set(timeout=30000);s.add(pred);assert str(s.check())=='unsat',name;counts['source_obligations_rebuilt_unsat']+=1;counts['SMT_artifacts_verified']+=2

 n=z3.BitVec('completion_remaining64',64)
 for upper in [92,0xffffffff]:
  s=z3.Solver();s.add(z3.UGE(n,1),z3.ULE(n,upper));assert str(s.check())=='sat';counts['nonempty_loop_domains']+=1
 counts['source_lift_visits']=sum(lifts.values());assert [x['configuration']for x in r['cases']]==list(configurations())and len(r['cases'])==396;instructions={}
 for row in r['cases']:
  t=unpack(row);trace(t,counts,instructions);assert json.loads(json.dumps(execute(row['configuration'])))==t;counts['cases_freshly_recomputed']+=1
 retained_rows,rc=retained();assert retained_rows==c['retained_saved_fields']and rc==c['retained_counts'];counts.update(rc)
 totals={'source_visits':sum(counts[g+'_defined_source_visits']for g in ['completion','overwrite_iteration']),'modeled_BRAA_visits':sum(counts[g+'_modeled_BRAA_edges']for g in ['completion','overwrite_iteration']),'read_effects':sum(counts[g+'_ordered_reads']for g in ['completion','overwrite_iteration']),'write_effects':sum(counts[g+'_ordered_writes']for g in ['completion','overwrite_iteration'])};totals['A64_executed_instructions']=totals['source_visits']-totals['modeled_BRAA_visits'];assert totals=={'source_visits':489164,'modeled_BRAA_visits':16144,'read_effects':32224,'write_effects':27944,'A64_executed_instructions':473020}
 deps=['daemon_digest_completion_contracts.json','daemon_digest_completion_proofs.json','daemon_digest_completion_profiles.json','daemon_digest_completion_model.py','daemon_digest_completion_inputs.py','prove_daemon_digest_completion.py','probe_daemon_digest_completion.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'verified_counts':dict(counts),'independent_A64_totals':totals,'source_lift_counts':lifts,'all_checks_pass':True,'new_port_emission_established':False,'native_cache_or_driver_link_established':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False}
 (ROOT/'daemon_digest_completion_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'counts':dict(counts),'totals':totals}),flush=True)
if __name__=='__main__':main()
