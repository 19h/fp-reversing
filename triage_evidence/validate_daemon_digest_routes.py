#!/usr/bin/env python3
"""Audit route cubes, source proofs and every isolated A64 byte/effect.
O(source+census inputs+cases*(visits+effects)+solver resources) time,
O(largest case+source spans) space. Native caller feasibility remains unknown.
"""
import json,struct
from pathlib import Path
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,TABLE
from recover_daemon_object_creation import sha,span
from recover_daemon_creation_predecessors import literal_pairs
from recover_daemon_descriptor_producers import verify_used_fixups
from recover_daemon_cache36 import ida_matches
from validate_daemon_object_clock import checked,logical_read,unsat
from prove_daemon_digest_routes import obligations
from probe_daemon_digest_routes import execute,cases,P
from replay_daemon_descriptor_producers import unpack
from recover_daemon_digest_routes import continuation_slots,continuation_census,phase_biases
def main():
 c=checked('daemon_digest_routes_contracts.json','recover_daemon_digest_routes.py');p=checked('daemon_digest_routes_proofs.json','prove_daemon_digest_routes.py');r=checked('daemon_digest_routes_profiles.json','probe_daemon_digest_routes.py');counts=Counter();totals=Counter();assert c['source_sha256']==r['source_sha256']==sha(SOURCE)
 for s in c['spans']:assert span(s['label'],int(s['start'],16),int(s['end'],16))==s;counts['original_source_spans']+=1
 assert literal_pairs(0xa86e)==c['literal_A86E_census'];counts['literal_modifier_candidates']=6
 assert verify_used_fixups([int(c['entry_slot'],16)])==c['entry_FIXUP'];assert c['entry_slot']=='0x101071540'and c['entry_table_index']=='0x6eca'and c['entry']=='0x100aee3a4';counts['entry_fixups_checked']=1
 assert verify_used_fixups([0x101071560])==c['observed_other_slot_FIXUP'];old=json.loads((ROOT/'daemon_object_clock_profiles.json').read_text());observed=[]
 for j,row in enumerate(old['cases']):
  for e in unpack(row)['edges']:
   if e['pc']=='0x100208f08':assert e['target']=='0x1002a78b8'and e['slot']=='0x101071560';observed.append({'clock_case_index':j,'edge':e})
 assert observed==c['retained_after_unlock_edges']and len(observed)==48;counts['retained_alternate_target_edges_checked']=48
 slots=continuation_slots();assert slots==c['original_IA7315_continuation_slots']and continuation_census()==c['direct_SP2F48_census']and phase_biases(slots)==c['continuation_phase_biases'];counts['original_continuation_slots_checked']=len(slots);counts['continuation_phase_low6_inputs_checked']=7*64;assert [x['phase32']for x in c['continuation_phase_biases']if x['all_64_low6_values_have_raw_count']]==['0x32b','0x371'];counts['raw_count_compatible_modes_checked']=2
 for x in c['continuation_FIXUPS']['records']:assert verify_used_fixups([int(x['address'],16)])['records'][0]==x
 counts['continuation_and_branch_fixups_checked']=len(c['continuation_FIXUPS']['records'])
 live=ida_matches('daemon_digest_routes_ida_bytes.json')+ida_matches('daemon_digest_routes_ida_return.json');assert live==c['live_IDB_matches'];counts['live_IDB_ranges']=len(live);counts['live_IDB_bytes']=sum(x['size_bytes']for x in live)
 for name,fn,mask,value,accepted in [('new_context',lambda v:(v^0xc58)^((v+0x5e8e)&0xffffffff),0x6292,0x202,1024),('existing_context',lambda v:((v+0x6a4a)&0xffffffff)^v,0x6eca,0x240,128)]:
  actual=0
  for x in range(65536):assert (fn(x)==0x6eca)==(x&mask==value);actual+=fn(x)==0x6eca
  assert actual==accepted==c['compact_routing_cubes'][name]['accepted_low16_inputs'];counts['exhaustive_low16_inputs']+=65536
 qs,lifts,details=obligations(c);assert lifts==p['source_lift_counts']and details==p['compact_routes']
 for (name,pred),proof in zip(qs,p['proofs'],strict=True):
  assert name==proof['name'];unsat(pred);counts['rebuilt_source_obligations_unsat']+=1
  for fk,hk in [('file','sha256'),('original_file','original_sha256')]:
   f=ROOT/proof[fk];assert sha(f)==proof[hk];forms=z3.parse_smt2_file(str(f));assert len(forms)==1;unsat(forms[0]);unsat(z3.Xor(forms[0],pred));counts['SMT_files_unsat_and_formula_matched']+=1
 counts['source_lift_visits']=sum(lifts.values());assert [x['configuration']for x in r['cases']]==list(cases());assert len(r['cases'])==128
 for row in r['cases']:
  cfg=row['configuration'];F=int(row['SP'],16);data={int(g['address'],16)+j:x for g in row['initial_fixtures']for j,x in enumerate(bytes.fromhex(g['bytes_hex']))};kind=cfg['kind'];phase=cfg['phase32'];initial=[int(x,16)for x in row['entry_registers31']];final=[int(x,16)for x in row['final_registers31']]
  def read(a,n):return bytes(data[a+j]for j in range(n))
  for pc,raw in row['steps']:assert IMAGE.read(pc,4).hex()==raw
  for e in row['events']:
   a=int(e['address'],16);n=e['size_bytes'];b=bytes.fromhex(e['bytes_hex']if e['kind']=='read'else e['after_hex']);assert len(b)==n
   if e['kind']=='read':
    expected=read(a,n)if P<=a<P+0x100000 else logical_read(a,n);assert b==expected;counts['ordered_source_reads_checked']+=1
   else:
    assert P<=a<a+n<=P+0x100000;data.update({a+j:x for j,x in enumerate(b)});counts['ordered_source_writes_checked']+=1
  if kind=='new_context':
   cursor=row['cursor_input'];ctx=F+0x39f0+cursor;assert final[8]==P+0x18000 and final[2]==cfg['word32']and final[4]==ctx and final[11]==((phase^0xc58)^((phase+0x5e8e)&0xffffffff));assert read(F+0x31c8,8)==(ctx+100).to_bytes(8,'little')and read(F+0x3388,8)==ctx.to_bytes(8,'little')and read(F+0x3620,8)==(cursor+128).to_bytes(8,'little');assert read(F+0x3648,8)==(0x1122334455667788).to_bytes(8,'little')and read(F+0x35a8,8)==(0x8877665544332211).to_bytes(8,'little');assert read(ctx+0x40,8)==bytes(8);assert list(struct.unpack('<5I',read(ctx+0x48,20)))==[0x93bc0ef6,0x1b34867e,0x6c43f109,0xe4cb7981,0x372bcc07];assert read(ctx+0x5c,8)==struct.pack('<II',20,2);assert not any(ctx<=int(e['address'],16)<ctx+64 for e in row['events']if e['kind']=='write');counts['new_context_field_layouts_checked']+=1
  elif kind=='existing_prefix':assert final[12]==((phase+0x5e48)&0xffffffff)and final[10]==cfg['word32'];counts['existing_prefix_fragments_checked']+=1
  elif kind=='existing_route':assert final[11]==(((phase+0x6a4a)&0xffffffff)^phase);counts['existing_route_fragments_checked']+=1
  elif kind=='existing_args':assert final[26]==0x101031fa0 and final[4]==P+0x20000 and final[2]==cfg['word32'];counts['existing_argument_fragments_checked']+=1
  elif kind=='saved_continuation':assert final[8]==0x1234567800000000|phase and final[17]==0x7315;counts['saved_continuation_fragments_checked']+=1
  else:
   assert kind=='callee_capture';signed=phase-(1<<32)if phase>>31 else phase;slot=TABLE+signed*8;assert row['original_table_slot']==hex(slot)and read(F+0x2f48,8)==logical_read(slot,8);assert read(F+0x2b88,8)==initial[4].to_bytes(8,'little')and read(F+0x2c8c,4)==(initial[2]&0xffffffff).to_bytes(4,'little')and read(F+0x3490,8)==initial[8].to_bytes(8,'little');counts['callee_frame_captures_checked']+=1;counts['negative_signed_index_cases_checked']+=signed<0
  assert json.loads(json.dumps(execute(cfg)))==row;counts['freshly_recomputed_A64_cases']+=1;counts['persisted_A64_cases']+=1;counts['source_visits_checked']+=row['source_visits'];totals.update({'source_visits':row['source_visits'],'read_effects':sum(e['kind']=='read'for e in row['events']),'write_effects':sum(e['kind']=='write'for e in row['events'])})
 assert totals==Counter(source_visits=2080,read_effects=400,write_effects=544);deps=['daemon_digest_routes_contracts.json','daemon_digest_routes_proofs.json','daemon_digest_routes_profiles.json','prove_daemon_digest_routes.py','probe_daemon_digest_routes.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'verified_counts':dict(counts),'independent_A64_totals':dict(totals),'source_lift_counts':lifts,'all_checks_pass':True,'native_caller_established':False,'new_port_emission_established':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_digest_routes_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts)}),flush=True)
if __name__=='__main__':main()
