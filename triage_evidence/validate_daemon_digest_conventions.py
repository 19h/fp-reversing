#!/usr/bin/env python3
"""Audit paired conventions with rebuilt proofs, fresh A64 and frozen journals.
O(source+retained visits/effects+new visits/effects+solver resources) time.
Space includes loaded artifact bytes, the largest decoded retained journal,
one private map and solver expressions. Native continuity unknown.
"""
import json
from pathlib import Path
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,TABLE
from recover_daemon_object_creation import sha,span
from recover_daemon_descriptor_producers import verify_used_fixups
from recover_daemon_cache36 import ida_matches
from recover_daemon_digest_conventions import retained_audit
from replay_daemon_descriptor_producers import unpack
from validate_daemon_object_clock import checked,logical_read,unsat
from prove_daemon_digest_conventions import obligations
from probe_daemon_digest_conventions import execute,cases,P
MASK=(1<<64)-1
def main():
 c=checked('daemon_digest_conventions_contracts.json','recover_daemon_digest_conventions.py');p=checked('daemon_digest_conventions_proofs.json','prove_daemon_digest_conventions.py');r=checked('daemon_digest_conventions_profiles.json','probe_daemon_digest_conventions.py');counts=Counter();totals=Counter();assert c['source_sha256']==r['source_sha256']==sha(SOURCE)
 for s in c['spans']:assert span(s['label'],int(s['start'],16),int(s['end'],16))==s;counts['original_source_spans']+=1
 assert verify_used_fixups([int(x['address'],16)for x in c['original_fixups']['records']])==c['original_fixups'];counts['original_fixups_checked']=len(c['original_fixups']['records']);live=ida_matches('daemon_digest_conventions_ida_bytes.json');assert live==c['live_IDB_matches'];counts['live_IDB_ranges']=len(live);counts['live_IDB_bytes']=sum(x['size_bytes']for x in live)
 b=c['post_finalize_malloc_bank256'];left=IMAGE.read(int(b['left'],16),256);right=IMAGE.read(int(b['right'],16),256);assert {j^right[left[j]^int(b['key'],16)]for j in range(256)}=={int(b['constant'],16)}and b['target']=='libSystem/_malloc';counts['exhaustive_allocator_bank_inputs']=256
 qs,lifts=obligations(c);assert lifts==p['source_lift_counts']
 for (name,pred),proof in zip(qs,p['proofs'],strict=True):
  assert name==proof['name'];unsat(pred);counts['rebuilt_source_obligations_unsat']+=1
  for fk,hk in [('file','sha256'),('original_file','original_sha256')]:
   f=ROOT/proof[fk];assert sha(f)==proof[hk];forms=z3.parse_smt2_file(str(f));assert len(forms)==1;unsat(forms[0]);unsat(z3.Xor(forms[0],pred));counts['SMT_files_unsat_and_formula_matched']+=1
 counts['source_lift_visits']=sum(lifts.values());assert [x['configuration']for x in r['cases']]==list(cases())and len(r['cases'])==377
 for row in r['cases']:
  cfg=row['configuration'];kind=cfg['kind'];F=int(row['SP'],16);C=int(row['context'],16);O=int(row['output'],16);I=int(row['input'],16);data={int(g['address'],16)+j:x for g in row['initial_fixtures']for j,x in enumerate(bytes.fromhex(g['bytes_hex']))};final=[int(v,16)for v in row['final_registers31']]
  def read(a,n):return bytes(data[a+j]for j in range(n))
  def word(a,n=8):return int.from_bytes(read(a,n),'little')
  for pc,raw in row['steps']:assert IMAGE.read(pc,4).hex()==raw
  for e in row['events']:
   a=int(e['address'],16);n=e['size_bytes'];raw=bytes.fromhex(e['bytes_hex']if e['kind']=='read'else e['after_hex']);assert len(raw)==n
   if e['kind']=='read':assert raw==(read(a,n)if P<=a<P+0x100000 else logical_read(a,n));counts['ordered_source_reads_checked']+=1
   else:assert P<=a<a+n<=P+0x100000;data.update({a+j:x for j,x in enumerate(raw)});counts['ordered_source_writes_checked']+=1
  if kind=='encoded_update':
   S=(cfg['N32']+(cfg['H32']&63))&0xffffffff;ret=int.from_bytes(logical_read(TABLE+cfg['return_index']*8,8),'little');assert final[12]==(0x995b if S>=64 else 0x9930)and final[9]==0x471c and word(F+0x2ea8)==ret and word(F+0x2bf8)==C and word(F+0x31dc,4)==(cfg['N32']+0x1ad72f12)&0xffffffff and word(F+0x2f50)==I;counts['encoded_update_fragments_checked']+=1
  elif kind in ['wrapped_pad','inline_pad']:
   offset=cfg['H32']&63;assert word(C+offset,1)==0x18
   if kind=='wrapped_pad':assert final[13]==offset+1 and final[8]==(0xbfc2 if offset>55 else 0x3b);counts['wrapped_padding_fragments_checked']+=1
   else:assert final[12]==offset+1 and final[15]==0x471c and final[8]==(0xbe37 if offset>55 else 0x18)and word(F+0x2f40)==C and word(F+0x2fe0)==O;counts['inline_padding_fragments_checked']+=1
  elif kind=='wrapped_finalize':
   out=O if cfg['output_present']else 0;ret=int.from_bytes(logical_read(TABLE+cfg['return_index']*8,8),'little');assert final[10]==(0xc567 if out else 0xc554)and word(F+0x3590)==ret and word(F+0x2df0)==C and word(F+0x3418)==out;counts['wrapped_finalize_entries_checked']+=1
  elif kind=='new_finalize_caller':assert final[10]==F+0x3388 and final[11]==F+0x31c8 and final[9]==0x9c and final[8]==0x100c03b20;counts['new_context_finalize_callers_checked']+=1
  elif kind=='saved_finalize_caller':assert final[10]==F+0x30b8 and final[11]==F+0x3678 and final[9]==0x9b and final[8]==0x100c03b20;counts['saved_context_finalize_callers_checked']+=1
  elif kind=='fixed20_caller':assert final[21]==I+0x238 and final[4]==C and final[5]==0x1ad72f26 and final[19]==0x9930 and final[20]==0xb5d and final[8]==0x100a0aad0;counts['fixed20_update_callers_checked']+=1
  elif kind=='identity_reserve':assert word(F+0x3610)==C and word(F+0x31a8)==F+0x39f0+cfg['cursor']and word(F+0x3620)==cfg['cursor']+32 and word(F+0x32e8)==I;counts['identity_output_reservations_checked']+=1
  elif kind=='post_finalize':
   a=I if cfg['A_present']else 0;b=17 if cfg['B_present']else 0;out=O if cfg['output_present']else 0;assert final[8]==(0x3c2d if a and b and out else 0x3bff)and word(F+0x37e8)==(a+0x2bef09d10e3bdd6e)&MASK and word(F+0x3810)==(a+0x63604e5d3cff75db)&MASK and word(F+0x37f8)==b and word(F+0x37f0)==b and word(F+0x3800)==out;counts['post_finalize_three_value_gates_checked']+=1
  else:assert kind=='malloc_arg'and final[0]==1028 and final[17]==0x6aa4;counts['malloc1028_argument_fragments_checked']+=1
  assert json.loads(json.dumps(execute(cfg)))==row;counts['persisted_A64_cases']+=1;counts['freshly_recomputed_A64_cases']+=1;counts['source_visits_checked']+=row['source_visits'];totals.update({'source_visits':row['source_visits'],'read_effects':sum(e['kind']=='read'for e in row['events']),'write_effects':sum(e['kind']=='write'for e in row['events'])})
 assert totals==Counter(source_visits=8326,read_effects=516,write_effects=972);audited,rc=retained_audit();assert audited==c['retained_identity_cases']and rc==c['retained_counts'];old=json.loads((ROOT/'daemon_identity_cache_profiles.json').read_text())
 for saved in audited:
  row=old['cases'][saved['case_index']];t=unpack(row);F=int(saved['SP'],16);C=int(saved['context'],16);H=int(saved['global_cache_owner'],16)
  strlen=next(m for m in t['API_models']if m['binding']['symbol']=='_strlen');N=int(strlen['returned_X0'],16);input_pointer=int(strlen['arguments1'][0],16)
  writes=[e for e in t['events']if e['kind']=='write'];capture_pcs=['0x100a0aae8','0x100a0ab24','0x100a0ab28','0x100a0ab2c'];captured=[e for e in writes if e['pc']in capture_pcs];typed={e['pc']:e for e in captured}
  assert len(captured)==len(typed)==4
  assert int.from_bytes(bytes.fromhex(typed['0x100a0aae8']['after_hex']),'little')==0x100baff6c
  assert int.from_bytes(bytes.fromhex(typed['0x100a0ab24']['after_hex']),'little')==C
  assert int.from_bytes(bytes.fromhex(typed['0x100a0ab28']['after_hex']),'little')==((N+0x1ad72f12)&0xffffffff)
  assert int.from_bytes(bytes.fromhex(typed['0x100a0ab2c']['after_hex']),'little')==input_pointer
  edge=next(e for e in t['edges']if e['pc']=='0x100a0ab3c');assert edge['slot']==hex(TABLE+8*(0x995b if N>=64 else 0x9930))
  def overlaps(event,base,size):
   start=int(event['address'],16);end=start+event['size_bytes'];assert start<=end<=(1<<64)
   return start<base+size and base<end
  assert not any(overlaps(e,H,36)for e in writes)
  if saved['inline_finalize_seen']:
   out=int(saved['reserved_output'],16);assert out-C==0x70 and (out+32<=H or H+36<=out)and not any(overlaps(e,out,32)for e in writes);counts['retained_distinct_output_cache_owners_checked']+=1
  counts['retained_encoded_call_frame_captures_checked']+=1
 counts.update({f'retained_{n}':x for n,x in rc.items()});deps=['daemon_digest_conventions_contracts.json','daemon_digest_conventions_proofs.json','daemon_digest_conventions_profiles.json','prove_daemon_digest_conventions.py','probe_daemon_digest_conventions.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'verified_counts':dict(counts),'independent_A64_totals':dict(totals),'source_lift_counts':lifts,'all_checks_pass':True,'new_port_emission_established':False,'completed_digest_or_cache_content_established':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_digest_conventions_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts)}),flush=True)
if __name__=='__main__':main()
