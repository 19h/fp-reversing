#!/usr/bin/env python3
"""Recompute source/metadata, solver obligations and every persisted A64 case.
O(source bytes + all replay visits + solver resources) time; O(largest JSON +
one emulator) space. Separate instruction engines are SMT lift and Unicorn.
"""
import json,hashlib,struct
from pathlib import Path
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,TABLE,FIXUPS
from recover_daemon_object_creation import sha,phases
from recover_daemon_descriptor_producers import verify_used_fixups
from prove_daemon_object_creation import obligations
from replay_daemon_object_creation import Run,cases
def checked(n,g):
 r=json.loads((ROOT/n).read_text());assert r['generator_sha256']==sha(ROOT/g)and r['full_goal_complete']is False
 for dep,h in r.get('dependencies',{}).items():assert sha(ROOT/dep)==h,(n,dep)
 return r
def main():
 c=checked('daemon_object_creation_contracts.json','recover_daemon_object_creation.py');p=checked('daemon_object_creation_proofs.json','prove_daemon_object_creation.py');r=checked('daemon_object_creation_replays.json','replay_daemon_object_creation.py');assert c['source_sha256']==r['source_sha256']==sha(SOURCE)
 for s in c['spans']:
  a,z=int(s['start'],16),int(s['end'],16);b=bytes.fromhex(s['bytes_hex']);assert b==IMAGE.read(a,z-a)and hashlib.sha256(b).hexdigest()==s['sha256'];assert len(list(CS.disasm(b,a)))*4==len(b)
 addresses=[int(x['address'],16)for x in c['original_fixups']['records']];assert verify_used_fixups(addresses)==c['original_fixups']
 for row in c['banks_exhaustive256']:
  l=IMAGE.read(int(row['left'],16),256);rr=IMAGE.read(int(row['right'],16),256);assert {x^rr[l[x]^int(row['key'],16)]for x in range(256)}=={int(row['constant'],16)}
 valid={int(x['index'],16)for x in c['IA_E9B9_slots']};coherent=[]
 for b in valid:
  l,h,d=phases(b)
  if b|d in valid:coherent.append((b-0x354d)&0xffffffff)
 assert coherent==[0x621b]
 authmarkers=[]
 for x in c['all_marker_bytes']:
  idx=0x9768|((x['byte']*0x93)&0xffffffff);assert x['index']==hex(idx)and x['slot']==hex(TABLE+idx*8)and x['fixup']==FIXUPS.get(TABLE+idx*8)
  if idx in valid:authmarkers.append((x['byte'],idx))
 assert authmarkers==[(0,0x9768),(1,0x97fb),(32,0x9768),(33,0x97fb),(224,0x97e8)]
 assert [int(x['branch_pc'],16)for x in c['text_census']['literal_E9B9_braa_pairs']]==[0x100321660,0x100406d74,0x1004c7b80,0x1009f7378,0x100a03684,0x100a04418]
 solved=0
 for row in p['proofs']:
  for filekey,hashkey in [('original_file','original_sha256'),('file','sha256')]:
   f=ROOT/row[filekey];assert sha(f)==row[hashkey];s=z3.Solver();s.set(timeout=30000);s.add(z3.parse_smt2_file(str(f)));assert str(s.check())=='unsat';solved+=1
 qs,counts=obligations(c);assert counts==p['source_lift_counts']and len(qs)==15
 for n,predicate in qs:s=z3.Solver();s.set(timeout=30000);s.add(predicate);assert str(s.check())=='unsat'
 configs=list(cases());assert [x['configuration']for x in r['cases']]==configs;totals=Counter();fresh_counts=Counter();retired=set();ranges=[(int(s['start'],16),int(s['end'],16))for s in c['spans']]
 for old,cfg in zip(r['cases'],configs):
  v=Run(cfg);new=v.run();assert old==json.loads(json.dumps(new)),(cfg,old['boundary_PC'],new['boundary_PC']);retired.update(a for a,b in v.steps);assert all(any(a<=pc<z for a,z in ranges)for pc,b in v.steps);assert {int(a,16)for a in new['used_fixups']}<=set(addresses);totals.update({'cases':1,'source_visits':new['source_visits'],'read_effects':new['read_effects'],'write_effects':len(new['private_writes']),'logical_edges':len(new['logical_edges']),'modeled_allocator_calls':len(new['modeled_allocator_calls'])})
 assert dict(totals)==r['verified_totals'];extra=[]
 for cfg in [{'kind':'allocation','marker':1,'controller':0xffffffff,'nonnull':b,'pattern':17,'placement':16}for b in [False,True]]+[{'kind':'zero','marker':0,'lock':0x690000f000,'pattern':17,'placement':16},{'kind':'setter','phase64':0xfedcba980000471c,'pattern':17}]:
  row=Run(cfg).run();extra.append(row);fresh_counts.update({'cases':1,'source_visits':row['source_visits']})
 alloc=[x for x in r['cases']if x['configuration']['kind']=='allocation'];assert len(alloc)==1024
 for nonnull in [False,True]:
  for pattern in [0,255]:assert {x['critical']['bank_input_byte']for x in alloc if x['configuration']['nonnull']==nonnull and x['configuration']['pattern']==pattern}==set(range(256))
 assert all(x['critical']['source_object_payload_writes']==0 for x in alloc);assert all(x['logical_edges'][0]['modifier']=='0xe9b9'for x in alloc)
 for x in r['cases']:
  for e in x['logical_edges']:
   a=int(e['slot'],16);word=int.from_bytes(IMAGE.read(a,8),'little');assert word>>63==1 and(word>>48)&1==0 and(word>>49)&3==0 and(word>>32)&65535==int(e['modifier'],16)
  for call in x['modeled_allocator_calls']:assert call['requested_bytes']==872 and call['native_call_executed']is False and call['preserved_GPR_and_SP_checked']==13
 idb=c['live_IDB_matches'];verified={'original_source_spans_checked':len(c['spans']),'original_fixups_checked':len(addresses),'bank_inputs_checked':256,'marker_bytes_checked':256,'binary_phase_candidates_checked':len(valid),'coherent_binary_phase_candidates':1,'marker_values_with_matching_E9B9_metadata':len(authmarkers),'literal_E9B9_branch_pairs':6,'SMT_file_queries_unsat':solved,'rebuilt_source_obligations_unsat':len(qs),'source_lift_visits':sum(counts.values()),'persisted_A64_cases':len(configs),'persisted_A64_source_visits':totals['source_visits'],'persisted_A64_cases_freshly_recomputed':len(configs),'additional_A64_cases':len(extra),'additional_A64_source_visits':fresh_counts['source_visits'],'live_IDB_ranges_checked':len(idb),'live_IDB_raw_bytes_checked':sum(x['size_bytes']for x in idb),'live_IDB_display_rows_checked':sum(x['display_rows']for x in idb),'live_IDB_undecoded_byte_rows':sum(x['undecoded_byte_rows']for x in idb)}
 assert 0x100a636ec not in retired;verified['distinct_retired_opcodes_within_checked_spans']=len(retired)
 deps=['daemon_object_creation_contracts.json','daemon_object_creation_proofs.json','daemon_object_creation_replays.json','replay_daemon_object_creation.py','prove_daemon_object_creation.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'verified_counts':verified,'independent_A64_totals':dict(totals),'extra_A64_cases':extra,'extra_A64_totals':dict(fresh_counts),'marker_values_with_matching_metadata':[{'byte':m,'index':hex(i)}for m,i in authmarkers],'all_checks_pass':True,'reader_B_reached':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_object_creation_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(verified),flush=True)
if __name__=='__main__':main()
