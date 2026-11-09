#!/usr/bin/env python3
"""Independently audit source/proofs, new local A64 compositions and journals.
O(source+all visits/effects+solver resources) time; space includes loaded
artifacts, one private map, largest decoded journal and solver expressions.
"""
import json
from collections import Counter
from pathlib import Path
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,TABLE,FIXUPS
from recover_daemon_object_creation import sha,span
from recover_daemon_descriptor_producers import verify_used_fixups
from recover_daemon_cache36 import ida_matches
from recover_daemon_compression_frame import census,retained,selector_reference,K
from prove_daemon_compression_frame import obligations
from probe_daemon_compression_frame import execute,cases,P,SIZE
from validate_daemon_object_clock import checked,logical_read,unsat
def main():
 c=checked('daemon_compression_frame_contracts.json','recover_daemon_compression_frame.py');p=checked('daemon_compression_frame_proofs.json','prove_daemon_compression_frame.py');r=checked('daemon_compression_frame_profiles.json','probe_daemon_compression_frame.py');counts=Counter();totals=Counter();assert c['source_sha256']==r['source_sha256']==sha(SOURCE)
 for s in c['spans']:assert span(s['label'],int(s['start'],16),int(s['end'],16))==s;counts['original_source_spans']+=1
 assert census()==c['direct_SP_census'];counts['direct_SP_accesses_checked']=len(c['direct_SP_census']['records']);assert counts['direct_SP_accesses_checked']==13
 assert verify_used_fixups([int(x['address'],16)for x in c['original_fixups']['records']])==c['original_fixups'];counts['original_fixups_checked']=len(c['original_fixups']['records']);live=ida_matches('daemon_compression_frame_ida_bytes.json')+ida_matches('daemon_compression_frame_ida_return.json');assert live==c['live_IDB_matches'];counts['live_IDB_ranges']=len(live);counts['live_IDB_bytes']=sum(x['size_bytes']for x in live)
 qs,lifts=obligations(c);assert lifts==p['source_lift_counts']
 for (name,pred),proof in zip(qs,p['proofs'],strict=True):
  assert name==proof['name'];unsat(pred);counts['rebuilt_source_obligations_unsat']+=1
  for fkey,hkey in [('file','sha256'),('original_file','original_sha256')]:
   f=ROOT/proof[fkey];assert sha(f)==proof[hkey];forms=z3.parse_smt2_file(str(f));assert len(forms)==1;unsat(forms[0]);unsat(z3.Xor(forms[0],pred));counts['SMT_files_unsat_and_formula_matched']+=1
 for premise in [z3.And(z3.UGE(z3.BitVec('frame_L32',32),1),z3.ULE(z3.BitVec('frame_L32',32),64)),z3.UGE(z3.BitVec('frame_N32',32)+(z3.BitVec('frame_H32',32)&63),64)]:
  solver=z3.Solver();solver.add(premise);assert str(solver.check())=='sat';counts['nonempty_arithmetic_premises_checked']+=1
 counts['source_lift_visits']=sum(lifts.values());assert [row['configuration']for row in r['cases']]==list(cases())and len(r['cases'])==716
 selector_results={}
 for row in r['cases']:
  cfg=row['configuration'];kind=cfg['kind'];F=int(row['SP'],16);C=int(row['context'],16);I=int(row['input'],16);data={int(g['address'],16)+j:b for g in row['initial_fixtures']for j,b in enumerate(bytes.fromhex(g['bytes_hex']))};initial=dict(data);final=[int(x,16)for x in row['final_registers31']];writes=[]
  def word(a,n=8):return int.from_bytes(bytes(data[a+j]for j in range(n)),'little')
  for pc,raw in row['steps']:assert IMAGE.read(pc,4).hex()==raw
  for e in row['events']:
   a=int(e['address'],16);n=e['size_bytes'];raw=bytes.fromhex(e['bytes_hex']if e['kind']=='read'else e['after_hex']);assert len(raw)==n
   if e['kind']=='read':assert raw==(bytes(data[a+j]for j in range(n))if P<=a<P+SIZE else logical_read(a,n));counts['ordered_source_reads_checked']+=1
   else:assert P<=a<a+n<=P+SIZE;data.update({a+j:b for j,b in enumerate(raw)});writes.append(e);counts['ordered_source_writes_checked']+=1
  for edge in row['edges']:
   slot=int(edge['slot'],16);fix=FIXUPS[slot];assert fix['target']==int(edge['target'],16)and f"div=0x{int(edge['modifier'],16):04X} "in fix['annotation']and not edge['hardware_authentication_executed'];counts['logical_dispatch_edges_checked']+=1;assert edge['target_origin']==('saved_continuation_fixture'if kind=='return'else'original_logical_cell_read')
  if kind=='copy':
   h=cfg['H32'];length=64-h;expected=bytes(initial[I+j]^0x98 for j in range(length));actual=bytes(data[C+h+j]for j in range(length));assert actual==expected and word(F+0x2e50)==C and word(F+0x30fc,4)==length and final[8]==0x471c and final[12]==C and final[21]==I+length and row['frontier_PC']=='0x100abee44'
   bw=[e for e in writes if e['pc']=='0x100b39424'];assert len(bw)==length and [int(e['address'],16)for e in bw]==list(range(C+h,C+64));assert not any(C+j in data for j in range(h));assert len(row['edges'])==length+2;counts['complete_first_block_copy_cases_checked']+=1;counts['encoded_copy_bytes_checked']+=length
  elif kind=='selector':
   b=cfg['selector'];ref=selector_reference(b);assert c['selector256'][b]=={'selector_byte':b,**ref};assert row['frontier_PC']==hex(ref['leaf_target'])and int(row['edges'][1]['slot'],16)==TABLE+8*ref['first_index']and int(row['edges'][2]['slot'],16)==TABLE+8*ref['leaf_index'];assert row['frontier_PC']==('0x1009e0cc4'if b==1 else'0x100a361b0'if b==2 else'0x100bdf3bc');counts['compact_selector_leaf_cases_checked']+=1;assert word(F+0x2de0)==FIXUPS[TABLE+cfg['return_index']*8]['target'];q=0x310 if cfg['return_index']==0x58 else 0x2f0;assert word(F+0x3620)==q+320 and final[16]==F+0x39f0+q and word(F+0x2a70)==C and final[2]==TABLE;assert not any(C<=int(e['address'],16)<C+100 for e in writes);selector_results.setdefault(b,set()).add(row['frontier_PC']);counts['selector_dispatch_cases_checked']+=1
  elif kind=='frame':
   E=int.from_bytes(bytes(initial[F+0x31dc+j]for j in range(4)),'little');expected={0x2a08:(4,E),0x2a60:(4,(E+0x318c+0x1960f475)&0xffffffff),0x2a58:(8,I),0x2a50:(8,int.from_bytes(bytes(initial[F+0x2e50+j]for j in range(8)),'little')),0x2a68:(4,int.from_bytes(bytes(initial[F+0x2c8c+j]for j in range(4)),'little')),0x2a20:(8,int.from_bytes(bytes(initial[F+0x3490+j]for j in range(8)),'little')),0x2a18:(4,0x20),0x2a48:(4,0xa243),0x2a10:(4,0x42),0x2a40:(4,0xa34a),0x2a38:(4,K),0x2a30:(4,0xa351),0x2a28:(4,64)};assert all(word(F+off,n)==v for off,(n,v)in expected.items());assert final[1]==0x318c and final[20]==int(row['entry_registers31'][20],16)and final[4]==C and final[30]==TABLE and row['frontier_PC']=='0x100b76438';counts['shared_frame_layouts_checked']+=1
  elif kind=='short':assert final[20]==0x58 and final[12]==C and row['frontier_PC']=='0x100abee44';counts['short_compression_callers_checked']+=1
  elif kind=='return':
   assert row['frontier_PC']==hex(FIXUPS[TABLE+cfg['return_index']*8]['target'])and word(F+0x3620)==0x2f0 and final[30]==TABLE and final[15]==0x471c and final[24]==I and final[27]==C and final[0]==F+0x2e5c and final[16]==F+0x35e4;counts['compression_return_cases_checked']+=1
  else:
   assert kind=='post';good=cfg['N32']>=cfg['L32']+64;assert row['frontier_PC']==('0x100bae8d0'if good else'0x100c9f804')and final[0]==I and final[1]==C and final[2]==0xa351 and final[4]==64;counts['next_block_gate_cases_checked']+=1
  assert execute(cfg)==row;counts['freshly_recomputed_A64_cases']+=1;counts['persisted_A64_cases']+=1;totals.update({'source_visits':row['source_visits'],'modeled_dispatch_visits':row['modeled_dispatch_visits'],'read_effects':sum(e['kind']=='read'for e in row['events']),'write_effects':len(writes)})
 assert len(selector_results)==256 and all(len(x)==1 for x in selector_results.values());counts['exhaustive_selector_bytes_checked']=256
 rows,rc=retained();assert rows==c['retained_cases']and rc==c['retained_counts'];counts.update({f'audited_{k}':v for k,v in rc.items()});deps=['daemon_compression_frame_contracts.json','daemon_compression_frame_proofs.json','daemon_compression_frame_profiles.json','recover_daemon_compression_frame.py','prove_daemon_compression_frame.py','probe_daemon_compression_frame.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'verified_counts':dict(counts),'independent_A64_totals':dict(totals),'source_lift_counts':lifts,'all_checks_pass':True,'new_port_emission_established':False,'completed_digest_or_cache_content_established':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_compression_frame_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts),'totals':dict(totals)}),flush=True)
if __name__=='__main__':main()
