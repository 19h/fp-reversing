#!/usr/bin/env python3
"""Source-projected protected key, exact tag/table stores, operation gate,
frame arithmetic and additive pointer-decode identities. Valid fixed component
cells; no all-state proof of the complete core prologue or later emitter epoch.
O(lift + BV DAGs + solver resources) time/space; no native target/PAC/API.
"""
import json
import z3
from daemon_receive_tools import ROOT,IMAGE,FIXUPS,POOL,TABLE
from capture_daemon_record720 import sha
from daemon_arena_lifetime_symbolic import LifetimeFlags
from lskd_values_symbolic import mem,cell

def obligations():
 src=json.loads((ROOT/'daemon_shared_roots_source.json').read_text());qs=[];counts={};P=z3.BitVec('shared_core_record_address64',64);v=LifetimeFlags({'spans':[]});v.seed('x0',P)
 for j,st in enumerate(src['protected_key_projection']):
  label='key_'+str(j);v.c={'spans':[{'label':label,'start':st['pc'],'bytes_hex':st['bytes_hex']}]};v.run(label)
 key=(z3.Extract(31,0,P)^0xeaae0ac9)*0x7398180b;qs.append(('all_u64_protected_record_key',v.read('w12')!=key));counts['projected_key']=20
 def run(n,a,z,seeds=(),memory=()):
  v=LifetimeFlags({'spans':[{'label':n,'start':hex(a),'bytes_hex':IMAGE.read(a,z-a).hex()}]})
  for r,x in seeds:v.seed(r,x)
  for a,nm,x in memory:mem(v,a,nm,x)
  v.run(n);counts[n]=v.count;return v
 F=0x680004f230;R=0x6800064000;K,tag,op=z3.BitVecs('shared_core_key32 shared_core_tag32 shared_core_operation32',32);T=z3.BitVec('shared_core_table64',64)
 v=run('tag_table_store',0x10061a90c,0x10061a984,[('sp',F),('x0',R),('w12',K),('x10',T)],[(R+8,4,tag^K)])
 qs.append(('all_u32_tag_zero_extension_and_table64',z3.Or(cell(v,F+0x9d0,8)!=z3.ZeroExt(32,tag),cell(v,F+0x9d8,8)!=T)))
 v=run('operation_gate',0x1004c244c,0x1004c24a4,[('sp',F),('x0',R),('w12',K)],[(R+12,4,op^K),(F+0x9d0,8,0x6cf4)]);h=z3.simplify(cell(v,F+0x928,4)).as_long();threshold=(h+0xad946d95)&0xffffffff;base=(0x6cf4+0x136d)&0xffffffff;index=z3.If(op<z3.BitVecVal(threshold,32),z3.BitVecVal(base^0xc5,32),z3.BitVecVal(base,32))
 qs.append(('all_u32_operation_decode_and_first_index',z3.Or(cell(v,F+0x9b8,4)!=op,cell(v,F+0x9a0,4)!=index)))
 slide=z3.BitVec('shared_core_loaded_word_delta64',64);left_slot=POOL+0x29c8;right_slot=POOL+0x4c18;assert isinstance(FIXUPS[left_slot]['target'],int)and isinstance(FIXUPS[right_slot]['target'],int)
 v=run('literal_root_decoders',0x10061a73c,0x10061a75c,[('x25',POOL)],[(left_slot,8,z3.BitVecVal(FIXUPS[left_slot]['target'],64)+slide),(right_slot,8,z3.BitVecVal(FIXUPS[right_slot]['target'],64)+slide)])
 qs.append(('all_u64_additive_left_right_decodes',z3.Or(v.read('x1')!=0x100fc4130+slide,v.read('x7')!=0x101031ea0+slide)))
 E=z3.BitVec('shared_core_entry_SP64',64);after_saves=E-128;FP=after_saves+112;frame=after_saves-(16*4096)-0xd50;qs.append(('all_u64_source_frame_geometry',z3.Or(frame!=E-0x10dd0,FP!=frame+0x10dc0,FP-0x88!=frame+0x10d38)))
 # Decode the two original target words; this local index theorem is linked
 # to actual source reads/def-use in the retained profile, not native execution.
 slots=[]
 for ix in [base,base^0xc5]:
  at=TABLE+ix*8;t=FIXUPS[at]['target'];word=int.from_bytes(IMAGE.read(at,8),'little');assert isinstance(t,int)and word>>63==1 and(word>>32)&65535==0x8a50;slots.append({'index':hex(ix),'slot':hex(at),'target':hex(t)})
 qs.append(('all_u32_first_slot_two_way_partition',z3.And(index!=base,index!=(base^0xc5))))
 return qs,counts,{'mode_tag':'0x6cf4','operation_signed_threshold':hex(threshold),'operation_phase_word':hex(h),'first_index_base':hex(base),'first_index_xor':hex(0xc5),'first_slots':slots,'root_word_slots':[hex(left_slot),hex(right_slot)],'additive_word_delta_is_not_full_native_relocation_test':True,'complete_prologue_all_state_invariance_proved':False}
if __name__=='__main__':
 qs,counts,meta=obligations();rows=[]
 for name,q in qs:
  a=ROOT/f'daemon_shared_roots_{name}_original.smt2';b=ROOT/f'daemon_shared_roots_{name}.smt2';s=z3.Solver();s.add(q);a.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(q));answer=str(s.check());assert answer=='unsat',(name,answer);b.write_text(s.to_smt2());rows.append({'name':name,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':answer});print(name,answer,flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['daemon_shared_roots_source.json','daemon_shared_roots_profiles.json','daemon_arena_lifetime_symbolic.py']},'proofs':rows,'source_lift_counts':counts,'metadata':meta,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_shared_roots_proofs.json').write_text(json.dumps(out,indent=2)+'\n');print(meta,flush=True)
