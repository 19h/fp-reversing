#!/usr/bin/env python3
"""Source pointer stores, sentinel dispatch and composed nonzero-key predicates.

Distinct fixed cells and declared source phases; no table mutation or native
reachability premise is synthesized. O(I) lift space/time plus solver cost.
"""
import z3
from lskd_state_symbolic import SelectLift,queries as state_queries
from lskd_values_symbolic import Lift,part,mem,cell
def queries(c,state):
 qs,counts=state_queries(state);qs=[x for x in qs if x[0]!='stop_saved_status_return'];counts.pop('stop_saved_status_return')
 F=0x51000000;POOL=0xfffffe00084716e0;TABLE=0xfffffe000ccc7b08
 for label,a,z,base,ix,off in[('vault_source_table_store',0xfffffe000a52fca8,0xfffffe000a52fcb4,'x26','w12',0x30),('allowed_source_table_store',0xfffffe000a55d150,0xfffffe000a55d15c,'x19','w8',0x60)]:
  v=Lift(part(c,label,a,z));v.seed(base,POOL);v.seed(ix,0x83);v.seed('sp',F);mem(v,POOL+0x83*8,8,TABLE+8);v.run(label);counts[label]=v.count;qs.append((label,cell(v,F+off,8)!=TABLE))
 E,K=z3.BitVecs('lookup_entry32 lookup_key32',32);secondary={}
 v=Lift(part(c,'vault_secondary_phase',0xfffffe000a56dfa0,0xfffffe000a56dfac));v.seed('w8',0x53e);v.run('vault_secondary_phase');counts['vault_secondary_phase']=v.count;qs.append(('vault_secondary_phase',z3.Or(v.read('w10')!=0x72d,v.read('w9')!=0x72d)))
 v=Lift(part(c,'allowed_secondary_phase',0xfffffe000a52dbdc,0xfffffe000a52dbf4));v.seed('w28',0x8ac);v.run('allowed_secondary_phase');counts['allowed_secondary_phase']=v.count;qs.append(('allowed_secondary_phase',z3.Or(v.read('w8')!=0x28b,v.read('w9')!=0x8ac,v.read('w10')!=0x8ac)))
 v=Lift(part(c,'vault_zero_sentinel',0xfffffe000a56dfbc,0xfffffe000a56dfe0));v.seed('w8',0x53e);v.seed('w10',0x72d);v.seed('w9',0x72d);v.seed('w11',E);v.run('vault_zero_sentinel');counts['vault_zero_sentinel']=v.count;secondary['vault']=v.read('w8');qs.append(('vault_zero_sentinel',v.read('w8')!=z3.If(E==0,z3.BitVecVal(0x53e,32),z3.BitVecVal(0x54a,32))))
 v=Lift(part(c,'allowed_zero_sentinel',0xfffffe000a52dc04,0xfffffe000a52dc1c));v.seed('w8',0x28b);v.seed('w9',0x8ac);v.seed('w10',0x8ac);v.seed('w11',E);v.run('allowed_zero_sentinel');counts['allowed_zero_sentinel']=v.count;secondary['allowed']=v.read('w8');qs.append(('allowed_zero_sentinel',v.read('w8')!=z3.If(E==0,z3.BitVecVal(0x297,32),z3.BitVecVal(0x28b,32))))
 for provider,a,z,dest,positive in[('vault',0xfffffe000a5939c8,0xfffffe000a5939e0,'w26',0x54a),('allowed',0xfffffe000a531174,0xfffffe000a531190,None,0x28b)]:
  name=provider+'_composed_nonzero_key_gate';v=SelectLift(part(c,name,a,z));v.seed('w11'if provider=='vault'else'w12',E);v.seed('w10'if provider=='vault'else'w11',K);v.seed('sp',F);v.run(name);counts[name]=v.count;status=v.read(dest)if dest else cell(v,F+0xb8,4)
  qs.append((name,z3.And(status==0x5e561849,secondary[provider]==positive)!=z3.And(E==K,K!=0)))
 OLD=z3.BitVec('unknown_old_x13',64);KEY=z3.BitVec('independent_index_key32',32);v=Lift(part(c,'allowed_full_register_kill',0xfffffe000a531164,0xfffffe000a531168));v.seed('x13',OLD);v.seed('w11',KEY);v.run('allowed_full_register_kill');counts['allowed_full_register_kill']=v.count;qs.append(('allowed_full_register_kill',v.read('x13')!=z3.ZeroExt(32,KEY&0x3ff)))
 return qs,counts
