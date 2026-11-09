#!/usr/bin/env python3
"""Source identities for predecessor gates and bounded candidate exclusions.
30 s/query; O(lifted instructions+solver resources) time/space. Fragment starts,
mode/frame ownership and table identity are explicit premises, not native entry.
"""
import json
from pathlib import Path
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from daemon_receive_tools import ROOT,TABLE
from prove_daemon_registry_lookup import RegistryLift,sha
from lskd_values_symbolic import part,mem,cell,resize
class PreLift(RegistryLift):
 def run(self,label):
  row=next(r for r in self.c['spans']if r['label']==label);old=self.c;cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
  for i in cs.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if i.mnemonic=='cmn':
    assert i.op_str=='w9, #2';a=self.read('w9');self.cmp_left=self.sleft=a;self.cmp_right=self.sright=z3.BitVecVal(0xfffffffe,32);self.equal=a+2==0;self.count+=1
   else:self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};RegistryLift.run(self,'one')
  self.c=old;return self
def obligations(c):
 c={'spans':c['spans']+[r['span']for r in c['literal_0156_census']]};qs=[];counts={};F=0x6800010000;S,H,W=z3.BitVecs('pred_mode32 pred_raw32 pred_input32',32);N,M,U=z3.BitVecs('pred_presence64 pred_marker64 pred_opaque64',64);D=H^0x8b3dc651
 def run(n,a,z,seeds=(),memory=()):
  v=PreLift(part(c,n,a,z))
  for reg,val in seeds:v.seed(reg,val)
  for at,nb,val in memory:mem(v,at,nb,val)
  v.run(n);counts[n]=v.count;return v
 def add(n,p,pre=z3.BoolVal(True)):qs.append((n,z3.And(pre,p)))
 setup=run('setup',0x100aee5c8,0x100aee658,[('sp',F),('x0',U),('x9',U),('x11',U),('x10',U),('x8',U),('x5',U)],[(F+o,n,val)for o,n,val in[(0x26c8,8,M),(0x2a58,8,U),(0x2a48,8,N),(0x2a60,8,U),(0x2a50,4,H),(0x2a70,8,U),(0x273c,4,S),(0x29a0,8,TABLE)]])
 raw=S+0xe293b0bf;f=(raw^z3.If(N==0,z3.BitVecVal(1,32),z3.BitVecVal(0,32)))&1;idx=(S+0x475d)^(f*0xe8)
 add('all_mode_presence_setup',z3.Or(setup.read('w8')!=raw,setup.read('w9')!=idx,setup.read('w16')!=H,setup.read('x15')!=M,cell(setup,F+0x2fac,4)!=H,cell(setup,F+0x2d78,8)!=N))
 add('selected_mode_presence_gate',z3.Or(setup.read('w9')!=z3.If(N==0,z3.BitVecVal(0x8e79,32),z3.BitVecVal(0x8e91,32)),setup.read('w8')&0x1d6c6a3f!=0x621b),S==0x471c)
 first=run('classifier1',0x100b67258,0x100b672cc,[('w8',0xe293f7db),('w16',H)]);add('all_raw32_first_classifier',z3.Or(first.read('w8')!=0x621b,first.read('w9')!=D,first.read('w10')!=0x471c))
 firstgate=run('gate1',0x100b672cc,0x100b672e0,[('w9',D),('w8',0x621b)]);add('all_raw32_first_index',firstgate.read('w9')!=z3.If(z3.ULT(D,201),z3.BitVecVal(0xadd1,32),z3.BitVecVal(0x621b,32)))
 second=run('classifier2',0x100b6de10,0x100b6de88,[('w8',0x621b),('w16',H)]);add('all_raw32_second_classifier',second.read('w9')!=D-2)
 secondgate=run('gate2',0x100b6de88,0x100b6de9c,[('w9',D-2),('w8',0x621b)]);add('all_raw32_second_index',secondgate.read('w9')!=z3.If(z3.UGE(D,2),z3.BitVecVal(0x9bd7,32),z3.BitVecVal(0x621b,32)))
 add('decoded_classifier_closed_interval',z3.And(z3.ULT(D,201),z3.ULT(D-2,0xfffffffe))!=z3.And(z3.UGE(D,2),z3.ULE(D,200)))
 marker=run('marker_bias',0x1009d0448,0x1009d0458,[('sp',F),('x15',0x12e36048b)]);add('marker_original64_bias_and_frame_save',z3.Or(marker.read('x8')!=0x1010c8254,cell(marker,F+0x26c8,8)!=0x1010c8254))
 counter=run('counter_bias',0x1009d0344,0x1009d0354,[('sp',F),('x9',0x16d542b72)]);add('counter_original64_bias_and_frame_save',cell(counter,F+0x26e8,8)!=0x1010c8238)
 frame=run('common_frame_save',0x100a035f0,0x100a03618,[('sp',F)]+[('x'+str(j),v)for j,v in [(19,0x1010b6358),(28,0x1010b8cc8),(23,0x1010ca2b0),(7,0x1010c9288),(24,0x100e79290),(26,0x1010c67d0),(20,0x7c003500),(25,0x100ff7140),(4,0x1010c67c0),(1,0x100ee7de0)]]);add('conditional_common_frame_global_roles',z3.Or(cell(frame,F+0x2698,8)!=0x1010ca2b0,cell(frame,F+0x26b0,8)!=0x1010c9288,cell(frame,F+0x26c0,8)!=0x1010c67c0,cell(frame,F+0x24a8,8)!=0x1010c67d0))
 reset=run('reset',0x100b280c8,0x100b280e8,[('sp',F),('w15',S)],[(F+0x2698,8,0x1010ca2b0),(F+0x26e8,8,0x1010c8238),(F+0x26b0,8,0x1010c9288)]);assert [x['size_bytes']for x in reset.stores]==[4,4,8];add('conditional_three_global_zero_stores',z3.Or(*[z3.Or(x['address']!=a,x['value']!=0)for x,a in zip(reset.stores,[0x1010ca2b0,0x1010c8238,0x1010c9288])]))
 save=run('saved_target',0x1009d02ac,0x1009d02b4,[('sp',F),('x14',TABLE),('w19',0x49d)],[(TABLE+0x49d*8,8,0x100aee5c8)]);add('candidate_saved_target49D',cell(save,F+0x2a68,8)!=0x100aee5c8)
 load=run('saved_branch',0x1009d0774,0x1009d077c,[('sp',F)],[(F+0x2a68,8,0x100aee5c8)]);add('candidate_saved_target_reload',z3.Or(load.read('x12')!=0x100aee5c8,load.read('x17')!=0xe30d))
 # These source-start exclusions do not exclude entry into a fragment's middle.
 specs=[('910A78',0x100910a78,0x100910ac0,'w12','w11'),('9B317C',0x1009b317c,0x1009b31cc,'w11','w11'),('A2CC44',0x100a2cc44,0x100a2cc90,'w12','w11'),('A35518',0x100a35518,0x100a35568,'w11','w11'),('ACDC84',0x100acdc84,0x100acdccc,'w11','w11'),('BAB15C',0x100bab15c,0x100bab198,'w11','w9'),('BE4F40',0x100be4f40,0x100be4f88,'w11','w11'),('C7D3F0',0x100c7d3f0,0x100c7d428,'w12','w9')]
 for n,a,z,source,index in specs:
  v=run('exclude_'+n,a,z,[(source,W),('w9',H)]);add('incompatible_whole_fragment_'+n,z3.And(v.read('w8')==0x621b,v.read(index)==0x9bd7))
 v=run('exclude_B67258',0x100b67258,0x100b672e0,[('w8',W),('w16',H)]);add('first_gate_not_direct_predecessor',z3.And(v.read('w8')==0x621b,v.read('w9')==0x9bd7))
 add('branch_X8_target_low32_incompatible',resize(z3.BitVecVal(0x100a035f0,64),32)==0x621b)
 return qs,counts
def main():
 c=json.loads((ROOT/'daemon_creation_predecessors_contracts.json').read_text());qs,counts=obligations(c);rows=[]
 for n,p in qs:
  a=ROOT/f'daemon_creation_predecessors_{n}_original.smt2';b=ROOT/f'daemon_creation_predecessors_{n}.smt2';s=z3.Solver();s.add(p);a.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(p));ans=str(s.check());print(json.dumps({'proof':n,'result':ans}),flush=True);assert ans=='unsat',(n,ans,str(s.model())if ans=='sat'else'');b.write_text(s.to_smt2());rows.append({'name':n,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':ans})
 deps=['daemon_creation_predecessors_contracts.json','prove_daemon_registry_lookup.py','lskd_values_symbolic.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':rows,'source_lift_counts':counts,'cmn_contract':'Only original CMN W9,#2 followed by CSET LO is supported: carry clear iff unsigned W9<FFFFFFFE.','native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_creation_predecessors_proofs.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'proof_pairs':len(rows),'source_lift_visits':sum(counts.values())}),flush=True)
if __name__=='__main__':main()
