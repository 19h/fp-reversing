#!/usr/bin/env python3
"""Original-instruction local BV proofs for query/type predicates, exact byte
stores and the original caller predicate. Readable cells and retained-register
values are explicit premises, not native environment or framework claims.
O(source/BV DAGs + solver resources) time/space. No native execution.
"""
import json
import z3
from daemon_receive_tools import ROOT,IMAGE
from daemon_arena_lifetime_symbolic import LifetimeFlags
from lskd_values_symbolic import mem,cell
from capture_daemon_record720 import sha
def obligations():
 qs=[];counts={}
 def run(name,a,z,seeds=(),memory=()):
  m=LifetimeFlags({'spans':[{'label':name,'start':hex(a),'bytes_hex':IMAGE.read(a,z-a).hex()}]})
  for r,v in seeds:m.seed(r,v)
  for at,n,v in memory:mem(m,at,n,v)
  m.negative,m.equal,m.carry,m.overflow=[z3.Bool('entitlement_'+name+'_'+f)for f in ['N','Z','C','V']];m.run(name);counts[name]=m.count;return m
 V,E,F=z3.BitVecs('entitlement_value64 entitlement_error64 entitlement_frame64',64)
 m=run('query_gate',0x1002b772c,0x1002b7758,[('x0',V),('x29',F),('w23',0x5397),('w27',0x5397),('w28',0xa7c7)],[(F-0x60,8,E)]);qs.append(('all_value_error_pairs_query_gate',z3.Or(m.read('x21')!=V,m.read('w8')!=z3.If(z3.And(V!=0,E==0),z3.BitVecVal(0xa7c7,32),z3.BitVecVal(0xa7e1,32)))))
 A,B=z3.BitVecs('entitlement_Boolean_type64 entitlement_value_type64',64);m=run('type_gate',0x10030ad08,0x10030ad20,[('x23',A),('x0',B),('w20',0x53c7),('w27',0x5397)]);qs.append(('all_64bit_type_ID_pairs',m.read('w8')!=z3.If(A==B,z3.BitVecVal(0x8a97,32),z3.BitVecVal(0x5397,32))))
 S,P,R,X=z3.BitVecs('entitlement_SP64 entitlement_flag_pointer64 entitlement_record64 entitlement_return64',64);m=run('Boolean_byte',0x10052bcc8,0x10052bcd0,[('sp',S),('x0',X)],[(S+0x30,8,P)]);qs.append(('all_return_bits_flag_store',cell(m,P,1)!=z3.Extract(7,0,X)))
 M=z3.BitVec('entitlement_marker32',32);m=run('marker_store',0x1004b115c,0x1004b1160,[('x19',R),('w28',M)]);qs.append(('all_marker_bits_record_store',cell(m,R+8,1)!=z3.Extract(7,0,M)))
 FLAG,MARK=z3.BitVecs('entitlement_flag8 entitlement_marker8',8);F0,S0=0x680004f230,0x680004f230;m=run('caller_gate',0x1004c464c,0x1004c4674,[('x28',F0),('sp',S0),('w21',0x960f)],[(F0+0xcc0,1,MARK),(S0+0x2cff,1,FLAG)]);qs.append(('all_flag_marker_bytes_caller_gate',m.read('w8')!=z3.If(z3.Or(FLAG==0,MARK==0x5b),z3.BitVecVal(0x961d,32),z3.BitVecVal(0x960f,32))))
 return qs,counts
if __name__=='__main__':
 qs,counts=obligations();rows=[]
 for name,q in qs:
  a=ROOT/('daemon_entitlement_result_'+name+'_original.smt2');b=ROOT/('daemon_entitlement_result_'+name+'.smt2');s=z3.Solver();s.add(q);a.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(q));answer=str(s.check());assert answer=='unsat',(name,answer);b.write_text(s.to_smt2());rows.append({'name':name,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':answer});print(name,answer,flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['daemon_entitlement_result_contracts.json','daemon_arena_lifetime_symbolic.py']},'proofs':rows,'source_lift_counts':counts,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_entitlement_result_proofs.json').write_text(json.dumps(out,indent=2)+'\n')
