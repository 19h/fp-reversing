#!/usr/bin/env python3
"""Local fill geometry, width and Duff-loop identities; no whole-path proof."""
import hashlib,json
from pathlib import Path
import z3
from kext_port_tools import ROOT
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 d,n,x=z3.BitVecs('destination64 length64 fill64',64);b=z3.BitVec('byte8',8);a=(-d)&7;prefix=z3.If(z3.ULT(n,a),n,a);rem=n-prefix;q=z3.LShR(rem,3);r=q&7;rounds=z3.LShR(q+7,3);stores=z3.If(r==0,rounds*8,(rounds-1)*8+r);word=z3.ZeroExt(56,b)*0x0101010101010101
 queries=[('alignment_low32',((z3.ZeroExt(32,-z3.Extract(31,0,d)))&7)!=a),('canonical_byte_word',word!=z3.Concat(*([b]*8))),('prefix_within_length',z3.UGT(prefix,n)),('length_partition',(prefix+(q<<3)+(rem&7))!=n),('duff_word_count',z3.And(q!=0,stores!=q)),('bulk_upper_fill_ignored',(z3.ZeroExt(32,z3.Extract(31,0,x))*0x0101010101010101)!=(z3.ZeroExt(32,z3.Extract(31,0,x+0x100000000))*0x0101010101010101))]
 rows=[]
 for name,query in queries:
  s=z3.Solver();s.set(timeout=30000);s.add(query);result=str(s.check());assert result=='unsat',(name,result);p=ROOT/('sample_state_'+name+'.smt2');p.write_text(s.to_smt2());rows.append({'name':name,'file':p.name,'sha256':sha(p),'result':result})
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'contracts_sha256':sha(ROOT/'sample_state_contracts.json'),'solver_version':z3.get_version_string(),'proofs':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'sample_state_proofs.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'proofs_unsat':len(rows)}),flush=True)
if __name__=='__main__':main()
