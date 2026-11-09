#!/usr/bin/env python3
"""Check common width gate/digest-length carriers across three source uses.

Reads seven full source-verified profile sets;does not execute target code.
O(profile bytes+selected edges) work/space. Not a complete verifier call graph.
"""
import hashlib,json
from pathlib import Path
from rpc502_startup_tools import unpack
ROOT=Path(__file__).resolve().parent

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 assertions=0;rows=[]
 def check(v,label):
  nonlocal assertions
  assert v,label;assertions+=1
 for name in['rpc502_late_profiles.json','rpc502_late_span_profiles.json','rpc502_late_signature_profiles.json']:
  p=json.loads((ROOT/name).read_text())
  for w in p['cases']:
   r=unpack(w);inputs=[e for e in r['parser_edges']if e['pc']=='0x10097617c'];outputs=[e for e in r['parser_edges']if e['pc']=='0x100a21ae4'];tails=[e for e in r['auth_points']if e['pc']=='0x10097531c'];check(len(inputs)==len(outputs)==3 and len(tails)==2,'three width uses/two preceding certificate records');check([int(e['registers_x0_x28'][19],16)for e in inputs]==[20,20,32],'two20-byte digest carriers then32-byte digest carrier');check([((int(e['registers_x0_x28'][13],16)-0x693be708)&0xffffffff)for e in inputs]==[64,32,32],'actual shared-gate modulus counts');widths=[int(e['registers_x0_x28'][15],16)^0x8b3dc651 for e in outputs];check(widths==[256,128,w['case']['C']],'actual shared-gate signature extents');check(all(int(e['registers_x0_x28'][12],16)==0x1daa for e in inputs),'all seven actual constrained dispatch seeds');passed=[e['target']=='0x1008aa474'for e in outputs];check(passed==[True,True,w['case']['C']==128],'actual common gate branch choices');rows.append({'case':w['case']['label'],'digest_extent_carriers_bytes':[20,20,32],'modulus_counts_limbs':[64,32,32],'signature_extents_bytes':widths,'actual_gate_admitted':passed})
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['rpc502_late_profiles.json','rpc502_late_span_profiles.json','rpc502_late_signature_profiles.json','rpc502_startup_tools.py']},'verified_counts':{'assertions':assertions,'cases':len(rows),'common_width_gate_uses':3*len(rows),'certificate_digest_carriers':2*len(rows),'later32_byte_digest_carriers':len(rows)},'case_summaries':rows,'native_target_executed':False,'all_checks_pass':True,'full_goal_complete':False};(ROOT/'rpc502_late_reuse_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out['verified_counts']),flush=True)
if __name__=='__main__':main()
