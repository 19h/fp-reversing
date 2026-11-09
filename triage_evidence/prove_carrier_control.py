#!/usr/bin/env python3
"""Local bit-vector equivalences only; no path/native reachability proof.

Four independent fixed-width queries; solver complexity is solver-dependent.
"""
import hashlib,json
from pathlib import Path
import z3
from kext_port_tools import ROOT
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=z3.BitVec('record_pointer64',64);e=z3.BitVec('entry_SP64',64)
 m=0x22fc8be22829caf1;raw=(((p&m)*2-p+0xdd03741dd7d6350e)^0x3c0a40f8ad6dcc8b)*0xded29631;compact=(p^0xe10934e57abbf985)*0xded29631
 probes=[('preparer_key64',raw!=compact),('preparer_selector32',z3.Extract(31,0,raw)!=z3.Extract(31,0,compact)),('first_frame_alias',(e-0x80+0x70-0xe8)!=(e-0x80-0x1070+0xff8)),('second_frame_alias',(e-0x60+0x50-0xe8)!=(e-0x60-0x600+0x568))];rows=[]
 for name,query in probes:
  s=z3.Solver();s.add(query);r=str(s.check());assert r=='unsat';out=ROOT/f'carrier_control_{name}.smt2';out.write_text(s.to_smt2());rows.append({'name':name,'file':out.name,'sha256':sha(out),'result':r})
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'contracts_sha256':sha(ROOT/'carrier_control_contracts.json'),'proofs':rows,'z3_version':z3.get_version_string(),'native_target_executed':False,'entry_reachability_proved':False,'full_goal_complete':False};(ROOT/'carrier_control_proofs.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'proofs_unsat':len(rows)}),flush=True)
if __name__=='__main__':main()
