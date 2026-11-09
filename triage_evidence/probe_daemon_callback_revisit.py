#!/usr/bin/env python3
"""Continue the sealed callback with unknown bytes preserved as symbolic copies.
O(snapshot+source visits+effects) time/space. Source APIs/PAC never execute.
"""
import json,hashlib,base64,zlib
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE
from daemon_callback_revisit_symbolic import Revisit

def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 snap=json.loads((ROOT/'daemon_callback_revisit_snapshot.json').read_text());v=Revisit.from_snapshot(snap);boundary=v.run_revisit(int(snap['boundary']['pc'],16),limit=300000);trace={'steps':v.steps,'boundary':boundary,'origins':[{'offset':off,**data}for off,data in sorted(v.unknown_inputs_used.items())],'definitions':v.definitions,'source_pool':v.pool,'used_fixups':[hex(a)for a in sorted(v.fixups)],'changed_bytes':[{'address':hex(a),'value':v.shape(value,1)}for a,value in sorted(v.bytes.items())if a in v.changed],'initial_registers':snap['logical_registers'],'initial_NZCV':snap['NZCV']};raw=json.dumps(trace,separators=(',',':')).encode();deps=['daemon_callback_revisit_snapshot.json','daemon_callback_revisit_symbolic.py','daemon_callback_simd.py','daemon_seed_material_symbolic.py','daemon_entropy_return_symbolic.py','daemon_receive_tools.py','daemon_receive_fixups.txt'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'source_visits':len(v.steps),'source_pool_instructions':len(v.pool),'unknown_input_bytes_used':len(v.unknown_inputs_used),'boundary':boundary,'payload_zlib_base64':base64.b64encode(zlib.compress(raw)).decode(),'payload_sha256':hashlib.sha256(raw).hexdigest(),'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_callback_revisit_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'source_visits':len(v.steps),'source_pool_instructions':len(v.pool),'unknown_input_bytes_used':len(v.unknown_inputs_used),'boundary':boundary}),flush=True)
if __name__=='__main__':main()
