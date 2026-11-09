#!/usr/bin/env python3
"""Four source contexts with arbitrary 112 private bytes; compressed journals.
Concrete branch targets/addresses and copy-or-constant byte terms certify
noninterference in selected representations. O(C*(B+V+events)) time/space;
no target imports or native authentication execute.
"""
import base64,hashlib,json,zlib
from pathlib import Path
from collections import Counter
from daemon_receive_tools import ROOT,SOURCE
from daemon_context_transfer_symbolic import Transfer
INDICES=[0,1,16,17]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 base=json.loads((ROOT/'daemon_arena_storage_profiles.json').read_text());rows=[];pool={}
 for index in INDICES:
  prior=base['cases'][index];v=Transfer(prior);boundary=v.run_path();assert boundary['pc']=='0x100409574'and len(v.origins)==112 and all('hex'in x for x in boundary['registers31']);assert not any('terms'in e['value']and not(0x6400000000<=int(e['address'],16)<0x6400010000)for s in v.steps for e in s['events']if e['kind']=='write')
  fields=[]
  for off in [0x5a8,0x448,0x4b8,0x4a0,0x468,0x4a8,0x3f8,0x510,0x458,0x530,0x528,0x480,0x4c0,0x588]:
   value=v.shape(__import__('z3').Concat(*[v.bytes[v.F+off+j]for j in range(7,-1,-1)]),8);fields.append({'offset_bytes':hex(off),'final_value':value})
  origins=[{'address':hex(a),**o}for a,o in sorted(v.origins.items())];payload={'steps':v.steps,'boundary':boundary,'origins':origins,'final_source_fields':fields,'changed_bytes':[{'address':hex(a),'value':v.shape(x,1)}for a,x in sorted(v.bytes.items())if a in v.changed]}
  rows.append({'prior_case_index':index,'input':prior['input'],'frame_SP':hex(v.F),'heap_base':hex(v.H),'steps':len(v.steps),'scalar_four_byte_writes':sum(s['pc']=='0x1003be568'for s in v.steps),'scalar_buffer_writes':sum(s['pc']=='0x1004c8398'for s in v.steps),'symbolic_unknown_bytes':len(origins),'fixup_addresses':[hex(a)for a in sorted(v.fixups)],'loader_zero_reads':v.zero_reads,'payload_zlib_base64':base64.b64encode(zlib.compress(json.dumps(payload,separators=(',',':')).encode())).decode()});pool.update(v.pool);print(json.dumps({'case':index,'steps':len(v.steps),'unknown_bytes':len(origins),'boundary':boundary['pc']}),flush=True)
 deps=['daemon_context_transfer_symbolic.py','daemon_arena_storage_profiles.json','daemon_receive_tools.py','daemon_receive_fixups.txt','lskd_values_symbolic.py','resolve_kernel_collection_interfaces.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'instruction_pool':list(pool.values()),'cases':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_context_transfer_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'contexts':len(rows),'visits':sum(r['steps']for r in rows),'source_instructions':len(pool)}),flush=True)
if __name__=='__main__':main()
