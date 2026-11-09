#!/usr/bin/env python3
"""Four sealed incoming contexts, universal u32 entropy/ABI-clobber SSA paths.
O(C*(prefix bytes+V+events+serialized expression bytes)) time/space. Prefix
journal was independently replayed previously; all bytes/read consistency
rechecked on restore. New source expressions stay exact via ordered SSA.
"""
import base64,hashlib,json,zlib
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE
from daemon_entropy_return_restore import restore

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 base=json.loads((ROOT/'daemon_arena_storage_profiles.json').read_text());prior=json.loads((ROOT/'daemon_context_transfer_profiles.json').read_text());rows=[];pool={}
 for context in prior['cases']:
  index=context['prior_case_index'];v=restore(base['cases'][index],context);v.model_return();b=v.run_return();assert b['pc']=='0x1002dc308'and len(v.origins)==112
  writes=[{'pc':s['pc'],**e}for s in v.steps for e in s['events']if e['kind']=='write'];payload={'steps':v.steps,'boundary':b,'definitions':v.definitions,'api_effects':v.api_effects,'origins':[{'address':hex(a),**o}for a,o in sorted(v.origins.items())],'writes':writes,'changed_bytes':[{'address':hex(a),'value':v.shape(v.bytes[a],1)}for a in sorted(v.changed)]}
  rows.append({'prior_case_index':index,'frame_SP':hex(v.F),'heap_base':hex(v.H),'steps':len(v.steps),'definitions':len(v.definitions),'write_count':len(writes),'fixup_addresses':[hex(a)for a in sorted(v.fixups)],'loader_zero_reads':v.zero_reads,'payload_zlib_base64':base64.b64encode(zlib.compress(json.dumps(payload,separators=(',',':')).encode())).decode()});pool.update(v.pool);print(json.dumps({'case':index,'steps':len(v.steps),'writes':len(writes),'definitions':len(v.definitions),'boundary':b['pc']}),flush=True)
 deps=['daemon_entropy_return_symbolic.py','daemon_entropy_return_restore.py','daemon_context_transfer_profiles.json','daemon_context_transfer_replays.json','daemon_arena_storage_profiles.json','daemon_context_transfer_symbolic.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'instruction_pool':list(pool.values()),'cases':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_entropy_return_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'contexts':len(rows),'visits':sum(r['steps']for r in rows),'source_instructions':len(pool)}),flush=True)
if __name__=='__main__':main()
