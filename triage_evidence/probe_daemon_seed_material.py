#!/usr/bin/env python3
"""Four universal time/entropy material continuations from sealed source states.
O(C*(prefix+source visits+events+serialized SSA bytes)) time/space. Imported
returns/output fields are declared inputs; no native API executes. Unsupported
frontiers are retained explicitly and do not count as completed paths.
"""
import base64,hashlib,json,zlib,sys
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE
from daemon_seed_material_symbolic import Material

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 base=json.loads((ROOT/'daemon_arena_storage_profiles.json').read_text());prefix=json.loads((ROOT/'daemon_context_transfer_profiles.json').read_text());entropy=json.loads((ROOT/'daemon_entropy_return_profiles.json').read_text());rows=[];pool={}
 wanted=[int(x)for x in sys.argv[1:]]or[0,1,16,17]
 for context in [x for x in entropy['cases']if x['prior_case_index']in wanted]:
  index=context['prior_case_index'];v=Material.from_sealed(base['cases'][index],next(x for x in prefix['cases']if x['prior_case_index']==index),context);error=None
  try:b=v.run_material()
  except AssertionError as e:error=str(e);b={'pc':hex(v.pc),'unsupported_frontier':error,'registers31':[v.shape(v.read('x'+str(j)),8)for j in range(31)],'SP':hex(v.concrete(v.read('sp'),'SP'))}
  payload={'steps':v.steps,'boundary':b,'definitions':v.definitions,'api_models':v.api_models,'origins':[{'address':hex(a),**o}for a,o in sorted(v.origins.items())],'phases':v.phases,'time_input_unknown_offsets':v.time_input_unknown,'changed_bytes':[{'address':hex(a),'value':v.shape(v.bytes[a],1)}for a in sorted(v.changed)]};rows.append({'prior_case_index':index,'frame_SP':hex(v.F),'heap_base':hex(v.H),'steps':len(v.steps),'definitions':len(v.definitions),'fixup_addresses':[hex(a)for a in sorted(v.fixups)],'loader_zero_reads':v.zero_reads,'completed_to_call_boundary':error is None,'payload_zlib_base64':base64.b64encode(zlib.compress(json.dumps(payload,separators=(',',':')).encode())).decode()});pool.update(v.pool);print(json.dumps({'case':index,'steps':len(v.steps),'definitions':len(v.definitions),'boundary':b['pc'],'error':error}),flush=True)
 deps=['daemon_seed_material_symbolic.py','daemon_entropy_return_symbolic.py','daemon_entropy_return_restore.py','daemon_context_transfer_profiles.json','daemon_entropy_return_profiles.json','daemon_arena_storage_profiles.json'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'instruction_pool':list(pool.values()),'cases':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_seed_material_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'contexts':len(rows),'visits':sum(r['steps']for r in rows),'source_instructions':len(pool),'all_reach_next_call':all(r['completed_to_call_boundary']for r in rows)}),flush=True)
if __name__=='__main__':main()
