#!/usr/bin/env python3
"""Original continuation from the first twist read, with exact finite reads.
O(contexts*(snapshots+visits+effects+SSA bytes)) time/space plus bounded
solver queries. Explicit unsupported frontiers remain incomplete.
"""
import base64,hashlib,json,sys,zlib
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE
from daemon_prng_output_symbolic import Output,START

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 base=json.loads((ROOT/'daemon_arena_storage_profiles.json').read_text());prefix=json.loads((ROOT/'daemon_context_transfer_profiles.json').read_text());entropy=json.loads((ROOT/'daemon_entropy_return_profiles.json').read_text());material=json.loads((ROOT/'daemon_seed_material_profiles.json').read_text());rows=[];pool={};wanted=[int(x)for x in sys.argv[1:]]or[0,1,16,17]
 for c in [x for x in material['cases']if x['prior_case_index']in wanted]:
  index=c['prior_case_index'];v=Output.from_material(base['cases'][index],next(x for x in prefix['cases']if x['prior_case_index']==index),next(x for x in entropy['cases']if x['prior_case_index']==index),c);error=None
  try:b=v.run_from(START,limit=200000)
  except AssertionError as e:error=str(e);b={'pc':hex(v.pc),'unsupported_frontier':error,'registers31':[v.shape(v.read('x'+str(j)),8)for j in range(31)],'SP':hex(v.concrete(v.read('sp'),'SP'))}
  payload={'steps':v.steps,'boundary':b,'definitions':v.definitions,'lookups':v.lookups,'proof_rejections':v.proof_rejections,'origins':[{'address':hex(a),**o}for a,o in sorted(v.origins.items())],'changed_bytes':[{'address':hex(a),'value':v.shape(v.bytes[a],1)}for a in sorted(v.changed)]};rows.append({'prior_case_index':index,'frame_SP':hex(v.F),'heap_base':hex(v.H),'steps':len(v.steps),'definitions':len(v.definitions),'finite_reads':len(v.lookups),'fixup_addresses':[hex(a)for a in sorted(v.fixups)],'loader_zero_reads':v.zero_reads,'reached_checkpoint':error is None,'payload_zlib_base64':base64.b64encode(zlib.compress(json.dumps(payload,separators=(',',':')).encode())).decode()});pool.update(v.pool);print(json.dumps({'case':index,'visits':len(v.steps),'finite_reads':len(v.lookups),'boundary':b,'error':error}),flush=True)
 deps=['daemon_prng_output_runner.py','daemon_prng_output_symbolic.py','daemon_seed_material_symbolic.py','daemon_seed_material_profiles.json','daemon_context_transfer_profiles.json','daemon_entropy_return_profiles.json','daemon_arena_storage_profiles.json'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'instruction_pool':list(pool.values()),'cases':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_prng_output_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(x['steps']for x in rows),'pool':len(pool)}),flush=True)
if __name__=='__main__':main()
