#!/usr/bin/env python3
"""Owned-path preservation, fresh static/solver recapture and scoped gates."""
import ast,json,re
from pathlib import Path
from recover_daemon_reader_context_footprint import ROOT,P,FLAGS,sha,build
from validate_daemon_reader_context_footprint import verify,certificates,alterations
BASE=ROOT.parent
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','daemon_existing_scalar_reader_report.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['recover_'+P+'.py','validate_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='6c3d78f082d763711912e555e97ee5780460ac17a18fbd34fce01a4a8f5b9215'
 m=json.loads(prior.read_text());assert len(m['files'])==7208;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert q.is_file();digest=sha(q)
  if row['path']in CHANGED:assert digest!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':digest})
  else:assert digest==row['sha256']and q.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==7201 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 assert sha('/Users/___/Downloads/zut/annotated-strace-rax-user.txt')=='78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e'
 s=json.loads((ROOT/(P+'_source.json')).read_text());c=json.loads((ROOT/(P+'_checks.json')).read_text());assert verify(s)and c['all_checks_pass']and c['dependencies'][P+'_source.json']==sha(ROOT/(P+'_source.json'))
 pp,tr=certificates(s);assert c['proofs']==pp and c['translations']==tr and c['alterations']==alterations(s)
 counts=c['verified_counts'];assert counts=={'source_ranges': 2, 'source_instructions': 392, 'source_bytes': 1568, 'preparation_instructions': 386, 'preparation_translated_nonbranch_instructions': 385, 'loads': 29, 'frame_loads': 28, 'table_loads': 1, 'u64_frame_loads': 22, 'u16_frame_loads': 6, 'frame_read_bytes': 188, 'table_read_bytes': 8, 'stores': 50, 'u64_stores': 44, 'u32_stores': 6, 'frame_write_bytes': 376, 'frame_read_upper_bound_bytes': 44616, 'frame_write_lower_bound_bytes': 2024, 'frame_write_upper_bound_bytes': 2492, 'nuisance_loads': 25, 'critical_store_fields': 6, 'projected_terminal_registers': 24, 'word_input_census_instructions': 484, 'word_input_census_bytes': 1936, 'word_input_GPRs': 22, 'compiler_container_extent_bytes': 2175420, 'prefix_stack_reservation_bytes': 64, 'retained_found_entries': 0, 'affine_cache_candidates': 50, 'affine_candidate_probe_assignments': 2, 'nuisance_cache_stores': 44, 'abstract_nuisance_input_bits': 1312, 'queries_unsat': 56, 'counterexamples_sat': 1, 'affine_cache_relations_proved': 50, 'nuisance_values_inverted': 25, 'distinct_preparation_sites_translated': 385, 'two_run_instruction_instances': 770, 'SSA_definitions_per_run': 335, 'rejected_alterations': 5}
 for obj,script in[(s,SCRIPTS[0]),(c,SCRIPTS[1])]:
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,digest in obj.get('dependencies',{}).items():assert sha(ROOT/n)==digest
 assert sha(c['solver']['path'])==c['solver']['sha256']and not c['full_cache_noninterference']and not c['native_frame_owner_proved']
 for n in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/n).read_text(),filename=n)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| CF'+str(j)+' |'in report for j in range(1,8))and all('QG'+str(j)+':'in report for j in range(1,8))
 links=0
 for n in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/n).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:assert q.exists(),(n,raw)
   links+=1
 d={'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':7208,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':5,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False}
 (ROOT/(P+'_delivery.json')).write_text(json.dumps(d,indent=2)+'\n')
 g={'scope':c['static_scope'],'generator_sha256':sha(__file__),'verified_counts':counts,'static_scope':c['static_scope'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_checks.json']+SCRIPTS},'goal_status':'active',**{k:False for k in FLAGS}}
 for j in range(1,8):g['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+' and CF1-CF7;392 captured instructions,385 preparation instructions/335 definitions per copy,28 frame reads/188 B,one8 B table read,50 affine stores/376 B. Fifty-six UNSAT certificates,one SAT whole-cache counterexample and five altered-ledger controls. Selected six-field/24-register projection independent of25 nuisance cuts;all25 values invertible from other cache cells. Compiler metadata/prefix and working-SP owner remain distinct. Native owner/initialization/PAC/peer and daemon-kext pairing remain unproved.'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(g,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
