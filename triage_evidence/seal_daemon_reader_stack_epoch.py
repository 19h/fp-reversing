#!/usr/bin/env python3
"""Owned-path preservation, fresh static/solver recapture and scoped gates."""
import ast,json,re
from pathlib import Path
from recover_daemon_reader_stack_epoch import ROOT,P,FLAGS,sha,build
from validate_daemon_reader_stack_epoch import verify,certificates,alterations
BASE=ROOT.parent
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','daemon_reader_context_footprint_report.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['recover_'+P+'.py','validate_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='6a253be5566fdcb70a5d7586f0ce6599fb1a0856abccf056e7820e5a6678c415'
 m=json.loads(prior.read_text());assert len(m['files'])==7218;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert q.is_file();digest=sha(q)
  if row['path']in CHANGED:assert digest!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':digest})
  else:assert digest==row['sha256']and q.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==7211 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 assert sha('/Users/___/Downloads/zut/annotated-strace-rax-user.txt')=='78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e'
 s=json.loads((ROOT/(P+'_source.json')).read_text());c=json.loads((ROOT/(P+'_checks.json')).read_text());assert verify(s)and c['all_checks_pass']and c['dependencies'][P+'_source.json']==sha(ROOT/(P+'_source.json'))
 pp,tr=certificates(s);assert c['proofs']==pp and c['profile_SP_summaries']==tr and c['alterations']==alterations(s)
 counts=c['verified_counts'];assert counts=={'profiles': 12, 'unique_path_intervals': 149, 'unique_path_instruction_sites': 11885, 'prefix_instructions': 18, 'path_plus_prefix_unique_sites': 11901, 'profile_interval_instances': 6367, 'profile_instruction_instances': 966122, 'internal_helper_calls': 108, 'import_calls': 180, 'extension_ranges': 36, 'extension_instruction_instances': 2422, 'extension_unique_instruction_sites': 1549, 'extension_SP_writes': 0, 'core_saved_bytes': 128, 'core_local_bytes': 68944, 'core_total_reservation_bytes': 69072, 'helper_local_bytes': 192, 'minimum_SP_below_entry_bytes': 69264, 'reader_frame_read_bound_bytes': 44616, 'reader_frame_bound_headroom_bytes': 24328, 'queries_unsat': 21, 'counterexamples_sat': 1, 'source_SP_updates_per_profile': 20, 'milestone_equalities_per_profile': 11, 'rejected_alterations': 5}
 for obj,script in[(s,SCRIPTS[0]),(c,SCRIPTS[1])]:
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,digest in obj.get('dependencies',{}).items():assert sha(ROOT/n)==digest
 assert sha(c['solver']['path'])==c['solver']['sha256']and not c['native_mapping_proved']and not c['fresh_runtime_replay']and c['import_callee_SP_preservation_is_premise']
 for n in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/n).read_text(),filename=n)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| SE'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8))
 links=0
 for n in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/n).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:assert q.exists(),(n,raw)
   links+=1
 d={'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':7218,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':5,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False}
 (ROOT/(P+'_delivery.json')).write_text(json.dumps(d,indent=2)+'\n')
 g={'scope':c['static_scope'],'generator_sha256':sha(__file__),'verified_counts':counts,'static_scope':c['static_scope'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_checks.json']+SCRIPTS},'goal_status':'active',**{k:False for k in FLAGS}}
 for j in range(1,8):g['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+' and SE1-SE8;12 frozen paths/6367 intervals/966122 audited instruction instances,149 unique intervals,11901 unique path-prefix sites,108 balanced helper calls and180 modeled imports. Thirty-six source-only no-SP-write/call ranges extend the reader contract. Twenty-one UNSAT queries,one SAT import-preservation premise control and five altered-ledger controls. Conditional K=F=E-0x10dd0;68944 B locals contain the44616 B reader bound with24328 B headroom. Native mapping,initialization,PAC,callee/endpoint identity and daemon-kext pairing remain unproved.'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(g,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
