#!/usr/bin/env python3
"""Owned-path preservation, fresh static/solver recapture and scoped gates."""
import ast,json,re
from pathlib import Path
from recover_daemon_context_input_producers import ROOT,P,FLAGS,sha,build
from validate_daemon_context_input_producers import verify,certificates,alterations
BASE=ROOT.parent
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','daemon_reader_context_footprint_report.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['recover_'+P+'.py','validate_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='3988cec4d74a41915869552d21620e973b4d93c2e97c0f7269f07bfed4190662'
 m=json.loads(prior.read_text());assert len(m['files'])==7228;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert q.is_file();digest=sha(q)
  if row['path']in CHANGED:assert digest!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':digest})
  else:assert digest==row['sha256']and q.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==7221 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 assert sha('/Users/___/Downloads/zut/annotated-strace-rax-user.txt')=='78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e'
 s=json.loads((ROOT/(P+'_source.json')).read_text());c=json.loads((ROOT/(P+'_checks.json')).read_text());assert verify(s)and c['all_checks_pass']and c['dependencies'][P+'_source.json']==sha(ROOT/(P+'_source.json'))
 pp,tr,summ=certificates(s);assert c['proofs']==pp and c['translations']==tr and c['tag_stage_summaries']==summ and c['alterations']==alterations(s)
 counts=c['verified_counts'];assert counts=={'text_bytes': 14849960, 'aligned_text_words': 3712490, 'candidate_writers': 25, 'covered_context_inputs': 25, 'u64_candidate_writers': 19, 'u16_candidate_writers': 6, 'candidate_windows': 25, 'candidate_window_instruction_instances': 90, 'candidate_stage_entries': 20, 'candidate_stage_instruction_instances': 504, 'tag_return_stages': 6, 'tag_dispatch_prefix_instructions': 4, 'word_dispatch_prefix_instructions': 2, 'common_word_call_instructions': 7, 'carried_target_liveness_instructions': 688, 'pointer_records': 14, 'candidate_writer_PCs_on_retained_path': 0, 'IDA_knowledge_queries': 2, 'IDA_semantic_facts_used': 0, 'queries_unsat': 34, 'counterexamples_sat': 1, 'translated_instruction_instances': 201, 'SSA_definitions': 149, 'rejected_alterations': 6}
 for obj,script in[(s,SCRIPTS[0]),(c,SCRIPTS[1])]:
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,digest in obj.get('dependencies',{}).items():assert sha(ROOT/n)==digest
 assert sha(c['solver']['path'])==c['solver']['sha256']and not c['all_aliases_excluded']and not c['same_active_frame_reaching_definition_proved']
 for n in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/n).read_text(),filename=n)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| CP'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8))
 links=0
 for n in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/n).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:assert q.exists(),(n,raw)
   links+=1
 d={'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':7228,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':5,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False}
 (ROOT/(P+'_delivery.json')).write_text(json.dumps(d,indent=2)+'\n')
 g={'scope':c['static_scope'],'generator_sha256':sha(__file__),'verified_counts':counts,'static_scope':c['static_scope'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_checks.json']+SCRIPTS},'goal_status':'active',**{k:False for k in FLAGS}}
 for j in range(1,8):g['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+' and CP1-CP8;25 original-text local SP-affine candidates,90 window and504 stage instruction instances,six tag-to-word ABI contracts,14 original fixup records and688 helper liveness instructions. Thirty-four UNSAT queries,one SAT raw32/low16 distinction and six changed-ledger controls. Read-only IDA knowledge is retained but unused semantically. All-alias exhaustiveness,same-active-frame reaching definitions,native initialization,PAC/endpoints and daemon-kext pairing remain unproved.'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(g,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
