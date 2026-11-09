#!/usr/bin/env python3
"""Owned-path preservation, fresh static/solver recapture and scoped gates."""
import ast,json,re
from pathlib import Path
from recover_daemon_outer_record_ingress import ROOT,P,FLAGS,sha,build
from validate_daemon_outer_record_ingress import verify,certificates,alterations
BASE=ROOT.parent
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','daemon_reader_option_default_report.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['recover_'+P+'.py','validate_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
from verify_daemon_outer_record_ingress_publication import sha,read,exists,size

def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='9ccb37994293e6567823e2f33b93395fb78a003e355baa04489e4221dcb29a9d'
 m=json.loads(read(prior));assert len(m['files'])==7348;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert exists(q);digest=sha(q)
  if row['path']in CHANGED:assert digest!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':digest})
  else:assert digest==row['sha256']and size(q)==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==7341 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
 assert sha('/Users/___/Downloads/zut/annotated-strace-rax-user.txt')=='78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e'
 s=json.loads(read(ROOT/(P+'_source.json')));c=json.loads(read(ROOT/(P+'_checks.json')));assert verify(s)and c['all_checks_pass']and c['dependencies'][P+'_source.json']==sha(ROOT/(P+'_source.json'))
 pp,tr,ctx=certificates(s);assert c['proofs']==pp and c['translations']==tr and c['alterations']==alterations(s)
 counts=c['verified_counts'];assert counts=={'source_fragments': 27, 'source_instruction_instances': 675, 'source_bytes': 2700, 'branch_terminated_ranges': 27, 'pointer_records': 35, 'branch_slot_modifier_matches': 41, 'bank_inputs_checked': 256, 'prior_ranges_recaptured': 88, 'prior_bytes_recaptured': 13064, 'source_SP_writes': 0, 'new_queries_unsat': 37, 'reused_queries_unsat': 3, 'counterexamples_sat': 1, 'distinct_translated_instruction_sites': 647, 'translated_instruction_instances': 690, 'SSA_definitions': 651, 'rejected_alterations': 6}
 for obj,script in[(s,SCRIPTS[0]),(c,SCRIPTS[1])]:
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,digest in obj.get('dependencies',{}).items():assert sha(ROOT/n)==digest
 assert sha(c['solver']['path'])==c['solver']['sha256']and c['wire_to_constructor_operands_proved']and not c['complete_parser_proved']
 for n in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse(read(ROOT/n),filename=n)
 report=read(BASE/REPORTS[0]);assert report.isascii()and all('| OI'+str(j)+' |'in report for j in range(1,11))and all('QG'+str(j)+':'in report for j in range(1,8))
 links=0
 for n in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',read(BASE/n)):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:assert exists(q),(n,raw)
   links+=1
 d={'preservation_basis':'Decoded logical artifact bytes;canonical JSON may reside in .json.zst after external migration. Seven owned logical-content updates remain explicit.','generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':7348,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':5,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False}
 (ROOT/(P+'_delivery.json')).write_text(json.dumps(d,indent=2)+'\n')
 g={'scope':c['static_scope'],'generator_sha256':sha(__file__),'verified_counts':counts,'static_scope':c['static_scope'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_checks.json']+SCRIPTS},'goal_status':'active',**{k:False for k in FLAGS}}
 for j in range(1,8):g['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+' and OI1-OI10;plain-wire header,complete three-type forest,scalar XOR operands,borrowed span,generic constructor,cursor and zero-ID termination,local first-child publication and error frontier.27 source ranges/675 instructions,647 modeled PCs/690 instances/651 definitions,37 new plus3 replayed UNSAT,one interpretation counterexample,six integrity controls. Frame/owner/native/PAC,complete constructor/parser/cleanup and daemon-kext pairing remain unproved.'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(g,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
