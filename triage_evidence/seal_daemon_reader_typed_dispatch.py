#!/usr/bin/env python3
"""Owned-path preservation, fresh static/solver recapture and scoped gates."""
import ast,json,re
from pathlib import Path
from recover_daemon_reader_typed_dispatch import ROOT,P,FLAGS,sha,build
from validate_daemon_reader_typed_dispatch import verify,certificates,alterations
BASE=ROOT.parent
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','daemon_reader_extent_families_report.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['recover_'+P+'.py','validate_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='2f454a15051e30d64a3f7681e8d25474c567173763f1e5282e50fb491e0c5a54'
 m=json.loads(prior.read_text());assert len(m['files'])==7248;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert q.is_file();digest=sha(q)
  if row['path']in CHANGED:assert digest!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':digest})
  else:assert digest==row['sha256']and q.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==7241 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 assert sha('/Users/___/Downloads/zut/annotated-strace-rax-user.txt')=='78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e'
 s=json.loads((ROOT/(P+'_source.json')).read_text());c=json.loads((ROOT/(P+'_checks.json')).read_text());assert verify(s)and c['all_checks_pass']and c['dependencies'][P+'_source.json']==sha(ROOT/(P+'_source.json'))
 pp,tr,summ=certificates(s);assert c['proofs']==pp and c['translations']==tr and c['family_summaries']==summ and c['alterations']==alterations(s)
 counts=c['verified_counts'];assert counts=={'families': 5, 'source_fragments': 54, 'source_instruction_instances': 1000, 'source_bytes': 4000, 'preparation_instructions': 386, 'pointer_records': 50, 'branch_slot_modifier_matches': 63, 'source_SP_writes': 0, 'queries_unsat': 46, 'counterexamples_sat': 1, 'distinct_translated_instruction_sites': 1331, 'translated_instruction_instances': 1412, 'SSA_definitions': 1276, 'rejected_alterations': 6}
 for obj,script in[(s,SCRIPTS[0]),(c,SCRIPTS[1])]:
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,digest in obj.get('dependencies',{}).items():assert sha(ROOT/n)==digest
 assert sha(c['solver']['path'])==c['solver']['sha256']and not c['native_buffer_owner_proved']and not c['complete_accessor_semantics_proved']
 for n in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/n).read_text(),filename=n)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| TD'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8))
 links=0
 for n in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/n).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:assert q.exists(),(n,raw)
   links+=1
 d={'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':7248,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':5,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False}
 (ROOT/(P+'_delivery.json')).write_text(json.dumps(d,indent=2)+'\n')
 g={'scope':c['static_scope'],'generator_sha256':sha(__file__),'verified_counts':counts,'static_scope':c['static_scope'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_checks.json']+SCRIPTS},'goal_status':'active',**{k:False for k in FLAGS}}
 for j in range(1,8):g['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+' and TD1-TD8;five exact three-tag forests,six exact scalar extent gates,five u32 caller/word-return interfaces,N19 recognized64 entry/span pointer,and alternate-tag end/status ordering. Fifty-four source blocks/1000 instructions plus386 preparation instructions;50 original fixup records/63 slot matches;1331 distinct translated PCs,1412 instances and1276 SSA definitions. Forty-six UNSAT queries,one SAT path counterexample and six changed-ledger controls. Complete accessor publication,native cache/epoch/admission/owner/PAC/endpoints and daemon-kext pairing remain unproved.'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(g,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
