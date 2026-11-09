#!/usr/bin/env python3
"""Read-only source/solver recapture and owned delivery ledgers.
O(prior bytes + source bytes + links); bit-vector solver cost is separate.
"""
import ast,json,re
from pathlib import Path
from recover_daemon_scalar_field_population import ROOT,P,FLAGS,sha,build
from validate_daemon_scalar_field_population import verify,proofs,alterations
BASE=ROOT.parent
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','daemon_builder_owner_join_report.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['recover_'+P+'.py','validate_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
SOURCE_COUNTS={'primary_fragments': 14, 'primary_instructions': 275, 'primary_bytes': 1100, 'helper_instructions': 5497, 'helper_bytes': 21988, 'helper_projection_ranges': 4, 'helper_projection_instructions': 22, 'helper_direct_SP_accesses': 44, 'helper_semantic_incoming_GPRs': 0, 'helper_initial_X0_uses': 1, 'helper_output_width_bits': 64, 'pointer_records': 23, 'branch_slot_modifiers_checked': 21, 'bank_inputs_checked': 256, 'retained_profiles': 12, 'lookup_miss_population_episodes': 12, 'typed_scalar_constructions': 12, 'found_value_entries_observed': 0, 'wire_field_instances': 12, 'IDA_knowledge_queries': 3, 'IDA_semantic_facts_used': 0, 'prior_ranges': 78, 'prior_bytes': 9672}
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='36598de339198ca97df3e90d9e4d27e5d2df71df43f985dc1f372d56ac0ea36e'
 m=json.loads(prior.read_text());assert len(m['files'])==7178;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert q.is_file();digest=sha(q)
  if row['path']in CHANGED:
   assert digest!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':digest})
  else:assert digest==row['sha256']and q.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==7171 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 assert sha('/Users/___/Downloads/zut/fairplayd.arm64e')=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 assert sha('/Users/___/Downloads/zut/annotated-strace-rax-user.txt')=='78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e'
 s=json.loads((ROOT/(P+'_source.json')).read_text());c=json.loads((ROOT/(P+'_checks.json')).read_text())
 assert s==build()and verify(s)and c['source_recapture_match']and c['all_checks_pass']
 pp,tr=proofs(s);assert c['proofs']==pp and c['translations']==tr and c['alterations']==alterations(s)
 assert c['all_primary_nonbranch_noncall_and_projected_instructions_covered_once']and not c['whole_helper_value_semantics_proved']
 sites=[pc for gs in tr.values()for g in gs for pc in g['source_sites']]
 expected=[i['ea']for f in s['fragments'].values()for i in f['instructions']if i['mnemonic']not in('braa','blraa')]
 assert sorted(sites)==sorted(expected)and len(sites)==len(set(sites))==282
 assert len(s['original_fixup_checks']['records'])==23
 assert len(s['branch_edges'])==14 and sum(len(e['selected_slots'])for e in s['branch_edges'])==21
 for obj,script in[(s,SCRIPTS[0]),(c,SCRIPTS[1])]:
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,digest in obj.get('dependencies',{}).items():assert sha(ROOT/n)==digest
 counts=c['verified_counts'];assert counts=={'primary_fragments': 14, 'primary_instructions': 275, 'primary_bytes': 1100, 'helper_instructions': 5497, 'helper_bytes': 21988, 'helper_projection_ranges': 4, 'helper_projection_instructions': 22, 'helper_direct_SP_accesses': 44, 'helper_semantic_incoming_GPRs': 0, 'helper_initial_X0_uses': 1, 'helper_output_width_bits': 64, 'pointer_records': 23, 'branch_slot_modifiers_checked': 21, 'bank_inputs_checked': 256, 'retained_profiles': 12, 'lookup_miss_population_episodes': 12, 'typed_scalar_constructions': 12, 'found_value_entries_observed': 0, 'wire_field_instances': 12, 'IDA_knowledge_queries': 3, 'IDA_semantic_facts_used': 0, 'prior_ranges': 78, 'prior_bytes': 9672, 'component_queries_unsat': 21, 'translated_instruction_instances': 282, 'SSA_definitions': 255, 'rejected_alterations': 10, 'byte_memory_joins': 1}
 assert s['verified_source_counts']==SOURCE_COUNTS
 assert sha(s['fixup_reference']['command'][0])==s['fixup_reference']['tool_sha256'];assert sha(c['solver']['path'])==c['solver']['sha256']
 for n in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/n).read_text(),filename=n)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| SG'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8))
 links=0
 for n in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/n).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:assert q.exists(),(n,raw)
   links+=1
 d={'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':7178,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':5,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False}
 (ROOT/(P+'_delivery.json')).write_text(json.dumps(d,indent=2)+'\n')
 quality={'scope':c['static_scope'],'generator_sha256':sha(__file__),'verified_counts':counts,'static_scope':c['static_scope'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_checks.json']+SCRIPTS},'goal_status':'active',**{k:False for k in FLAGS}}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+' and SG1-SG8;14 main fragments/275 instructions,complete5497-instruction helper and four22-instruction projections;23 original pointers,21 slot/modifier matches,256 bank cases,21 UNSAT components,282 selected translations/255 definitions and10 rejected alterations. Full helper value semantics and found-value workflow remain unproved. Source64-bit output/32-bit consumer/C1 scalar join is conditional;12 frozen fields establish model bytes,inferred low word is not a snapshot. Read-only IDA knowledge yielded no relevant checked fact. Native state/owners/PAC and daemon-kext pairing remain unknown.'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(quality,indent=2)+'\n')
 print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
