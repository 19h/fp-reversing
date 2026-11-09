#!/usr/bin/env python3
"""Read-only source/solver recapture and owned delivery ledgers.
O(prior bytes + source bytes + links); bit-vector solver cost is separate.
"""
import ast,json,re
from pathlib import Path
from recover_daemon_builder_owner_join import ROOT,P,FLAGS,sha,build
from validate_daemon_builder_owner_join import verify,proofs,alterations,EXCLUDED_QUERIES
BASE=ROOT.parent
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','daemon_collection_retirement_report.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['recover_'+P+'.py','validate_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
SOURCE_COUNTS={'fragments': 17, 'instructions': 573, 'fragment_bytes': 2292, 'pointer_records': 29, 'branch_edges': 17, 'branch_slot_modifiers_checked': 26, 'call_sites': 5, 'bank_inputs_checked': 1280, 'literal_pointer_store_candidates': 3, 'literal_census_window_bytes': 156, 'retained_profiles': 12, 'recorded_builder_allocations': 12, 'recorded_child_allocations': 24, 'recorded_child1_root_field_instances': 16, 'native_graphs_observed': 0, 'outer_cleanup_entries_observed': 0, 'prior_ranges': 63, 'prior_bytes': 4308, 'prose_compositions_corrected': 1}
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='33bffc6511ef66a22f8da40c4e414273dbd47abaedd290f66ae21b25230a4f0b'
 m=json.loads(prior.read_text());assert len(m['files'])==7168;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert q.is_file();digest=sha(q)
  if row['path']in CHANGED:
   assert digest!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':digest})
  else:assert digest==row['sha256']and q.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==7161 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 assert sha('/Users/___/Downloads/zut/fairplayd.arm64e')=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 assert sha('/Users/___/Downloads/zut/annotated-strace-rax-user.txt')=='78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e'
 s=json.loads((ROOT/(P+'_source.json')).read_text());c=json.loads((ROOT/(P+'_checks.json')).read_text())
 assert s==build()and verify(s)and c['source_recapture_match']and c['all_checks_pass']
 pp,tr,sem=proofs(s);assert c['proofs']==pp and c['translations']==tr and c['alterations']==alterations(s)
 assert c['all_nonbranch_noncall_source_instructions_covered_once']and c['semantic_rejections']==sem and c['excluded_queries']==EXCLUDED_QUERIES
 assert len(EXCLUDED_QUERIES)==2 and all(q['result']=='unknown'and not q['accepted']for q in EXCLUDED_QUERIES)
 sites=[pc for gs in tr.values()for g in gs for pc in g['source_sites']]
 expected=[i['ea']for f in s['fragments'].values()for i in f['instructions']if i['mnemonic']not in('braa','blraa')]
 assert sorted(sites)==sorted(expected)and len(sites)==len(set(sites))==551
 assert len(s['original_fixup_checks']['records'])==29
 assert len(s['branch_edges'])==17 and sum(len(e['selected_slots'])for e in s['branch_edges'])==26
 for obj,script in[(s,SCRIPTS[0]),(c,SCRIPTS[1])]:
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,digest in obj.get('dependencies',{}).items():assert sha(ROOT/n)==digest
 counts=c['verified_counts'];assert counts=={'fragments': 17, 'instructions': 573, 'fragment_bytes': 2292, 'pointer_records': 29, 'branch_edges': 17, 'branch_slot_modifiers_checked': 26, 'call_sites': 5, 'bank_inputs_checked': 1280, 'literal_pointer_store_candidates': 3, 'literal_census_window_bytes': 156, 'retained_profiles': 12, 'recorded_builder_allocations': 12, 'recorded_child_allocations': 24, 'recorded_child1_root_field_instances': 16, 'native_graphs_observed': 0, 'outer_cleanup_entries_observed': 0, 'prior_ranges': 63, 'prior_bytes': 4308, 'prose_compositions_corrected': 1, 'component_queries_unsat': 28, 'translated_instruction_instances': 551, 'SSA_definitions': 501, 'rejected_alterations': 10, 'rejected_semantic_interpretations': 2, 'compositional_memory_queries': 6, 'excluded_queries': 2}
 assert s['verified_source_counts']==SOURCE_COUNTS
 assert sha(s['fixup_reference']['command'][0])==s['fixup_reference']['tool_sha256'];assert sha(c['solver']['path'])==c['solver']['sha256']
 for n in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/n).read_text(),filename=n)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| BO'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8))
 links=0
 for n in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/n).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:assert q.exists(),(n,raw)
   links+=1
 d={'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':7168,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':5,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False}
 (ROOT/(P+'_delivery.json')).write_text(json.dumps(d,indent=2)+'\n')
 quality={'scope':c['static_scope'],'generator_sha256':sha(__file__),'verified_counts':counts,'static_scope':c['static_scope'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_checks.json']+SCRIPTS},'goal_status':'active',**{k:False for k in FLAGS}}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+' and BO1-BO8;17 fragments/573 instructions,29 original pointers,26 selected slot/modifier matches,1280 bank cases,five original call sites,28 UNSAT queries including six compositional memory components,551 unique translated instances/501 definitions,10 rejected alterations and2 SAT interpretation rejections. Two aggregate queries returned unknown and remain explicitly excluded. Corrected source X8 forwarding and128 B builder/two16 B child/80 B descriptor joins are conditional; frozen records are allocation/liveness evidence,not native heap snapshots. Native owners/PAC/public IPC pairing remain unknown.'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(quality,indent=2)+'\n')
 print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
