#!/usr/bin/env python3
"""Seal the bounded operation-dispatch increment and preserve prior artifacts.
O(prior artifact bytes + report links) time, O(manifest + largest JSON) space.
Only six owned existing index/publisher paths may change. No native target use.
"""
import ast,hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
REPORTS=['daemon_mig_handover_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['capture_daemon_mig_handover.py','daemon_mig_handover_symbolic.py','prove_daemon_mig_handover.py','validate_daemon_mig_handover.py','seal_daemon_mig_handover.py','verify_daemon_mig_handover_publication.py']
EVIDENCE=['daemon_mig_handover_source.json','daemon_mig_handover_symbolic.json','daemon_mig_handover_proofs.json','daemon_mig_handover_checks.json']
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 prior=ROOT/'daemon_mig_handover_prior_manifest.json';assert sha(prior)=='2a12909f939b5e16c01b1f3d8f67a8804a99752abf91b3286c1162fc94954b6b';m=json.loads(prior.read_text());assert len(m['files'])==4975;changed=[];unchanged=0
 for r in m['files']:
  p=BASE/r['path'];assert p.is_file();h=sha(p)
  if r['path']in CHANGED:assert h!=r['sha256'];changed.append({'path':r['path'],'prior_sha256':r['sha256'],'sha256':h})
  else:assert h==r['sha256']and p.stat().st_size==r['size_bytes'],r['path'];unchanged+=1
 assert {r['path']for r in changed}==CHANGED and unchanged==4969
 for r in m['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and(BASE/r['path']).stat().st_size==r['size_bytes']
 assert sha('/Users/___/Downloads/zut/fairplayd.arm64e')=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 objects=[json.loads((ROOT/n).read_text())for n in EVIDENCE];source,symbolic,proofs,checks=objects
 for obj,script in zip(objects,SCRIPTS[:4],strict=True):
  assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h,(script,n)
 assert len(bytes.fromhex(source['copy_helper']['bytes_hex']))==604 and len(source['post_copy_source_spans'])==5
 assert source['cursor_decode']['target']=='0x1010b8d10'and source['cached_cursor_native_value']=='unknown'
 assert len(symbolic['cases'])==3 and len(proofs['proofs'])==14
 meta=proofs['metadata'];assert meta['total_source_copy_calls']==5 and not meta['native_callee_effects_executed']and not meta['cached_runtime_word_value_known']
 ledgers={(r['operation32'],r['class']):r for r in meta['record_ledgers']}
 assert len(ledgers[('0xad952088','any')]['defined_record_offsets'])==104 and len(ledgers[('0xad952088','any')]['undefined_record_offsets'])==24
 assert len(ledgers[('0xa70e6eb4','allnonnull')]['defined_record_offsets'])==28 and len(ledgers[('0xa70e6eb4','allnonnull')]['undefined_record_offsets'])==12
 assert {r['target']for r in meta['next_call_targets']}=={'0x1004d4268','0x10046ef4c'}
 guard=0x680004f230+0x10d38
 for case in symbolic['cases']:
  for event in case['effects']:
   if event['kind']=='write':
    a=int(event['address'],16);assert not(a<guard+8 and guard<a+event['size_bytes'])
 assert checks['all_checks_pass']and checks['symbolic_source_uses_Z3_scalar_semantics']and checks['CPU_replay_uses_Unicorn']
 for flag in ['native_target_executed','host_API_executed','new_port_emission_established','idb_mutated','native_callee_effects_executed','cached_runtime_word_value_known','full_goal_complete']:assert checks[flag]is False
 assert checks['verified_counts']=={'symbolic_cases':3,'source_obligations_rebuilt':14,'accepted_SMT_files':28,'source_copy_calls':5,'continuous_A64_cases':24,'isolated_component_cases':68,'isolated_component_A64_instructions':1088,'record128_defined_bytes':104,'record40_defined_bytes':28,'record128_undefined_bytes':24,'record40_undefined_bytes':12}
 assert checks['independent_A64_totals']['source_visits']==46832 and len(checks['fresh_replay_cases'])==24
 smt={r[k]for r in proofs['proofs']for k in ['file','original_file']};assert len(smt)==28 and smt=={p.name for p in ROOT.glob('daemon_mig_handover_*.smt2')}
 for r in proofs['proofs']:assert r['result']=='unsat'and sha(ROOT/r['file'])==r['sha256']and sha(ROOT/r['original_file'])==r['original_sha256']
 for n in SCRIPTS:ast.parse((ROOT/n).read_text(),filename=n)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| MH'+str(j)+' |'in report for j in range(1,11))and all('QG'+str(j)+':'in report for j in range(1,8))
 links=0
 for n in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/n).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   p=Path(raw.split('#',1)[0]);p=p if p.is_absolute()else BASE/p
   if p.name not in ['daemon_mig_handover_delivery.json','daemon_mig_handover_quality_gates.json']:assert p.exists(),(n,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':4975,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'accepted_SMT_files':28,'Python_syntax_checks':len(SCRIPTS),'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/'daemon_mig_handover_delivery.json').write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Two post-copy private handovers, distinct128/40-byte layouts, scalar/byte caller consumers and source copy composition. Native admission, cached/runtime returned words, callee effects and deeper joins unproved.','generator_sha256':sha(__file__),'verified_counts':checks['verified_counts'],'independent_A64_totals':checks['independent_A64_totals'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in EVIDENCE},'native_target_executed':False,'host_API_executed':False,'idb_mutated':False,'fresh_IDA_query_performed':False,'new_port_emission_established':False,'all_native_setup_states_covered':False,'later_emitter_epoch_join_established':False,'full_goal_complete':False,'goal_status':'active'}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', MH1-MH10, original bytes/fixups, rebuilt SMT, continuous private CPU witnesses and prior artifact preservation'}
 (ROOT/'daemon_mig_handover_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_checked':4975,'unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
