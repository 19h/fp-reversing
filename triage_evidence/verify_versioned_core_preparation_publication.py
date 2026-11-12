#!/usr/bin/env python3
"""Fresh preparation replay/audit, publication delta and decoded-path checks.

O(owned bytes+source+replays+manifest) time/space plus 30 s/query.
No native API/IPC/IDB operation or history rewrite.
"""
import json,subprocess
from pathlib import Path
from hashlib import sha256
from compression import zstd
import z3
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
import verify_corefp_late_preparation_publication as H
import recover_versioned_core_preparation as R
import audit_versioned_core_preparation as A
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='5e284860aad34840c03864bcc42041d5dae640db'
BASELINE_SHA='57ea7f7b2da093b6473f755dfe367da70ed66551fbb6c112f30374a400104e38'
CHECKS_SHA='b5a8adb34c380be6daf899d7b481a7a55e7e814b353ee24a39c076f88d781941'
AUDIT_SHA='8c4dc35c7293c4f8f0e9bf9a2381dc2ec636e63301dbd9e045d1ce5cceb53520'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md','versioned_request_abi_report.md','versioned_core_entry_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'versioned_core_preparation_report.md','triage_evidence/recover_versioned_core_preparation.py','triage_evidence/audit_versioned_core_preparation.py','triage_evidence/verify_versioned_core_preparation_publication.py','triage_evidence/versioned_core_preparation_checks.json','triage_evidence/versioned_core_preparation_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/versioned_core_preparation_checks.json','triage_evidence/versioned_core_preparation_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}

def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)

def main():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
 assert R.build()==e;fresh=A.build()
 for key in a:
  if key!='source_proofs':assert fresh[key]==a[key],key
 assert [(q['label'],q['result'])for q in a['source_proofs']]==[(q['label'],q['result'])for q in fresh['source_proofs']]and len(a['source_proofs'])==12
 for q in a['source_proofs']:
  s=z3.Solver();s.set(timeout=30000);s.from_string(q['query']);assert s.check()==z3.unsat
 assert e['verified_counts']=={'cases':28,'source_instruction_visits':131572,'write_bytes_checked':49056,'read_bytes_checked':123520,'continuation_visits':117964}
 assert a['verified_counts']=={'source_queries_unsat':12,'source_lift_instructions':238,'bank_rules':2,'bank_inputs':512,'original_pointer_records':99,'authenticated_transfers_checked':1344,'final_snapshot_bytes':18480,'complete_block_helper_returns':12}
 assert e['parent_pins']==R.PINS and e['dependencies']=={n:sha(ROOT/n)for n in R.DEPS}and e['generator_sha256']==a['generator_sha256']==sha(ROOT/('recover_'+R.P+'.py'))and a['auditor_sha256']==sha(ROOT/('audit_'+R.P+'.py'))
 assert sum(len(r['instructions'])for r in e['source_regions'])==8737 and a['normalized_common_operation']=='0xd17'and a['frame_word_census']['instruction_words_checked']==1922
 assert not a['kernel_only_cell']['normalized_file_backed']and not a['kernel_only_cell']['native_runtime_value_known']
 for obj in [e,a]:assert not obj['native_target_executed']and not obj['full_goal_complete']and obj['model_memory_writes']==0
 assert all(not row['complete_core_processing_executed']and row['prefixes_reexecuted']for row in e['cases'])and a['all_checks_pass']
 report=read(BASE/'versioned_core_preparation_report.md');assert all(f'| VP{k} |'in report for k in range(1,9))and all(f'**QG{k}**'in report for k in range(1,8))
 assert all(word in report for word in ['131,572','0x5bed6383','0xfffffe000a5a6e5c','unknown','1,922','47 B','0x0d17'])
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
 assert len(before)==len(old['files'])==8593 and len(after)==len(new['files'])==8599
 assert not before.keys()-after.keys()and after.keys()-before.keys()==ADDED and {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
 for path in CHANGED|ADDED:assert sha(BASE/path)==after[path]['sha256']and size(BASE/path)==after[path]['size_bytes']
 assert new['validation']['versioned_core_preparation_increment_checks']==e['verified_counts']and new['validation']['versioned_core_preparation_audit_checks']==a['verified_counts']
 assert new['validation']['reports']==old['validation']['reports']+1==477 and new['goal_status']=='active'and new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 for path in ARCHIVES:assert not(BASE/path).exists()
 for path in OWNED:path_hygiene(read(BASE/(path[:-4]if path.endswith('.zst')else path)).encode())
 for obj in [e,a]:path_hygiene(json.dumps(H.paths_in_typed_payloads(obj)).encode())
 fields=sum(H.hex_hygiene(obj)[0]for obj in [e,a]);path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,(delta^OWNED)
 print(json.dumps({'unchanged_manifest_entries':8584,'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':477,'source_queries_unsat':12,'private_cases':28,'source_instruction_visits':131572,'complete_local_helper_returns':12,'decoded_hex_fields_path_checked':fields,'native_API_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
