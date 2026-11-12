#!/usr/bin/env python3
"""Fresh source/proof/replay, publication delta and decoded path checks.

O(owned bytes+source+replays+manifest) time/space plus 30 s/query.
No native API, IPC, IDB mutation or history rewrite.
"""
import json,subprocess
from pathlib import Path
from hashlib import sha256
from compression import zstd
import z3
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
import verify_corefp_late_preparation_publication as H
import recover_versioned_core_entry as R
import probe_versioned_core_entry as P

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='1438f7671c9d59b3eb956a76a163cea44f2a3e0d'
BASELINE_SHA='b1a9ab82be5ec924c812c6d84a6364f80c67d632c0e80cd442096c7d02bba95e'
CHECKS_SHA='3843173c58a27020559624f24f9c71d4c9c44d355f3c073d705daacd94db62b5'
REPLAYS_SHA='0f55e7933e0430ffed4e38c8b6e4e3fee0635ba8777de7c008f52b91335c5761'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md','versioned_request_abi_report.md','daemon_postblock_dispatch_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'versioned_core_entry_report.md','triage_evidence/recover_versioned_core_entry.py','triage_evidence/probe_versioned_core_entry.py','triage_evidence/verify_versioned_core_entry_publication.py','triage_evidence/versioned_core_entry_checks.json','triage_evidence/versioned_core_entry_replays.json'}
ARCHIVES={MANIFEST,'triage_evidence/versioned_core_entry_checks.json','triage_evidence/versioned_core_entry_replays.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}

def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)

def main():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_replays.json'))==REPLAYS_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));p=json.loads(read(ROOT/(R.P+'_replays.json')))
 fresh=R.build()
 for key in e:
  if key!='source_proofs':assert fresh[key]==e[key],key
 assert [(q['label'],q['result'])for q in fresh['source_proofs']]==[(q['label'],q['result'])for q in e['source_proofs']]and len(e['source_proofs'])==14
 for q in e['source_proofs']:
  solver=z3.Solver();solver.set(timeout=30000);solver.from_string(q['query']);assert solver.check()==z3.unsat
 assert P.build()==p and p['all_checks_pass']and p['verified_counts']=={'cases':86,'source_instruction_visits':43582,'write_bytes_checked':50296,'read_bytes_checked':56834}
 assert p['boundary_counts']=={'returned_rejection':28,'initial_scalar_gate_admitted_before_processing':58}and p['model_memory_writes']==0
 assert e['verified_counts']=={'source_regions':5,'source_instruction_instances':682,'source_bytes_instances':2728,'bank_rules':15,'bank_inputs':3840,'proofs_unsat':14,'typed_views':2}
 assert e['parent_pins']==R.PINS and e['dependencies']==p['dependencies']=={n:sha(ROOT/n)for n in R.DEPS}
 assert e['generator_sha256']==p['source_generator_sha256']==sha(ROOT/('recover_'+R.P+'.py'))and p['generator_sha256']==sha(ROOT/('probe_'+R.P+'.py'))
 for key in ['native_target_executed','native_API_executed','IDB_mutated','live_IDA_claim','native_caller_admission_established','native_daemon_kext_pairing_established','full_goal_complete']:assert not e[key]
 assert not p['native_target_executed']and not p['complete_core_processing_executed']and not p['full_goal_complete']
 report=read(BASE/'versioned_core_entry_report.md');assert all(f'| VE{k} |'in report for k in range(1,9))and all(f'**QG{k}**'in report for k in range(1,8))
 assert all(word in report for word in ['43,582','56,834','50,296','0x3da4b356','0xb4d3a486','unknown','0xffff5b37'])
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
 assert len(before)==len(old['files'])==8587 and len(after)==len(new['files'])==8593
 assert not before.keys()-after.keys()and after.keys()-before.keys()==ADDED and {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
 for path in CHANGED|ADDED:assert sha(BASE/path)==after[path]['sha256']and size(BASE/path)==after[path]['size_bytes']
 assert new['validation']['versioned_core_entry_increment_checks']==e['verified_counts']and new['validation']['versioned_core_entry_replay_checks']==p['verified_counts']
 assert new['validation']['versioned_core_entry_static_scope']==e['scope']and new['validation']['reports']==old['validation']['reports']+1==476 and new['goal_status']=='active'
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 for path in ARCHIVES:assert not(BASE/path).exists()
 for path in OWNED:path_hygiene(read(BASE/(path[:-4]if path.endswith('.zst')else path)).encode())
 for obj in [e,p]:path_hygiene(json.dumps(H.paths_in_typed_payloads(obj)).encode())
 fields=sum(H.hex_hygiene(obj)[0]for obj in [e,p]);path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,(delta^OWNED)
 print(json.dumps({'unchanged_manifest_entries':8578,'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':476,'source_regions':5,'bank_inputs':3840,'source_queries_unsat':14,'private_A64_cases':86,'private_instruction_visits':43582,'decoded_hex_fields_path_checked':fields,'native_API_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
