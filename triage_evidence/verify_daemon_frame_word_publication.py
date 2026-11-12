#!/usr/bin/env python3
"""Verify conditional frame-word evidence and exact sixteen-file publication.

O(owned decoded bytes+parent visits+manifest) time/space;30 s/query.
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
import recover_daemon_frame_word as R
import audit_daemon_frame_word as A
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='4822b7ae6409e780bfcbe4106201ab2c56bd4af0'
BASELINE_SHA='5f8c30afe23568f0f3577f163e9d452bcdbb0cf5b85961be201604be175941b8'
CHECKS_SHA='706e180b05604b5e1930b415a2acdb9f61ff78c41104be8ac3fee89e472c959b'
AUDIT_SHA='f494b2c285e17e6568199152716fb286b7eaef37958c3e74c238b140ca09d951'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md',
 'versioned_request_abi_report.md','daemon_versioned_ingress_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_frame_word_report.md','triage_evidence/recover_daemon_frame_word.py','triage_evidence/audit_daemon_frame_word.py',
 'triage_evidence/verify_daemon_frame_word_publication.py','triage_evidence/daemon_frame_word_checks.json','triage_evidence/daemon_frame_word_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_frame_word_checks.json','triage_evidence/daemon_frame_word_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'source_regions':6,'source_instructions':148,'store_candidates':47,'actual_partial_cases':4,'actual_visits_rechecked':191598,'queries_unsat':10,'control_cases':20,'control_visits':1010,'less_than_controls':10}
INDEPENDENT={'source_visits':1010,'register_values_checked':32320,'NZCV_values_checked':1010,'read_B_checked':760,'logical_PAC_transfers':50,'write_B_checked':280}

def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)

def receipts():
 assert sha(ROOT/'daemon_frame_word_checks.json')==CHECKS_SHA and sha(ROOT/'daemon_frame_word_audit.json')==AUDIT_SHA
 parent=R.inputs();e=json.loads(read(ROOT/'daemon_frame_word_checks.json'));a=json.loads(read(ROOT/'daemon_frame_word_audit.json'))
 assert e['generator_sha256']==a['generator_sha256']==sha(ROOT/'recover_daemon_frame_word.py')and a['auditor_sha256']==sha(ROOT/'audit_daemon_frame_word.py')
 assert a['checks_sha256']==CHECKS_SHA and e['parent_pins']==a['parent_pins']==R.PINS and len(R.PINS)==16
 assert e['dependencies']==a['dependencies']=={n:sha(ROOT/n)for n in R.DEPS}and len(R.DEPS)==19
 assert a['parent_auditor_sha256']==sha(ROOT/'audit_daemon_versioned_ingress.py')
 assert e['source_regions']==R.source()and sum(len(s['instructions'])for s in e['source_regions'])==148
 assert e['source_fixups']==R.Parent.R.verify_fixups(set(R.SLOTS))and e['verified_counts']==a['verified_counts']==COUNTS
 fresh=R.obligations();assert len(fresh)==10 and [r['label']for r in fresh]==[r['label']for r in e['source_proofs']]
 for row in e['source_proofs']:
  s=z3.Solver();s.set(timeout=30000);s.from_string(row['query']);assert str(s.check())==row['result']=='unsat'
 assert e['bounded_store_census']==R.census()and a['independent_census']==A.independent_census(e['bounded_store_census'])
 assert e['actual_frontiers']==R.actual(parent)and len(a['actual_frontier_checks'])==4
 assert e['control_cases']==R.controls()and len(a['independent_controls'])==20 and a['independent_totals']==INDEPENDENT and a['source_proofs_unsat']==10 and a['all_checks_pass']
 for c,r in zip(e['control_cases'],a['independent_controls']):
  assert all(c[k]==r[k]for k in ['epoch','value_u32','limit_u32','less_than','boundary'])and r['all_checks_pass']and r['verified_counts']['source_visits']==c['source_visits']
 assert not a['parent_A64_replays_repeated']
 for k in ['native_target_executed','native_API_executed','IDB_mutated','live_IDA_claim','actual_partial_fixture_resumed','native_daemon_kext_pairing_established','full_goal_complete']:assert not e[k]and not a[k]
 report=read(BASE/'daemon_frame_word_report.md');assert all(f'| FW{i} |'in report for i in range(1,9))and all(f'**QG{i}**'in report for i in range(1,8))
 assert all(s in report for s in [e['source_sha256'],'191598','32320','0x100530748','0x10063736c','unknown','1010'])
 return e,a

def main():
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
 assert len(before)==len(old['files'])==8557 and len(after)==len(new['files'])==8563
 assert not before.keys()-after.keys()and after.keys()-before.keys()==ADDED and {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
 e,a=receipts();assert new['validation']['daemon_frame_word_increment_checks']==COUNTS and new['validation']['daemon_frame_word_static_scope']==e['scope']
 assert new['validation']['reports']==old['validation']['reports']+1==471 and new['goal_status']=='active'
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']and len(OWNED)==16
 for p in ARCHIVES:assert not(BASE/p).exists()
 for p in OWNED:path_hygiene(read(BASE/(p[:-4]if p.endswith('.zst')else p)).encode())
 for v in [e,a]:path_hygiene(json.dumps(H.paths_in_typed_payloads(v)).encode())
 n=sum(H.hex_hygiene(v)[0]for v in [e,a]);path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,(delta^OWNED)
 print(json.dumps({'unchanged_manifest_entries':len(before)-len(CHANGED),'owned_physical_files':16,'original_inputs_preserved':3,'reports':471,
  'conditional_controls':20,'original_A64_visits':1010,'queries_unsat':10,'actual_partial_cases_preserved':4,'store_candidates':47,
  'decoded_hex_fields_path_checked':n,'native_target_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}))

if __name__=='__main__':main()
