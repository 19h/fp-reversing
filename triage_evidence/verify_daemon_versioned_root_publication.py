#!/usr/bin/env python3
"""Pin whole-root receipts, scoped findings and exact sixteen-file publication.

O(owned decoded bytes+pinned journals+manifest) time/space;30 s/query.
No native API/IPC, IDB mutation or history rewrite.
"""
import json,subprocess
from pathlib import Path
from hashlib import sha256
from compression import zstd
import z3
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
import verify_corefp_late_preparation_publication as H
import recover_daemon_versioned_root as R
import audit_daemon_versioned_root as A
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='86f41cc413d3755adabbe8045000aedb43d6221b'
BASELINE_SHA='95818d07dd24acc5ca2f5eab23a9e90421e66fdaf65e6e74522357de1460ff76'
CHECKS_SHA='a5a48b3b767a521c59f86d046de0e39bf482a3391bbc7d42d628869351062853'
AUDIT_SHA='daf272f893cea203713992296a905162532dcd6e91864d184c5cd4d406b46a3a'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md',
 'versioned_request_abi_report.md','daemon_versioned_header_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_versioned_root_report.md','triage_evidence/recover_daemon_versioned_root.py','triage_evidence/audit_daemon_versioned_root.py',
 'triage_evidence/verify_daemon_versioned_root_publication.py','triage_evidence/daemon_versioned_root_checks.json','triage_evidence/daemon_versioned_root_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_versioned_root_checks.json','triage_evidence/daemon_versioned_root_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'cases':16,'epochs':2,'variants':8,'source_visits':299242,'source_instructions':30180,'read_events':55189,'write_events':15473,'API_models':22}
INDEPENDENT={'source_visits':598484,'write_bytes_checked':138618,'register_effects_checked':518050,'write_effects_checked':30946,'unknown_copied_bytes_checked':0,'read_bytes_checked':561890,'NZCV_effects_checked':25760,'API_models_checked':44}
VARIANTS=['null_A','null_B','malloc_failure','clear1','clear2','clear6','prefix','extended']

def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)

def receipts():
 assert sha(ROOT/'daemon_versioned_root_checks.json')==CHECKS_SHA and sha(ROOT/'daemon_versioned_root_audit.json')==AUDIT_SHA
 pins,old=R.inputs();e=json.loads(read(ROOT/'daemon_versioned_root_checks.json'));a=json.loads(read(ROOT/'daemon_versioned_root_audit.json'))
 assert e['generator_sha256']==a['generator_sha256']==sha(ROOT/'recover_daemon_versioned_root.py')and a['auditor_sha256']==sha(ROOT/'audit_daemon_versioned_root.py')
 assert a['checks_sha256']==CHECKS_SHA and e['parent_pins']==a['parent_pins']==R.PINS and len(R.PINS)==10
 assert e['dependencies']==a['dependencies']=={n:sha(ROOT/n)for n in R.DEPS}and len(R.DEPS)==14
 assert e['source_regions']==R.source()and sum(len(s['instructions'])for s in e['source_regions'])==428
 assert e['verified_counts']==a['verified_counts']==COUNTS and a['source_proofs_unsat']==9 and a['all_checks_pass']
 fresh=R.obligations();assert len(fresh)==9 and [v['label']for v in fresh]==[v['label']for v in e['source_proofs']]
 for row in e['source_proofs']:
  s=z3.Solver();s.set(timeout=30000);s.from_string(row['query']);assert str(s.check())==row['result']=='unsat'
 used={int(at,16)for c in e['cases']for at in c['trace']['used_fixups']};assert e['source_fixups']==R.verify_fixups(used)
 epochs=[j for j,row in enumerate(old['steps'])if row['pc']=='0x100add594'];assert epochs==[121357,145961]
 assert len(a['interface_joins'])==len(e['cases'])==16 and len(a['independent_replays'])==32 and a['independent_totals']==INDEPENDENT
 for j,(case,join)in enumerate(zip(e['cases'],a['interface_joins'])):
  assert case['configuration']==R.configuration(j//8,VARIANTS[j%8])and case['prefix_source_visits']==epochs[j//8]and join==A.interfaces(case)
  assert case['trace']['boundary']['kind']=='return_outside_source_image'and case['trace']['boundary']['pc']==hex(R.RET)and case['trace']['boundary']['target']==hex(R.RETURN)
  for k,replay in enumerate(a['independent_replays'][2*j:2*j+2]):
   assert replay['all_checks_pass']and replay['pattern']==[0,3][k]and replay['epoch']==j//8 and replay['variant']==VARIANTS[j%8]
   assert replay['verified_counts']['source_visits']==case['counts']['source_visits']and replay['verified_counts'].get('API_models_checked',0)==len(case['API_models'])and replay['boundary']==case['trace']['boundary']and not replay['native_target_executed']
 flags=['prefix_reexecuted','native_target_executed','native_API_executed','IDB_mutated','live_IDA_claim','native_entry_admission_established','complete_IOKit_buffer_join_established','native_daemon_kext_pairing_established','full_goal_complete']
 assert not any(e[k]or a[k]for k in flags)
 report=read(BASE/'daemon_versioned_root_report.md');assert all(f'| VR{i} |'in report for i in range(1,11))and all(f'**QG{i}**'in report for i in range(1,8))
 assert all(s in report for s in [R.H.THIN,'598484','299242','0x10049f358','0x10028db6c','0x1002dc500','unknown','121357','145961','30180'])
 return e,a

def main():
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
 assert len(before)==len(old['files'])==8545 and len(after)==len(new['files'])==8551
 assert not before.keys()-after.keys()and after.keys()-before.keys()==ADDED and {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
 e,a=receipts();assert new['validation']['daemon_versioned_root_increment_checks']==COUNTS and new['validation']['daemon_versioned_root_static_scope']==e['scope']
 assert new['validation']['reports']==old['validation']['reports']+1==469 and new['goal_status']=='active'
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']and len(OWNED)==16
 for p in ARCHIVES:assert not(BASE/p).exists()
 for p in OWNED:path_hygiene(read(BASE/(p[:-4]if p.endswith('.zst')else p)).encode())
 for v in [e,a]:path_hygiene(json.dumps(H.paths_in_typed_payloads(v)).encode())
 n=sum(H.hex_hygiene(v)[0]for v in [e,a]);path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,(delta^OWNED)
 print(json.dumps({'unchanged_manifest_entries':len(before)-len(CHANGED),'owned_physical_files':16,'original_inputs_preserved':3,'reports':469,
  'source_cases':16,'source_visits':299242,'independent_A64_visits':598484,'queries_unsat':9,'allocator_models':22,'independent_allocator_checks':44,
  'decoded_hex_fields_path_checked':n,'native_target_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}))

if __name__=='__main__':main()
