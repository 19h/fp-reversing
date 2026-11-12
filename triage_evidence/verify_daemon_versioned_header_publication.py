#!/usr/bin/env python3
"""Pin the constructor/emitter receipts and exact sixteen-file publication.

O(owned decoded bytes + pinned journals + manifest) time/space;
30 s/SMT query. No native API/IPC, IDB mutation or history rewrite.
"""
import json,subprocess
from pathlib import Path
from hashlib import sha256
from compression import zstd
import z3
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
import verify_corefp_late_preparation_publication as H
import recover_daemon_versioned_header as R
import audit_daemon_versioned_header as A
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='dc9ec3ba4fa04291e2e67e74b84badc844196900'
BASELINE_SHA='92bf61012d7a3eac89956b1b194027298714914492d51a3c8c28f3dcd0e8714a'
CHECKS_SHA='0567208d2807a90c176f476e393f5123192143c3fa856a0e86cf380f74f06fe0'
AUDIT_SHA='8219f4c7a9289dce98e1b6438cfeef41df9d435c257dee5c7acd6d5e801a3bd8'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md',
 'versioned_request_abi_report.md','daemon_callback_revisit_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_versioned_header_report.md','triage_evidence/recover_daemon_versioned_header.py','triage_evidence/audit_daemon_versioned_header.py',
 'triage_evidence/verify_daemon_versioned_header_publication.py','triage_evidence/daemon_versioned_header_checks.json','triage_evidence/daemon_versioned_header_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_versioned_header_checks.json','triage_evidence/daemon_versioned_header_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'cases':6,'epochs':2,'layouts':3,'source_visits':84018,'source_instructions':7632,'read_events':16488,'write_events':4518}

def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)

def receipts():
 assert sha(ROOT/'daemon_versioned_header_checks.json')==CHECKS_SHA and sha(ROOT/'daemon_versioned_header_audit.json')==AUDIT_SHA
 pins,old=R.inputs();e=json.loads(read(ROOT/'daemon_versioned_header_checks.json'));a=json.loads(read(ROOT/'daemon_versioned_header_audit.json'))
 assert e['generator_sha256']==a['generator_sha256']==sha(ROOT/'recover_daemon_versioned_header.py')and a['auditor_sha256']==sha(ROOT/'audit_daemon_versioned_header.py')
 assert a['checks_sha256']==CHECKS_SHA and e['parent_pins']==a['parent_pins']==R.PINS and len(R.PINS)==8
 assert e['dependencies']==a['dependencies']=={n:sha(ROOT/n)for n in R.DEPS}and len(R.DEPS)==10
 assert e['source_regions']==R.source()and sum(len(s['instructions'])for s in e['source_regions'])==295
 assert e['verified_counts']==a['verified_counts']==COUNTS and a['source_proofs_unsat']==11 and a['SAT_probes']==3 and a['all_checks_pass']
 fresh=R.obligations();assert len(fresh['proofs'])==len(e['source_checks']['proofs'])==11
 for row in e['source_checks']['proofs']+e['source_checks']['falsifiers_and_witnesses']:
  s=z3.Solver();s.set(timeout=30000);s.from_string(row['query']);assert str(s.check())==row['result']
 assert len(a['interface_joins'])==len(e['cases'])==6 and len(a['independent_replays'])==12
 epochs=[j for j,row in enumerate(old['steps'])if row['pc']=='0x100add594'];assert epochs==[121357,145961]
 for j,(case,join)in enumerate(zip(e['cases'],a['interface_joins'])):
  assert case['configuration']==R.fixture(j//3,j%3)and case['prefix_source_visits']==epochs[j//3]and join==A.interfaces(case)
  assert case['counts']=={'source_visits':14003,'source_instructions':1272,'read_events':2748,'write_events':753}
  assert case['trace']['boundary']['kind']=='declared_before_capability_read'and case['trace']['boundary']['pc']=='0x100552fa0'
  for r in a['independent_replays'][2*j:2*j+2]:assert r['all_checks_pass']and r['verified_counts']['source_visits']==14003 and r['boundary']==case['trace']['boundary']and not r['native_target_executed']
 assert a['independent_totals']=={'source_visits':168036,'register_effects_checked':144000,'write_bytes_checked':39432,'write_effects_checked':9036,'unknown_copied_bytes_checked':0,'read_bytes_checked':166272,'NZCV_effects_checked':7752}
 assert a['alignment_controls']==A.alignment_controls()and sum(r['source_visits']for r in a['alignment_controls'])==184
 flags=['prefix_reexecuted','native_target_executed','native_API_executed','IDB_mutated','live_IDA_claim','native_parent_frame_recovered','complete_IOKit_buffer_join_established','native_daemon_kext_pairing_established','full_goal_complete']
 assert not any(e[k]or a[k]for k in flags)
 report=read(BASE/'daemon_versioned_header_report.md');assert all(f'| VH{i} |'in report for i in range(1,9))and all(f'**QG{i}**'in report for i in range(1,8))
 assert all(s in report for s in [R.THIN,'R & 5 == 0','0x8b3dc651','168036','16300','184','552','unknown','121357','145961'])
 return e,a

def main():
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
 assert len(before)==len(old['files'])==8539 and len(after)==len(new['files'])==8545
 assert not before.keys()-after.keys()and after.keys()-before.keys()==ADDED and {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
 e,a=receipts();assert new['validation']['daemon_versioned_header_increment_checks']==COUNTS and new['validation']['daemon_versioned_header_static_scope']==e['scope']
 assert new['validation']['reports']==old['validation']['reports']+1==468 and new['goal_status']=='active'
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']and len(OWNED)==16
 for p in ARCHIVES:assert not(BASE/p).exists()
 for p in OWNED:path_hygiene(read(BASE/(p[:-4]if p.endswith('.zst')else p)).encode())
 path_hygiene(json.dumps(H.paths_in_typed_payloads(e)).encode());n=sum(H.hex_hygiene(v)[0]for v in [e,a]);path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,(delta^OWNED)
 print(json.dumps({'unchanged_manifest_entries':len(before)-len(CHANGED),'owned_physical_files':16,'original_inputs_preserved':3,'reports':468,
  'source_cases':6,'source_visits':84018,'independent_A64_visits':168036,'queries_unsat':11,'SAT_probes':3,'packing_controls':8,'packing_visits':184,
  'decoded_hex_fields_path_checked':n,'native_target_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}))

if __name__=='__main__':main()
