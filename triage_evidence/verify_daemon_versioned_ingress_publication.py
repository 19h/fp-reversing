#!/usr/bin/env python3
"""Pin source ingress, bounded caller census and sixteen-file publication.

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
import recover_daemon_versioned_ingress as R
import audit_daemon_versioned_ingress as A
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='1fe0f295d94bd86518e9c737ea541b3e75df0c09'
BASELINE_SHA='9327f5703218c83486c7797eba486d79d5d3a8d16cadc21e2056bbaea192ac2f'
CHECKS_SHA='2d4969ed238a663b7a7593df603707f2e4057a9826d4557640906a3d4eb92438'
AUDIT_SHA='24c814b1edef1753d40600c9f03e8eb60efcd5c4cd3b1a3f2dba7c40091d6c4d'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md',
 'versioned_request_abi_report.md','daemon_versioned_root_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_versioned_ingress_report.md','triage_evidence/recover_daemon_versioned_ingress.py','triage_evidence/audit_daemon_versioned_ingress.py',
 'triage_evidence/verify_daemon_versioned_ingress_publication.py','triage_evidence/daemon_versioned_ingress_checks.json','triage_evidence/daemon_versioned_ingress_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_versioned_ingress_checks.json','triage_evidence/daemon_versioned_ingress_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'cases':20,'epochs':2,'variants_per_epoch':10,'source_visits':352926,'source_pool_entries':49236,'read_events':59932,'write_events':16992,'API_models':22}
INDEPENDENT={'source_visits':705852,'write_bytes_checked':152616,'register_effects_checked':618868,'write_effects_checked':33984,'unknown_copied_bytes_checked':192,'read_bytes_checked':610472,'NZCV_effects_checked':27576,'API_models_checked':44}
VARIANTS=['exclude47d','adapter_prefix']+R.VARIANTS

def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)

def receipts():
 assert sha(ROOT/'daemon_versioned_ingress_checks.json')==CHECKS_SHA and sha(ROOT/'daemon_versioned_ingress_audit.json')==AUDIT_SHA
 pins,old=R.inputs();e=json.loads(read(ROOT/'daemon_versioned_ingress_checks.json'));a=json.loads(read(ROOT/'daemon_versioned_ingress_audit.json'))
 assert e['generator_sha256']==a['generator_sha256']==sha(ROOT/'recover_daemon_versioned_ingress.py')and a['auditor_sha256']==sha(ROOT/'audit_daemon_versioned_ingress.py')
 assert a['checks_sha256']==CHECKS_SHA and e['parent_pins']==a['parent_pins']==R.PINS and len(R.PINS)==14
 assert e['dependencies']==a['dependencies']=={n:sha(ROOT/n)for n in R.DEPS}and len(R.DEPS)==18
 assert e['source_regions']==R.source()and sum(len(s['instructions'])for s in e['source_regions'])==431
 assert e['verified_counts']==a['verified_counts']==COUNTS and a['source_proofs_unsat']==12 and a['all_checks_pass']
 fresh=R.obligations();assert len(fresh)==12 and [v['label']for v in fresh]==[v['label']for v in e['source_proofs']]
 for row in e['source_proofs']:
  s=z3.Solver();s.set(timeout=30000);s.from_string(row['query']);assert str(s.check())==row['result']=='unsat'
 used={int(at,16)for c in e['cases']for at in c['trace']['used_fixups']};assert e['source_fixups']==R.R.verify_fixups(used)
 census=e['bounded_census'];assert census==R.census()and e['bank_rules']==R.banks()
 assert [(r['modifier16'],len(r['candidates']),len(r['collision_slots']))for r in census['literal_patterns']]==[('0xdbd5',4,4),('0xfbe5',5,4)]and not census['direct_B_BL_to_adapter_or_root']
 assert a['status_controls']==A.status_controls()and len(a['status_controls'])==4 and sum(r['source_visits']for r in a['status_controls'])==80
 epochs=[j for j,row in enumerate(old['steps'])if row['pc']=='0x100add594'];assert epochs==[121357,145961]
 assert len(a['interface_joins'])==len(e['cases'])==20 and len(a['independent_replays'])==40 and a['independent_totals']==INDEPENDENT
 for j,(case,join)in enumerate(zip(e['cases'],a['interface_joins'])):
  assert case['configuration']==R.configuration(j//10,VARIANTS[j%10])and case['prefix_source_visits']==epochs[j//10]and join==A.interfaces(case)
  for k,replay in enumerate(a['independent_replays'][2*j:2*j+2]):
   assert replay['all_checks_pass']and replay['pattern']==[0,3][k]and replay['epoch']==j//10 and replay['variant']==VARIANTS[j%10]
   assert replay['verified_counts']['source_visits']==case['counts']['source_visits']and replay['verified_counts'].get('API_models_checked',0)==len(case['API_models'])and replay['boundary']==case['trace']['boundary']and not replay['native_target_executed']
 assert sum(j.get('caller_result_read',False)for j in a['interface_joins'])==12
 assert sum('unresolved_frame_word'in j for j in a['interface_joins'])==4
 assert all(not j['caller_zero_gate']for j in a['interface_joins']if j.get('caller_result_read'))
 flags=['prefix_reexecuted','native_target_executed','native_API_executed','IDB_mutated','live_IDA_claim','native_caller_admission_established','complete_IOKit_buffer_join_established','native_daemon_kext_pairing_established','full_goal_complete']
 assert not any(e[k]or a[k]for k in flags)
 report=read(BASE/'daemon_versioned_ingress_report.md');assert all(f'| VI{i} |'in report for i in range(1,11))and all(f'**QG{i}**'in report for i in range(1,8))
 assert all(s in report for s in [R.R.H.THIN,'705852','352926','0x73113b31','0x6cf4','0x10063736c','0x1008c26d4','unknown','121357','145961','49236'])
 return e,a

def main():
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
 assert len(before)==len(old['files'])==8551 and len(after)==len(new['files'])==8557
 assert not before.keys()-after.keys()and after.keys()-before.keys()==ADDED and {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
 e,a=receipts();assert new['validation']['daemon_versioned_ingress_increment_checks']==COUNTS and new['validation']['daemon_versioned_ingress_static_scope']==e['scope']
 assert new['validation']['reports']==old['validation']['reports']+1==470 and new['goal_status']=='active'
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']and len(OWNED)==16
 for p in ARCHIVES:assert not(BASE/p).exists()
 for p in OWNED:path_hygiene(read(BASE/(p[:-4]if p.endswith('.zst')else p)).encode())
 for v in [e,a]:path_hygiene(json.dumps(H.paths_in_typed_payloads(v)).encode())
 n=sum(H.hex_hygiene(v)[0]for v in [e,a]);path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,(delta^OWNED)
 print(json.dumps({'unchanged_manifest_entries':len(before)-len(CHANGED),'owned_physical_files':16,'original_inputs_preserved':3,'reports':470,
  'source_cases':20,'source_visits':352926,'independent_A64_visits':705852,'queries_unsat':12,'status_controls':4,'status_control_visits':80,'complete_caller_cases':12,'unresolved_caller_cases':4,
  'decoded_hex_fields_path_checked':n,'native_target_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}))

if __name__=='__main__':main()
