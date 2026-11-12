#!/usr/bin/env python3
"""Verify composed preparation, nested ABI and sixteen-file publication.

O(owned decoded bytes+parent journals+manifest) time/space;30 s/query.
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
import recover_daemon_remainder_preparation as R
import audit_daemon_remainder_preparation as A
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='8c381240143c5b54c32ea2c04004c7041c1acf87'
BASELINE_SHA='4fbd0fe8a3c8c2f666672a9d9be98c2e0b6570c2fd47d3143f3c0d4d269170cd'
CHECKS_SHA='36251efa700d49f6ca3fa384607a77748a7923ede4247b99ef3065ad0f4029b2'
AUDIT_SHA='3adc6dae4e51a8a2c1b966dfc82508fd4f3603fc7cb8ceb74cce8697b85f7e33'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md',
 'daemon_frame_admission_report.md','daemon_frame_word_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_remainder_preparation_report.md','triage_evidence/recover_daemon_remainder_preparation.py','triage_evidence/audit_daemon_remainder_preparation.py',
 'triage_evidence/verify_daemon_remainder_preparation_publication.py','triage_evidence/daemon_remainder_preparation_checks.json','triage_evidence/daemon_remainder_preparation_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_remainder_preparation_checks.json','triage_evidence/daemon_remainder_preparation_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'cases':8,'epochs':2,'variants_per_epoch':4,'source_visits':11204,'source_pool_entries':6752,'read_events':464,'write_events':312}
INDEPENDENT={'source_visits':22408,'register_effects_checked':21296,'NZCV_effects_checked':312,'write_bytes_checked':3312,'write_effects_checked':624,'unknown_copied_bytes_checked':0,'read_bytes_checked':6024}

def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)

def receipts():
 assert sha(ROOT/'daemon_remainder_preparation_checks.json')==CHECKS_SHA and sha(ROOT/'daemon_remainder_preparation_audit.json')==AUDIT_SHA
 pins,old,parent=R.inputs();e=json.loads(read(ROOT/'daemon_remainder_preparation_checks.json'));a=json.loads(read(ROOT/'daemon_remainder_preparation_audit.json'))
 assert e['generator_sha256']==a['generator_sha256']==sha(ROOT/'recover_daemon_remainder_preparation.py')and a['auditor_sha256']==sha(ROOT/'audit_daemon_remainder_preparation.py')
 assert a['checks_sha256']==CHECKS_SHA and e['parent_pins']==a['parent_pins']==R.PINS and len(R.PINS)==20
 assert e['dependencies']==a['dependencies']=={n:sha(ROOT/n)for n in R.DEPS}and len(R.DEPS)==21
 assert a['ingress_auditor_sha256']==sha(ROOT/'audit_daemon_versioned_ingress.py')and e['source_regions']==R.source()and sum(len(s['instructions'])for s in e['source_regions'])==356
 assert e['verified_counts']==a['verified_counts']==COUNTS and a['source_proofs_unsat']==7 and a['all_checks_pass']
 fresh=R.obligations();assert len(fresh)==7 and [r['label']for r in fresh]==[r['label']for r in e['source_proofs']]
 for row in e['source_proofs']:
  s=z3.Solver();s.set(timeout=30000);s.from_string(row['query']);assert str(s.check())==row['result']=='unsat'
 used={int(at,16)for c in e['cases']for at in c['trace']['used_fixups']};assert e['source_fixups']==R.R.R.verify_fixups(used)
 collision=[{'slot':hex(at),'target':r['target'],'annotation':r['annotation']}for at,r in sorted(R.FIXUPS.items())if'div=0x9298 'in r['line']]
 assert e['modifier9298_collision_slots']==collision and len(collision)==4 and a['modifier9298_collision_fixup_records']==R.R.R.verify_fixups({int(r['slot'],16)for r in collision})
 bank=e['helper_dispatch_bank'];assert bank==R.selected(0x101031da0,0x100e99900,0x86,0x8c2,R.POOL)and bank['inputs_checked']==256 and(int(bank['target'],16)+0xffffffffd0c4d1ee)&((1<<64)-1)==R.TABLE
 assert len(e['cases'])==len(a['interface_joins'])==8 and len(a['independent_replays'])==16 and a['independent_totals']==INDEPENDENT
 for j,(case,join)in enumerate(zip(e['cases'],a['interface_joins'])):
  c=case['configuration'];original=next(v for v in parent['cases']if v['configuration']['epoch']==c['epoch']and v['configuration']['name']==c['parent_variant']);oc=original['configuration'];cut=next(k for k,r in enumerate(original['trace']['steps'])if r['pc']==hex(R.ENTRY));value=j%2
  expected={**oc,'parent_variant':oc['name'],'parent_entry_source_visits':cut,'parent_prefix_source_visits':original['prefix_source_visits'],'name':oc['name']+'_word'+str(value),'entry':hex(R.ENTRY),'declared_decoded_object_word':value,'prior_raw_object_word':'0x8b3dc64d','declared_raw_object_word':hex(value^R.Parent.C)}
  assert c==expected and join==A.interfaces(case)and not case['API_models']
  for pattern,r in zip([0,3],a['independent_replays'][2*j:2*j+2]):assert r['pattern']==pattern and r['epoch']==c['epoch']and r['variant']==c['name']and r['all_checks_pass']and r['verified_counts']['source_visits']==case['counts']['source_visits']and r['boundary']==case['trace']['boundary']and not r['modeled_retirement_checked']
 assert sum(j['nested_helper_entered']for j in a['interface_joins'])==4
 for k in ['prefixes_reexecuted','native_target_executed','native_API_executed','IDB_mutated','live_IDA_claim','actual_partial_fixture_resumed','native_caller_admission_established','native_daemon_kext_pairing_established','full_goal_complete']:assert not e[k]and not a[k]
 report=read(BASE/'daemon_remainder_preparation_report.md');assert all(f'| RP{i} |'in report for i in range(1,10))and all(f'**QG{i}**'in report for i in range(1,8))
 assert all(s in report for s in [e['source_sha256'],'22408','11204','0x1004234c4','0x10063736c','unknown','0x2570','0xb521e742'])
 return e,a

def main():
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
 assert len(before)==len(old['files'])==8569 and len(after)==len(new['files'])==8575
 assert not before.keys()-after.keys()and after.keys()-before.keys()==ADDED and {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
 e,a=receipts();assert new['validation']['daemon_remainder_preparation_increment_checks']==COUNTS and new['validation']['daemon_remainder_preparation_static_scope']==e['scope']
 assert new['validation']['reports']==old['validation']['reports']+1==473 and new['goal_status']=='active'
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']and len(OWNED)==16
 for p in ARCHIVES:assert not(BASE/p).exists()
 for p in OWNED:path_hygiene(read(BASE/(p[:-4]if p.endswith('.zst')else p)).encode())
 for v in [e,a]:path_hygiene(json.dumps(H.paths_in_typed_payloads(v)).encode())
 n=sum(H.hex_hygiene(v)[0]for v in [e,a]);path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,(delta^OWNED)
 print(json.dumps({'unchanged_manifest_entries':len(before)-len(CHANGED),'owned_physical_files':16,'original_inputs_preserved':3,'reports':473,'source_cases':8,'independent_A64_replays':16,'original_A64_visits':22408,'queries_unsat':7,'nested_helper_entries':4,'decoded_hex_fields_path_checked':n,'native_target_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}))

if __name__=='__main__':main()
