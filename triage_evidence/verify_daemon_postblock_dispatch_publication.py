#!/usr/bin/env python3
"""Verify source-to-API joins, original kernel ABI and exact publication delta.

O(owned decoded bytes+parent receipts+kernel+manifest) time/space;30 s/query.
Read-only; no native API, Mach/IOKit operation, IDB mutation or history rewrite.
"""
import json,subprocess
from pathlib import Path
from hashlib import sha256
from compression import zstd
import z3
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
import verify_corefp_late_preparation_publication as H
import recover_daemon_postblock_dispatch as R
import audit_daemon_postblock_dispatch as A
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='12b2a74d1630c96e892b725b76650835d2d50b86'
BASELINE_SHA='2fb44e426a22de04dd13637d89a39cc2c14b5db30670e384e00cafcd58f86821'
CHECKS_SHA='3cd216630458c65aa34c0f2b1f6155c35a7cfc8206eb97b0fdcc6788e0b401b0'
AUDIT_SHA='63c6794ca1def87e2c7a7ac18d3d9b046e58930e0195e3a67567b929b815f78e'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md','daemon_nested_helper_processing_report.md','daemon_versioned_header_report.md','daemon_versioned_root_report.md','versioned_request_abi_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_postblock_dispatch_report.md','triage_evidence/recover_daemon_postblock_dispatch.py','triage_evidence/audit_daemon_postblock_dispatch.py','triage_evidence/verify_daemon_postblock_dispatch_publication.py','triage_evidence/daemon_postblock_dispatch_checks.json','triage_evidence/daemon_postblock_dispatch_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_postblock_dispatch_checks.json','triage_evidence/daemon_postblock_dispatch_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'cases':4,'epochs':2,'variants_per_epoch':2,'source_visits':1330,'source_pool_entries':1334,'read_events':308,'write_events':120}
INDEPENDENT={'source_visits':2660,'register_effects_checked':2416,'read_bytes_checked':3272,'write_bytes_checked':1248,'write_effects_checked':240,'unknown_copied_bytes_checked':0,'NZCV_effects_checked':40}

def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)

def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 pins,old,ingress,preparation,previous=R.inputs();e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')));pa=json.loads(read(ROOT/'daemon_nested_helper_processing_audit.json'))
 assert e['generator_sha256']==a['generator_sha256']==sha(ROOT/('recover_'+R.P+'.py'))and a['auditor_sha256']==sha(ROOT/('audit_'+R.P+'.py'))and a['checks_sha256']==CHECKS_SHA
 assert e['parent_pins']==a['parent_pins']==R.PINS and len(R.PINS)==24 and e['dependencies']==a['dependencies']=={n:sha(ROOT/n)for n in R.DEPS}and len(R.DEPS)==25
 assert e['source_regions']==R.source()and len(e['source_regions'])==8 and sum(len(s['instructions'])for s in e['source_regions'])==362
 assert e['verified_counts']==a['verified_counts']==COUNTS and a['independent_totals']==INDEPENDENT and a['all_checks_pass']and a['source_proofs_unsat']==10
 fresh=R.obligations();assert len(fresh)==10 and [r['label']for r in fresh]==[r['label']for r in e['source_proofs']]
 for row in e['source_proofs']:
  s=z3.Solver();s.set(timeout=30000);s.from_string(row['query']);assert str(s.check())==row['result']=='unsat'
 assert e['source_fixups']==R.Parent.Parent.R.R.verify_fixups({int(at,16)for case in e['cases']for at in case['trace']['used_fixups']})
 imported=next(r for r in e['source_fixups']['records']if r.get('address')=='0x1010a0640');assert imported['import_name']=='_IOConnectCallStructMethod'and imported['import_ordinal']==104 and imported['library_ordinal']==4 and imported['diversity']=='0x7a6c'
 collision=[{'slot':hex(at),'target':hex(r['target'])}for at,r in sorted(R.FIXUPS.items())if'div=0x0A74 'in r['line']]
 assert len(collision)==4 and collision==e['modifier0a74_collision_slots']and e['collision_fixups']==R.Parent.Parent.R.R.verify_fixups({int(r['slot'],16)for r in collision})
 assert a['ABI_pins']==A.ABI_PINS and a['kernel_dependencies']=={n:sha(ROOT/n)for n in ['kernel_native_reader.py','kext_port_tools.py','recover_kext_cold_init.py']}and a['kernel_comparison']==A.kernel_comparison()
 assert len(e['cases'])==len(a['interface_joins'])==4 and len(a['independent_replays'])==8
 assert {(c['configuration']['epoch'],c['configuration']['parent_variant'])for c in e['cases']}=={(epoch,v)for epoch in [0,1]for v in ['prefix','extended']}
 for j,(case,join)in enumerate(zip(e['cases'],a['interface_joins'])):
  c=case['configuration'];original=next(v for v in ingress['cases']if v['configuration']['epoch']==c['epoch']and v['configuration']['name']==c['parent_variant']);prep=next(v for v in preparation['cases']if v['configuration']['epoch']==c['epoch']and v['configuration']['name']==c['preparation_variant']);prior=next(v for v in previous['cases']if v['configuration']['epoch']==c['epoch']and v['configuration']['name']==c['name']);pj=next(v for v in pa['interface_joins']if v['epoch']==c['epoch']and v['variant']==c['name'])
  assert c=={**prior['configuration'],'processing_prefix_source_visits':7000,'entry':hex(R.ENTRY)}and c['operand_profile']=='baseline'and c['declared_decoded_object_word']==0
  assert join==A.interfaces(case,original,prep,prior,pj)and not case['API_models'];mode=c['parent_variant']=='extended';visits=361 if mode else 304
  assert case['counts']=={'source_visits':visits,'source_pool_entries':visits+1,'read_events':86 if mode else 68,'write_events':38 if mode else 22}
  for pattern,row in zip([0,3],a['independent_replays'][2*j:2*j+2]):assert row['pattern']==pattern and row['epoch']==c['epoch']and row['variant']==c['name']and row['all_checks_pass']and row['verified_counts']['source_visits']==visits and row['boundary']==case['trace']['boundary']and not row['modeled_retirement_checked']and row['api_view_bytes_checked']==552 and row['api_unspecified_bytes_preserved']==(492 if mode else 508)
 for key in ['prefixes_reexecuted','native_target_executed','native_API_executed','IDB_mutated','live_IDA_claim','actual_partial_fixture_resumed','native_caller_admission_established','native_daemon_kext_pairing_established','full_goal_complete']:assert not e[key]and not a[key]
 report=read(BASE/'daemon_postblock_dispatch_report.md');assert all(f'| PD{k} |'in report for k in range(1,9))and all(f'**QG{k}**'in report for k in range(1,8))
 assert all(s in report for s in [e['source_sha256'],'2,660','1,330','0x100478a04','0x1004601d0','unknown','0x6a8','508','492'])
 return e,a

def main():
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
 assert len(before)==len(old['files'])==8581 and len(after)==len(new['files'])==8587
 assert not before.keys()-after.keys()and after.keys()-before.keys()==ADDED and {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
 e,a=receipts();assert new['validation']['daemon_postblock_dispatch_increment_checks']==COUNTS and new['validation']['daemon_postblock_dispatch_static_scope']==e['scope']
 assert new['validation']['reports']==old['validation']['reports']+1==475 and new['goal_status']=='active'and len(OWNED)==18
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 for p in ARCHIVES:assert not(BASE/p).exists()
 for p in OWNED:path_hygiene(read(BASE/(p[:-4]if p.endswith('.zst')else p)).encode())
 for obj in [e,a]:path_hygiene(json.dumps(H.paths_in_typed_payloads(obj)).encode())
 fields=sum(H.hex_hygiene(obj)[0]for obj in [e,a]);path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,(delta^OWNED)
 print(json.dumps({'unchanged_manifest_entries':8570,'owned_physical_files':18,'original_inputs_preserved':3,'reports':475,'source_cases':4,'independent_A64_replays':8,'original_A64_visits':2660,'queries_unsat':10,'kernel_function_bytes_compared':240,'API_boundary_bytes_compared':4416,'decoded_hex_fields_path_checked':fields,'API_call_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}))

if __name__=='__main__':main()
