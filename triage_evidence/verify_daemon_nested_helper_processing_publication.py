#!/usr/bin/env python3
"""Verify nested-helper receipts, semantic joins and exact publication ownership.

O(owned decoded bytes+parent receipts+manifest) time/space;30 s/proof query.
Read-only; no native API, IPC, IDB mutation or history rewrite.
"""
import json,subprocess
from pathlib import Path
from hashlib import sha256
from compression import zstd
import z3
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
import verify_corefp_late_preparation_publication as H
import recover_daemon_nested_helper_processing as R
import audit_daemon_nested_helper_processing as A
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='0b158df1113c0059e072d163f5854cf63b8d858e'
BASELINE_SHA='f9cfe92b3665239c9da1f96c21819a4ebdfe2bee065da6ebf0056e434fe0e520'
CHECKS_SHA='16df39b49898247cb851f0a4110537ae68c014eebad9e330304ba1b0a440efdd'
AUDIT_SHA='4744bb1b70ae274d76b081ee3ba6115a7bbc842e42088ef3560dc3828b5ebe06'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md','daemon_remainder_preparation_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_nested_helper_processing_report.md','triage_evidence/recover_daemon_nested_helper_processing.py','triage_evidence/audit_daemon_nested_helper_processing.py','triage_evidence/verify_daemon_nested_helper_processing_publication.py','triage_evidence/daemon_nested_helper_processing_checks.json','triage_evidence/daemon_nested_helper_processing_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_nested_helper_processing_checks.json','triage_evidence/daemon_nested_helper_processing_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'cases':16,'epochs':2,'variants_per_epoch':8,'source_visits':112000,'source_pool_entries':58496,'read_events':20384,'write_events':2880}
INDEPENDENT={'source_visits':224000,'register_effects_checked':216032,'NZCV_effects_checked':2016,'read_bytes_checked':161248,'write_bytes_checked':21760,'write_effects_checked':5760,'unknown_copied_bytes_checked':0}

def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)

def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 pins,old,ingress,previous=R.inputs();e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
 assert e['generator_sha256']==a['generator_sha256']==sha(ROOT/('recover_'+R.P+'.py'))and a['auditor_sha256']==sha(ROOT/('audit_'+R.P+'.py'))and a['checks_sha256']==CHECKS_SHA
 assert e['parent_pins']==a['parent_pins']==R.PINS and len(R.PINS)==22
 assert e['dependencies']==a['dependencies']=={n:sha(ROOT/n)for n in R.DEPS}and len(R.DEPS)==23
 assert e['source_regions']==R.source()and len(e['source_regions'])==11 and sum(len(s['instructions'])for s in e['source_regions'])==203
 assert e['verified_counts']==a['verified_counts']==COUNTS and a['independent_totals']==INDEPENDENT and a['source_proofs_unsat']==7 and a['all_checks_pass']
 fresh=R.obligations();assert len(fresh)==7 and [q['label']for q in fresh]==[q['label']for q in e['source_proofs']]
 for row in e['source_proofs']:
  s=z3.Solver();s.set(timeout=30000);s.from_string(row['query']);assert str(s.check())==row['result']=='unsat'
 assert e['source_fixups']==R.Parent.R.R.verify_fixups({int(at,16)for c in e['cases']for at in c['trace']['used_fixups']})
 assert e['caller_branch_slots']==R.Parent.R.R.verify_fixups({R.TABLE+n*8 for n in [0x524a,0x553e,0x554a]})
 assert len(e['cases'])==len(a['interface_joins'])==16 and len(a['independent_replays'])==32
 assert len({(c['configuration']['epoch'],c['configuration']['name'])for c in e['cases']})==16
 for j,(case,join)in enumerate(zip(e['cases'],a['interface_joins'])):
  c=case['configuration'];prior=next(v for v in previous['cases']if v['configuration']['epoch']==c['epoch']and v['configuration']['name']==c['preparation_variant']);pc=prior['configuration'];offset=R.PROFILES[c['operand_profile']];f=int(c['caller_SP'],16)-0x9d0;overlays=[]
  if offset is not None:
   field={0x6c8:'input_block_hex',0x610:'input_pointer0_hex',0x600:'input_pointer20_hex'}[offset];baseline=next(v for v in a['interface_joins']if v['epoch']==c['epoch']and v['variant']==pc['name']+'_baseline');byte=bytes.fromhex(baseline[field])[0]
   overlays=[{'address':hex(f+offset),'old_byte_hex':bytes([byte]).hex(),'new_byte_hex':bytes([byte^1]).hex(),'xor_mask_u8':1}]
  expected={**pc,'preparation_variant':pc['name'],'name':pc['name']+'_'+c['operand_profile'],'operand_profile':c['operand_profile'],'operand_overlays':overlays,'entry':hex(R.ENTRY),'preparation_prefix_source_visits':len(prior['trace']['steps'])}
  assert c==expected and pc['declared_decoded_object_word']==0 and join==A.interfaces(case,prior)and not case['API_models']
  assert case['counts']=={'source_visits':7000,'source_pool_entries':3656,'read_events':1274,'write_events':180}
  for pattern,row in zip([0,3],a['independent_replays'][2*j:2*j+2]):assert row['pattern']==pattern and row['epoch']==c['epoch']and row['variant']==c['name']and row['all_checks_pass']and row['verified_counts']['source_visits']==7000 and row['boundary']==case['trace']['boundary']and not row['modeled_retirement_checked']
 assert a['profile_relations']==A.profile_relations(a['interface_joins'])and len(a['profile_relations'])==12
 expected_distances={(0,'prefix_word0'):(61,72),(0,'extended_word0'):(59,63),(1,'prefix_word0'):(61,72),(1,'extended_word0'):(63,61)}
 for row in a['profile_relations']:
  n,m=expected_distances[row['epoch'],row['preparation_variant']];first,local,changed={'block_bit0':(1,0,n),'pointer0_bit0':(0,1,n),'pointer20_bit0':(0,0,m)}[row['profile']]
  assert row['output_distances_bits']=={'preprocessed_block_hex':first,'decoded_pointer0_hex':local,'core_block_hex':changed,'output_block_hex':changed}
 for key in ['prefixes_reexecuted','native_target_executed','native_API_executed','IDB_mutated','live_IDA_claim','actual_partial_fixture_resumed','native_caller_admission_established','native_daemon_kext_pairing_established','full_goal_complete']:assert not e[key]and not a[key]
 report=read(BASE/'daemon_nested_helper_processing_report.md');assert all(f'| NP{k} |'in report for k in range(1,9))and all(f'**QG{k}**'in report for k in range(1,8))
 assert all(s in report for s in [e['source_sha256'],'224,000','112,000','0x100383700','0x10015fa00','unknown','0x1c','0x858da19d'])
 return e,a

def main():
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
 assert len(before)==len(old['files'])==8575 and len(after)==len(new['files'])==8581
 assert not before.keys()-after.keys()and after.keys()-before.keys()==ADDED and {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
 e,a=receipts();assert new['validation']['daemon_nested_helper_processing_increment_checks']==COUNTS and new['validation']['daemon_nested_helper_processing_static_scope']==e['scope']
 assert new['validation']['reports']==old['validation']['reports']+1==474 and new['goal_status']=='active'and len(OWNED)==15
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 for p in ARCHIVES:assert not(BASE/p).exists()
 for p in OWNED:path_hygiene(read(BASE/(p[:-4]if p.endswith('.zst')else p)).encode())
 for obj in [e,a]:path_hygiene(json.dumps(H.paths_in_typed_payloads(obj)).encode())
 fields=sum(H.hex_hygiene(obj)[0]for obj in [e,a]);path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,(delta^OWNED)
 print(json.dumps({'unchanged_manifest_entries':8567,'owned_physical_files':15,'original_inputs_preserved':3,'reports':474,'source_cases':16,'independent_A64_replays':32,'original_A64_visits':224000,'queries_unsat':7,'decoded_hex_fields_path_checked':fields,'native_target_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}))

if __name__=='__main__':main()
