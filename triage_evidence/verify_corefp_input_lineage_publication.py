#!/usr/bin/env python3
"""Pin entry-record/control/base lineage and the exact publication delta.

O(owned decoded content + pinned journals + manifest) time/space;
30 s/SMT query. No native target/API/IPC, IDA or history rewrite.
"""
import json,subprocess
from pathlib import Path
from hashlib import sha256
from compression import zstd
import z3
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
import verify_corefp_word_inputs_publication as F
import verify_corefp_late_preparation_publication as H
import audit_corefp_input_lineage as A
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='a0023dd146fcf814357be2d444335d79e6f8e80f'
BASELINE_SHA='cb5a7d8eb2ac38a65334b0ba6231b1b762cd69269f1e7ecad8042c9c824490cc'
CHECKS_SHA='067707e91f1811a94a89e73a96ffbd54dafb6c4b8c4d0bd29933b0bdafeee3b2'
AUDIT_SHA='3ed4b338a5dd56853c213ee4168928cd093e4281e41fe5e013efaf7cbbdd2098'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','corefp_pool_caller_report.md','corefp_word_inputs_report.md','foundational_triage_report.md','interface_abi_report.md',
 'interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'corefp_input_lineage_report.md','triage_evidence/recover_corefp_input_lineage.py','triage_evidence/audit_corefp_input_lineage.py',
 'triage_evidence/verify_corefp_input_lineage_publication.py','triage_evidence/corefp_input_lineage_checks.json','triage_evidence/corefp_input_lineage_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/corefp_input_lineage_checks.json','triage_evidence/corefp_input_lineage_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
PINS={**F.PINS,'corefp_word_inputs_checks.json':F.CHECKS_SHA,'corefp_word_inputs_audit.json':F.AUDIT_SHA}
COUNTS={'profiles':6,'regions':72,'primary_source_instructions':83,'primary_source_B':332,'auxiliary_source_instructions':9,'auxiliary_source_B':36,
 'regional_visits':498,'regional_reads':60,'regional_writes':42,'regional_PAC_models':0,'preservation_contracts':15,'census_instructions':2216,'census_B':8864,
 'unique_source_instructions':2273,'unique_source_B':9092,'new_queries_unsat':29}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def receipts():
    assert sha(ROOT/'corefp_input_lineage_checks.json')==CHECKS_SHA and sha(ROOT/'corefp_input_lineage_audit.json')==AUDIT_SHA
    e=json.loads(read(ROOT/'corefp_input_lineage_checks.json'));a=json.loads(read(ROOT/'corefp_input_lineage_audit.json'));r=a['result']
    assert e['generator_sha256']==a['generator_sha256']==sha(ROOT/'recover_corefp_input_lineage.py')and a['auditor_sha256']==sha(ROOT/'audit_corefp_input_lineage.py')
    assert a['checks_sha256']==CHECKS_SHA and e['parent_pins']==a['parent_pins']==PINS and len(PINS)==20
    assert e['dependencies']==a['dependencies']and len(e['dependencies'])==23
    pins={}
    for name,h in {**PINS,**e['dependencies']}.items():
        assert sha(ROOT/name)==h
        if name in PINS:pins[name]=json.loads(read(ROOT/name))
    assert e['thin_sha256']=='8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c'
    assert a['fresh_replay_completed']and a['process_exit_code']==0 and r['all_checks_pass']and e['verified_counts']==r['verified_counts']==COUNTS
    assert r['independent_replay']==pins['corefp_word_inputs_audit.json']['result']['independent_replay']
    assert e['replay_totals']=={k:v for k,v in r['independent_replay'].items()if not k.startswith('initial_')}
    expected={'actual_full_frames':72,'independent_scalar_frames':72,'finite_component_cases':147456,'finite_source_visits':2002944,
      'auxiliary_cases':1024,'auxiliary_source_visits':9216,'stable_control_buffer_epochs':30,'word_header_handoffs':32,
      'new_queries_unsat':29,'frozen_queries_unsat':1234,'total_queries_unsat':1263}
    for k,v in expected.items():assert r[k]==v
    proofs=e['source_checks']['proofs'];assert len(proofs)==len({p['label']for p in proofs})==29
    for p in proofs:
        q=z3.Solver();q.set(timeout=30000);q.from_string(p['query']);assert p['result']=='unsat'and q.check()==z3.unsat,p['label']
    assert e['source_checks']['normalization_cut']=={'pc':'0x1af814','register':'W8','identity':'record_source_key','replacement':'(low32(record) XOR 0x542fbf9b)*0x4386951d mod 2^32'}
    assert e['source_checks']['selected_operation_u32']=='0x7f48'and e['source_checks']['control_chain_u32']==list(map(hex,[0xedff,0xad01,0x7f48,0xc644,0xf82c]))
    s=A.C.Pointers()
    def source(lo,hi):return [{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'instruction':i.mnemonic+' '+i.op_str}for i in A.C.CS.disasm(s.read(lo,hi-lo),lo)]
    assert len(e['source_regions'])==12 and len(e['auxiliary_regions'])==3
    for region,(name,lo,hi)in zip(e['source_regions']+e['auxiliary_regions'],A.SPECS+A.AUX):
        assert region['name']==name and region['start']==hex(lo)and region['end']==hex(hi)and region['instructions']==source(lo,hi)
    assert sum(len(v['instructions'])for v in e['source_regions'])==83 and sum(len(v['instructions'])for v in e['auxiliary_regions'])==9
    A.check_census(e,s);unique={int(row['pc'],16)for region in e['source_regions']+e['auxiliary_regions']+[e['census']]for row in region['instructions']};assert len(unique)==2273
    assert len(e['blocks'])==len(a['component_oracles'])==72 and len(a['interface_joins'])==6
    assert sum(len(b['visits'])for b in e['blocks'])==498 and sum(len(b['reads'])for b in e['blocks'])==60 and sum(len(b['writes'])for b in e['blocks'])==42
    assert sum(v['size_B']for b in e['blocks']for v in b['reads'])==384 and sum(v['size_B']for b in e['blocks']for v in b['writes'])==264 and not any(b['PAC_models']for b in e['blocks'])
    offset=0;cases=visits=0
    for p,join in zip(pins['corefp_workspace_checks.json']['profiles'],a['interface_joins']):
        label=p['configuration']['label'];blocks=e['blocks'][offset:offset+12];oracles=a['component_oracles'][offset:offset+12];offset+=12
        assert [b['name']for b in blocks]==[v[0]for v in A.SPECS]and all(b['label']==label for b in blocks)
        for b,o in zip(blocks,oracles):
            start,end=b['entry']['source_visit'],b['end']['source_visit'];_,lo,hi=next(v for v in A.SPECS if v[0]==b['name'])
            assert end-start==(hi-lo)//4 and b['visits']==p['visits'][start:end]
            for k in ['reads','writes','PAC_models']:assert b[k]==[v for v in p[k]if start<=v['visit']<end]
            A.scalar(b,s)
            domains=[['record',32],['operation',32],['buffer',64],['source',64],['length',32]]if b['name']=='record_decode'else[['buffer',64],['companion',64]]if b['name']=='buffer_cache'else[['value',64 if b['name']in ['control_first_reload','first_base','second_base']else 32]]
            count=sum(bits//8*256 for _,bits in domains)
            assert o['name']==b['name']and o['label']==label and o['domains']==domains and o['cases']==count and o['source_visits']==count*len(b['visits'])and o['source_bytes_preserved']and len(o['ordered_frames_and_stack_sha256'])==64
            cases+=count;visits+=o['source_visits']
        assert join==A.joins(p,blocks,pins)and join['retained_direction']=='reverse'
        assert join['other_operation_same_master']=={'operation_u32':'0x7f49','master_u32':'0xf82c','native_admission_established':False}
    assert offset==72 and (cases,visits)==(147456,2002944)and sum(len(j['epochs'])for j in a['interface_joins'])==30 and sum(j['header_handoffs']for j in a['interface_joins'])==32
    aux=a['auxiliary_oracle'];assert aux['finite_cases']==1024 and aux['source_visits']==9216 and aux['two_control_cases']==2 and aux['control_source_visits']==18
    assert aux['selected_operation_u32']==aux['selected_result_u32']=='0x7f48'and aux['off_operation_u32']=='0x7f49'and aux['off_operation_result_u32']=='0x7f50'
    assert aux['general_identity_rejected']and aux['source_bytes_preserved']and not aux['dispatch_executed']and len(aux['ordered_frames_sha256'])==64
    flags=['native_API_executed','IDB_mutated','new_live_IDA_claim','earlier_arithmetic_passes_universally_reduced','general_raw_preparation_contract_established','full_goal_complete']
    assert not any(e[k]or a[k]for k in flags)and not e['native_target_executed']and not r['native_target_executed']and e['whole_transform_algorithm']==a['whole_transform_algorithm']=='unknown'
    report=read(BASE/'corefp_input_lineage_report.md');assert all(f'| IL{i} |'in report for i in range(1,7))and all(f'**QG{i}**'in report for i in range(1,8))
    assert all(x in report for x in [e['thin_sha256'],'332','9092','147456','2002944','1263','7f49)=7f50','0x468','488136','0x1af814'])
    return e,a


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==len(old['files'])==8521 and len(after)==len(new['files'])==8527
    assert not before.keys()-after.keys()and after.keys()-before.keys()==ADDED and {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
    for row in new['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
    e,a=receipts();assert new['validation']['corefp_input_lineage_increment_checks']==COUNTS and new['validation']['corefp_input_lineage_static_scope']==e['scope']
    assert new['validation']['reports']==old['validation']['reports']+1==465 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']and len(OWNED)==16
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene(read(BASE/(p[:-4]if p.endswith('.zst')else p)).encode())
    path_hygiene(json.dumps(H.paths_in_typed_payloads(e)).encode());n=sum(H.hex_hygiene(v)[0]for v in [e,a]);path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,(delta^OWNED)
    print(json.dumps({'unchanged_manifest_entries':len(before)-len(CHANGED),'owned_physical_files':16,'original_inputs_preserved':3,'reports':465,
      'source_profiles':6,'source_visits':488136,'queries_unsat':1263,'finite_component_cases':147456,'finite_source_visits':2002944,'auxiliary_cases':1024,
      'stable_control_buffer_epochs':30,'word_header_handoffs':32,'decoded_hex_fields_path_checked':n,'native_target_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
