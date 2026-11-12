#!/usr/bin/env python3
"""Pin original header/setup interfaces, audit receipts and publication delta.

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
import verify_corefp_word_recurrence_publication as F
import verify_corefp_late_preparation_publication as H
import audit_corefp_word_inputs as A
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='c288be9967266c19f08020386833279897a97b5a'
BASELINE_SHA='c879f653c9956f11efc22d71dd6ec6bb9253d613eb6728c90bcefaf7eaf8d4c6'
CHECKS_SHA='58779662b64b33c6bc97f9014e1f59c49319d8e4d80c2310304c79e2db69f562'
AUDIT_SHA='89d8acdb397c8d2d0dd3ab246e8eecf47b719ab612f11fb159392c8163678ae1'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','corefp_scan_entry_report.md','corefp_word_recurrence_report.md','foundational_triage_report.md','interface_abi_report.md',
 'interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'corefp_word_inputs_report.md','triage_evidence/recover_corefp_word_inputs.py','triage_evidence/audit_corefp_word_inputs.py',
 'triage_evidence/verify_corefp_word_inputs_publication.py','triage_evidence/corefp_word_inputs_checks.json','triage_evidence/corefp_word_inputs_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/corefp_word_inputs_checks.json','triage_evidence/corefp_word_inputs_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
PINS={**F.PINS,'corefp_word_recurrence_checks.json':F.CHECKS_SHA,'corefp_word_recurrence_audit.json':F.AUDIT_SHA}
COUNTS={'profiles':6,'regions':74,'source_instructions':339,'source_B':1356,'regional_visits':2226,'regional_reads':104,'regional_writes':66,'regional_PAC_models':0,
 'census_instructions':1791,'census_B':7164,'preservation_contracts':16,'new_queries_unsat':42}
RESETS=[(0x1b4924,0x1b492c,0x37a981c3),(0x1b5040,0x1b5048,0x37a981c3),(0x1b58bc,0x1b58c4,0x20390963),(0x1b5f9c,0x1b5fa4,0x20390963)]
COUNTERS=[(0x1b4d44,0x1b4d6c,9,9),(0x1b51c8,0x1b51cc,20,20),(0x1b5c10,0x1b5c38,1,1),(0x1b63d0,0x1b63d4,16,16)]


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def receipts():
    assert sha(ROOT/'corefp_word_inputs_checks.json')==CHECKS_SHA and sha(ROOT/'corefp_word_inputs_audit.json')==AUDIT_SHA
    e=json.loads(read(ROOT/'corefp_word_inputs_checks.json'));a=json.loads(read(ROOT/'corefp_word_inputs_audit.json'));r=a['result']
    assert e['generator_sha256']==a['generator_sha256']==sha(ROOT/'recover_corefp_word_inputs.py')and a['auditor_sha256']==sha(ROOT/'audit_corefp_word_inputs.py')
    assert a['checks_sha256']==CHECKS_SHA and e['parent_pins']==a['parent_pins']==PINS and len(PINS)==18
    assert e['dependencies']==a['dependencies']and len(e['dependencies'])==21
    pins={}
    for name,h in {**PINS,**e['dependencies']}.items():
        assert sha(ROOT/name)==h
        if name in PINS:pins[name]=json.loads(read(ROOT/name))
    assert e['thin_sha256']=='8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c'
    assert a['fresh_replay_completed']and a['process_exit_code']==0 and r['all_checks_pass']and e['verified_counts']==r['verified_counts']==COUNTS
    assert r['independent_replay']==pins['corefp_word_recurrence_audit.json']['result']['independent_replay']
    assert e['replay_totals']=={k:v for k,v in r['independent_replay'].items()if not k.startswith('initial_')}
    expected={'actual_full_frames':74,'independent_scalar_frames':74,'finite_header_cases':98304,'finite_setup_cases':30720,'finite_source_visits':3784704,
      'off_premise_prefixes':32,'off_premise_source_visits':742,'stable_control_epochs':24,'header_handoffs':32,'new_queries_unsat':42,'frozen_queries_unsat':1192,'total_queries_unsat':1234}
    for k,v in expected.items():assert r[k]==v
    proofs=e['source_checks']['proofs'];assert len(proofs)==len({p['label']for p in proofs})==42
    for p in proofs:
        q=z3.Solver();q.set(timeout=30000);q.from_string(p['query']);assert p['result']=='unsat'and q.check()==z3.unsat,p['label']
    s=A.C.Pointers()
    def source(lo,hi):return [{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'instruction':i.mnemonic+' '+i.op_str}for i in A.C.CS.disasm(s.read(lo,hi-lo),lo)]
    assert len(e['source_regions'])==11
    for region,(name,lo,hi)in zip(e['source_regions'],A.SPECS):
        assert region['name']==name and region['start']==hex(lo)and region['end']==hex(hi)and region['instructions']==source(lo,hi)
    assert sum(len(v['instructions'])for v in e['source_regions'])==339
    assert len(e['threshold_resets'])==len(e['counter_regions'])==4
    for region,(lo,hi,bias)in zip(e['threshold_resets'],RESETS):
        assert (region['start'],region['end'],region['bias_u32'])==(hex(lo),hex(hi),hex(bias))and region['instructions']==source(lo,hi)
    for region,(lo,hi,src,dst)in zip(e['counter_regions'],COUNTERS):
        assert (region['start'],region['end'],region['input'],region['output'])==(hex(lo),hex(hi),src,dst)and region['instructions']==source(lo,hi)
    A.check_census(e,s)
    assert len(e['blocks'])==74 and len(e['joins'])==len(a['interface_joins'])==6 and len(a['component_oracles'])==62
    assert sum(len(b['visits'])for b in e['blocks'])==2226 and sum(len(b['reads'])for b in e['blocks'])==104 and sum(len(b['writes'])for b in e['blocks'])==66
    assert sum(v['size_B']for b in e['blocks']for v in b['reads'])==736 and sum(v['size_B']for b in e['blocks']for v in b['writes'])==336 and not any(b['PAC_models']for b in e['blocks'])
    offset=0;oi=0;header_cases=setup_cases=finite_visits=negative_visits=0
    for p,join,interfaces in zip(pins['corefp_workspace_checks.json']['profiles'],e['joins'],a['interface_joins']):
        label=p['configuration']['label'];blocks=[b for b in e['blocks']if b['label']==label];offset+=len(blocks)
        assert join['label']==interfaces['label']==label and int(join['master_W22'],16)&A.M==0xf82c
        assert join['control_chain_u32']==interfaces['control_chain_u32']==list(map(hex,[0x8569,0x8568,0x4d3a,0x4d25,0xd373,0x7c09,0x55be]))
        for b in blocks:
            start,end=b['entry']['source_visit'],b['end']['source_visit'];_,lo,hi=next(v for v in A.SPECS if v[0]==b['name'])
            assert end-start==(hi-lo)//4 and b['visits']==p['visits'][start:end]
            for k in ['reads','writes','PAC_models']:assert b[k]==[v for v in p[k]if start<=v['visit']<end]
            A.scalar(b,s)
            if b['name']in ['copy_a','second_meta']:continue
            o=a['component_oracles'][oi];oi+=1;header=b['name']in A.HEADERS;cases=3072 if header else 1024
            assert o['name']==b['name']and o['label']==label and o['cases']==cases and o['source_visits']==cases*len(b['visits'])and o['source_bytes_preserved']
            assert len(o['ordered_frames_sha256'if header else'ordered_frames_and_stack_sha256'])==64
            finite_visits+=o['source_visits']
            if not header:setup_cases+=cases;continue
            header_cases+=cases;assert len(o['off_premise_controls'])==1;control=o['off_premise_controls'][0];d=A.HEADERS[b['name']]
            assert control=={'threshold_register':'X21','retained_threshold_u32':hex(d['bias']),'changed_threshold_u32':hex(d['bias']-1),'counter_u32':hex(d['bias']-1),
              'actual_index_u64':hex(A.MOD-1),'candidate_index_u64':hex(A.M),'actual_address_u64':hex(A.BUF-8),'candidate_address_u64':hex(A.BUF+8*A.M),
              'stopped_before_word_load':True,'common_contract_rejected':True}
            negative_visits+=len(b['visits'])-1
        assert interfaces==A.joins(p,blocks,pins)
    assert offset==74 and oi==62 and (header_cases,setup_cases,finite_visits,negative_visits)==(98304,30720,3784704,742)
    assert sum(len(j['epochs'])for j in a['interface_joins'])==24 and sum(len(j['header_interfaces'])for j in a['interface_joins'])==32
    flags=['native_API_executed','IDB_mutated','new_live_IDA_claim','earlier_arithmetic_passes_universally_reduced','general_raw_preparation_contract_established','full_goal_complete']
    assert not any(e[k]or a[k]for k in flags)and not e['native_target_executed']and not r['native_target_executed']and e['whole_transform_algorithm']==a['whole_transform_algorithm']=='unknown'
    report=read(BASE/'corefp_word_inputs_report.md');assert all(f'| WI{i} |'in report for i in range(1,7))and all(f'**QG{i}**'in report for i in range(1,8))
    assert all(x in report for x in [e['thin_sha256'],'1356','7192','129024','3784704','1234','742','f82c','0x410','488136'])
    return e,a


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==len(old['files'])==8515 and len(after)==len(new['files'])==8521
    assert not before.keys()-after.keys()and after.keys()-before.keys()==ADDED and {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
    for row in new['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
    e,a=receipts();assert new['validation']['corefp_word_inputs_increment_checks']==COUNTS and new['validation']['corefp_word_inputs_static_scope']==e['scope']
    assert new['validation']['reports']==old['validation']['reports']+1==464 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']and len(OWNED)==16
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene(read(BASE/(p[:-4]if p.endswith('.zst')else p)).encode())
    path_hygiene(json.dumps(H.paths_in_typed_payloads(e)).encode());n=sum(H.hex_hygiene(v)[0]for v in [e,a]);path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,(delta^OWNED)
    print(json.dumps({'unchanged_manifest_entries':len(before)-len(CHANGED),'owned_physical_files':16,'original_inputs_preserved':3,'reports':464,
      'source_profiles':6,'source_visits':488136,'queries_unsat':1234,'finite_component_cases':129024,'finite_source_visits':3784704,'off_premise_prefixes':32,
      'stable_control_epochs':24,'header_handoffs':32,'decoded_hex_fields_path_checked':n,'native_target_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
