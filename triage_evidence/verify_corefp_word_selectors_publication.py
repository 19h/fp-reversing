#!/usr/bin/env python3
"""Pin word-selector evidence and the exact publication delta.

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
import verify_corefp_word_traversal_publication as F
import verify_corefp_late_preparation_publication as H
import audit_corefp_word_selectors as A
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='7add16109e9e4c378d5de4b5c2b79eb8cb42ca0e'
BASELINE_SHA='9d6be37550333d4e13b856838d9bd3e10e5dc799d6b05c777cfee09bcbbf3015'
CHECKS_SHA='1e35085771500199a64eb4ef921d4a1952873d801df2acb60a3505e23f234a93'
AUDIT_SHA='507df66a1e24b113ca25392d66862339f9bdae5d001ae28821d9fb86b4a90412'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','corefp_word_inputs_report.md','corefp_word_traversal_report.md','foundational_triage_report.md','interface_abi_report.md',
 'interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'corefp_word_selectors_report.md','triage_evidence/recover_corefp_word_selectors.py','triage_evidence/audit_corefp_word_selectors.py',
 'triage_evidence/verify_corefp_word_selectors_publication.py','triage_evidence/corefp_word_selectors_checks.json','triage_evidence/corefp_word_selectors_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/corefp_word_selectors_checks.json','triage_evidence/corefp_word_selectors_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
PINS={**F.PINS,'corefp_word_traversal_checks.json':F.CHECKS_SHA,'corefp_word_traversal_audit.json':F.AUDIT_SHA}
COUNTS={'profiles': 6, 'regions': 18, 'source_instructions': 117, 'source_B': 468, 'regional_visits': 702, 'regional_reads': 78, 'regional_read_B': 600, 'regional_writes': 48, 'regional_write_B': 240, 'regional_PAC_models': 0, 'new_queries_unsat': 28}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def receipts():
    assert sha(ROOT/'corefp_word_selectors_checks.json')==CHECKS_SHA and sha(ROOT/'corefp_word_selectors_audit.json')==AUDIT_SHA
    raw,e,s,pins=A.inputs();a=json.loads(read(ROOT/'corefp_word_selectors_audit.json'));r=a['result']
    assert e['generator_sha256']==a['generator_sha256']==sha(ROOT/'recover_corefp_word_selectors.py')and a['auditor_sha256']==sha(ROOT/'audit_corefp_word_selectors.py')
    assert a['checks_sha256']==CHECKS_SHA and e['parent_pins']==a['parent_pins']==PINS and len(PINS)==24
    assert e['dependencies']==a['dependencies']and len(e['dependencies'])==27
    assert a['fresh_replay_completed']and a['process_exit_code']==0 and r['all_checks_pass']and e['verified_counts']==r['verified_counts']==COUNTS
    assert r['independent_replay']==pins['corefp_word_traversal_audit.json']['result']['independent_replay']
    assert e['replay_totals']=={k:v for k,v in r['independent_replay'].items()if not k.startswith('initial_')}
    expected={'actual_full_frames':18,'independent_scalar_frames':18,'finite_cases':44736,'finite_source_visits':1861056,'split_control_cases':48,'split_control_source_visits':2640,
      'zero_divisor_cases':12312,'zero_divisor_source_visits':12402,'stable_cache_epochs':18,'stable_word_epochs':48,'selector_chains_checked':12,'new_queries_unsat':28,'frozen_queries_unsat':1301,'total_queries_unsat':1329}
    for k,v in expected.items():assert r[k]==v
    proofs=e['source_checks']['proofs'];assert len(proofs)==len({p['label']for p in proofs})==28 and len(A.frozen(pins))==1301
    for p in proofs:
        q=z3.Solver();q.set(timeout=30000);q.from_string(p['query']);assert p['result']=='unsat'and q.check()==z3.unsat,p['label']
    assert e['source_checks']['normalization_cut']=={'pc':'0x1b45f4','register':'X1','replacement':'zero_extend_64(N)','premise':'N <= 0x1fffffff; encoded byte count = ((N << 3) OR residual3) XOR 0x458e3e59','source_binding_label':'first_count_source_binding'}
    assert sum(len(v['instructions'])for v in e['source_regions'])==117 and len(e['blocks'])==len(a['component_oracles'])==18 and len(a['interface_joins'])==len(a['zero_divisor_oracles'])==6
    assert sum(len(b['visits'])for b in e['blocks'])==702 and sum(len(b['reads'])for b in e['blocks'])==78 and sum(len(b['writes'])for b in e['blocks'])==48
    assert sum(v['size_B']for b in e['blocks']for v in b['reads'])==600 and sum(v['size_B']for b in e['blocks']for v in b['writes'])==240 and not any(b['PAC_models']for b in e['blocks'])
    for j,(p,join,zero)in enumerate(zip(pins['corefp_workspace_checks.json']['profiles'],a['interface_joins'],a['zero_divisor_oracles'])):
        label=p['configuration']['label'];blocks=e['blocks'][3*j:3*j+3];oracles=a['component_oracles'][3*j:3*j+3]
        assert [b['name']for b in blocks]==[v[0]for v in A.SPECS]and all(b['label']==label for b in blocks)
        for b,o in zip(blocks,oracles):
            start,end=b['entry']['source_visit'],b['end']['source_visit'];_,lo,hi=next(v for v in A.SPECS if v[0]==b['name']);assert end-start==(hi-lo)//4 and b['visits']==p['visits'][start:end]
            for k in ['reads','writes','PAC_models']:assert b[k]==[v for v in p[k]if start<=v['visit']<end]
            A.scalar(b,s);count={'pointer_cache':2048,'first_selector':2304,'second_selector':3104}[b['name']]
            assert o['label']==label and o['name']==b['name']and o['cases']==count and o['source_visits']==count*len(b['visits'])and o['source_bytes_preserved']and len(o['ordered_frames_and_stack_sha256'])==64
            domains=[['biased_pointer',64]]if b['name']=='pointer_cache'else[['word_seed',64],['count',32,1,32]]+([['control',32]]if b['name']=='second_selector'else[])
            assert o['domains']==domains and o['control_cases']==(0 if b['name']=='pointer_cache'else 4)and o['control_source_visits']==o['control_cases']*len(b['visits'])
            want=[]if b['name']=='pointer_cache'else[{'all_raw_words_u64':hex(v),'N':4,'remainder_u32':hex(v if b['name']=='first_selector'else(v+2)%4)}for v in range(4)];assert o['split_controls']==want
        assert join==A.joins(p,blocks,pins)and len(join['cache_epochs'])==3 and len(join['word_epochs'])==8 and len(join['chains'])==2
        assert zero['label']==label and zero['prefix_stop_PC']=='0x1b461c'and zero['first_index_u32']=='0x68f4137b'and zero['u64_UDIV_PC']=='0x1b462c'
        assert zero['u64_cases']==2051 and zero['prefix_cases']==1 and zero['cases']==2052 and zero['source_visits']==2067 and zero['source_bytes_preserved']and not zero['buffer_read_executed']and not zero['native_fault_established']and len(zero['ordered_u64_frames_sha256'])==64
    assert sum(v['cases']for v in a['component_oracles'])==44736 and sum(v['source_visits']for v in a['component_oracles'])==1861056
    assert sum(v['control_cases']for v in a['component_oracles'])==48 and sum(v['control_source_visits']for v in a['component_oracles'])==2640
    flags=['native_API_executed','IDB_mutated','new_live_IDA_claim','earlier_arithmetic_passes_universally_reduced','general_raw_preparation_contract_established','full_goal_complete']
    assert not any(e[k]or a[k]for k in flags)and not e['native_target_executed']and not r['native_target_executed']and e['whole_transform_algorithm']==a['whole_transform_algorithm']=='unknown'
    report=read(BASE/'corefp_word_selectors_report.md');assert all(f'| WS{i} |'in report for i in range(1,7))and all(f'**QG{i}**'in report for i in range(1,8))
    assert all(v in report for v in [e['thin_sha256'],'468','44736','1861056','1329','12312','0x1b45f4','0x1b461c','0x70','DDI 0602','residual3','K0(C)'])
    return e,a


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==len(old['files'])==8533 and len(after)==len(new['files'])==8539
    assert not before.keys()-after.keys()and after.keys()-before.keys()==ADDED and {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
    for row in new['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
    e,a=receipts();assert new['validation']['corefp_word_selectors_increment_checks']==COUNTS and new['validation']['corefp_word_selectors_static_scope']==e['scope']
    assert new['validation']['reports']==old['validation']['reports']+1==467 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']and len(OWNED)==16
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene(read(BASE/(p[:-4]if p.endswith('.zst')else p)).encode())
    path_hygiene(json.dumps(H.paths_in_typed_payloads(e)).encode());n=sum(H.hex_hygiene(v)[0]for v in [e,a]);path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,(delta^OWNED)
    print(json.dumps({'unchanged_manifest_entries':len(before)-len(CHANGED),'owned_physical_files':16,'original_inputs_preserved':3,'reports':467,
      'source_profiles':6,'source_visits':488136,'queries_unsat':1329,'finite_cases':44736,'finite_source_visits':1861056,'split_control_cases':48,
      'stable_cache_epochs':18,'stable_word_epochs':48,'selector_chains_checked':12,'decoded_hex_fields_path_checked':n,'native_target_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
