#!/usr/bin/env python3
"""Pin scan-entry contracts, carrier/epoch joins and publication delta.

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
import verify_corefp_phase_parameters_publication as F
import verify_corefp_late_preparation_publication as H
import audit_corefp_scan_entry as A
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='ac4ca2f96586c7839bd085844994b1f0021e183b'
BASELINE_SHA='846073dcecf185a6376402b197e3768cc815a82259795e39d6911346856b216d'
CHECKS_SHA='05d8c579009d0a2c79705fcd7b491bb548f5173ae8e7a423c176a4316065869e'
AUDIT_SHA='b3598b3e866886d404522ff56cc6a394f7ad876d4dde425b258101b76465f383'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','corefp_phase_parameters_report.md','corefp_preparation_scans_report.md','foundational_triage_report.md','interface_abi_report.md',
 'interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'corefp_scan_entry_report.md','triage_evidence/recover_corefp_scan_entry.py','triage_evidence/audit_corefp_scan_entry.py',
 'triage_evidence/verify_corefp_scan_entry_publication.py','triage_evidence/corefp_scan_entry_checks.json','triage_evidence/corefp_scan_entry_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/corefp_scan_entry_checks.json','triage_evidence/corefp_scan_entry_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
PINS={**F.PINS,'corefp_phase_parameters_checks.json':F.CHECKS_SHA,'corefp_phase_parameters_audit.json':F.AUDIT_SHA}
COUNTS={'profiles':6,'regions':30,'primary_source_instructions':218,'primary_source_B':872,'regional_visits':1308,'regional_reads':24,'regional_writes':24,
 'regional_PAC_models':0,'corridor_static_instructions':1143,'corridor_static_B':4572,'corridor_branch_sites':7,'new_queries_unsat':23,'shared_seed_joins':6,'initial_bank_xor_joins':18}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def receipts():
    assert sha(ROOT/'corefp_scan_entry_checks.json')==CHECKS_SHA and sha(ROOT/'corefp_scan_entry_audit.json')==AUDIT_SHA
    e=json.loads(read(ROOT/'corefp_scan_entry_checks.json'));a=json.loads(read(ROOT/'corefp_scan_entry_audit.json'));r=a['result']
    assert e['generator_sha256']==a['generator_sha256']==sha(ROOT/'recover_corefp_scan_entry.py')and a['auditor_sha256']==sha(ROOT/'audit_corefp_scan_entry.py')
    assert a['checks_sha256']==CHECKS_SHA and e['parent_pins']==a['parent_pins']==PINS and len(PINS)==12
    assert e['dependencies']==a['dependencies']and len(e['dependencies'])==15
    for name,h in {**PINS,**e['dependencies']}.items():assert sha(ROOT/name)==h
    assert e['thin_sha256']=='8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c'
    assert a['fresh_replay_completed']and a['process_exit_code']==0 and r['all_checks_pass']and e['verified_counts']==r['verified_counts']==COUNTS
    assert r['independent_replay']==F.F.TOTALS and e['replay_totals']=={k:v for k,v in F.F.TOTALS.items()if not k.startswith('initial_')}
    expected={'actual_full_frames':30,'finite_initializer_cases':61440,'initializer_output_words_checked':184320,'finite_encoding_pairs':18432,
      'encoded_pair_words_checked':55296,'finite_control_writer_cases':6144,'finite_source_visits':6180864,'off_premise_controls':6,'off_premise_source_visits':612,
      'stable_field_epochs':18,'stable_control_epochs':6,'corridor_PAC_models_checked':130,'new_queries_unsat':23,'frozen_queries_unsat':1121,'total_queries_unsat':1144}
    for k,v in expected.items():assert r[k]==v
    old,_=F.receipts();proofs=e['source_checks']['proofs'];assert len(proofs)==len({p['label']for p in proofs})==23
    for p in proofs:
        q=z3.Solver();q.set(timeout=30000);q.from_string(p['query']);assert p['result']=='unsat'and q.check()==z3.unsat,p['label']
    s=A.C.Pointers()
    def source(lo,hi):return [{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'instruction':i.mnemonic+' '+i.op_str}for i in A.C.CS.disasm(s.read(lo,hi-lo),lo)]
    assert len(e['source_regions'])==5 and len(e['tail_source_regions'])==2
    for region,(name,lo,hi)in zip(e['source_regions'],A.SPECS):assert region['name']==name and int(region['start'],16)==lo and int(region['end'],16)==hi and region['instructions']==source(lo,hi)
    assert sum(len(x['instructions'])for x in e['source_regions'])==218
    for region,(lo,hi)in zip(e['tail_source_regions'],[(0x1b5444,0x1b54ac),(0x1b6620,0x1b6688)]):assert int(region['start'],16)==lo and int(region['end'],16)==hi and region['instructions']==source(lo,hi)
    c=e['corridor'];assert c['start']=='0x1b54d0'and c['end']=='0x1b66ac'and c['instructions']==source(0x1b54d0,0x1b66ac)and len(c['instructions'])==1143
    names={'w5','x5','w26','x26','w30','x30','lr','w22','x22'};branches=[]
    for i in A.C.CS.disasm(s.read(0x1b54d0,4572),0x1b54d0):
        rr,ww=i.regs_access();assert not names&{i.reg_name(j)for j in ww}and not any(i.group(j)for j in [2,3])
        if i.group(1):assert i.mnemonic=='braa';branches.append(hex(i.address))
    assert branches==c['branch_sites']and len(branches)==7 and c['preserved_registers']==['X5','X26','X30','X22']
    parent=json.loads(read(ROOT/'corefp_workspace_checks.json'));se=json.loads(read(ROOT/'corefp_preparation_scans_checks.json'))
    assert len(e['blocks'])==30 and len(e['joins'])==len(a['component_oracles'])==len(a['slot_epochs'])==6
    for j,(p,join,oracle,epochs)in enumerate(zip(parent['profiles'],e['joins'],a['component_oracles'],a['slot_epochs'])):
        assert join['label']==oracle['label']==epochs['label']==p['configuration']['label']==F.F.LABELS[j]
        for k,(name,lo,hi)in enumerate(A.SPECS):
            b=e['blocks'][j*5+k];assert b['label']==join['label']and b['name']==name
            start,end=b['entry']['source_visit'],b['end']['source_visit'];assert end-start==(hi-lo)//4 and b['visits']==p['visits'][start:end]
            for key in ['reads','writes','PAC_models']:assert b[key]==[v for v in p[key]if start<=v['visit']<end]
            assert not b['PAC_models']
        assert join['first_scan_end']==se['blocks'][j*2]['end']and join['second_scan_end']==se['blocks'][j*2+1]['end']==old['blocks'][j]['entry']
        left,right=[list(map(lambda v:int(v,16)&A.M,join[t]['CPU']['X31']))for t in ['first_scan_end','second_scan_end']]
        assert left[5]==right[5]==right[12]==(left[14]-0xdecc2544)%2**32 and left[14]==right[4]
        assert join['downstream_shared_seed_u32']==hex(left[5])and join['common_final_h_u32']==hex(left[14])
        assert len(set(join['initializer_seeds_u64']))==1 and all(x^y==A.D for x,y in zip(*[list(map(lambda v:int(v,16),row))for row in join['initializer_inputs_u32']]))
        assert len(join['corridor_PAC_models'])==(23 if p['configuration']['length_u32']==32 else 21)
        assert all(0x1b54d0<=int(v['target'],16)-A.C.BASE<=0x1b66ac for v in join['corridor_PAC_models'])
        assert epochs['epochs']==A.epochs(p)and len(epochs['epochs'])==4
        assert len(oracle['initializers'])==2
        for kind,m in enumerate(oracle['initializers']):
            assert m['finite_initializer_cases']==5120 and m['finite_source_visits']==5120*(102 if not kind else 83)and m['output_words_checked']==15360 and m['source_bytes_preserved']and len(m['ordered_frames_sha256'])==64
            assert len(m['off_premise_controls'])==(1 if not kind else 0)
            for control in m['off_premise_controls']:
                seed=int(control['seed_u64'],16);words=list(map(lambda v:int(v,16),control['input_words_u32']));n=control['shift'];got=list(map(lambda v:int(v,16),control['actual_words_u32']))
                assert control['control_u64']=='0x0'and n==((0x32f291f3&0xcd0d6df7)-0x4d23)%64 and n!=2 and control['fixed_two_candidate_rejected']
                assert got==[u^v for u,v in zip(words,A.mix64(seed,n))]and got!=[u^v for u,v in zip(words,A.mix64(seed))]
        assert oracle['fields']['finite_encoding_pairs']==3072 and oracle['fields']['finite_source_visits']==73728 and oracle['fields']['paired_words_checked']==9216 and oracle['fields']['source_bytes_preserved']
        assert oracle['control']['finite_control_writer_cases']==1024 and oracle['control']['finite_source_visits']==9216 and oracle['control']['zero_extended_u64_stores_checked']==1024 and oracle['control']['source_bytes_preserved']
    flags=['native_API_executed','IDB_mutated','new_live_IDA_claim','earlier_arithmetic_passes_universally_reduced','general_raw_preparation_contract_established','source_context_initializer_established','full_goal_complete']
    assert not any(e[k]or a[k]for k in flags)and not e['native_target_executed']and not r['native_target_executed']and e['whole_transform_algorithm']==a['whole_transform_algorithm']=='unknown'
    report=read(BASE/'corefp_scan_entry_report.md');assert all(f'| SE{i} |'in report for i in range(1,7))and all(f'**QG{i}**'in report for i in range(1,8))
    assert all(x in report for x in [e['thin_sha256'],'0xeb3e515b','0x8568','0x4d3a','1143','130','61440','6180864','1144'])
    return e,a


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==len(old['files'])==8497 and len(after)==len(new['files'])==8503
    assert not before.keys()-after.keys()and after.keys()-before.keys()==ADDED and {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
    for row in new['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
    e,a=receipts();assert new['validation']['corefp_scan_entry_increment_checks']==COUNTS and new['validation']['corefp_scan_entry_static_scope']==e['scope']
    assert new['validation']['reports']==old['validation']['reports']+1==461 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']and len(OWNED)==16
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene(read(BASE/(p[:-4]if p.endswith('.zst')else p)).encode())
    path_hygiene(json.dumps(H.paths_in_typed_payloads(e)).encode());n=sum(H.hex_hygiene(x)[0]for x in [e,a]);path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,(delta^OWNED)
    print(json.dumps({'unchanged_manifest_entries':len(before)-len(CHANGED),'owned_physical_files':16,'original_inputs_preserved':3,'reports':461,
      'source_profiles':6,'source_visits':488136,'queries_unsat':1144,'finite_initializer_cases':61440,'finite_encoding_pairs':18432,'finite_control_writer_cases':6144,
      'finite_source_visits':6180864,'off_premise_controls':6,'decoded_hex_fields_path_checked':n,'native_target_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
