#!/usr/bin/env python3
"""Pin word recurrence, conditional stream joins and exact publication delta.

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
import verify_corefp_word_codec_publication as F
import verify_corefp_late_preparation_publication as H
import audit_corefp_word_recurrence as A
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='9135aa9920f14579909cc37774b02d020c2475d7'
BASELINE_SHA='32a3c321685b908aa72423173eb9e134b4c73075a672048e92ae86a17b415bcf'
CHECKS_SHA='561769cd0f59a45dc0f07d7a9912453b7bfbf1ab05402be98a40776f37c8a3e8'
AUDIT_SHA='ef828966d89deda9f6c5559e313f6dd45e3b1d1351d9ec6fd5031e2dafbfacac'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','corefp_scan_entry_report.md','corefp_word_codec_report.md','foundational_triage_report.md','interface_abi_report.md',
 'interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'corefp_word_recurrence_report.md','triage_evidence/recover_corefp_word_recurrence.py','triage_evidence/audit_corefp_word_recurrence.py',
 'triage_evidence/verify_corefp_word_recurrence_publication.py','triage_evidence/corefp_word_recurrence_checks.json','triage_evidence/corefp_word_recurrence_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/corefp_word_recurrence_checks.json','triage_evidence/corefp_word_recurrence_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
PINS={**F.PINS,'corefp_word_codec_checks.json':F.CHECKS_SHA,'corefp_word_codec_audit.json':F.AUDIT_SHA}
COUNTS={'profiles':6,'regions':32,'source_instructions':1075,'source_B':4300,'regional_visits':8226,'regional_reads':18,'regional_writes':0,'regional_PAC_models':0,'word_steps':32,'new_queries_unsat':37,'normalization_cuts':16}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def receipts():
    assert sha(ROOT/'corefp_word_recurrence_checks.json')==CHECKS_SHA and sha(ROOT/'corefp_word_recurrence_audit.json')==AUDIT_SHA
    e=json.loads(read(ROOT/'corefp_word_recurrence_checks.json'));a=json.loads(read(ROOT/'corefp_word_recurrence_audit.json'));r=a['result']
    assert e['generator_sha256']==a['generator_sha256']==sha(ROOT/'recover_corefp_word_recurrence.py')and a['auditor_sha256']==sha(ROOT/'audit_corefp_word_recurrence.py')
    assert a['checks_sha256']==CHECKS_SHA and e['parent_pins']==a['parent_pins']==PINS and len(PINS)==16
    assert e['dependencies']==a['dependencies']and len(e['dependencies'])==19
    for name,h in {**PINS,**e['dependencies']}.items():assert sha(ROOT/name)==h
    assert e['thin_sha256']=='8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c'
    assert a['fresh_replay_completed']and a['process_exit_code']==0 and r['all_checks_pass']and e['verified_counts']==r['verified_counts']==COUNTS
    old_a=json.loads(read(ROOT/'corefp_word_codec_audit.json'));assert r['independent_replay']==old_a['result']['independent_replay']and e['replay_totals']=={k:v for k,v in r['independent_replay'].items()if not k.startswith('initial_')}
    expected={'actual_full_frames':32,'independent_scalar_frames':32,'finite_component_cases':229888,'finite_source_visits':59095584,'off_premise_cases':38,
      'off_premise_source_visits':10434,'rejected_metadata_domains':32,'paired_streams':6,'new_queries_unsat':37,'frozen_queries_unsat':1155,'total_queries_unsat':1192}
    for k,v in expected.items():assert r[k]==v
    proofs=e['source_checks']['proofs'];assert len(proofs)==len({p['label']for p in proofs})==37
    for p in proofs:
        q=z3.Solver();q.set(timeout=30000);q.from_string(p['query']);assert p['result']=='unsat'and q.check()==z3.unsat,p['label']
    s=A.C.Pointers()
    def source(lo,hi):return [{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'instruction':i.mnemonic+' '+i.op_str}for i in A.C.CS.disasm(s.read(lo,hi-lo),lo)]
    assert len(e['source_regions'])==4 and len(e['models'])==4
    for region,(name,lo,hi),model,config in zip(e['source_regions'],A.SPECS,e['models'],A.CONFIG):
        assert region['name']==name and region['start']==hex(lo)and region['end']==hex(hi)and region['instructions']==source(lo,hi)
        for k in ['q','u','bank','out','h','a','b','idx']:assert model[k]==config[k]
        assert [(model['mba'][j][3]+model['fold'][j][3]+model['delta'][j])%A.MOD for j in range(2)]==config['offset']
    assert sum(len(x['instructions'])for x in e['source_regions'])==1075
    cuts=e['source_checks']['cuts'];assert len(cuts)==16 and sum(not c['metadata_u64']for c in cuts)==10
    for c in cuts:
        lo,hi=map(lambda k:int(c[k],16),['start','end']);assert c['instructions']==source(lo,hi)
        model=e['models'][c['kind']];assert [lo,hi,c['register'],int(c['bias_u64'],16)]==model[c['type']][c['stage']]
    parent=json.loads(read(ROOT/'corefp_workspace_checks.json'));codec=json.loads(read(ROOT/'corefp_word_codec_checks.json'));entry=json.loads(read(ROOT/'corefp_scan_entry_checks.json'))
    assert len(e['blocks'])==len(a['component_oracles'])==32 and len(e['joins'])==len(a['stream_joins'])==6
    assert sum(len(b['visits'])for b in e['blocks'])==8226 and sum(len(b['reads'])for b in e['blocks'])==18 and not any(b['writes']or b['PAC_models']for b in e['blocks'])
    offset=0
    for p,join,streams in zip(parent['profiles'],e['joins'],a['stream_joins']):
        assert join['label']==p['configuration']['label'];n=p['configuration']['length_u32']//8;blocks=e['blocks'][offset:offset+2*n];offset+=2*n
        assert [sum(b['name']==name for b in blocks)for name in ['first_head','first_tail','second_head','second_tail']]==[1,n-1,n-1,1]
        for b in blocks:
            assert b['label']==join['label'];start,end=b['entry']['source_visit'],b['end']['source_visit'];name,lo,hi=next(v for v in A.SPECS if v[0]==b['name'])
            assert end-start==(hi-lo)//4 and b['visits']==p['visits'][start:end]
            for k in ['reads','writes','PAC_models']:assert b[k]==[v for v in p[k]if start<=v['visit']<end]
            old=next(v for v in codec['blocks']if v['label']==b['label']and v['name']==name and v['end']['source_visit']==start);assert b['entry']==old['end'];A.scalar(b,s)
        assert streams==A.stream_join(p,blocks,join,codec,entry)
        assert streams['shared_seed_u64']==('0x65e683634cf8c95c'if n==4 else'0x7651b2bf6eff9a8a')and streams['final_bank_xors_u32']==['0xeb3e515b']*3
    for b,o in zip(e['blocks'],a['component_oracles']):
        assert o['name']==b['name']and o['label']==b['label']and o['cases']==7184 and o['source_visits']==7184*len(b['visits'])and o['source_bytes_preserved']and len(o['ordered_frames_sha256'])==64
        assert o['off_premise_controls']and o['off_premise_controls'][-1]['common_contract_rejected']
        for c in o['off_premise_controls']:
            assert int(c['changed_control_u64'],16)==int(c['retained_control_u64'],16)^1
            q,u,i=map(lambda k:int(c[k],16),['q_u64','product_u64','index_u64']);bank=list(map(lambda v:int(v,16),c['incoming_bank_u32']));out,h,v,t=A.oracle(q,u,i,bank)
            assert c['candidate_bank_u32']==list(map(hex,out))and c['candidate_h_u64']==hex(h)
            assert c['common_contract_rejected']==(c['actual_bank_u32']!=c['candidate_bank_u32']or c['actual_h_u64']!=c['candidate_h_u64'])
    assert sum(o['cases']for o in a['component_oracles'])==229888 and sum(o['source_visits']for o in a['component_oracles'])==59095584
    assert sum(len(o['off_premise_controls'])for o in a['component_oracles'])==38 and sum(len(b['visits'])*len(o['off_premise_controls'])for b,o in zip(e['blocks'],a['component_oracles']))==10434
    flags=['native_API_executed','IDB_mutated','new_live_IDA_claim','earlier_arithmetic_passes_universally_reduced','general_raw_preparation_contract_established','full_goal_complete']
    assert not any(e[k]or a[k]for k in flags)and e['word_recurrence_universally_reduced']and a['word_recurrence_universally_reduced']and not e['native_target_executed']and not r['native_target_executed']and e['whole_transform_algorithm']==a['whole_transform_algorithm']=='unknown'
    report=read(BASE/'corefp_word_recurrence_report.md');assert all(f'| WR{i} |'in report for i in range(1,7))and all(f'**QG{i}**'in report for i in range(1,8))
    assert all(x in report for x in [e['thin_sha256'],'1075','229888','59095584','1192','10434','eb3e515b','7651b2bf6eff9a8a','65e683634cf8c95c'])
    return e,a


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==len(old['files'])==8509 and len(after)==len(new['files'])==8515
    assert not before.keys()-after.keys()and after.keys()-before.keys()==ADDED and {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
    for row in new['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
    e,a=receipts();assert new['validation']['corefp_word_recurrence_increment_checks']==COUNTS and new['validation']['corefp_word_recurrence_static_scope']==e['scope']
    assert new['validation']['reports']==old['validation']['reports']+1==463 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']and len(OWNED)==16
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene(read(BASE/(p[:-4]if p.endswith('.zst')else p)).encode())
    path_hygiene(json.dumps(H.paths_in_typed_payloads(e)).encode());n=sum(H.hex_hygiene(v)[0]for v in [e,a]);path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,(delta^OWNED)
    print(json.dumps({'unchanged_manifest_entries':len(before)-len(CHANGED),'owned_physical_files':16,'original_inputs_preserved':3,'reports':463,
      'source_profiles':6,'source_visits':488136,'queries_unsat':1192,'finite_component_cases':229888,'finite_source_visits':59095584,'off_premise_cases':38,'paired_streams':6,
      'decoded_hex_fields_path_checked':n,'native_target_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
