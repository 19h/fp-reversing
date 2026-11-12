#!/usr/bin/env python3
"""Pin word-codec contracts, epochs, falsifiers and publication delta.

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
import verify_corefp_scan_entry_publication as F
import verify_corefp_late_preparation_publication as H
import audit_corefp_word_codec as A
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='7cd1e748f72e6250b9f18361435897593aa9e530'
BASELINE_SHA='ac96580d8d3a641ccd3d06c46b72de5d4678d474a9c68d5e847bed6f3ceb07ab'
CHECKS_SHA='c766552ae9fa883d70da2d80dbbf80cae4a41fa29f32d7c007156ad8cf22d23e'
AUDIT_SHA='5865d5245303b5d947b5b366158da41aad3d7a5b751141f4e0a9279f9f8f53a3'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','corefp_scan_entry_report.md','foundational_triage_report.md','interface_abi_report.md',
 'interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'corefp_word_codec_report.md','triage_evidence/recover_corefp_word_codec.py','triage_evidence/audit_corefp_word_codec.py',
 'triage_evidence/verify_corefp_word_codec_publication.py','triage_evidence/corefp_word_codec_checks.json','triage_evidence/corefp_word_codec_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/corefp_word_codec_checks.json','triage_evidence/corefp_word_codec_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
PINS={**F.PINS,'corefp_scan_entry_checks.json':F.CHECKS_SHA,'corefp_scan_entry_audit.json':F.AUDIT_SHA}
COUNTS={'profiles':6,'regions':32,'source_instructions':97,'source_B':388,'regional_visits':766,'regional_reads':0,'regional_writes':16,'regional_PAC_models':0,'stable_word_epochs':16,'new_queries_unsat':11,
 'region_counts':{'first_head':6,'first_tail':10,'second_head':10,'second_tail':6}}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def receipts():
    assert sha(ROOT/'corefp_word_codec_checks.json')==CHECKS_SHA and sha(ROOT/'corefp_word_codec_audit.json')==AUDIT_SHA
    e=json.loads(read(ROOT/'corefp_word_codec_checks.json'));a=json.loads(read(ROOT/'corefp_word_codec_audit.json'));r=a['result']
    assert e['generator_sha256']==a['generator_sha256']==sha(ROOT/'recover_corefp_word_codec.py')and a['auditor_sha256']==sha(ROOT/'audit_corefp_word_codec.py')
    assert a['checks_sha256']==CHECKS_SHA and e['parent_pins']==a['parent_pins']==PINS and len(PINS)==14
    assert e['dependencies']==a['dependencies']and len(e['dependencies'])==17
    for name,h in {**PINS,**e['dependencies']}.items():assert sha(ROOT/name)==h
    assert e['thin_sha256']=='8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c'
    assert a['fresh_replay_completed']and a['process_exit_code']==0 and r['all_checks_pass']and e['verified_counts']==r['verified_counts']==COUNTS
    assert r['independent_replay']==F.F.F.TOTALS and e['replay_totals']=={k:v for k,v in F.F.F.TOTALS.items()if not k.startswith('initial_')}
    expected={'actual_full_frames':32,'independent_scalar_frames':32,'finite_component_cases':131072,'finite_source_visits':3137536,'off_premise_controls':22,
      'stable_word_epochs':16,'new_queries_unsat':11,'frozen_queries_unsat':1144,'total_queries_unsat':1155}
    for k,v in expected.items():assert r[k]==v
    assert len(e['proofs'])==len({p['label']for p in e['proofs']})==11
    for p in e['proofs']:
        q=z3.Solver();q.set(timeout=30000);q.from_string(p['query']);assert p['result']=='unsat'and q.check()==z3.unsat,p['label']
    s=A.C.Pointers();assert len(e['source_regions'])==4
    for region,(name,lo,hi)in zip(e['source_regions'],A.SPECS):
        assert region['name']==name and region['start']==hex(lo)and region['end']==hex(hi)
        assert region['instructions']==[{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'instruction':i.mnemonic+' '+i.op_str}for i in A.C.CS.disasm(s.read(lo,hi-lo),lo)]
    assert sum(len(x['instructions'])for x in e['source_regions'])==97
    parent=json.loads(read(ROOT/'corefp_workspace_checks.json'));assert len(e['blocks'])==len(a['component_oracles'])==32 and len(e['joins'])==6
    assert sum(len(b['visits'])for b in e['blocks'])==766 and sum(len(b['writes'])for b in e['blocks'])==16 and not any(b['reads']or b['PAC_models']for b in e['blocks'])
    offset=0
    for p,join in zip(parent['profiles'],e['joins']):
        assert join['label']==p['configuration']['label'];A.check_epochs(p,join)
        n=p['configuration']['length_u32']//8;blocks=e['blocks'][offset:offset+2*n];offset+=2*n
        assert [sum(b['name']==name for b in blocks)for name in ['first_head','first_tail','second_head','second_tail']]==[1,n-1,n-1,1]
        for b in blocks:
            assert b['label']==join['label'];start,end=b['entry']['source_visit'],b['end']['source_visit'];name,lo,hi=next(x for x in A.SPECS if x[0]==b['name'])
            assert end-start==(hi-lo)//4 and b['visits']==p['visits'][start:end]
            for key in ['reads','writes','PAC_models']:assert b[key]==[v for v in p[key]if start<=v['visit']<end]
            ep=next(x for x in join['epochs']if x['raw_read_visit'if name.startswith('first')else'encoded_read_visit']==start-1)
            assert int(b['entry']['CPU']['X31'][28 if name=='first_head'else 3],16)==int(ep['raw_word_u64'if name.startswith('first')else'encoded_word_u64'],16)
            A.scalar(b,s)
    for b,o in zip(e['blocks'],a['component_oracles']):
        assert o['name']==b['name']and o['label']==b['label']and o['cases']==4096 and o['source_visits']==4096*len(b['visits'])and o['source_bytes_preserved']and len(o['ordered_frames_and_stores_sha256'])==64
        assert len(o['off_premise_controls'])==(0 if b['name']=='first_tail'else 1)
        for c in o['off_premise_controls']:
            assert int(c['changed_control_u64'],16)==int(c['retained_control_u64'],16)^1 and c['common_contract_rejected']
            w,h=map(lambda k:int(c[k],16),['loaded_word_u64','incoming_hash_u64']);common=h^(((w if b['name']=='first_head'else w^A.KEY)*A.MULT)%A.MOD)
            assert int(c['common_candidate_hash_u64'],16)==common
            if b['name']=='first_head':assert int(c['actual_hash_u64'],16)==common and int(c['actual_stored_word_u64'],16)!=w^A.KEY
            else:assert int(c['actual_hash_u64'],16)!=common and c['actual_stored_word_u64']is None
    assert sum(o['cases']for o in a['component_oracles'])==131072 and sum(o['source_visits']for o in a['component_oracles'])==3137536
    assert sum(len(o['off_premise_controls'])for o in a['component_oracles'])==22
    assert sum(len(b['visits'])*len(o['off_premise_controls'])for b,o in zip(e['blocks'],a['component_oracles']))==686
    flags=['native_API_executed','IDB_mutated','new_live_IDA_claim','earlier_arithmetic_passes_universally_reduced','general_raw_preparation_contract_established','full_goal_complete']
    assert not any(e[k]or a[k]for k in flags)and not e['native_target_executed']and not r['native_target_executed']and e['whole_transform_algorithm']==a['whole_transform_algorithm']=='unknown'
    report=read(BASE/'corefp_word_codec_report.md');assert all(f'| WC{i} |'in report for i in range(1,6))and all(f'**QG{i}**'in report for i in range(1,8))
    assert all(x in report for x in [e['thin_sha256'],'0xcccccccccccccccc','0xabdf5fe3f3ef5db9','131072','3137536','1155','686'])
    return e,a


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==len(old['files'])==8503 and len(after)==len(new['files'])==8509
    assert not before.keys()-after.keys()and after.keys()-before.keys()==ADDED and {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
    for row in new['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
    e,a=receipts();assert new['validation']['corefp_word_codec_increment_checks']==COUNTS and new['validation']['corefp_word_codec_static_scope']==e['scope']
    assert new['validation']['reports']==old['validation']['reports']+1==462 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']and len(OWNED)==15
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene(read(BASE/(p[:-4]if p.endswith('.zst')else p)).encode())
    path_hygiene(json.dumps(H.paths_in_typed_payloads(e)).encode());n=sum(H.hex_hygiene(x)[0]for x in [e,a]);path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,(delta^OWNED)
    print(json.dumps({'unchanged_manifest_entries':len(before)-len(CHANGED),'owned_physical_files':15,'original_inputs_preserved':3,'reports':462,
      'source_profiles':6,'source_visits':488136,'queries_unsat':1155,'finite_component_cases':131072,'finite_source_visits':3137536,'off_premise_controls':22,
      'decoded_hex_fields_path_checked':n,'native_target_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
