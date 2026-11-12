#!/usr/bin/env python3
"""Pin cyclic word-control evidence and the exact publication delta.

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
import verify_corefp_input_lineage_publication as F
import verify_corefp_late_preparation_publication as H
import audit_corefp_word_traversal as A
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='6bb5b204b91d4f5c0c03e4ad597d0aebf1bda5d5'
BASELINE_SHA='c8acdb9b3789dc9cff7d9994dec44524690a173075649d00fe9c5052562e5bb4'
CHECKS_SHA='e1d391b7a07e5d84bda136d93e776baaddbff63bd1a85f5536641120b8a61b09'
AUDIT_SHA='2ca82c17b39cb0951e154798b2dad92e3836254bfe97c9bb062c3a536658ee9d'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','corefp_input_lineage_report.md','corefp_word_recurrence_report.md','foundational_triage_report.md','interface_abi_report.md',
 'interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'corefp_word_traversal_report.md','triage_evidence/recover_corefp_word_traversal.py','triage_evidence/audit_corefp_word_traversal.py',
 'triage_evidence/verify_corefp_word_traversal_publication.py','triage_evidence/corefp_word_traversal_checks.json','triage_evidence/corefp_word_traversal_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/corefp_word_traversal_checks.json','triage_evidence/corefp_word_traversal_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
PINS={**F.PINS,'corefp_input_lineage_checks.json':F.CHECKS_SHA,'corefp_input_lineage_audit.json':F.AUDIT_SHA}
COUNTS={'profiles':6,'regions':130,'source_instructions':245,'source_B':980,'regional_visits':1634,'regional_reads':106,'regional_writes':18,'regional_PAC_models':0,
 'preservation_contracts':10,'census_instructions':1411,'census_B':5644,'unique_source_instructions':1619,'unique_source_B':6476,'logical_target_rows':12,'distinct_target_rows':11,'new_queries_unsat':38}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def receipts():
    assert sha(ROOT/'corefp_word_traversal_checks.json')==CHECKS_SHA and sha(ROOT/'corefp_word_traversal_audit.json')==AUDIT_SHA
    raw,e,s,pins=A.inputs();a=json.loads(read(ROOT/'corefp_word_traversal_audit.json'));r=a['result']
    assert e['generator_sha256']==a['generator_sha256']==sha(ROOT/'recover_corefp_word_traversal.py')and a['auditor_sha256']==sha(ROOT/'audit_corefp_word_traversal.py')
    assert a['checks_sha256']==CHECKS_SHA and e['parent_pins']==a['parent_pins']==PINS and len(PINS)==22
    assert e['dependencies']==a['dependencies']and len(e['dependencies'])==25
    assert a['fresh_replay_completed']and a['process_exit_code']==0 and r['all_checks_pass']and e['verified_counts']==r['verified_counts']==COUNTS
    assert r['independent_replay']==pins['corefp_input_lineage_audit.json']['result']['independent_replay']
    assert e['replay_totals']=={k:v for k,v in r['independent_replay'].items()if not k.startswith('initial_')}
    expected={'actual_full_frames':130,'independent_scalar_frames':130,'branch_cases':92160,'branch_source_visits':2039808,'bound_count_cases':30720,'bound_count_source_visits':835584,
      'finite_cases':122880,'finite_source_visits':2875392,'negative_cases':34,'negative_source_visits':800,'stable_table_epochs':32,'retained_decisions':32,'initial_edges_checked':24,
      'new_queries_unsat':38,'frozen_queries_unsat':1263,'total_queries_unsat':1301,'outside_domain_queries_sat':2}
    for k,v in expected.items():assert r[k]==v
    proofs=e['source_checks']['proofs'];assert len(proofs)==len({p['label']for p in proofs})==38
    for p in proofs:
        q=z3.Solver();q.set(timeout=30000);q.from_string(p['query']);assert p['result']=='unsat'and q.check()==z3.unsat,p['label']
    for control in e['source_checks']['outside_domain_controls']:
        q=z3.Solver();q.set(timeout=30000);q.from_string(control['query']);q.add(z3.BitVec('selector_remainder32',32)==int(control['remainder_u32'],16));assert control['result']=='sat'and q.check()==z3.sat
    assert len(e['source_checks']['outside_domain_controls'])==2 and A.outside_oracles(e,s)==a['outside_domain_oracles']
    assert sum(len(v['instructions'])for v in e['source_regions'])==245 and sum(len(v['instructions'])for v in e['remainder_interfaces'])==5
    unique={row['pc']for region in e['source_regions']+[e['census']]for row in region['instructions']};assert len(unique)==1619
    unique.update(row['pc']for region in e['remainder_interfaces']for row in region['instructions']);assert len(unique)==1624
    assert len({v['row']['address']for v in e['target_rows']})==11
    assert len(e['blocks'])==130 and len(a['interface_joins'])==6 and len(a['branch_oracles'])==32 and len(a['bound_count_oracles'])==30
    assert sum(len(b['visits'])for b in e['blocks'])==1634 and sum(len(b['reads'])for b in e['blocks'])==106 and sum(len(b['writes'])for b in e['blocks'])==18
    assert sum(v['size_B']for b in e['blocks']for v in b['reads'])==728 and sum(v['size_B']for b in e['blocks']for v in b['writes'])==96 and not any(b['PAC_models']for b in e['blocks'])
    for b in e['blocks']:
        p=next(v for v in pins['corefp_workspace_checks.json']['profiles']if v['configuration']['label']==b['label']);start,end=b['entry']['source_visit'],b['end']['source_visit'];_,lo,hi=next(v for v in A.SPECS if v[0]==b['name'])
        assert end-start==(hi-lo)//4 and b['visits']==p['visits'][start:end]
        for k in ['reads','writes','PAC_models']:assert b[k]==[v for v in p[k]if start<=v['visit']<end]
        A.scalar(b,s)
    for p,join in zip(pins['corefp_workspace_checks.json']['profiles'],a['interface_joins']):
        blocks=[b for b in e['blocks']if b['label']==p['configuration']['label']];assert join==A.joins(p,blocks,e,pins,s)
        N=p['configuration']['length_u32']//8;assert join['word_count_u32']==hex(N)and len(join['decisions'])==len(join['table_epochs'])==2*N
    for o in a['branch_oracles']:
        d=next(v for v in A.CONFIG if v['name']==o['name']);domains=['counter','upper']if d['lo']is None else['counter','lower','upper'];count=1024*len(domains)
        lengths=sum((hi-lo)//4 for name,lo,hi in A.SPECS if name in [d['header'],d['dispatch']]);assert o['domains']==domains and o['cases']==count and o['source_visits']==count*lengths and o['negative_source_visits']==lengths
        c=o['negative_flag_control'];assert c['correct_wrap_flag']==0 and c['supplied_wrap_flag']==1 and c['actual_index_u32']!=c['candidate_index_u32']and c['contract_rejected']and not c['branch_executed']and o['source_bytes_preserved']and len(o['ordered_frames_sha256'])==64
    for o in a['bound_count_oracles']:
        lengths=sum((hi-lo)//4 for name,lo,hi in A.SPECS if name==o['name']or(o['name']=='second_bound_encode'and name=='second_bound_decode'));assert o['cases']==1024 and o['source_visits']==1024*lengths and o['source_bytes_preserved']and len(o['ordered_frames_and_stack_sha256'])==64
    assert sum(v['cases']for v in a['branch_oracles']+a['bound_count_oracles'])==122880 and sum(v['source_visits']for v in a['branch_oracles']+a['bound_count_oracles'])==2875392
    assert sum(v['negative_source_visits']for v in a['branch_oracles'])+sum(v['source_visits']for v in a['outside_domain_oracles'])==800
    flags=['native_API_executed','IDB_mutated','new_live_IDA_claim','earlier_arithmetic_passes_universally_reduced','general_raw_preparation_contract_established','full_goal_complete']
    assert not any(e[k]or a[k]for k in flags)and not e['native_target_executed']and not r['native_target_executed']and e['whole_transform_algorithm']==a['whole_transform_algorithm']=='unknown'
    report=read(BASE/'corefp_word_traversal_report.md');assert all(f'| WT{i} |'in report for i in range(1,7))and all(f'**QG{i}**'in report for i in range(1,8))
    assert all(x in report for x in [e['thin_sha256'],'980','6496','122880','2875392','1301','max(1,r)','0x488','488136','d5974002','5341d782'])
    return e,a


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==len(old['files'])==8527 and len(after)==len(new['files'])==8533
    assert not before.keys()-after.keys()and after.keys()-before.keys()==ADDED and {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
    for row in new['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
    e,a=receipts();assert new['validation']['corefp_word_traversal_increment_checks']==COUNTS and new['validation']['corefp_word_traversal_static_scope']==e['scope']
    assert new['validation']['reports']==old['validation']['reports']+1==466 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']and len(OWNED)==16
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene(read(BASE/(p[:-4]if p.endswith('.zst')else p)).encode())
    path_hygiene(json.dumps(H.paths_in_typed_payloads(e)).encode());n=sum(H.hex_hygiene(v)[0]for v in [e,a]);path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,(delta^OWNED)
    print(json.dumps({'unchanged_manifest_entries':len(before)-len(CHANGED),'owned_physical_files':16,'original_inputs_preserved':3,'reports':466,
      'source_profiles':6,'source_visits':488136,'queries_unsat':1301,'queries_sat':2,'finite_cases':122880,'finite_source_visits':2875392,'negative_cases':34,
      'stable_table_epochs':32,'retained_decisions':32,'initial_edges_checked':24,'decoded_hex_fields_path_checked':n,'native_target_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
