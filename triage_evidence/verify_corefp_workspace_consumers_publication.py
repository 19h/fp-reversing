#!/usr/bin/env python3
"""Pin consumer transfer receipts, manifest delta and decoded path hygiene.

O(owned decoded content + manifest) time/space; SMT 30 s/query.
No target/API/IPC, IDA access or history rewrite.
"""
import json,struct,subprocess
from pathlib import Path
from hashlib import sha256
from collections import Counter
from compression import zstd
import z3
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
from verify_fpsd1200_process_publication import paths_in_typed_payloads
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='16606b9dab91b2451b510c818d35ac3aba032cf0'
BASELINE_SHA='d8bc98988fc0a8ad512e392ae32b699dec31e4a93cfe76d512885aaf9fa67356'
CHECKS_SHA='5f976ce1950bfcea57f1852576bd61d4e62f92f3fd3efb7cd0005624f18779ea'
AUDIT_SHA='adb5603bc9624068bd09c45981d628e8997079c349309648429bb5bd9e5c9a19'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','corefp_workspace_report.md','corefp_pool_transform_report.md','foundational_triage_report.md',
 'interface_abi_report.md','interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'corefp_workspace_consumers_report.md','triage_evidence/recover_corefp_workspace_consumers.py','triage_evidence/audit_corefp_workspace_consumers.py',
 'triage_evidence/verify_corefp_workspace_consumers_publication.py','triage_evidence/corefp_workspace_consumers_checks.json','triage_evidence/corefp_workspace_consumers_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/corefp_workspace_consumers_checks.json','triage_evidence/corefp_workspace_consumers_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles':6,'blocks':8,'source_instructions':823,'source_B':3292,'regional_visits':6584,'table_reads':1280,'mixed_word_nodes':36,'regional_writes':120,'new_queries_unsat':335}
TOTALS={'initial_CPU_frames_checked':6,'initial_RAM_B_checked':3313664,'visits_checked':488136,'reads_checked':63394,'writes_checked':40562,
 'PAC_models_checked':21086,'models_checked':30,'points_checked':182,'final_RAM_B_checked':3313664}
LABELS=['separate_ramp16','separate_zero16','separate_flip16','separate_ramp32','separate_ramp32','separate_zero32','separate_zero32','separate_clobber']
ORDINALS=[0,0,0,0,1,0,1,0]


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def receipts():
    assert sha(ROOT/'corefp_workspace_consumers_checks.json')==CHECKS_SHA and sha(ROOT/'corefp_workspace_consumers_audit.json')==AUDIT_SHA
    e=json.loads(read(ROOT/'corefp_workspace_consumers_checks.json'));a=json.loads(read(ROOT/'corefp_workspace_consumers_audit.json'))
    assert e['generator_sha256']==a['generator_sha256']==sha(ROOT/'recover_corefp_workspace_consumers.py')and a['auditor_sha256']==sha(ROOT/'audit_corefp_workspace_consumers.py')
    assert a['checks_sha256']==CHECKS_SHA and a['dependencies']==e['dependencies']
    for n,h in e['dependencies'].items():assert sha(ROOT/n)==h
    for kind,name in [('checks','corefp_workspace_checks.json'),('audit','corefp_workspace_audit.json')]:
        assert e['parent_'+kind+'_sha256']==a['parent_'+kind+'_sha256']==sha(ROOT/name)
    parent=json.loads(read(ROOT/'corefp_workspace_checks.json'));pa=json.loads(read(ROOT/'corefp_workspace_audit.json'))
    assert e['thin_sha256']==parent['thin_sha256']=='8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c'
    r=a['result'];assert a['fresh_replay_completed']and a['process_exit_code']==0 and r['all_checks_pass']
    assert r['verified_counts']==e['verified_counts']==COUNTS and r['independent_replay']==TOTALS
    assert r['independent_interpreter']=={'instructions':6584,'reads':1632,'writes':120,'stack_final_B':10496}
    assert r['canonical_word_instances_checked']==288 and r['canonical_final_destinations_checked']==128 and r['canonical_offset_B']==144
    assert r['canonical_first_block_invariance_profiles']==6 and r['canonical_second_block_invariance_profiles']==2 and r['constant_offsets_across_retained_blocks']
    m=e['source_model'];assert m['source_instruction_count']==len(m['instructions'])==823 and m['source_B']==len(bytes.fromhex(m['source_bytes_hex']))==3292
    assert b''.join(bytes.fromhex(i['bytes_hex'])for i in m['instructions'])==bytes.fromhex(m['source_bytes_hex'])
    assert [int(i['pc'],16)for i in m['instructions']]==list(range(0x1ba0c0,0x1bad9c,4))
    assert m['lookup_count']==len(m['lookups'])==160 and m['mixed_word_nodes']==len(m['word_nodes'])==36 and m['substitution_layers']==10
    assert Counter(n['layer']for n in m['word_nodes'])==Counter({j:4 for j in range(1,10)})and Counter(n['layer']for n in m['lookups'])==Counter({j:16 for j in range(10)})
    assert m['lookups'][15]['pc']=='0x1ba20c'and m['lookups'][15]['layer']==1 and m['lookups'][16]['pc']=='0x1ba238'and m['lookups'][16]['layer']==0
    assert m['premises']=={'frame_pointer_minus_SP_B':0x520,'masked_split_shift_sum':24,'nonalias_stack_table_interfaces':True}
    proofs=m['proofs']+e['canonical_phase_proofs']+pa['source_checks']['proofs']+[p for f in pa['frozen_source_checks']for p in f['proofs']]
    assert len(m['proofs'])==330 and len(e['canonical_phase_proofs'])==5 and r['frozen_queries_unsat']==28 and r['total_queries_unsat']==len(proofs)==363
    for p in proofs:
        assert p['result']=='unsat';q=z3.Solver();q.set(timeout=30000);q.from_string(p['query']);assert q.check()==z3.unsat,p['label']
    assert [b['label']for b in e['blocks']]==[b['label']for b in a['block_oracles']]==LABELS and [b['block_index']for b in e['blocks']]==ORDINALS
    assert len(a['interpreter_oracles'])==len(a['block_oracles'])==len(e['blocks'])==8
    for block,o,i in zip(e['blocks'],a['block_oracles'],a['interpreter_oracles']):
        assert o['block_index']==block['block_index']and o['table_reads_checked']==160 and o['mixed_words_checked']==36 and o['final_destinations_checked']==16
        assert o['workspace_pointers_restored']and o['stack_status_u32']==0 and o['whole_transform_algorithm']=='unknown'
        assert o['canonical_G_sha256']=='d5c79b57d35ed544ad0bfc85109f8ba7116cdfb4b697fd9f1e3b7e575d17fd83'
        assert len(block['reads'])==204 and len(block['writes'])==15 and block['end']['source_visit']-block['entry']['source_visit']==823
        assert i=={'instructions':823,'reads':204,'writes':15,'stack_final_B':1312,'all_CPU_fields_match':True}
        assert o['canonical_round_offsets_u32']==a['block_oracles'][0]['canonical_round_offsets_u32']
        expected_inputs=['0x8f2dcc03','0x7c2f1537','0x16eb16d8','0xccdd8dd4']if not block['block_index']else ['0x1bb95897','0xe8bb81a3','0x827f824c','0x58491940']
        assert o['canonical_inputs_u32']==expected_inputs and o['canonical_final16_hex']==('30103254cea096d11bd42b7aab598412'if not block['block_index']else 'edc841629239fe868524fe64711d0994')
        assert tuple(o['source_shift_pair_u32'])in [(0,24),(24,0),(16,8)]
    packed=struct.pack('<36I',*[int(v,16)for v in a['block_oracles'][0]['canonical_round_offsets_u32']])
    assert sha256(packed).hexdigest()==r['canonical_offset_sha256']=='2ff2cdf425505ad399c66f1430ab0c9f373735d24bc34e2a37ed9b5c05043016'
    assert e['replay_totals']=={k:v for k,v in TOTALS.items()if not k.startswith('initial_')}
    assert not any(e[k]for k in ['native_target_executed','native_API_executed','IDB_mutated','new_live_IDA_claim','source_context_initializer_established','full_goal_complete'])
    assert not any(a[k]for k in ['native_API_executed','IDB_mutated','new_live_IDA_claim','source_context_initializer_established','native_key_schedule_established','full_goal_complete'])and not r['native_target_executed']
    assert e['whole_transform_algorithm']==a['whole_transform_algorithm']=='unknown'
    report=read(BASE/'corefp_workspace_consumers_report.md');assert e['thin_sha256']in report and all(f'| WC{i} |'in report for i in range(1,7))and all(f'**QG{i}**'in report for i in range(1,8))
    assert len(m['final_destinations'])==16 and sum('register'in d for d in m['final_destinations'].values())==4
    for j in range(144,160):
        d=m['final_destinations']['q'+str(j)];loc='W'+str(d['register'])if 'register'in d else '[SP+'+hex(d['stack_offset'])+']'
        assert f"| q{j} | `{m['lookups'][j]['pc']}` | `{loc}` |"in report
    return e


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==len(old['files'])==8467 and len(after)==len(new['files'])==8473
    assert not before.keys()-after.keys()and after.keys()-before.keys()==ADDED and {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
    for row in new['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
    e=receipts()
    assert new['validation']['corefp_workspace_consumers_increment_checks']==COUNTS and new['validation']['corefp_workspace_consumers_static_scope']==e['scope']
    assert new['validation']['reports']==old['validation']['reports']+1==456 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']and len(OWNED)==16
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        logical=p[:-4]if p.endswith('.zst')else p;path_hygiene(read(BASE/logical).encode())
        if logical=='triage_evidence/corefp_workspace_consumers_checks.json':path_hygiene(json.dumps(paths_in_typed_payloads(e)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,(delta^OWNED)
    print(json.dumps({'unchanged_manifest_entries':len(before)-len(CHANGED),'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':456,
      'complete_profiles':6,'regional_blocks':8,'source_visits':488136,'queries_unsat':363,'table_reads_checked':1280,'mixed_word_instances_checked':288,
      'final_private_destinations_checked':128,'native_target_executed':False,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
