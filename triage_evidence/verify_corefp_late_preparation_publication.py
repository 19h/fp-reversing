#!/usr/bin/env python3
"""Pin late-preparation source proofs, epoch boundaries and publication delta.

O(owned decoded content + pinned journals + manifest) time/space;
30 s/SMT query. No target/API/IPC, IDA access or history rewrite.
"""
import json,subprocess
from pathlib import Path
from hashlib import sha256
from compression import zstd
import z3
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
from verify_fpsd1200_process_publication import paths_in_typed_payloads
import verify_corefp_output_packing_publication as F
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='9e0353d469f7b46432c0ffbd00be219642c67817'
BASELINE_SHA='4b6cef9ec0667560356f84917b2d98ec407a9499445ba772ebb279e9af3fb0a2'
CHECKS_SHA='9d2e47cd821ee5a6f2ffaa8f93e9387890c5ef46ffdaab02bc9955b33b7a0fa9'
AUDIT_SHA='c4c82c683affdd92fc38fcf579cb074509acc43e78611bb8bfd431134c31e5ef'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','corefp_output_packing_report.md','corefp_workspace_consumers_report.md','foundational_triage_report.md',
 'interface_abi_report.md','interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'corefp_late_preparation_report.md','triage_evidence/recover_corefp_late_preparation.py','triage_evidence/audit_corefp_late_preparation.py',
 'triage_evidence/verify_corefp_late_preparation_publication.py','triage_evidence/corefp_late_preparation_checks.json','triage_evidence/corefp_late_preparation_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/corefp_late_preparation_checks.json','triage_evidence/corefp_late_preparation_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles':6,'first_blocks':6,'source_instructions':3590,'source_B':14360,'regional_visits':21540,'regional_reads':3816,'regional_writes':948,
 'late_prepared_reads':96,'expanded_byte_tables':192,'preparation_words':24,'consumer_results_preserved':96,'output_bytes':96,'new_queries_unsat':420,'regional_PAC_models':6}
PINS={**F.PINS,'corefp_output_packing_checks.json':F.CHECKS_SHA,'corefp_output_packing_audit.json':F.AUDIT_SHA}
LABELS=['separate_ramp16','separate_zero16','separate_flip16','separate_ramp32','separate_zero32','separate_clobber']
CONSTANT='405d850bd17f414f2d5b9ae4907df42b';MASK='9c5ddd036790f68bf47bdb66585cad41';RAW_CONSTANT='dc005808b6efb7c4d9204182c821596a'
WORD_SLOTS=[0x3f0,0x284,0x364,0x3f4];WORD_STORES=['0x1b8a64','0x1b8ab8','0x1b8b0c','0x1b8b4c']
INVERSE=[39,102,194,204,148,117,192,238]
PREP_PCS=[0x1b8a2c,0x1b8868,0x1b88bc,0x1b8994,0x1b897c,0x1b8a68,0x1b8a98,0x1b87dc,0x1b89c8,0x1b8910,0x1b8abc,0x1b8aec,0x1b8b10,0x1b89e8,0x1b8890,0x1b893c]


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def linear(x,columns):
    v=0
    for j,c in enumerate(columns):
        if x>>j&1:v^=c
    return v


def hex_hygiene(value,key=''):
    count=0;extent=0
    if isinstance(value,dict):
        for k,v in value.items():
            n,b=hex_hygiene(v,k);count+=n;extent+=b
    elif isinstance(value,list):
        for v in value:
            n,b=hex_hygiene(v,key);count+=n;extent+=b
    elif isinstance(value,str)and key.endswith('_hex'):
        raw=bytes.fromhex(value);path_hygiene(raw);count=1;extent=len(raw)
    return count,extent


def receipts():
    assert sha(ROOT/'corefp_late_preparation_checks.json')==CHECKS_SHA and sha(ROOT/'corefp_late_preparation_audit.json')==AUDIT_SHA
    e=json.loads(read(ROOT/'corefp_late_preparation_checks.json'));a=json.loads(read(ROOT/'corefp_late_preparation_audit.json'));r=a['result']
    assert e['generator_sha256']==a['generator_sha256']==sha(ROOT/'recover_corefp_late_preparation.py')and a['auditor_sha256']==sha(ROOT/'audit_corefp_late_preparation.py')
    assert a['checks_sha256']==CHECKS_SHA and e['parent_pins']==a['parent_pins']==PINS and e['dependencies']==a['dependencies']and len(e['dependencies'])==9
    for name,h in {**PINS,**e['dependencies']}.items():assert sha(ROOT/name)==h
    assert e['thin_sha256']=='8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c'
    assert a['fresh_replay_completed']and a['process_exit_code']==0 and r['all_checks_pass']and e['verified_counts']==r['verified_counts']==COUNTS
    assert r['independent_replay']==F.TOTALS and e['replay_totals']=={k:v for k,v in F.TOTALS.items()if not k.startswith('initial_')}
    assert r['independent_interpreter']=={'instructions':21540,'reads':3816,'writes':948,'stack_final_B':7872}
    expected={'finite_cases':24576,'finite_source_visits':88227840,'finite_emulated_instructions':88203264,'finite_PAC_models':24576,
      'finite_preparation_words_checked':98304,'finite_output_B':393216,'actual_machine_frames':6,'complete_inverse_values_checked':256,'frozen_queries_unsat':620,'total_queries_unsat':1040}
    for key,v in expected.items():assert r[key]==v
    assert r['constant_across_six_domains']and e['word_slots']==WORD_SLOTS and e['word_store_PCs']==WORD_STORES and e['inverse_H_columns_u8']==INVERSE
    assert len(e['instructions'])==3590 and len(bytes.fromhex(e['source_bytes_hex']))==14360
    assert [int(i['pc'],16)for i in e['instructions']]==list(range(0x1b87dc,0x1bbff4,4))
    assert b''.join(bytes.fromhex(i['bytes_hex'])for i in e['instructions'])==bytes.fromhex(e['source_bytes_hex'])
    assert all(linear(linear(x,INVERSE),F.COLS)==x for x in range(256))and sorted(linear(x,INVERSE)for x in range(256))==list(range(256))
    assert bytes(x^y for x,y in zip(bytes.fromhex(CONSTANT),bytes.fromhex(MASK))).hex()==RAW_CONSTANT
    pe=json.loads(read(ROOT/'corefp_output_packing_checks.json'));ce=json.loads(read(ROOT/'corefp_workspace_consumers_checks.json'));pa=json.loads(read(ROOT/'corefp_workspace_audit.json'))
    parent=json.loads(read(ROOT/'corefp_workspace_checks.json'));ca=json.loads(read(ROOT/'corefp_workspace_consumers_audit.json'))
    new=[p for m in e['transfer_models']for p in m['proofs']]
    frozen=[pe['common_inverse_proof']]+[p for m in pe['transfer_models']for p in m['proofs']]+ce['source_model']['proofs']+ce['canonical_phase_proofs']+pa['source_checks']['proofs']+[p for f in pa['frozen_source_checks']for p in f['proofs']]
    assert len(new)==420 and len(frozen)==620
    for p in new+frozen:
        assert p['result']=='unsat';q=z3.Solver();q.set(timeout=30000);q.from_string(p['query']);assert q.check()==z3.unsat,p['label']
    assert len(e['blocks'])==len(e['transfer_models'])==len(a['interpreter_oracles'])==len(a['machine_oracles'])==len(a['component_oracles'])==6
    assert [b['label']for b in e['blocks']]==LABELS
    index=0
    for p,b,m,i,t,o in zip(parent['profiles'],e['blocks'],e['transfer_models'],a['interpreter_oracles'],a['machine_oracles'],a['component_oracles']):
        assert b['label']==m['label']==t['label']==o['label']==p['configuration']['label']and m['constant16_hex']==CONSTANT
        assert m['all_GPRs_flags_stack_reads_writes_match']and m['source_reads_checked']==636 and m['source_writes_checked']==158 and len(m['proofs'])==70 and len(m['symbolic_tables'])==32
        assert len(b['reads'])==636 and len(b['writes'])==158 and sum(r['size_B']for r in b['reads'])==2438 and sum(w['size_B']for w in b['writes'])==660
        assert b['end']['source_visit']-b['entry']['source_visit']==3590 and b['end']==pe['blocks'][index]['end']
        assert i=={'instructions':3590,'reads':636,'writes':158,'stack_final_B':1312,'all_CPU_fields_match':True}
        assert t['actual_frame_cases']==1 and t['finite_cases']==4096 and t['finite_source_visits']==14704640 and t['finite_emulated_instructions']==14700544 and t['finite_PAC_models']==4096
        assert t['finite_preparation_words_checked']==16384 and t['finite_output_B']==65536 and t['source_bytes_preserved']and len(t['ordered_outputs_sha256'])==64
        prepared=bytes.fromhex(b['entry']['stack1312_hex'])[0x498:0x4a8];assert prepared.hex()==m['actual_prepared16_hex']==o['prepared16_hex']
        words=[int.from_bytes(bytes(linear(v,INVERSE)for v in prepared[j*4:j*4+4]),'big')^(0xab if j==1 else 0)for j in range(4)]
        assert words==b['prepared_words_u32']==o['prepared_words_u32']
        assert b['actual_canonical_g16']==list(bytes.fromhex(ca['block_oracles'][index]['canonical_final16_hex']))
        out=bytes(F.h8(b['actual_canonical_g16'][F.PERM[j]])^prepared[j]^bytes.fromhex(CONSTANT)[j]for j in range(16))
        assert out.hex()==b['end']['output16_hex']==o['actual_output16_hex']and o['late_reads_checked']==o['canonical_results_unchanged']==16
        assert len(b['PAC_models'])==1 and b['PAC_models'][0]['pc']=='0x1b9b34'and b['PAC_models'][0]['target']=='0x5001b9b38'and b['PAC_models'][0]['modifier']=='0x1410'
        base=int(b['entry']['stack_base'],16)+0x498;allprep=[r for r in p['reads']if base<=int(r['address'],16)<base+16]
        earlier=[r for r in allprep if r['visit']<b['entry']['source_visit']];later=[r for r in allprep if r['visit']>=b['entry']['source_visit']]
        assert len(allprep)==56 and len(earlier)==40 and len(later)==16
        epoch1=[r for r in earlier if int(p['visits'][r['visit']]['pc'],16)<0x1b6000]
        epoch2=[r for r in earlier if r not in epoch1]
        assert len(epoch1)==len(epoch2)==20
        assert {p['visits'][r['visit']]['pc']for r in epoch1}=={'0x1b536c','0x1b5380','0x1b5390','0x1b53a0','0x1b53cc','0x1b544c'}
        assert {p['visits'][r['visit']]['pc']for r in epoch2}=={'0x1b6530','0x1b6544','0x1b6554','0x1b6560','0x1b65ac','0x1b6628'}
        assert {int(p['visits'][r['visit']]['pc'],16)for r in later}==set(PREP_PCS)
        for rr in later:assert int(p['visits'][rr['visit']]['pc'],16)==PREP_PCS[int(rr['address'],16)-base]and rr['size_B']==1
        assert sum(v['pc']=='0x1b87dc'for v in p['visits'])==1 and sum(v['pc']=='0x1bbff4'for v in p['visits'])==p['configuration']['length_u32']//16
        preparation=pa['preparation_oracles'][LABELS.index(b['label'])]
        assert preparation['mask16_hex']==MASK and preparation['prepared16_hex']==prepared.hex()
        assert bytes(a^v for a,v in zip(prepared,bytes.fromhex(preparation['input16_hex']))).hex()==MASK
        index+=p['configuration']['length_u32']//16
    assert index==8
    flags=['native_API_executed','IDB_mutated','new_live_IDA_claim','source_context_initializer_established','general_raw_preparation_contract_established','general_second_block_contract_established','full_goal_complete']
    assert not any(e[k]or a[k]for k in flags)and not e['native_target_executed']and not r['native_target_executed']and e['whole_transform_algorithm']==a['whole_transform_algorithm']=='unknown'
    report=read(BASE/'corefp_late_preparation_report.md');assert all(x in report for x in [e['thin_sha256'],CONSTANT,MASK,RAW_CONSTANT])
    assert all(f'| LP{i} |'in report for i in range(1,7))and all(f'**QG{i}**'in report for i in range(1,8))
    for j in range(4):assert f'| {j} | `{WORD_STORES[j]}` | `[SP+{hex(WORD_SLOTS[j])}]` |'in report
    return e,a


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==len(old['files'])==8479 and len(after)==len(new['files'])==8485
    assert not before.keys()-after.keys()and after.keys()-before.keys()==ADDED and {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
    for row in new['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
    e,a=receipts()
    assert new['validation']['corefp_late_preparation_increment_checks']==COUNTS and new['validation']['corefp_late_preparation_static_scope']==e['scope']
    assert new['validation']['reports']==old['validation']['reports']+1==458 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']and len(OWNED)==16
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        logical=p[:-4]if p.endswith('.zst')else p;path_hygiene(read(BASE/logical).encode())
        if logical=='triage_evidence/corefp_late_preparation_checks.json':path_hygiene(json.dumps(paths_in_typed_payloads(e)).encode())
    hex_count=sum(hex_hygiene(v)[0]for v in [e,a]);path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,(delta^OWNED)
    print(json.dumps({'unchanged_manifest_entries':len(before)-len(CHANGED),'owned_physical_files':16,'original_inputs_preserved':3,'reports':458,
      'complete_profiles':6,'first_block_regions':6,'source_visits':488136,'queries_unsat':1040,'finite_component_cases':24576,'finite_source_visits':88227840,
      'earlier_prepared_reads_outside_quantifier':240,'decoded_hex_fields_path_checked':hex_count,'native_target_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
