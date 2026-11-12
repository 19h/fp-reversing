#!/usr/bin/env python3
"""Pin duplicate scan contracts, scratch lifetimes and publication integrity.

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
import verify_corefp_late_preparation_publication as F
import audit_corefp_preparation_scans as A
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='b36da01339d73b0672b9e1fcac9640fbec99e2af'
BASELINE_SHA='fdff5a1d64d44bf5e9428ec3d0b31222bf2a5ad6a342592d5b605b72749adfcc'
CHECKS_SHA='f851533a1fb3fce78c54cbb712107589e2b477d8e28e0a1ce03ee699c7cbafee'
AUDIT_SHA='d35d4144e7d6e04d1fa8e1e3c25725f4297a82dd60eced0f33dcfec065ba22a8'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','corefp_late_preparation_report.md','corefp_workspace_report.md','foundational_triage_report.md','interface_abi_report.md',
 'interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'corefp_preparation_scans_report.md','triage_evidence/recover_corefp_preparation_scans.py','triage_evidence/audit_corefp_preparation_scans.py',
 'triage_evidence/verify_corefp_preparation_scans_publication.py','triage_evidence/corefp_preparation_scans_checks.json','triage_evidence/corefp_preparation_scans_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/corefp_preparation_scans_checks.json','triage_evidence/corefp_preparation_scans_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles':6,'scan_regions':12,'static_instructions':184,'static_source_B':736,'regional_visits':6674,'regional_reads':654,'regional_writes':0,
 'regional_PAC_models':204,'prepared_read_instances':240,'scan_steps':192,'new_queries_unsat':30}
PINS={**F.PINS,'corefp_late_preparation_checks.json':F.CHECKS_SHA,'corefp_late_preparation_audit.json':F.AUDIT_SHA}
TOTALS={'initial_CPU_frames_checked':6,'initial_RAM_B_checked':3313664,'visits_checked':488136,'reads_checked':63394,'writes_checked':40562,
 'PAC_models_checked':21086,'models_checked':30,'points_checked':182,'final_RAM_B_checked':3313664}
LABELS=['separate_ramp16','separate_zero16','separate_flip16','separate_ramp32','separate_zero32','separate_clobber']
CELLS={0x1ca8310:(0x4d3a,0x1b53c8,0x831f),0x1ca8268:(0x4d25,0x1b5444,0x831f),0x1ceecb0:(0xda6e,0x1b54d0,0x831f),
 0x1cac730:(0x55be,0x1b65a8,0xc9c2),0x1cac8e8:(0x55f5,0x1b6620,0xc9c2),0x1ca2980:(0x4208,0x1b6620,0x9720),0x1ca2bf8:(0x4257,0x1b66ac,0x9720)}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def static_lifetimes(s):
    report=read(BASE/'corefp_preparation_scans_report.md');count=0
    for lo,last,reg,expected,n in [(0x1b54d0,0x1b5618,1,'ldr w1, [sp, #0x410]',83),(0x1b66ac,0x1b6710,3,'eor w3, w9, w2',26)]:
        ins=list(A.C.CS.disasm(s.read(lo,last+4-lo),lo));assert len(ins)==n and all(not any(i.group(g)for g in [1,2,3])for i in ins)
        names={'w'+str(reg),'x'+str(reg)}
        for i in ins:
            rr,ww=i.regs_access();r={i.reg_name(x)for x in rr};w={i.reg_name(x)for x in ww}
            assert not names&r
            if i.address!=last:assert not names&w
            else:assert names&w and i.mnemonic+' '+i.op_str==expected and hex(last)in report
        count+=len(ins)
    uses=[(0x1b54d0,26,0x1b66d8),(0x1b54d0,30,0x1b66f0),(0x1b54d0,22,0x1b6788),(0x1b66ac,15,0x1b6808),(0x1b66ac,10,0x1b6870),(0x1b66ac,11,0x1b6890)]
    for start,j,expected in uses:
        names={'w'+str(j),'x'+str(j)}|({'lr'}if j==30 else set())
        for i in A.C.CS.disasm(s.read(start,0x1b69c4-start),start):
            rr,ww=i.regs_access();r={i.reg_name(x)for x in rr};w={i.reg_name(x)for x in ww}
            if r&names:assert i.address==expected and hex(expected)in report;break
            assert not w&names
        else:raise AssertionError('missing accumulator read')
    assert count==109
    return count


def receipts():
    assert sha(ROOT/'corefp_preparation_scans_checks.json')==CHECKS_SHA and sha(ROOT/'corefp_preparation_scans_audit.json')==AUDIT_SHA
    e=json.loads(read(ROOT/'corefp_preparation_scans_checks.json'));a=json.loads(read(ROOT/'corefp_preparation_scans_audit.json'));r=a['result']
    assert e['generator_sha256']==a['generator_sha256']==sha(ROOT/'recover_corefp_preparation_scans.py')and a['auditor_sha256']==sha(ROOT/'audit_corefp_preparation_scans.py')
    assert a['checks_sha256']==CHECKS_SHA and e['parent_pins']==a['parent_pins']==PINS and e['dependencies']==a['dependencies']and len(e['dependencies'])==11
    for name,h in {**PINS,**e['dependencies']}.items():assert sha(ROOT/name)==h
    assert e['thin_sha256']=='8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c'
    assert a['fresh_replay_completed']and a['process_exit_code']==0 and r['all_checks_pass']and e['verified_counts']==r['verified_counts']==COUNTS
    assert r['independent_replay']==TOTALS and e['replay_totals']=={k:v for k,v in TOTALS.items()if not k.startswith('initial_')}
    assert r['independent_scalar']=={'visits':6674,'reads':654,'PAC_models':204,'stack_unchanged_B':15744}
    expected={'finite_cases':52224,'finite_source_visits':29978304,'finite_PAC_models':887808,'finite_steps':835584,'finite_state_u32_checked':208896,
      'finite_residue_u32_checked':52224,'actual_full_frame_cases':12,'forced_split_full_frame_cases':180,'split_values_covered_per_region':15,
      'relocated_dispatch_cells_checked':7,'paired_delta_matches':6,'frozen_queries_unsat':1040,'total_queries_unsat':1070}
    for k,v in expected.items():assert r[k]==v
    s=A.C.Pointers();assert len(e['source_regions'])==2
    for region,spec in zip(e['source_regions'],A.SPECS):
        ins=list(A.C.CS.disasm(s.read(spec['start'],spec['end']-spec['start']),spec['start']))
        assert int(region['start'],16)==spec['start']and int(region['end'],16)==spec['end']and len(ins)==(89 if spec['kind']==0 else 95)
        assert region['instructions']==[{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'instruction':i.mnemonic+' '+i.op_str}for i in ins]
    for part in e['source_checks']['slices']:
        for row in part['instructions']:
            pc=int(row['pc'],16);ins=next(A.C.CS.disasm(s.read(pc,4),pc));assert row=={'pc':hex(pc),'bytes_hex':bytes(ins.bytes).hex(),'instruction':ins.mnemonic+' '+ins.op_str}
    static_lifetimes(s)
    pa=json.loads(read(ROOT/'corefp_workspace_audit.json'));pe=json.loads(read(ROOT/'corefp_output_packing_checks.json'));ce=json.loads(read(ROOT/'corefp_workspace_consumers_checks.json'));le=json.loads(read(ROOT/'corefp_late_preparation_checks.json'))
    frozen=[p for m in le['transfer_models']for p in m['proofs']]+[pe['common_inverse_proof']]+[p for m in pe['transfer_models']for p in m['proofs']]+ce['source_model']['proofs']+ce['canonical_phase_proofs']+pa['source_checks']['proofs']+[p for f in pa['frozen_source_checks']for p in f['proofs']]
    new=e['source_checks']['proofs'];assert len(new)==30 and len(frozen)==1040
    for p in new+frozen:
        assert p['result']=='unsat';q=z3.Solver();q.set(timeout=30000);q.from_string(p['query']);assert q.check()==z3.unsat,p['label']
    assert len(e['blocks'])==len(e['oracles'])==len(a['scalar_oracles'])==len(a['machine_oracles'])==len(a['component_oracles'])==12
    assert [b['label']for b in e['blocks']]==[label for label in LABELS for _ in range(2)]and [b['kind']for b in e['blocks']]==[0,1]*6
    for b,o,t,c in zip(e['blocks'],e['oracles'],a['machine_oracles'],a['component_oracles']):
        kind=b['kind'];spec=A.SPECS[kind];assert b['label']==o['label']==t['label']==c['label']and kind==o['kind']==t['kind']==c['kind']
        prepared=bytes.fromhex(b['entry']['stack1312_hex'])[0x498:0x4a8];n=A.select_split(prepared,kind);state,delta,residue=A.run_fold(prepared,b['initial_dispatch']['CPU'],kind)
        assert n==o['split']==c['split']and o['final_state_u32']==c['final_state_u32']==list(map(hex,state))and o['xor_deltas_u32']==c['xor_deltas_u32']==list(map(hex,delta))
        assert o['head_residue_u32']==c['head_residue_u32']==hex(residue)and int(b['end']['CPU']['X31'][1 if not kind else 3],16)==residue
        assert b['entry']['stack1312_hex']==b['end']['stack1312_hex']and not b['writes']and len(b['reads'])==(54 if not kind else 55)and len(b['PAC_models'])==17
        assert len(b['visits'])==b['end']['source_visit']-b['entry']['source_visit']==(583-4*n if not kind else 590-5*n)
        assert t['finite_cases']==4352 and t['finite_source_visits']==(2505664 if not kind else 2490720)and t['finite_PAC_models']==73984 and t['finite_steps']==69632
        assert t['finite_state_u32_checked']==17408 and t['finite_residue_u32_checked']==4352 and t['actual_full_frame_cases']==1 and t['forced_split_full_frame_cases']==15
        assert t['all_split_values_covered']and t['source_bytes_preserved']and t['no_memory_writes']and t['full_frames_differ_only_by_head_residue']and {int(k)for k in t['split_histogram']}==set(range(1,16))
        assert sum(t['split_histogram'].values())==4352 and len(t['ordered_states_sha256'])==64 and len(t['forced_split_frames'])==15
        for forced in t['forced_split_frames']:
            _,_,rr=A.run_fold(prepared,b['initial_dispatch']['CPU'],kind,forced['split']);assert forced['residue_register']==(1 if not kind else 3)and forced['residue_u32']==hex(rr)
            frame=json.loads(json.dumps(b['end']['CPU']));frame['X31'][forced['residue_register']]=hex(rr);assert sha256(json.dumps(frame,sort_keys=True).encode()).hexdigest()==forced['CPU_sha256']
        assert len({row['CPU_sha256']for row in t['forced_split_frames']})>1
    for j in range(0,12,2):assert e['oracles'][j]['xor_deltas_u32']==e['oracles'][j+1]['xor_deltas_u32']and e['oracles'][j]['final_state_u32'][3]==e['oracles'][j+1]['final_state_u32'][3]
    report=read(BASE/'corefp_preparation_scans_report.md');assert e['thin_sha256']in report and all(f'| PS{i} |'in report for i in range(1,7))and all(f'**QG{i}**'in report for i in range(1,8))
    assert len(a['dispatch_cells'])==7 and {int(row['address'],16)for row in a['dispatch_cells']}==set(CELLS)
    for row in a['dispatch_cells']:
        at=int(row['address'],16);index,target,modifier=CELLS[at];assert at==0x1c81940+index*8 and int(row['target'],16)==target and int(row['diversity'],16)==modifier
        assert row['chain_membership_verified']and row['authenticated']and not row['bind'];page=A.C.initial_page(s,(A.C.BASE+at)&~4095)
        assert int.from_bytes(page[at%4096:at%4096+8],'little')==A.C.BASE+target
        assert f'| `{index:x}` | `{hex(at)}` | `{hex(target)}` | `{modifier:x}` |'in report
    flags=['native_API_executed','IDB_mutated','new_live_IDA_claim','general_raw_preparation_contract_established','source_context_initializer_established','full_goal_complete']
    assert not any(e[k]or a[k]for k in flags)and not e['native_target_executed']and not r['native_target_executed']and e['whole_transform_algorithm']==a['whole_transform_algorithm']=='unknown'
    return e,a


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==len(old['files'])==8485 and len(after)==len(new['files'])==8491
    assert not before.keys()-after.keys()and after.keys()-before.keys()==ADDED and {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
    for row in new['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
    e,a=receipts()
    assert new['validation']['corefp_preparation_scans_increment_checks']==COUNTS and new['validation']['corefp_preparation_scans_static_scope']==e['scope']
    assert new['validation']['reports']==old['validation']['reports']+1==459 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']and len(OWNED)==16
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        logical=p[:-4]if p.endswith('.zst')else p;path_hygiene(read(BASE/logical).encode())
        if logical=='triage_evidence/corefp_preparation_scans_checks.json':path_hygiene(json.dumps(F.paths_in_typed_payloads(e)).encode())
    hex_count=sum(F.hex_hygiene(v)[0]for v in [e,a]);path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,(delta^OWNED)
    print(json.dumps({'unchanged_manifest_entries':len(before)-len(CHANGED),'owned_physical_files':16,'original_inputs_preserved':3,'reports':459,
      'complete_profiles':6,'scan_regions':12,'source_visits':488136,'queries_unsat':1070,'finite_component_cases':52224,'finite_source_visits':29978304,
      'forced_split_full_frames':180,'source_residue_lifetime_instructions':109,'decoded_hex_fields_path_checked':hex_count,
      'native_target_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
