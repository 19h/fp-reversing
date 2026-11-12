#!/usr/bin/env python3
"""Pin scalar/encoding contracts, original bindings and publication delta.

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
import verify_corefp_preparation_scans_publication as F
import audit_corefp_phase_parameters as A
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='ac62a5614a11b684ebbe749228804974357335fd'
BASELINE_SHA='36ad251b998111015bb54a4787a41359446583470e3618c6db456f365ab1c484'
CHECKS_SHA='cd03e79296510d37ca618ba00e43a1e9566216e8f229a625f7270c020f5f55c8'
AUDIT_SHA='8389aac58db7e1123f7a902f215167fa35d1df68cf3a38542073d4d0775cbb44'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','corefp_preparation_scans_report.md','corefp_workspace_report.md','foundational_triage_report.md','interface_abi_report.md',
 'interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'corefp_phase_parameters_report.md','triage_evidence/recover_corefp_phase_parameters.py','triage_evidence/audit_corefp_phase_parameters.py',
 'triage_evidence/verify_corefp_phase_parameters_publication.py','triage_evidence/corefp_phase_parameters_checks.json','triage_evidence/corefp_phase_parameters_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/corefp_phase_parameters_checks.json','triage_evidence/corefp_phase_parameters_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
PINS={**F.PINS,'corefp_preparation_scans_checks.json':F.CHECKS_SHA,'corefp_preparation_scans_audit.json':F.AUDIT_SHA}
COUNTS={'profiles':6,'source_instructions':198,'source_B':792,'core_instructions':169,'regional_visits':1188,'regional_reads':36,'regional_writes':72,
 'regional_PAC_models':6,'new_queries_unsat':51,'phase_classes':5,'paired_seed_matches':6,'bank_xor_matches':18}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def receipts():
    assert sha(ROOT/'corefp_phase_parameters_checks.json')==CHECKS_SHA and sha(ROOT/'corefp_phase_parameters_audit.json')==AUDIT_SHA
    e=json.loads(read(ROOT/'corefp_phase_parameters_checks.json'));a=json.loads(read(ROOT/'corefp_phase_parameters_audit.json'));r=a['result']
    assert e['generator_sha256']==a['generator_sha256']==sha(ROOT/'recover_corefp_phase_parameters.py')and a['auditor_sha256']==sha(ROOT/'audit_corefp_phase_parameters.py')
    assert a['checks_sha256']==CHECKS_SHA and e['parent_pins']==a['parent_pins']==PINS and len(PINS)==10
    assert e['dependencies']==a['dependencies']and len(e['dependencies'])==13
    for name,h in {**PINS,**e['dependencies']}.items():assert sha(ROOT/name)==h
    assert e['thin_sha256']=='8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c'
    assert a['fresh_replay_completed']and a['process_exit_code']==0 and r['all_checks_pass']and e['verified_counts']==r['verified_counts']==COUNTS
    assert r['independent_replay']==F.TOTALS and e['replay_totals']=={k:v for k,v in F.TOTALS.items()if not k.startswith('initial_')}
    assert r['independent_scalar']=={'instructions':1188,'reads':36,'writes':72,'stack_final_B':7872}
    expected={'finite_phase_cases':55296,'independent_input_cases':49152,'coherent_parameter_cases':6144,'finite_phase_source_visits':10948608,
      'finite_constructor_cases':6144,'finite_constructor_source_visits':221184,'finite_PAC_models':55296,'actual_full_frames':6,
      'joint_mask_rotation_pairs_checked':6144,'new_queries_unsat':51,'frozen_queries_unsat':1070,'total_queries_unsat':1121}
    for k,v in expected.items():assert r[k]==v
    s=A.C.Pointers();ins=[{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'instruction':i.mnemonic+' '+i.op_str}for i in A.C.CS.disasm(s.read(A.START,A.END-A.START),A.START)]
    assert ins==e['instructions']and len(ins)==198 and len(bytes.fromhex(''.join(i['bytes_hex']for i in ins)))==792
    assert e['source_checks']['normalization_cut']['start']=='0x1b6854'and e['source_checks']['normalization_cut']['end']=='0x1b6868'
    pe=json.loads(read(ROOT/'corefp_output_packing_checks.json'));ce=json.loads(read(ROOT/'corefp_workspace_consumers_checks.json'));le=json.loads(read(ROOT/'corefp_late_preparation_checks.json'))
    wa=json.loads(read(ROOT/'corefp_workspace_audit.json'));se=json.loads(read(ROOT/'corefp_preparation_scans_checks.json'));parent=json.loads(read(ROOT/'corefp_workspace_checks.json'))
    frozen=se['source_checks']['proofs']+[p for m in le['transfer_models']for p in m['proofs']]+[pe['common_inverse_proof']]+[p for m in pe['transfer_models']for p in m['proofs']]+ce['source_model']['proofs']+ce['canonical_phase_proofs']+wa['source_checks']['proofs']+[p for f in wa['frozen_source_checks']for p in f['proofs']]
    new=e['source_checks']['proofs'];assert len(new)==51 and len(frozen)==1070 and len({p['label']for p in new})==51
    assert {'word_rotation_'+str(j)for j in range(8)}|{'index_rotation_'+str(j)for j in range(8)}<={p['label']for p in new}
    for p in new+frozen:
        q=z3.Solver();q.set(timeout=30000);q.from_string(p['query']);assert p['result']=='unsat'and q.check()==z3.unsat,p['label']
    assert len(e['blocks'])==len(e['parameter_oracles'])==len(a['machine_oracles'])==len(a['scalar_oracles'])==6 and e['parameter_oracles']==a['parameter_oracles']
    for j,(b,o,m,c,p)in enumerate(zip(e['blocks'],e['parameter_oracles'],a['machine_oracles'],a['scalar_oracles'],parent['profiles'])):
        assert b['label']==o['label']==m['label']==p['configuration']['label']==F.LABELS[j]and b['entry']==se['blocks'][2*j+1]['end']
        lo,hi=b['entry']['source_visit'],b['end']['source_visit'];assert hi-lo==198 and b['core_end']['source_visit']-lo==169 and b['visits']==p['visits'][lo:hi]
        for key in ['reads','writes','PAC_models']:assert b[key]==[row for row in p[key]if lo<=row['visit']<hi]
        assert len(b['reads'])==6 and len(b['writes'])==12 and sum(x['size_B']for x in b['reads'])==sum(x['size_B']for x in b['writes'])==48
        assert len(b['PAC_models'])==1 and b['PAC_models'][0]['pc']=='0x1b69c0'and b['PAC_models'][0]['target']=='0x5001b69c4'and b['PAC_models'][0]['modifier']=='0x2c2a'
        pr=b['PAC_models'][0]['pointer_row'];at=int(pr['address'],16);assert at==0x1c81940+8*0x7887==0x1cbdd78
        assert pr['word']=='0x80082c2a001b69c4'and pr['target']=='0x1b69c4'and pr['diversity']=='0x2c2a'and pr['authenticated']and pr['chain_membership_verified']and not pr['bind']
        page=A.C.initial_page(s,(A.C.BASE+at)&~4095);assert int.from_bytes(page[at%4096:at%4096+8],'little')==A.C.BASE+A.END
        values=[int(b['entry']['CPU']['X31'][k],16)&A.M for k in A.INPUTS];q=A.oracle(values)
        assert values[-1]==values[-2]and all(x^y==A.D for x,y in zip(values[:3],values[3:6]))and o['bank_xors_u32']==[hex(A.D)]*3
        assert o['left_mixed_u32']==list(map(hex,q['left']))and o['right_mixed_u32']==list(map(hex,q['right']))and o['effective_bits_upper_bound']==42
        for k,v in [('mask_u32',hex(q['M'])),('rotate_per_byte',q['r1']),('index_xor_u8',hex(q['b'])),('first_xor_u32',hex(q['K'])),('second_xor_u32',hex(q['Q']))]:assert o[k]==v==wa['workspace_oracles'][j][k]
        assert q['K']^q['Q']==0xfda4d47e and q['m1']==q['m2']and q['r1']==q['r2']
        assert m['finite_phase_cases']==9216 and m['independent_input_cases']==8192 and m['coherent_parameter_cases']==m['finite_constructor_cases']==m['joint_mask_rotation_pairs_checked']==1024
        assert m['finite_phase_source_visits']==9216*198 and m['finite_constructor_source_visits']==1024*36 and m['finite_PAC_models']==9216 and m['actual_full_frames']==1 and m['source_bytes_preserved']and len(m['ordered_frames_sha256'])==64
        assert c=={'instructions':198,'reads':6,'writes':12,'stack_final_B':1312,'all_CPU_fields_match':True}
        assert {x['omitted_premise']for x in m['premise_counterexamples']}=={'bank_xor','shared_seed'}
        for row in m['premise_counterexamples']:
            x=list(map(lambda v:int(v,16),row['inputs_u32']));q=A.oracle(x);assert row['masks_u8']==[q['m1'],q['m2']]and row['rotations']==[q['r1'],q['r2']]and(q['m1']!=q['m2']or q['r1']!=q['r2'])
            if row['omitted_premise']=='bank_xor':assert x[-1]==x[-2]and all(u^v==A.D^1 for u,v in zip(x[:3],x[3:6]))
            else:assert x[-1]!=x[-2]and all(u^v==A.D for u,v in zip(x[:3],x[3:6]))
    flags=['native_API_executed','IDB_mutated','new_live_IDA_claim','upstream_shared_seed_and_bank_xor_universal','general_raw_preparation_contract_established','source_context_initializer_established','full_goal_complete']
    assert not any(e[k]or a[k]for k in flags)and not e['native_target_executed']and not r['native_target_executed']and e['whole_transform_algorithm']==a['whole_transform_algorithm']=='unknown'
    report=read(BASE/'corefp_phase_parameters_report.md');assert all(f'| PP{i} |'in report for i in range(1,7))and all(f'**QG{i}**'in report for i in range(1,8))
    assert all(x in report for x in [e['thin_sha256'],'0xfda4d47e','0x1cbdd78','55296','6144','1121','42'])
    return e,a


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==len(old['files'])==8491 and len(after)==len(new['files'])==8497
    assert not before.keys()-after.keys()and after.keys()-before.keys()==ADDED and {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
    for row in new['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
    e,a=receipts()
    assert new['validation']['corefp_phase_parameters_increment_checks']==COUNTS and new['validation']['corefp_phase_parameters_static_scope']==e['scope']
    assert new['validation']['reports']==old['validation']['reports']+1==460 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']and len(OWNED)==16
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        logical=p[:-4]if p.endswith('.zst')else p;path_hygiene(read(BASE/logical).encode())
        if logical=='triage_evidence/corefp_phase_parameters_checks.json':path_hygiene(json.dumps(F.F.paths_in_typed_payloads(e)).encode())
    n=sum(F.F.hex_hygiene(v)[0]for v in [e,a]);path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,(delta^OWNED)
    print(json.dumps({'unchanged_manifest_entries':len(before)-len(CHANGED),'owned_physical_files':16,'original_inputs_preserved':3,'reports':460,
      'source_profiles':6,'source_visits':488136,'queries_unsat':1121,'finite_phase_cases':55296,'finite_constructor_cases':6144,'finite_source_visits':11169792,
      'decoded_hex_fields_path_checked':n,'native_target_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
