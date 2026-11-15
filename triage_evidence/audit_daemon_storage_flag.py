#!/usr/bin/env python3
"""Source-level mode partition, selector publication and independent replay.
O(parent bytes + source DAG + replay visits*32) time/space, excluding solver
search (30 s/query). No source cut, target execution or new runtime premise.
"""
import json
from collections import Counter
import z3
from daemon_receive_tools import ROOT, SOURCE, TABLE, FIXUPS, IMAGE
from audit_daemon_environment_outputs import DEC
from audit_daemon_append_fields import Lift, Trace, number
from lskd_values_symbolic import mem
from verify_daemon_reader_record_payloads_publication import read, sha
import recover_daemon_storage_flag as R

DEPS = ['audit_daemon_append_fields.py', 'audit_daemon_state_table_mixing.py',
        'audit_daemon_environment_outputs.py', 'lskd_values_symbolic.py', 'recover_daemon_return_bank_origins.py']
TAG1, TAG2, CLEAR = 0x4e40e175, 0x4e40e176, 0xd299e642


def replay(e):
    parents = {g:json.loads(read(ROOT/(name+'_checks.json'))) for g,name in [
        ('constructor','daemon_state_container_construction'),('initializer','daemon_constructor_gate')]}
    totals, key, row = Counter(), None, None
    for s in e['slices']:
        current = s['group'],s['class_index']
        if current != key:
            group,ci = current
            packed = parents[group]['contexts'][ci]['allocation_cases'][1]['interval_packed'] if group=='constructor' else parents[group]['classes'][ci]['interval_packed']
            row,key = R.unpack(packed),current
        assert s['entry']==row['source_frames'][s['start_visit']] and s['exit']==row['source_frames'][s['end_visit_exclusive']]
        v = Trace(s['reads'],s['writes'])
        for k,x in enumerate(s['entry']['registers31']):v.seed('x'+str(k),int(x,16))
        v.seed('sp',int(s['entry']['SP'],16))
        flags = int(s['entry']['NZCV'],16)
        v.n,v.z,v.carry,v.overflow = [z3.BoolVal(bool(flags&(1<<b))) for b in [31,30,29,28]]
        for j in range(s['start_visit'],s['end_visit_exclusive']+1):
            f = row['source_frames'][j]
            assert f['Q_registers32']==s['entry']['Q_registers32']
            assert all(number(v.read('x'+str(k)))==int(f['registers31'][k],16) for k in range(31))
            assert number(v.read('sp'))==int(f['SP'],16)
            actual = [z3.simplify(t) for t in [v.n,v.z,v.carry,v.overflow]]
            assert all(z3.is_true(t) or z3.is_false(t) for t in actual)
            assert sum(int(z3.is_true(t))<<b for t,b in zip(actual,[31,30,29,28]))==int(f['NZCV'],16)
            totals.update(GP_SP_values_checked=32,Q_values_checked=32,NZCV_frames_checked=1)
            if j==s['end_visit_exclusive']:break
            pc = int(row['source_visits'][j]['pc'],16)
            assert row['source_visits'][j]['bytes_hex']==IMAGE.read(pc,4).hex()
            ins = next(DEC.disasm(IMAGE.read(pc,4),pc))
            assert not any(ins.reg_name(r).startswith(('v','q','d','s')) and ins.reg_name(r)!='sp' for r in ins.regs_access()[0]+ins.regs_access()[1])
            v.one(ins)
            totals['source_visits_checked']+=1
        assert v.ri==len(s['reads']) and v.wi==len(s['writes'])
        totals.update(read_events_checked=v.ri,write_events_checked=v.wi,slices_checked=1)
    return dict(totals)


def obligations():
    out = []
    def prove(label, bad):
        s = z3.Solver()
        s.set(timeout=30000)
        assert s.check() == z3.sat
        s.add(z3.simplify(bad))
        answer = s.check()
        assert answer == z3.unsat, (label, str(answer), s.reason_unknown())
        out.append({'label':label,'premises_nonvacuous':True,'result':'unsat','query':s.to_smt2()})
        print(json.dumps({'source_proof':label,'result':'unsat'}),flush=True)
    frame, pointer, u = z3.BitVecs('flag_frame64 flag_input_pointer64 flag_object64',64)
    tag, header = z3.BitVecs('flag_tag32 flag_pointed_header32',32)
    v = Lift()
    for reg,value in {'x15':frame+0x8000,'x20':pointer,'w8':tag}.items():v.seed(reg,value)
    v.run_block(0x10083c8c4,0x10083c8cc)
    prove('save_pointer_and_tag_at_distinct_private_fields',z3.Or(
        v.stores[0]['address']!=frame+0x9c20,v.stores[0]['value']!=pointer,
        v.stores[1]['address']!=frame+0x9c2c,v.stores[1]['value']!=tag))
    v = Lift()
    v.seed('sp',frame);v.seed('w9',0x66c1);mem(v,frame+0x9c20,8,pointer)
    v.run_block(0x10098aab0,0x10098aaf4)
    prove('pointer_gate_selects_null_or_nonnull_source',v.read('w8')!=z3.If(pointer==0,z3.BitVecVal(0x66d6,32),z3.BitVecVal(0x66c1,32)))
    prove('pointer_gate_rebuilds_phase_and_frame_base',z3.Or(v.read('w11')!=0x245b,v.read('w10')!=0x76bf,v.read('x14')!=frame+0x8000,v.read('x12')!=pointer))
    v = Lift()
    for reg,value in {'sp':frame,'x12':pointer,'x14':frame+0x8000,'w11':0x245b}.items():v.seed(reg,value)
    mem(v,pointer,4,header);mem(v,frame+0x9c2c,4,tag)
    v.run_block(0x1008a3be0,0x1008a3c20)
    fail = z3.And(header==0,tag!=TAG1)
    prove('nonnull_gate_conditional_compare_partition',v.read('w11')!=z3.If(fail,z3.BitVecVal(0x246d,32),z3.BitVecVal(0x245b,32)))
    prove('nonnull_gate_forwards_tag_and_rebuilds_comparison_phase',z3.Or(v.read('w10')!=tag,v.read('w9')!=0x1e2))
    v = Lift()
    for reg,value in {'sp':frame,'x14':frame+0x8000,'w10':0x76bf}.items():v.seed(reg,value)
    mem(v,frame+0x9c2c,4,tag)
    v.run_block(0x100753c74,0x100753cb4)
    prove('null_gate_admits_only_first_tag',v.read('w10')!=z3.If(tag==TAG1,z3.BitVecVal(0xae32,32),z3.BitVecVal(0x76bf,32)))
    prove('null_gate_rebuilds_next_phase',v.read('w9')!=0x6cf4)
    v = Lift()
    v.seed('sp',frame);v.seed('w9',0x1e2);v.seed('w10',tag)
    v.run_block(0x10068f774,0x10068f7d0)
    boolean = z3.If(tag==TAG2,z3.BitVecVal(1,8),z3.BitVecVal(0,8))
    prove('second_tag_comparison_writes_canonical_boolean',z3.Or(v.stores[0]['address']!=frame+0x662f,v.stores[0]['value']!=boolean))
    prove('boolean_selects_following_constructor_route',v.read('w8')!=z3.If(tag==TAG2,z3.BitVecVal(0x9a68,32),z3.BitVecVal(0x9a64,32)))
    prove('comparison_writer_rebuilds_next_phase',v.read('w9')!=0x6cf4)
    v = Lift()
    v.seed('sp',frame);v.seed('w9',0x6cf4)
    v.run_block(0x100910200,0x100910210)
    prove('null_first_tag_writes_zero_and_selects_other_constructor_route',z3.Or(
        v.stores[0]['address']!=frame+0x662f,v.stores[0]['value']!=0,v.read('w8')!=0x9a64))
    b = z3.BitVec('flag_saved_byte8',8)
    v = Lift()
    v.seed('sp',frame);v.seed('x11',u);mem(v,frame+0x662f,1,b)
    v.run_block(0x1008258b0,0x1008258d4)
    flag = z3.If(b==0,z3.BitVecVal(CLEAR|4,32),z3.BitVecVal(CLEAR,32))
    prove('all_saved_bytes_select_raw_U_flag',z3.Or(v.stores[0]['address']!=u+0x28,v.stores[0]['value']!=flag))
    prove('U_mask4_is_inverse_saved_byte_truth',((v.stores[0]['value']&4)!=0)!=(b==0))
    base0, base8 = z3.BitVecs('flag_base0_64 flag_base8_64',64)
    v = Lift()
    v.seed('sp',frame)
    for off,value in [(0x2338,base0),(0x76e0,u),(0x3e00,base8)]:mem(v,frame+off,8,value)
    v.run_block(0x100825884,0x100825894)
    prove('U_base_fields_copy_two_separate_saved_cells',z3.Or(
        v.stores[0]['address']!=u,v.stores[0]['value']!=base0,
        v.stores[1]['address']!=u+8,v.stores[1]['value']!=base8))
    flags, offset = z3.BitVecs('flag_reader_flags32 flag_reader_offset32',32)
    v = Lift()
    for reg,value in {'x13':TABLE,'x14':u,'w16':0xbff7,'w15':offset-0x89271580,'w24':0x89271580,'w3':0xc4}.items():v.seed(reg,value)
    mem(v,TABLE+8*0xc4,8,z3.BitVecVal(FIXUPS[TABLE+8*0xc4]['target'],64));mem(v,u+0x28,4,flags)
    v.run_block(0x1005320f8,0x10053214c)
    wanted = z3.If(flags&4!=0,z3.BitVecVal(0xc00f,32),z3.BitVecVal(0xbff7,32))
    prove('word_selector_uses_exact_mask4',v.read('w16')!=wanted)
    prove('word_selector_preserves_offset_and_rebuilds_return_phase',z3.Or(v.read('w22')!=offset,v.read('w6')!=0x602d,v.read('x27')!=0x1003fb284))
    return out


def controls():
    """Finite scalar truth table only; no serialized bytes or execution witness."""
    specs = [('null_first',False,0,TAG1,True,0),('null_second',False,0,TAG2,False,None),
             ('zero_first',True,0,TAG1,True,0),('zero_second',True,0,TAG2,False,None),
             ('nonzero_first',True,6,TAG1,True,0),('retained_nonzero_second',True,6,TAG2,True,1),
             ('nonzero_other',True,6,0,True,0),('zero_other',True,0,0,False,None)]
    out=[]
    for label,nonnull,h,t,admitted,b in specs:
        ok = t==TAG1 if not nonnull else h!=0 or t==TAG1
        actual = int(nonnull and t==TAG2) if ok else None
        assert (ok,actual)==(admitted,b)
        out.append({'label':label,'pointer_nonnull':nonnull,'pointed_header32':h if nonnull else 'not_read',
                    'tag32':hex(t),'reaches_selector_writer':ok,'saved_flag_byte':actual,
                    'U_flag_mask4_if_later_published':None if actual is None else 4 if actual==0 else 0,
                    'source_scalar_model_only':True,'native_admission_established':False})
    return out


def audit():
    e=json.loads(read(ROOT/(R.P+'_checks.json')))
    assert e==R.extract()
    return {'scope':__doc__,'generator_sha256':sha(R.__file__),'auditor_sha256':sha(__file__),
            'source_sha256':sha(SOURCE),'dependencies':{p:sha(ROOT/p) for p in DEPS},
            'independent_totals':replay(e),'source_proofs':obligations(),'scalar_controls':controls(),
            'conditional_selector_custody_established':True,'native_epoch_join_established':False,
            'alternate_constructor_completion_established':False,'new_port_emission_established':False,
            'proof_cuts':0,'target_instruction_rewrites':0,'prior_admissions_rerun':False,'new_target_intervals':0,
            'new_guest_input_bytes':0,'new_API_return_premises':0,'native_target_executed':False,'full_goal_complete':False}


if __name__ == '__main__':
    a=audit()
    (ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n')
    print(json.dumps({'source_proofs':len(a['source_proofs']),**a['independent_totals']}),flush=True)
