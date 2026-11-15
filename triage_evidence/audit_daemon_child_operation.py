#!/usr/bin/env python3
"""Universal child-prelude source equations and independent retained replay.
O(parent bytes + selected visits*32 + source DAG) time/space, excluding
solver search (30 s/query). No proof cut or new target/runtime premise.
"""
import json
import z3
from daemon_receive_tools import ROOT, SOURCE, TABLE, FIXUPS
from audit_daemon_alternative_fill import Source
from audit_daemon_append_fields import number
from collections import Counter
from audit_daemon_environment_outputs import DEC
from audit_daemon_append_fields import Trace
from daemon_receive_tools import IMAGE
from verify_daemon_reader_record_payloads_publication import read,sha
from lskd_values_symbolic import resize
import recover_daemon_child_operation as R

DEPS=['audit_daemon_alternative_fill.py','audit_daemon_append_fields.py','audit_daemon_storage_flag.py',
      'audit_daemon_state_table_mixing.py','audit_daemon_environment_outputs.py','lskd_values_symbolic.py',
      'recover_daemon_return_bank_origins.py']


class BranchTrace(Trace):
    def one(self,ins):
        if ins.mnemonic=='braa':
            target=number(self.read(ins.reg_name(ins.operands[0].reg)))
            modifier=number(self.read(ins.reg_name(ins.operands[1].reg)))
            assert target==self.next_pc
            assert (target,modifier) in {(t,m) for idx,t,m in R.ROUTES}
            return
        super().one(ins)


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
        v = BranchTrace(s['reads'],s['writes'])
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
            v.next_pc=int(row['source_frames'][j+1]['pc'],16)
            v.one(ins)
            if ins.mnemonic=='braa':totals['logical_authenticated_edges_checked']+=1
            totals['source_visits_checked']+=1
        assert v.ri==len(s['reads']) and v.wi==len(s['writes'])
        totals.update(read_events_checked=v.ri,write_events_checked=v.wi,slices_checked=1)
    return dict(totals)


def obligations():
    out=[]
    def prove(label,bad):
        s=z3.Solver();s.set(timeout=30000);assert s.check()==z3.sat
        s.add(z3.simplify(bad));answer=s.check();assert answer==z3.unsat,(label,str(answer),s.reason_unknown())
        out.append({'label':label,'premises_nonvacuous':True,'result':'unsat','query':s.to_smt2()})
        print(json.dumps({'source_proof':label,'result':'unsat'}),flush=True)
    def run(name,values,regs):
        v=Source(values)
        for n,x in regs.items():v.seed(n,x)
        a,b=R.SPANS[name];v.run_block(a,b-4 if name!='validation_bridge' else b)
        return v
    def addresses(v,expected):
        assert len(v.loads)==len(expected)
        return [a!=x for (pc,a,n),x in zip(v.loads,expected)]
    frame,u,dest,cursor,base0,base8,continuation,target=z3.BitVecs(
        'child_frame64 child_U64 child_destination64 child_cursor64 child_base0_64 child_base8_64 child_continuation64 child_target64',64)
    payload,coordinate,flags,status=z3.BitVecs('child_payload32 child_coordinate32 child_flags32 child_status32',32)
    v=run('entry',{0x100762e68:(8,TABLE),0x100762e6c:(8,0x1009679f0),0x100762e80:(8,0x1010c8268)},
          {'sp':frame,'w28':0x155f})
    prove('entry_rebuilds_phase_and_private_token_pointer',z3.Or(v.read('w25')!=0x6cf4,v.read('x21')!=frame+0x5378,
        v.read('w9')!=0x74b496cd,v.read('w8')!=0x237c979d,v.read('x10')!=0x1009679f0,v.read('x17')!=0xbe0b,
        *addresses(v,[frame+0x9d8,TABLE+8*0x192e,frame+0x858])))
    v=run('token_context',{0x100967a0c:(8,TABLE),0x100967a10:(8,0x10077b08c)}, {'sp':frame,'w25':0x6cf4})
    constants={'w23':0x74,'w26':0x1a,'w3':0xdc836863,'w4':0xffffffb5,'w5':0xdc836864,
               'w6':0xffffff96,'w7':0xdc836865,'w20':0x54,'w22':0xdc836866}
    prove('token_context_constants_and_frame_XOR_descriptor',z3.Or(*[v.read(n)!=x for n,x in constants.items()],
        v.read('x24')!=(frame+0x9e0)^0xc00e63b366f327e4,v.read('x10')!=0x10077b08c,v.read('x17')!=0xe70e,
        *addresses(v,[frame+0x9d8,TABLE+8*0x7a4e])))
    v=run('token_writer',{0x10077b0a4:(8,TABLE),0x10077b0a8:(8,0x1007948e4),0x10077b11c:(8,0x6cf4)},
          {**constants,'sp':frame,'x21':dest,'w8':coordinate+0x237c979d,'w9':payload,'w28':0x155f})
    assert len(v.stores)==4
    for j,w in enumerate(v.stores):
        prove('generic_token_byte_'+str(j),z3.Or(w['address']!=dest+z3.ZeroExt(32,coordinate+j),w['size_bytes']!=1,
            w['value']!=z3.Extract(31-8*j,24-8*j,payload^0xec2d0e54)))
    prove('token_writer_return_and_forwarded_private_fields',z3.Or(v.read('x14')!=0x1007948e4,v.read('x17')!=0x6878,
        v.read('x12')!=frame+0xa698,v.read('x13')!=frame+0xa0a0,v.read('w9')!=0x4382ea2d,
        *addresses(v,[frame+0x9d8,TABLE+8*0x155f,frame+0x9d0])))
    v=run('child_reload',{0x1007948f8:(8,u),0x1007948fc:(8,dest),0x100794904:(8,0x6cf4),
                        0x100794918:(8,TABLE),0x10079491c:(8,0x100746474)}, {'sp':frame})
    prove('saved_pair_reloaded_and_operation_tag_prepared',z3.Or(v.read('x20')!=u,v.read('x10')!=dest,
        v.read('x22')!=frame+0x5378,v.read('w21')!=0xf29,v.read('w9')!=0x403e,
        v.read('w8')!=0x8b3dc650,v.read('w12')!=0x76657273,v.read('w11')!=0x8b3dc655,
        v.read('w19')!=0x76d8ea80,v.read('x13')!=0x100746474,v.read('x17')!=0x7da4,
        *addresses(v,[frame+0xaf18,frame+0xaf20,frame+0x9d0,frame+0x9d8,TABLE+8*0x291c])))
    v=run('frame_setup',{0x100746488:(8,TABLE),0x10074648c:(8,0x1008c25f4),0x1007464a8:(8,cursor),
                        0x1007464f0:(8,target)}, {'sp':frame,'w9':0x403e,'w21':0xf29,'w19':0x76d8ea80,
        'w12':0x76657273,'w11':0x8b3dc655,'x10':dest,'x22':frame+0x5378,'x20':u})
    expected=[(frame+0x8b90,8,0x1008c25f4),(frame+0x2d64,4,0x76d8ea80),(frame+0x2090,4,0x76657273),
              (frame+0x2690,4,0x8b3dc655),(frame+0xd80,8,dest),(frame+0x4e08,8,frame+0xc070+cursor),
              (frame+0x16d0,8,cursor+32),(frame+0x4450,8,frame+0x5378),(frame+0x42e0,8,u)]
    assert len(v.stores)==len(expected)
    prove('operation_frame_saved_fields_and_32_byte_cursor_advance',z3.Or(*[
        z3.Or(w['address']!=a,w['size_bytes']!=n,w['value']!=resize(x,8*n)) for w,(a,n,x) in zip(v.stores,expected)]))
    prove('operation_frame_null_U_partition',z3.Or(v.read('x9')!=target,
        v.read('w10')!=0x2a9e,v.read('w27')!=0x74c29d88,v.read('x17')!=0x5469,
        *addresses(v,[frame+0x9d8,TABLE+8*0xf29,frame+0x16d0,TABLE+8*z3.If(u==0,z3.BitVecVal(0x4045,64),z3.BitVecVal(0x403e,64))])))
    v=run('base_gate',{0x100532e34:(8,base0),0x100532e54:(8,TABLE),0x100532e58:(8,target)},
          {'sp':frame,'x20':u,'w10':0x2a9e})
    prove('base0_gate_selects_alternative_or_companion_check',z3.Or(v.read('x10')!=target,v.read('w9')!=0x571e,v.read('w13')!=0x2a1b,
        v.read('x17')!=0x696a,*addresses(v,[u,frame+0x9d8,TABLE+8*z3.If(base0==0,z3.BitVecVal(0xae23,64),z3.BitVecVal(0x2a9e,64))])))
    v=run('clear_base_gate',{0x100528100:(8,base8),0x100528120:(8,TABLE),0x100528124:(8,target)},
          {'sp':frame,'x20':u,'w13':0x2a1b})
    prove('base8_gate_requires_nonnull_companion_when_base0_null',z3.Or(v.read('x10')!=target,v.read('w9')!=0x571e,v.read('x17')!=0x696a,
        *addresses(v,[u+8,frame+0x9d8,TABLE+8*z3.If(base8!=0,z3.BitVecVal(0x2a9e,64),z3.BitVecVal(0x2a1b,64))])))
    v=run('flag0_gate',{0x1004e385c:(4,flags),0x1004e3880:(8,TABLE),0x1004e3884:(8,target)},
          {'sp':frame,'x20':u,'w9':0x571e})
    prove('flag_bit0_must_be_clear_to_continue',z3.Or(v.read('x10')!=target,v.read('w13')!=flags,v.read('w27')!=0x74c29d4b,
        v.read('x17')!=0xc161,*addresses(v,[u+0x28,frame+0x9d8,TABLE+8*z3.If(flags&1==0,z3.BitVecVal(0xbc27,64),z3.BitVecVal(0x571e,64))])))
    v=run('flag1_gate',{0x10058c720:(8,TABLE),0x10058c724:(8,target)},
          {'sp':frame,'w9':0x571e,'w13':flags})
    prove('flag_bit1_must_be_set_to_continue',z3.Or(v.read('x9')!=target,v.read('w10')!=0x6cf4,v.read('w27')!=0x74c29d48,
        v.read('x17')!=0xc161,*addresses(v,[frame+0x9d8,TABLE+8*z3.If(flags&2!=0,z3.BitVecVal(0x5727,64),z3.BitVecVal(0x571e,64))])))
    v=run('validation_bridge',{0x1005f1494:(8,TABLE),0x1005f1498:(8,0x1005015e8)}, {'sp':frame,'w10':0x6cf4})
    prove('validation_bridge_sets_inner_continuation_index',z3.Or(v.read('w9')!=0x1362,v.read('x14')!=0x1005015e8,
        *addresses(v,[frame+0x9d8,TABLE+8*0x2a7d])))
    v=run('frame_return',{0x100924854:(8,cursor),0x100924864:(8,continuation),0x100924868:(8,0x6cf4)}, {'sp':frame,'w27':status})
    prove('frame_return_rewinds_cursor_and_preserves_raw_status',z3.Or(v.stores[0]['address']!=frame+0x16d0,
        v.stores[0]['value']!=cursor-32,v.read('x8')!=continuation,v.read('x17')!=0x8eb3,v.read('x23')!=0x6cf4,v.read('w27')!=status,
        *addresses(v,[frame+0x16d0,frame+0x8b90,frame+0x9d0])))
    v=run('outer_return',{0x1008c25f4:(8,continuation)}, {'sp':frame,'w27':status})
    prove('outer_return_loads_saved_result_continuation',z3.Or(v.read('x8')!=continuation,v.read('x17')!=0x9325,
        v.read('w27')!=status,*addresses(v,[frame+0x3980])))
    v=run('result_gate',{0x10072c458:(8,0x6cf4),0x10072c4a4:(8,TABLE),0x10072c4a8:(8,target)},
          {'sp':frame,'w27':status})
    prove('outer_result_gate_accepts_exact_raw_status',z3.Or(v.read('x8')!=target,v.read('w19')!=0x8c1deaf7,v.read('w23')!=0x764d,
        v.read('x17')!=0xb0c4,*addresses(v,[frame+0x9d0,frame+0x9d8,TABLE+8*z3.If(status==0x8b3dc651,z3.BitVecVal(0x8eff,64),z3.BitVecVal(0x8e61,64))])))
    return out


def controls():
    out=[]
    for flag in range(8):
        accepted=(flag&1)==0 and (flag&2)!=0
        assert accepted==(flag in [2,6])
        out.append({'low_three_flag_bits':flag,'passes_low_two_bit_guards':accepted,'mask4':bool(flag&4),
                    'source_scalar_model_only':True,'native_admission_established':False})
    assert (0x74b496cd^0xec2d0e54).to_bytes(4,'big').hex()=='98999899'
    assert (0x76657273).to_bytes(4,'big').decode('ascii')=='vers'
    return out


def audit():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.extract()
    return {'scope':__doc__,'generator_sha256':sha(R.__file__),'auditor_sha256':sha(__file__),
        'source_sha256':sha(SOURCE),'dependencies':{p:sha(ROOT/p) for p in DEPS},'independent_totals':replay(e),
        'source_proofs':obligations(),'scalar_controls':controls(),'conditional_child_prelude_contract_established':True,
        'alternative_execution_observed':False,'native_epoch_join_established':False,'new_port_emission_established':False,
        'proof_cuts':0,'target_instruction_rewrites':0,'prior_admissions_rerun':False,'new_target_intervals':0,
        'new_guest_input_bytes':0,'new_API_return_premises':0,'native_target_executed':False,'full_goal_complete':False}


if __name__=='__main__':
    e=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(e,indent=2)+'\n')
    print(json.dumps({'independent_totals':e['independent_totals'],'source_proofs':len(e['source_proofs'])}),flush=True)
