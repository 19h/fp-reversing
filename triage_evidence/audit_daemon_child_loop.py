#!/usr/bin/env python3
"""Independent loop/output/status replay and universal source equations.
O(parent bytes + selected visits*32 + proof DAG) time/space, excluding solver
search (30 s/query). No proof cuts, target rewriting or runtime execution.
"""
import json
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,TABLE
from audit_daemon_environment_outputs import DEC
from audit_daemon_append_fields import Trace,number
from audit_daemon_alternative_fill import Source
from lskd_values_symbolic import resize
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_daemon_child_loop as R

DEPS=['audit_daemon_append_fields.py','audit_daemon_alternative_fill.py','audit_daemon_state_table_mixing.py',
      'audit_daemon_environment_outputs.py','lskd_values_symbolic.py','recover_daemon_return_bank_origins.py',
      'daemon_seed_material_symbolic.py']


class BranchTrace(Trace):
    def one(self,ins):
        if ins.mnemonic=='braa':
            target=number(self.read(ins.reg_name(ins.operands[0].reg)))
            modifier=number(self.read(ins.reg_name(ins.operands[1].reg)))
            assert target==self.next_pc and (target,modifier) in ({(t,m) for i,t,m in R.ROUTES}|set(R.SAVED_EDGES))
            return
        super().one(ins)


def replay(e):
    parent=json.loads(read(ROOT/'daemon_constructor_buffer_checks.json'))
    totals,key,row=Counter(),None,None
    for s in e['slices']:
        current=s['class_index'],s['interval_index']
        if current!=key:
            ci,ii=current;row=R.unpack(parent['branches'][ci]['intervals'][ii]['interval_packed']);key=current
        assert s['entry']==row['source_frames'][s['start_visit']] and s['exit']==row['source_frames'][s['end_visit_exclusive']]
        v=BranchTrace(s['reads'],s['writes'])
        for k,x in enumerate(s['entry']['registers31']):v.seed('x'+str(k),int(x,16))
        v.seed('sp',int(s['entry']['SP'],16))
        flags=int(s['entry']['NZCV'],16)
        v.n,v.z,v.carry,v.overflow=[z3.BoolVal(bool(flags&(1<<b))) for b in [31,30,29,28]]
        for j in range(s['start_visit'],s['end_visit_exclusive']+1):
            f=row['source_frames'][j]
            assert f['Q_registers32']==s['entry']['Q_registers32']
            assert all(number(v.read('x'+str(k)))==int(f['registers31'][k],16) for k in range(31))
            assert number(v.read('sp'))==int(f['SP'],16)
            actual=[z3.simplify(t) for t in [v.n,v.z,v.carry,v.overflow]]
            assert all(z3.is_true(t) or z3.is_false(t) for t in actual)
            assert sum(int(z3.is_true(t))<<b for t,b in zip(actual,[31,30,29,28]))==int(f['NZCV'],16)
            totals.update(GP_SP_values_checked=32,Q_values_checked=32,NZCV_frames_checked=1)
            if j==s['end_visit_exclusive']:break
            pc=int(row['source_visits'][j]['pc'],16)
            assert row['source_visits'][j]['bytes_hex']==IMAGE.read(pc,4).hex()
            ins=next(DEC.disasm(IMAGE.read(pc,4),pc))
            assert not any(ins.reg_name(r).startswith(('v','q','d','s')) and ins.reg_name(r)!='sp' for r in ins.regs_access()[0]+ins.regs_access()[1])
            v.next_pc=int(row['source_frames'][j+1]['pc'],16);v.one(ins)
            if ins.mnemonic=='braa':totals['logical_authenticated_edges_checked']+=1
            totals['source_visits_checked']+=1
        assert v.ri==len(s['reads']) and v.wi==len(s['writes'])
        totals.update(read_events_checked=v.ri,write_events_checked=v.wi,slices_checked=1)
    return dict(totals)


def obligations():
    out=[]
    def prove(label,bad,premises=()):
        s=z3.Solver();s.set(timeout=30000);s.add(*premises);assert s.check()==z3.sat,label
        s.add(z3.simplify(bad));answer=s.check();assert answer==z3.unsat,(label,str(answer),s.reason_unknown())
        out.append({'label':label,'premises_nonvacuous':True,'result':'unsat','query':s.to_smt2()})
        print(json.dumps({'source_proof':label,'result':'unsat'}),flush=True)
    def run(name,values,regs):
        v=Source(values)
        for n,x in regs.items():v.seed(n,x)
        a,b=R.SPANS[name];last=next(DEC.disasm(IMAGE.read(b-4,4),b-4))
        v.run_block(a,b-4 if last.mnemonic=='braa' else b);return v
    def addresses(v,expected):
        assert len(v.loads)==len(expected)
        return [a!=x for (pc,a,n),x in zip(v.loads,expected)]
    def stores(v,expected):
        assert len(v.stores)==len(expected)
        return [z3.Or(w['address']!=a,w['size_bytes']!=n,w['value']!=resize(x,8*n))
            for w,(a,n,x) in zip(v.stores,expected)]
    def bv64(x):return z3.BitVecVal(x,64)
    frame,target,count64,u,dest,cursor,continuation=z3.BitVecs(
        'child_loop_frame64 child_loop_target64 child_loop_count64 child_loop_U64 child_loop_output64 child_loop_cursor64 child_loop_continuation64',64)
    tag,i,count,coord,status,flags=z3.BitVecs(
        'child_loop_tag32 child_loop_index32 child_loop_count32 child_loop_coord32 child_loop_status32 child_loop_flags32',32)
    v=run('tag_partition',{0x1008efa24:(8,TABLE),0x1008efa28:(8,target)},
        {'sp':frame,'w13':0x82e2,'w12':tag})
    prove('tag_partition_uses_signed_LT_and_rebuilds_phase',z3.Or(v.read('w16')!=0x3fa5,
        v.read('x13')!=target,v.read('x17')!=0xd40d,*addresses(v,[frame+0x9d8,
        TABLE+8*z3.If(tag<z3.BitVecVal(0x76657273,32),bv64(0x82f6),bv64(0x82e2))])))
    v=run('tag_exact',{0x100a38150:(8,TABLE),0x100a38154:(8,target)},
        {'sp':frame,'w16':0x3fa5,'w12':tag})
    prove('exact_vers_tag_initializes_index_zero',z3.Or(v.read('w15')!=0,v.read('w14')!=0x1e5c,
        v.read('x12')!=target,v.read('x17')!=0x987b,*addresses(v,[frame+0x9d8,
        TABLE+8*z3.If(tag==0x76657273,bv64(0x68d9),bv64(0x3fa5))])))
    v=run('loop_gate',{0x1009a15ac:(8,TABLE),0x1009a15b0:(8,target)},
        {'sp':frame,'w14':0x1e5c,'w15':i,'x19':count64})
    prove('gate_compares_u64_count_with_zero_extended_u32_index',z3.Or(
        v.read('x10')!=z3.ZeroExt(32,i),v.read('w8')!=0x97a,v.read('w12')!=0x6cf4,
        v.read('x9')!=target,v.read('x17')!=0x1d3b,*stores(v,[(frame+0x4f6c,4,i)]),
        *addresses(v,[frame+0x9d8,TABLE+8*z3.If(z3.UGT(count64,z3.ZeroExt(32,i)),bv64(0x6a7e),bv64(0x1e5c))])))
    v=run('loop_backedge',{0x100957a68:(8,0x6cf4),0x100957a7c:(4,i),0x100957a8c:(8,count64),
        0x100957a90:(8,TABLE),0x100957a94:(8,target)}, {'sp':frame})
    prove('backedge_reloads_count_and_rebuilds_phase_and_u32_increment',z3.Or(
        v.read('w15')!=i+1,v.read('x19')!=count64,v.read('w14')!=0x1e5c,
        v.read('x8')!=target,v.read('x17')!=0x987b,*addresses(v,[frame+0x9d0,frame+0x4f6c,
        frame+0x7df8,frame+0x9d8,TABLE+8*0x68d9])))
    old_rank=z3.ZeroExt(32,count)-z3.ZeroExt(32,i)
    new_rank=z3.ZeroExt(32,count)-z3.ZeroExt(32,i+1)
    prove('active_u32_iteration_cannot_wrap_and_rank_decreases',z3.Or(
        z3.ZeroExt(32,i+1)!=z3.ZeroExt(32,i)+1,
        z3.UGT(z3.ZeroExt(32,i+1),z3.ZeroExt(32,count)),z3.UGE(new_rank,old_rank)),[z3.ULT(i,count)])
    prove('count_above_u32_always_exceeds_zero_extended_index',
        z3.Not(z3.UGT(count64,z3.ZeroExt(32,i))),[z3.UGT(count64,0xffffffff)])
    prove('zero_count_has_no_active_index_and_count_itself_is_exit',z3.Or(
        z3.UGT(bv64(0),z3.ZeroExt(32,i)),z3.UGT(z3.ZeroExt(32,count),z3.ZeroExt(32,count))))
    v=run('optional_output',{0x1008d34a0:(8,dest),0x1008d34c4:(8,TABLE),0x1008d34c8:(8,target)},
        {'sp':frame,'w12':0x6cf4})
    prove('optional_coordinate_output_null_partition',z3.Or(v.read('w8')!=0x4045,v.read('w9')!=0x3f00,
        v.read('x10')!=dest,v.read('x12')!=frame+0x8000,v.read('x11')!=target,v.read('x17')!=0x5a94,
        *addresses(v,[frame+0xd80,frame+0x9d8,TABLE+8*z3.If(dest==0,bv64(0x3f00),bv64(0x3f0d))])))
    v=run('output_store',{0x10076d5dc:(4,coord),0x10076d5e4:(8,TABLE),0x10076d5e8:(8,target)},
        {'sp':frame,'x10':dest,'w9':0x3f00,'w8':0x4045,'x12':frame+0x8000})
    prove('output_is_four_byte_encoded_coordinate_copy',z3.Or(*stores(v,[(dest,4,coord)]),
        v.read('w8')!=0x4045,v.read('x12')!=frame+0x8000,v.read('x9')!=target,v.read('x17')!=0x5a94,
        *addresses(v,[frame+0x816c,frame+0x9d8,TABLE+8*0x3f00])))
    v=run('status_save',{}, {'x12':frame+0x8000,'w27':status})
    prove('nested_raw_status_saved_as_u32',z3.Or(*stores(v,[(frame+0x8d8c,4,status)])))
    v=run('coordinate_save',{}, {'x9':dest,'w10':coord})
    prove('coordinate_custody_writer_copies_u32',z3.Or(*stores(v,[(dest,4,coord)])))
    v=run('postprocess',{0x1006d1424:(8,u),0x1006d1428:(4,flags),0x1006d143c:(4,status),
        0x1006d1440:(4,tag),0x1006d1464:(8,TABLE),0x1006d1468:(8,target)},
        {'sp':frame,'w8':0x4045,'x12':frame+0x8000})
    mode=z3.And(flags&4==0,tag==0x69746772)
    prove('postprocess_restores_raw_status_and_selects_clear_itgr',z3.Or(v.read('w27')!=status,
        v.read('w25')!=0x63e,v.read('x8')!=target,v.read('x17')!=0x5469,*addresses(v,[frame+0x42e0,
        u+0x28,frame+0x8d8c,frame+0x2090,frame+0x9d8,TABLE+8*z3.If(mode,bv64(0x8aae),bv64(0x4045))])))
    difference=tag-z3.BitVecVal(0x69746772,32);clear=flags&4==0
    expected=[z3.And(clear,z3.Extract(31,31,difference)==1),mode,
        z3.And(clear,z3.UGE(tag,0x69746772)),
        z3.And(clear,z3.Extract(31,31,tag)==1,z3.Extract(31,31,difference)==0)]
    prove('postprocess_CCMP_all_NZCV_bits_match_compare_or_zero_fallback',z3.Or(*[
        x!=y for x,y in zip([v.n,v.z,v.carry,v.overflow],expected)]))
    prove('vers_cannot_select_itgr_continuation',mode,[tag==0x76657273])
    v=run('frame_return',{0x100924854:(8,cursor),0x100924864:(8,continuation),0x100924868:(8,0x6cf4)},
        {'sp':frame,'w27':status})
    prove('frame_return_reverses_32_byte_cursor_step_and_preserves_raw_status',z3.Or(
        *stores(v,[(frame+0x16d0,8,cursor-32)]),v.read('w27')!=status,v.read('x8')!=continuation,
        v.read('x23')!=0x6cf4,v.read('x17')!=0x8eb3,*addresses(v,[frame+0x16d0,frame+0x8b90,frame+0x9d0])))
    v=run('outer_return',{0x1008c25f4:(8,continuation)}, {'sp':frame,'w27':status})
    prove('outer_return_preserves_raw_status',z3.Or(v.read('w27')!=status,v.read('x8')!=continuation,
        v.read('x17')!=0x9325,*addresses(v,[frame+0x3980])))
    v=run('outer_gate',{0x10072c458:(8,0x6cf4),0x10072c4a4:(8,TABLE),0x10072c4a8:(8,target)},
        {'sp':frame,'w27':status})
    prove('outer_gate_accepts_exact_restored_status_word',z3.Or(v.read('w27')!=status,
        v.read('x8')!=target,v.read('x17')!=0xb0c4,*addresses(v,[frame+0x9d0,frame+0x9d8,
        TABLE+8*z3.If(status==0x8b3dc651,bv64(0x8eff),bv64(0x8e61))])))
    return out


def controls():
    rows=[]
    for tag in [0x76657273,0x69746772,0x76657272,0x76657274,0xffffffff]:
        for flags in [0,4]:
            signed=tag if tag<0x80000000 else tag-0x100000000
            rows.append({'kind':'tag_and_mask','tag32':hex(tag),'flags32':hex(flags),
                'partition_index32':hex(0x82f6 if signed<0x76657273 else 0x82e2),
                'vers_loop_selected':tag==0x76657273,
                'postprocess_index32':hex(0x8aae if flags&4==0 and tag==0x69746772 else 0x4045),
                'source_scalar_model_only':True,'native_admission_established':False})
    for count in [0,1,4,0xffffffff]:
        for i in sorted({0,max(0,count-1),count}):
            active=i<count
            assert not active or i+1<=count<=0xffffffff
            rows.append({'kind':'u32_loop_boundary','count32':count,'index32':i,'body_selected':active,
                'next_index32_if_body_returns':i+1 if active else None,
                'source_scalar_model_only':True,'native_admission_established':False})
    rows.append({'kind':'outside_decoded_u32_count_domain','count64':hex(0x100000000),
        'index32':0xffffffff,'body_selected':True,'next_index32_if_body_returns':0,
        'source_scalar_model_only':True,'native_admission_established':False})
    assert (0x76d8ea95+0x89271580)&0xffffffff==21
    return rows


def audit():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.extract()
    return {'scope':__doc__,'generator_sha256':sha(R.__file__),'auditor_sha256':sha(__file__),
        'source_sha256':sha(SOURCE),'dependencies':{p:sha(ROOT/p) for p in DEPS},'independent_totals':replay(e),
        'source_proofs':obligations(),'scalar_controls':controls(),
        'conditional_loop_output_status_contract_established':True,
        'arbitrary_body_termination_established':False,'native_epoch_join_established':False,
        'new_port_emission_established':False,'proof_cuts':0,'target_instruction_rewrites':0,
        'prior_admissions_rerun':False,'new_target_intervals':0,'new_guest_input_bytes':0,
        'new_API_return_premises':0,'native_target_executed':False,'full_goal_complete':False}


if __name__=='__main__':
    e=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(e,indent=2)+'\n')
    print(json.dumps({'independent_totals':e['independent_totals'],'source_proofs':len(e['source_proofs']),
        'scalar_controls':len(e['scalar_controls'])}),flush=True)
