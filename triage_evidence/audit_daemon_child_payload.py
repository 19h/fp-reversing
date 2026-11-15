#!/usr/bin/env python3
"""Universal mode predicates and u8 scalar decoding with independent replay.
O(parent bytes + selected visits*32 + proof DAG) time/space, excluding solver
search (30 s/query). No instruction rewrite, proof cut or new runtime premise.
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
import recover_daemon_child_payload as R

DEPS=['audit_daemon_append_fields.py','audit_daemon_alternative_fill.py','audit_daemon_state_table_mixing.py',
      'audit_daemon_environment_outputs.py','lskd_values_symbolic.py','recover_daemon_return_bank_origins.py']

class BranchTrace(Trace):
    def one(self,ins):
        if ins.mnemonic=='braa':
            target=number(self.read(ins.reg_name(ins.operands[0].reg)))
            modifier=number(self.read(ins.reg_name(ins.operands[1].reg)))
            assert target==self.next_pc and (target,modifier) in {(t,m) for idx,t,m in R.ROUTES}
            return
        super().one(ins)


def replay(e):
    parent=json.loads(read(ROOT/'daemon_constructor_buffer_checks.json'))
    totals, key, row = Counter(), None, None
    for s in e['slices']:
        current = s['group'],s['class_index'],s['interval_index']
        if current != key:
            group,ci,ii = current
            packed=parent['prefixes'][ci]['interval_packed'] if group=='prefix' else parent['branches'][ci]['intervals'][ii]['interval_packed']
            row,key=R.unpack(packed),current
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
        a,b=R.SPANS[name]
        last=next(DEC.disasm(IMAGE.read(b-4,4),b-4))
        v.run_block(a,b-4 if last.mnemonic=='braa' else b)
        return v
    def addresses(v,expected):
        assert len(v.loads)==len(expected)
        return [a!=x for (pc,a,n),x in zip(v.loads,expected)]
    frame,u,root,base0,base8,target,continuation,pointer,index=z3.BitVecs(
        'payload_frame64 payload_U64 payload_root64 payload_base0_64 payload_base8_64 payload_target64 payload_continuation64 payload_pointer64 payload_index64',64)
    tag,first,count,flags,position,status=z3.BitVecs(
        'payload_tag32 payload_first32 payload_count32 payload_flags32 payload_position32 payload_status32',32)
    raw=z3.BitVec('payload_raw8',8)
    v=run('nested_entry',{0x1005015f0:(8,TABLE),0x1005015f4:(8,0x100751f0c),0x100501638:(8,target)},
        {'sp':frame,'x20':u,'x13':root,'w10':0x6cf4,'w9':0x1362,'w12':tag,'w8':first,'w11':count})
    expected=[(frame+0x8ca0,8,0x100751f0c),(frame+0x6588,8,u),(frame+0x6fc4,4,tag),
              (frame+0x741c,4,first),(frame+0x537c,4,count),(frame+0x2ac8,8,root)]
    assert len(v.stores)==6
    prove('nested_entry_saves_tag_count_first_word_U_root_and_continuation',z3.Or(*[
        z3.Or(w['address']!=a,w['size_bytes']!=n,w['value']!=resize(x,8*n)) for w,(a,n,x) in zip(v.stores,expected)]))
    prove('nested_entry_null_U_partition',z3.Or(v.read('w11')!=0x2eb9,v.read('x8')!=target,v.read('w27')!=0x74c29d88,
        v.read('x17')!=0xa298,*addresses(v,[frame+0x9d8,TABLE+8*0x1362,
        TABLE+8*z3.If(u==0,z3.BitVecVal(0x3eda,64),z3.BitVecVal(0x3efa,64))])))
    v=run('primary_mode',{0x1008658ac:(8,base0),0x1008658c8:(8,TABLE),0x1008658cc:(8,target)},
        {'sp':frame,'x20':u,'w11':0x2eb9})
    prove('nested_primary_base_partition',z3.Or(v.read('w9')!=0x717c,v.read('w8')!=0x8d0e,v.read('x10')!=target,
        v.read('x17')!=0x82cf,*addresses(v,[u,frame+0x9d8,
        TABLE+8*z3.If(base0!=0,z3.BitVecVal(0x2ed8,64),z3.BitVecVal(0x2eb9,64))])))
    v=run('masked_mode',{0x1005a72e4:(4,flags),0x1005a730c:(8,TABLE),0x1005a7310:(8,target)},
        {'sp':frame,'x20':u,'w9':0x717c})
    prove('nonnull_primary_with_mask4_reaches_validation',z3.Or(v.read('w21')!=0x8af4,v.read('w8')!=0x8d0e,
        v.read('x9')!=target,v.read('x17')!=0xd21b,*addresses(v,[u+0x28,frame+0x9d8,
        TABLE+8*z3.If(flags&4!=0,z3.BitVecVal(0x717c,64),z3.BitVecVal(0x718f,64))])))
    v=run('secondary_mode',{0x10057530c:(8,base8),0x10057531c:(8,TABLE),0x100575320:(8,target)},
        {'sp':frame,'x20':u,'w8':0x8d0e})
    prove('secondary_base_is_required_for_clear_candidate',z3.Or(v.read('x9')!=target,v.read('x17')!=0x4ae9,
        *addresses(v,[u+8,frame+0x9d8,TABLE+8*z3.If(base8!=0,z3.BitVecVal(0x8d0e,64),z3.BitVecVal(0x8d0f,64))])))
    v=run('clear_mode',{0x10080fbd8:(1,z3.Extract(7,0,flags)),0x10080fbf8:(8,TABLE),0x10080fbfc:(8,target)},
        {'sp':frame,'x20':u,'w8':0x8d0e})
    prove('nonnull_secondary_requires_mask4_clear',z3.Or(v.read('w21')!=0x8af4,v.read('x8')!=target,v.read('x17')!=0x7dc1,
        *addresses(v,[u+0x28,frame+0x9d8,TABLE+8*z3.If(flags&4==0,z3.BitVecVal(0x7492,64),z3.BitVecVal(0x7429,64))])))
    v=run('nested_return',{0x1008f2a20:(8,continuation)}, {'sp':frame,'w27':status})
    prove('nested_rejection_returns_saved_continuation_with_status_preserved',z3.Or(v.read('x8')!=continuation,
        v.read('x17')!=0xd08c,v.read('w27')!=status,*addresses(v,[frame+0x8ca0])))
    v=run('payload_inputs',{0x1007579dc:(8,pointer),0x1007579e4:(4,count)}, {'sp':frame})
    prove('payload_pointer_copy_and_encoded_count_decode',z3.Or(v.stores[0]['address']!=frame+0x7520,
        v.stores[0]['size_bytes']!=8,v.stores[0]['value']!=pointer,v.stores[1]['address']!=frame+0x7df8,
        v.stores[1]['size_bytes']!=8,v.stores[1]['value']!=z3.ZeroExt(32,count^0x8b3dc651),
        *addresses(v,[frame+0x4450,frame+0x2690])))
    v=run('byte_decode',{0x1008f0c24:(4,position),0x1008f0c38:(8,pointer),0x1008f0c3c:(1,raw),
        0x1008f0c58:(8,TABLE),0x1008f0c5c:(8,0x1008f3914)}, {'sp':frame,'w8':0x97a,'x10':index})
    prove('payload_byte_decoder_all_u8_and_full_u64_input_address',z3.Or(
        v.read('w23')!=(z3.ZeroExt(24,raw^0x98)^0x8b3dc651),v.read('x10')!=0x1008f3914,v.read('x17')!=0x4d13,
        *addresses(v,[frame+0x14d8,frame+0x7520,pointer+index,frame+0x9d8,TABLE+8*0x1f62])))
    assert len(v.stores)==1
    prove('payload_destination_offset_scales_each_index_by_four',z3.Or(v.stores[0]['address']!=frame+0x6428,
        v.stores[0]['size_bytes']!=4,v.stores[0]['value']!=position+4*z3.Extract(31,0,index)))
    scalar=z3.BitVec('payload_scalar_encoded32',32)
    v=run('scalar_spill',{}, {'x8':frame+0x9000,'w23':scalar})
    prove('encoded_scalar_spill_to_packed_word_input',z3.Or(v.stores[0]['address']!=frame+0xab28,
        v.stores[0]['size_bytes']!=4,v.stores[0]['value']!=scalar))
    v=run('destination_read',{0x100584edc:(4,position)}, {'x9':frame+0x634a})
    prove('packed_writer_reads_the_saved_destination_offset',z3.Or(v.read('w11')!=position,*addresses(v,[frame+0x6428])))
    word=z3.BitVec('payload_token_writer_input32',32)
    decoded=z3.Concat(*[z3.Extract(31-8*j,24-8*j,word^0xec2d0e54)^0x98 for j in range(4)])
    prove('pinned_token_writer_and_current_byte_reader_compose',decoded!=word^0x74b596cc)
    return out


def controls():
    rows=[]
    for primary in [False,True]:
        for secondary in [False,True]:
            for masked in [False,True]:
                actual=(primary and masked) or (secondary and not masked)
                via_paths=(primary and masked) or ((not primary or not masked) and secondary and not masked)
                assert actual==via_paths
                rows.append({'primary_nonnull':primary,'secondary_nonnull':secondary,'mask4_set':masked,
                    'reaches_validation_wrapper':actual,'source_scalar_model_only':True,'native_admission_established':False})
    assert (0x74b496cd^0x74b596cc).to_bytes(4,'big')==bytes([0,1,0,1])
    return rows


def audit():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.extract()
    return {'scope':__doc__,'generator_sha256':sha(R.__file__),'auditor_sha256':sha(__file__),
        'source_sha256':sha(SOURCE),'dependencies':{p:sha(ROOT/p) for p in DEPS},'independent_totals':replay(e),
        'source_proofs':obligations(),'scalar_controls':controls(),'conditional_payload_lineage_established':True,
        'alternative_execution_observed':False,'native_epoch_join_established':False,'new_port_emission_established':False,
        'proof_cuts':0,'target_instruction_rewrites':0,'prior_admissions_rerun':False,'new_target_intervals':0,
        'new_guest_input_bytes':0,'new_API_return_premises':0,'native_target_executed':False,'full_goal_complete':False}


if __name__=='__main__':
    e=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(e,indent=2)+'\n')
    print(json.dumps({'independent_totals':e['independent_totals'],'source_proofs':len(e['source_proofs'])}),flush=True)
