#!/usr/bin/env python3
"""Conditional SecureTime context comparison and comparison-record consumer.

Original source, bounded slot-window census and scalar certificates. Actual bank
roots, saved source phase, control/context producers and native epochs remain
unknown. No target execution or IDB mutation. O(B+I+W) extraction and O(I)
expression construction; SMT cost separate.
"""
import argparse
import json
import struct

import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_EXT_SXTB

from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE
from recover_aes_cleanup_epoch import span
from recover_kext_cold_init import pointer
from recover_lskd_clock_accumulator import FlowLift
from recover_lskd_clock_reader import TABLE
from lskd_values_symbolic import part,mem,cell,resize
from verify_daemon_reader_record_payloads_publication import read,sha

SPANS={
    'producer':(0xfffffe000a5244bc,0xfffffe000a5246c4),
    'comparator':(0xfffffe000a52f458,0xfffffe000a52f4f0),
    'noop_candidate':(0xfffffe000a52fd10,0xfffffe000a52fd18),
    'different_carries':(0xfffffe000a55ee4c,0xfffffe000a55ee88),
    'equal_carries':(0xfffffe000a55b298,0xfffffe000a55b2cc),
    'comparison_join':(0xfffffe000a528950,0xfffffe000a5289a0),
    'control_gate':(0xfffffe000a522b00,0xfffffe000a522b64),
    'status_gate':(0xfffffe000a5237a8,0xfffffe000a5237d8),
    'alternate_hop':(0xfffffe000a522538,0xfffffe000a52254c),
}
INDICES=[0xa0c,0xa20,0xa35,0x143,0x156,0x2eb,0x155,0x940,0x17,0x418,0x498]


class CompareLift(FlowLift):
    def operand(self,ins,operand,width):
        if operand.ext==ARM64_EXT_SXTB:
            assert not operand.shift.type
            return z3.SignExt(width-8,z3.Extract(7,0,self.read(ins.reg_name(operand.reg))))
        return super().operand(ins,operand,width)

    def run(self,label):
        saved=self.c;row=next(s for s in saved['spans'] if s['label']==label)
        cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
        data=bytes.fromhex(row['bytes_hex']);instructions=list(cs.disasm(data,int(row['start'],16)))
        assert len(instructions)*4==len(data)
        for ins in instructions:
            self.pc=ins.address;ops=ins.operands
            if ins.mnemonic=='cset' and ins.op_str.endswith(', hs'):
                self.write(ins.reg_name(ops[0].reg),z3.If(z3.UGE(self.cmp_left,self.cmp_right),z3.BitVecVal(1,32),z3.BitVecVal(0,32)))
                self.count+=1
            elif ins.mnemonic=='tst':
                width=self.width(ins.reg_name(ops[0].reg))
                self.equal=(self.operand(ins,ops[0],width)&self.operand(ins,ops[1],width))==0;self.count+=1
            elif ins.mnemonic=='sxtb':
                self.write(ins.reg_name(ops[0].reg),z3.SignExt(24,z3.Extract(7,0,self.read(ins.reg_name(ops[1].reg)))))
                self.count+=1
            elif ins.mnemonic=='cinc':
                assert ins.op_str.endswith(', gt')
                value=self.read(ins.reg_name(ops[1].reg))
                self.write(ins.reg_name(ops[0].reg),value+z3.If(self.cmp_left>self.cmp_right,z3.BitVecVal(1,32),z3.BitVecVal(0,32)))
                self.count+=1
            else:
                self.c={'spans':[{'label':label,'start':hex(ins.address),'bytes_hex':bytes(ins.bytes).hex()}]}
                super().run(label)
        self.c=saved;return self


def prove(capture):
    q={};counts={};controls={}
    r=z3.BitVec('record64',64);key=(r^0x4c2e944469e35e3f)*0x7a59c441
    ks=z3.BitVec('codec_key64',64);lo=resize(ks,32)
    left,right=z3.BitVecs('decoded_left64 decoded_right64',64)
    mode,tail,yes,no=z3.BitVecs('mode32 tail32 selected_yes32 selected_no32',32)
    def run(label,start,end,seeds,cells=()):
        obj=CompareLift(part(capture,label,start,end))
        for reg,val in seeds.items():obj.seed(reg,val)
        for address,width,val in cells:mem(obj,address,width,val)
        obj.run(label);counts[label]=obj.count;return obj
    def bit(predicate):return z3.If(predicate,z3.BitVecVal(1,32),z3.BitVecVal(0,32))

    obj=run('comparator_key',0xfffffe000a52f45c,0xfffffe000a52f498,{'x0':r})
    q['comparator_key']=obj.read('x8')!=key
    obj=run('comparator_operands',0xfffffe000a52f498,0xfffffe000a52f4b0,{'x0':r,'x8':ks},
        [(r,8,left+ks),(r+32,8,right-ks),(r+24,4,mode+lo),(r+28,4,tail)])
    q['comparator_operands']=z3.Or(obj.read('x9')!=left,obj.read('x10')!=right,
        obj.read('w12')!=mode,obj.read('w11')!=tail)
    obj=run('comparator_predicate',0xfffffe000a52f4b0,0xfffffe000a52f4c4,
        {'x9':left,'x10':right,'w12':mode})
    predicate=z3.If((mode&1)!=0,z3.UGE(left,right),left!=right)
    q['comparator_predicate']=obj.read('w9')!=bit(predicate)
    predicate_bit=z3.BitVec('predicate32',32)
    obj=run('comparator_payload_offset',0xfffffe000a52f4c4,0xfffffe000a52f4d4,{'w9':predicate_bit})
    offset=z3.If(predicate_bit!=0,z3.BitVecVal(12,64),z3.BitVecVal(20,64))
    q['comparator_payload_offset']=obj.read('x9')!=offset
    selected=z3.If(predicate_bit!=0,yes,no)
    obj=run('comparator_result',0xfffffe000a52f4d4,0xfffffe000a52f4ec,
        {'x0':r,'x9':offset,'x8':ks,'w11':tail},[(r+offset,4,selected)])
    q['comparator_result']=cell(obj,r+16,4)!=(selected^lo^(tail+lo))
    result_stores=[{'pc':hex(s['pc']),'offset_B':z3.simplify(s['address']-r).as_long(),
        'size_B':s['size_bytes']} for s in obj.stores]
    assert result_stores==[{'pc':'0xfffffe000a52f4e8','offset_B':16,'size_B':4}]

    a,b=z3.BitVecs('biased_left64 biased_right64',64);bias=z3.BitVecVal(0x081864b3,64)
    carry_a=bit(z3.ULT(a,bias));carry_b=bit(z3.ULT(b,bias));cx=carry_a^carry_b
    f=0x51000000
    obj=run('producer_carry_and_record',0xfffffe000a5245b4,0xfffffe000a524654,
        {'x24':a,'x10':b-0xab53c9aef42360b8,'x8':0xab53c9aef42360b8,
         'x13':bias,'w23':0x6e3,'w9':0xf60746de,'x25':r,'x29':r+0xb0})
    actual_key=obj.read('x10');actual_lo=resize(actual_key,32)
    q['producer_carry_handoff']=obj.read('x22')!=resize(cx,64)
    q['producer_record_fields']=z3.Or(cell(obj,r,8)!=actual_key,
        cell(obj,r+8,4)!=0x392d87ef-actual_lo,
        cell(obj,r+12,4)!=(actual_lo^0xf6074dc1),
        cell(obj,r+20,4)!=(actual_lo^0xf6074dd4),
        cell(obj,r+24,4)!=actual_lo,
        cell(obj,r+28,4)!=0xf6074c82-actual_lo,
        cell(obj,r+32,8)!=resize(cx,64)-actual_key)
    q['producer_key']=actual_key!=key
    selected_index=z3.If(cx!=0,lo^0xf6074dc1,lo^0xf6074dd4)^lo^0xf6074c82
    q['record_to_two_indices']=selected_index!=z3.If(cx!=0,z3.BitVecVal(0x143,32),z3.BitVecVal(0x156,32))
    q['record_index_fits_positive_signed32']=z3.Or(selected_index<0,
        z3.And(selected_index!=0x143,selected_index!=0x156))
    seed=z3.BitVec('discarded_seed98_64',64)
    controls['old_seed_handoff_is_false']=seed!=resize(cx,64)

    # Both paths read the declared saved source phase and the same control cell.
    obj=run('different_carries_prefix',0xfffffe000a55ee50,0xfffffe000a55ee78,
        {'sp':f,'w21':carry_b,'w22':cx},[(f+0x1f4,4,0x6e3)])
    q['different_carries_routing']=z3.Or(obj.read('w8')!=0x2eb,obj.read('w9')!=1,obj.read('w10')!=1,
        obj.read('w21')!=carry_b,z3.And(cx!=0,obj.read('x22')!=1))
    obj=run('equal_carries_prefix',0xfffffe000a55b29c,0xfffffe000a55b2b8,
        {'sp':f,'x24':a,'x26':b,'w22':cx},[(f+0x1f4,4,0x6e3)])
    q['equal_carries_routing']=z3.Or(obj.read('w8')!=0x2eb,obj.read('w9')!=1,
        obj.read('w21')!=bit(z3.ULT(a,b)),z3.And(cx==0,obj.read('w10')!=1))
    control=z3.BitVec('saved_control64',64)
    obj=run('equal_carries_reload',0xfffffe000a55b2bc,0xfffffe000a55b2c4,
        {'sp':f,'x9':1},[(f+0x1e8,8,control)])
    q['equal_carries_common_state']=z3.Or(obj.read('x22')!=1,obj.read('x14')!=control)
    obj=run('different_carries_reload',0xfffffe000a55ee7c,0xfffffe000a55ee80,
        {'sp':f},[(f+0x1e8,8,control)])
    q['different_carries_control_reload']=obj.read('x14')!=control
    decoded_a,decoded_b=z3.BitVecs('current_decoded_accumulator64 context_decoded64',64)
    raw_context=z3.BitVec('raw_context_word178_64',64)
    q['context_operand_normalization']=(raw_context+0xab53c9aef42360b8)!=(raw_context+0xab53c9aeec0afc05+bias)
    aa,bb=decoded_a+bias,decoded_b+bias
    ca,cb=z3.ULT(aa,bias),z3.ULT(bb,bias)
    joined=z3.If(ca!=cb,cb,z3.ULT(aa,bb))
    q['complete_unsigned_context_comparison']=joined!=z3.ULT(decoded_a,decoded_b)
    controls['wrapped_operands_alone_are_insufficient']=z3.ULT(aa,bb)!=z3.ULT(decoded_a,decoded_b)

    selected_bit=z3.BitVec('comparison_bit32',32)
    obj=run('comparison_join_route',0xfffffe000a528954,0xfffffe000a528984,
        {'w9':1,'w21':selected_bit})
    q['comparison_join_route']=z3.And(z3.ULE(selected_bit,1),z3.Or(obj.read('w8')!=0x6e3,
        obj.read('w11')!=z3.If(selected_bit==1,z3.BitVecVal(0x940,32),z3.BitVecVal(0x155,32))))
    restored=z3.BitVec('restored_view64',64)
    obj=run('comparison_join_state',0xfffffe000a528988,0xfffffe000a52899c,
        {'sp':f},[(f+0x1b0,8,restored)])
    q['comparison_join_state']=z3.Or(obj.read('w21')!=0x0636782c,obj.read('x24')!=restored)
    obj=run('control_byte_gate',0xfffffe000a522b04,0xfffffe000a522b58,
        {'w9':1,'w10':1,'w22':1,'x14':control})
    raw=0x06371ecb+bit(z3.Extract(7,0,control)==1)
    q['control_byte_gate']=z3.Or(obj.read('w8')!=0x6e3,obj.read('w11')!=0x155,obj.read('w21')!=raw)
    status=z3.BitVec('private_status32',32)
    obj=run('status_dispatch',0xfffffe000a5237ac,0xfffffe000a5237cc,{'w8':0x6e3,'w21':status})
    q['status_dispatch']=obj.read('w9')!=z3.If(status==0x06371ecc,z3.BitVecVal(0x418,32),z3.BitVecVal(0x17,32))
    comparison=z3.ULT(decoded_a,decoded_b)
    final_status=z3.If(comparison,raw,z3.BitVecVal(0x0636782c,32))
    final_index=z3.If(final_status==0x06371ecc,z3.BitVecVal(0x418,32),z3.BitVecVal(0x17,32))
    q['composed_context_and_control_gate']=final_index!=z3.If(z3.And(comparison,z3.Extract(7,0,control)==1),
        z3.BitVecVal(0x418,32),z3.BitVecVal(0x17,32))
    obj=run('alternate_hop',0xfffffe000a52253c,0xfffffe000a522540,{'w8':0x6e3})
    q['alternate_hop']=obj.read('w9')!=0x498

    results={}
    for name,query in q.items():
        solver=z3.Solver();solver.set(timeout=10000);solver.add(query);result=solver.check()
        print(name,result,flush=True)
        assert result==z3.unsat,(name,str(result),solver.model() if result==z3.sat else solver.reason_unknown())
        results[name]={'result':str(result),'query':solver.sexpr()}
    negatives={}
    for name,query in controls.items():
        solver=z3.Solver();solver.set(timeout=10000);solver.add(query);assert solver.check()==z3.sat
        model=solver.model();negatives[name]={'result':'sat','query':solver.sexpr(),
            'model':{str(v):hex(model[v].as_long()) for v in sorted(model,key=str)}}
    return results,counts,negatives,result_stores


def build():
    k=Kernel();spans=[]
    for label,bounds in SPANS.items():
        row=span(k,*bounds);row['bytes_hex']=row.pop('bytes');row['label']=label;spans.append(row)
    proofs,counts,controls,stores=prove({'spans':spans})
    window=[];candidates=[]
    for ix in range(0x9fe,0xafe):
        a=TABLE+8*ix;word=struct.unpack('<Q',k.read(a,8))[0]
        row={'index':hex(ix),'slot':hex(a),'original_word':hex(word),
            'normalized_target':hex(struct.unpack('<Q',IMAGE.read(a,8))[0]),
            'matches_auth_flag_and_diversity':bool(word>>63 and (word>>32)&0xffff==0x2971)}
        if row['matches_auth_flag_and_diversity']:
            meta=pointer(k,a);assert meta['target']==row['normalized_target'];row['original_fixup']=meta;candidates.append(ix)
        window.append(row)
    assert candidates==[0xa0c,0xa20,0xa35]
    slots={hex(ix):pointer(k,TABLE+8*ix) for ix in INDICES}
    assert slots['0xa35']['target']=='0xfffffe000a52f458'
    assert slots['0xa20']['target']=='0xfffffe000a52fd10'
    assert slots['0xa0c']['target']=='0xfffffe000c4ba95c'
    symbols=k.symbols([0xfffffe000c4ba95c]);assert symbols['0xfffffe000c4ba95c'][0]['name']=='_IOMallocTypeVarImpl'
    reference=ROOT.parent/'com.apple.driver.FairPlayIOKit.c';lines=read(reference).splitlines(keepends=True)
    excerpts=[{'first_line':a,'last_line':z,'text':''.join(lines[a-1:z])} for a,z in [(37158,37193),(47428,47489)]]
    preceding=json.loads(read(ROOT/'lskd_clock_accumulator_checks.json'))
    return {'scope':__doc__,'generator_sha256':sha(__file__),'kernel_collection_sha256':k.sha256,
        'normalized_image_sha256':sha(SOURCE),'spans':spans,'proofs':proofs,'source_lift_counts':counts,
        'negative_controls':controls,'result_stores':stores,'helper_window':window,'slots':slots,
        'candidate_exact_symbols':symbols,'supplied_reference':{'path':reference.name,'sha256':sha(reference),'excerpts':excerpts},
        'corrected_predecessor':{'path':'lskd_clock_accumulator_checks.json','sha256':sha(ROOT/'lskd_clock_accumulator_checks.json'),
            'handoff_query':'context_compare_operands','wrong_prior_attribution':'R+20 contained seed98-key',
            'corrected_attribution':'R+20 contains zero_extend64(W11 XOR W21)-key; X22 overwritten at a5245c8',
            'predecessor_counts':preceding['verified_counts']},
        'selected_contract':{'conditional_phase32':'0x6e3','conditional_saved_phase32':'0x6e3',
            'conditional_helper_bank_constant8':'0x37','conditional_helper_target':'0xfffffe000a52f458',
            'context_decoding_additive64':'0xab53c9aeec0afc05',
            'actual_helper_bank_roots_proven':False,'actual_saved_phase_proven':False,
            'context_root_producer_proven':False,'control_word_producer_proven':False,
            'upstream_request_recovered':False,'native_epoch_matched':False},
        'verified_counts':{'spans':len(spans),'instructions':sum(len(s['instructions']) for s in spans),
            'code_B':sum(len(bytes.fromhex(s['bytes_hex'])) for s in spans),
            'source_lifted_instances':sum(counts.values()),'queries_unsat':len(proofs),'negative_controls_sat':len(controls),
            'helper_window_slots':len(window),'matching_diversity_candidates':len(candidates),
            'original_slots':len(slots),'helper_result_written_B':4},
        'solver_version':z3.get_version_string(),'dependencies':{n:sha(ROOT/n) for n in [
            'kernel_native_reader.py','kext_port_tools.py','lskd_values_symbolic.py','recover_aes_cleanup_epoch.py',
            'recover_kext_cold_init.py','recover_lskd_clock_reader.py','recover_lskd_clock_accumulator.py',
            'lskd_clock_accumulator_checks.json','verify_daemon_reader_record_payloads_publication.py']},
        'new_IDA_access':False,'new_native_execution':False,'new_IDB_mutations':False,'full_goal_complete':False}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--verify',action='store_true');args=p.parse_args()
    output=build();path=ROOT/'lskd_context_compare_checks.json'
    if args.verify:assert json.loads(read(path))==output
    else:path.write_text(json.dumps(output,indent=2)+'\n')
    print(json.dumps(output['verified_counts']))
