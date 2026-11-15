#!/usr/bin/env python3
"""Independent count contracts, writeback replay and saved-byte epoch audit.
O(P+C*E+Q*log(E+Q)+32V+proof DAG) time, O(parent receipts+largest
interval+selected frames+proof DAG) space; solver search 30 s/query.
No native API/IPC, hardware PAC, new target execution or IDB operation.
"""
import gc
import json
from bisect import bisect_left
from collections import Counter
import z3
from capstone.arm64 import ARM64_OP_IMM
from daemon_receive_tools import ROOT, SOURCE, IMAGE, FIXUPS, TABLE
from verify_daemon_reader_record_payloads_publication import read, sha
from recover_daemon_record_extension import unpack
from recover_daemon_record_banks import instruction
from audit_daemon_record_input_origin import check_frame, independent_origins
from audit_daemon_append_fields import Lift, Trace, number
from audit_daemon_alternative_fill import Source
from lskd_values_symbolic import mem, resize
import recover_daemon_payload_count_flow as R

DEPS=['audit_daemon_record_input_origin.py','audit_daemon_append_fields.py','audit_daemon_alternative_fill.py',
      'audit_daemon_state_table_mixing.py','lskd_values_symbolic.py','daemon_receive_fixups.txt']


class Writeback:
    def one(self,i):
        if not i.writeback:return super().one(i)
        self.pc=i.address;o=i.operands;m=i.mnemonic
        if m=='ldr':
            assert i.address==0x10083e784 and len(o)==3 and o[2].type==ARM64_OP_IMM and o[2].imm==4
            assert o[1].mem.disp==0 and i.reg_name(o[0].reg)=='w13' and i.reg_name(o[1].mem.base)=='x12'
            a=self.address(i,o[1]);v=self.load(a,4);self.write('w13',v);self.write('x12',a+4);return
        assert m in ['ldp','stp']
        pair=[i.reg_name(o[j].reg) for j in range(2)];n=self.width(pair[0])//8
        base=i.reg_name(o[2].mem.base);assert base=='sp' and n==8 and not o[2].mem.index
        a=self.address(i,o[2])
        if len(o)==4:
            assert o[3].type==ARM64_OP_IMM and o[2].mem.disp==0
            after=self.read(base)+o[3].imm
        else:
            assert len(o)==3 and o[2].mem.disp<0;after=a
        for j,name in enumerate(pair):
            if m=='ldp':self.write(name,self.load(z3.simplify(a+8*j),8))
            else:self.store(z3.simplify(a+8*j),8,self.read(name),i.address)
        self.write(base,after)


class PostSource(Writeback,Source):pass
class PostLift(Writeback,Lift):pass
class PostTrace(Writeback,Trace):pass


def replay(chunk):
    v=PostTrace(chunk['reads'],chunk['writes']);f=chunk['frames'][0]
    for j,x in enumerate(f['registers31']):v.seed('x'+str(j),int(x,16))
    v.seed('sp',int(f['SP'],16));flags=int(f['NZCV'],16)
    v.n,v.z,v.carry,v.overflow=[z3.BoolVal(bool(flags&(1<<k))) for k in [31,30,29,28]]
    edges={e['source_visit_index']:e for e in chunk['edges']};counts=Counter()
    for j,visit in enumerate(chunk['visits']):
        f,nextframe=chunk['frames'][j:j+2];check_frame(v,f)
        pc=int(visit['pc'],16);assert f['pc']==visit['pc'] and visit['bytes_hex']==IMAGE.read(pc,4).hex()
        i=instruction(pc);nxt=pc+4
        assert not any(i.reg_name(r).startswith(('v','q','d','s')) and i.reg_name(r)!='sp' for r in sum(i.regs_access(),[]))
        if i.mnemonic in ['braa','blraa','retab']:
            target=number(v.read('x30' if i.mnemonic=='retab' else i.reg_name(i.operands[0].reg)))
            edge=edges[chunk['start_visit']+j]
            assert edge['pc']==hex(pc) and edge['target']==hex(target) and edge['kind']==i.mnemonic
            if i.mnemonic!='retab':assert edge['modifier']==hex(number(v.read(i.reg_name(i.operands[1].reg))))
            if i.mnemonic=='blraa':v.write('x30',z3.BitVecVal(pc+4,64))
            nxt=target;counts['logical_edges']+=1
        else:
            v.one(i)
            if i.writeback:counts['writeback_instructions_checked']+=1
        assert nextframe['pc']==hex(nxt);counts['source_visits']+=1
    check_frame(v,chunk['frames'][-1]);assert v.ri==len(chunk['reads']) and v.wi==len(chunk['writes'])
    counts.update(GP_SP_values=32*(len(chunk['visits'])+1),NZCV_frames=len(chunk['visits'])+1,
                  reads=v.ri,writes=v.wi,chunks=1)
    return dict(counts)


def obligations():
    out=[]
    def prove(label,bad):
        s=z3.Solver();s.set(timeout=30000);assert s.check()==z3.sat
        s.add(z3.simplify(bad));result=s.check();assert result==z3.unsat,(label,str(result),s.reason_unknown())
        out.append({'label':label,'premises_nonvacuous':True,'result':'unsat','query':s.to_smt2()})
        print(json.dumps({'source_proof':label,'result':'unsat'}),flush=True)
    n,q,i=z3.BitVecs('pcf_count32 pcf_q32 pcf_index32',32)
    pointer,state,sp,biased,other,q64=z3.BitVecs('pcf_pointer64 pcf_state64 pcf_sp64 pcf_biased64 pcf_other64 pcf_q64',64)
    v=PostSource({0x10083e784:(4,n)});v.seed('x12',pointer);v.run_block(0x10083e784,0x10083e788)
    prove('original_context_u32_read_and_data_pointer_advance',z3.Or(v.read('w13')!=n,v.read('x12')!=pointer+4,v.loads[0][1]!=pointer))
    v=Lift();v.seed('w13',n);v.run_block(0x10083e788,0x10083e7a0)
    v.seed('w16',q);v.seed('x26',state);v.run_block(0x10083e834,0x10083e84c);w,=v.stores
    prove('composed_original_encoded_count_state_field',z3.Or(w['address']!=state+0xce4,w['value']!=n+0x0d38177c-q))
    lowq=z3.Extract(31,0,q64)
    v=Source({0x100bab354:(4,n+0x0d38177c-lowq),0x100bab35c:(4,z3.Extract(31,0,other))})
    for reg,x in {'x16':state,'x13':q64,'w8':0x250}.items():v.seed(reg,x)
    v.run_block(0x100bab334,0x100bab384)
    prove('original_unsigned_carry_reconstructs_all_u32_counts',z3.Or(v.read('x10')!=z3.ZeroExt(32,n)+0x0d38177c,
        v.read('x12')!=0x4a2cb691b94eaf9a,*[a!=state+off for (pc,a,size),off in zip(v.loads,[0x2c,0x1c])]))
    v=Lift();v.seed('x10',z3.ZeroExt(32,n)+0x0d38177c);v.seed('x12',0x4a2cb691b94eaf9a)
    v.run_block(0x100bab4d0,0x100bab4d4)
    prove('composed_source_count_bias',v.read('x1')!=z3.ZeroExt(32,n)+0x4a2cb691c686c716)
    v=Source({0x100c1db44:(4,5),0x100c1db50:(4,i+0x4a384b6e),0x100c1db60:(8,biased)})
    v.seed('sp',sp);v.seed('x29',state);v.run_block(0x100c1db44,0x100c1db64)
    prove('original_word_cursor_advances_four_and_reloads_count',z3.Or(v.read('w22')!=i+0x4a384b72,
          v.read('x23')!=biased,*[a!=want for (pc,a,size),want in zip(v.loads,[sp+0x58,state-0xd4,sp+0x2d0])]))
    v=Lift();v.seed('x23',z3.ZeroExt(32,n)+0x4a2cb691c686c716);v.seed('w22',i+0x4a384b6e)
    v.run_block(0x100bdafc4,0x100bdaffc)
    prove('original_word_gate_modular_u64_comparison',z3.Or(v.read('w24')!=i,v.read('x8')!=z3.If(
        z3.ULT(z3.ZeroExt(32,i),z3.ZeroExt(32,n)-4),z3.BitVecVal(1,64),z3.BitVecVal(0,64))))
    v=Lift();v.seed('x23',z3.ZeroExt(32,n)+0x4a2cb691c686c716);v.seed('x24',z3.ZeroExt(32,i))
    v.run_block(0x100a8c730,0x100a8c758)
    prove('original_tail_entry_count_exceeds_cursor',v.read('w9')!=z3.If(z3.UGT(n,i),z3.BitVecVal(1,32),z3.BitVecVal(0,32)))
    v=Lift()
    for reg,x in {'x8':z3.ZeroExt(32,n)+0x61fec49d,'x13':0x61fec49d,'w9':i+0x4a384b6e,
                  'w16':0xb5c7b493,'w0':0xf4,'w21':0x6659}.items():v.seed(reg,x)
    v.run_block(0x100a396b0,0x100a396cc)
    prove('original_tail_step_and_next_selector',z3.Or(v.read('w10')!=i+0x4a384b6f,v.read('w9')!=z3.If(
        z3.UGT(n,i+1),z3.BitVecVal(0x66ad,32),z3.BitVecVal(0x6659,32))))
    for selector,target in [(0x66ad,0x100a39694),(0x6659,0x100bd8394)]:
        slot=TABLE+8*selector;assert FIXUPS[slot]['target']==target
        v=Source({0x100a396cc:(8,target)})
        for reg,x in {'x20':TABLE,'w9':selector,'w10':i}.items():v.seed(reg,x)
        v.run_block(0x100a396cc,0x100a396d8)
        prove('original_tail_dispatch_'+hex(selector),z3.Or(v.loads[0][1]!=slot,v.read('x11')!=target,
              v.read('x9')!=z3.ZeroExt(32,i),v.read('x17')!=0xa96e))
    v=Source({0x100c3ca28:(8,pointer)});v.seed('x16',state);v.seed('sp',sp)
    v.run_block(0x100c3ca28,0x100c3ca30);w,=v.stores
    prove('original_advanced_data_pointer_publication',z3.Or(v.loads[0][1]!=state+0x20,w['address']!=sp+0x1e0,w['value']!=pointer))
    for pc,delta,pair in [(0x100acd9c8,-0x60,['x28','x27']),(0x100add598,-0x30,['x22','x21'])]:
        v=PostLift();v.seed('sp',sp);v.seed(pair[0],pointer);v.seed(pair[1],biased);v.run_block(pc,pc+4)
        prove('original_preindexed_pair_save_'+hex(pc),z3.Or(v.read('sp')!=sp+delta,
            *[z3.Or(w['address']!=sp+delta+8*j,w['value']!=value) for j,(w,value) in enumerate(zip(v.stores,[pointer,biased]))]))
    for pc,delta,pair in [(0x100a6d3c4,0x60,['x28','x27']),(0x100add7f4,0x30,['x22','x21'])]:
        v=PostLift();v.seed('sp',sp);mem(v,sp,8,pointer);mem(v,sp+8,8,biased);v.run_block(pc,pc+4)
        prove('original_postindexed_pair_restore_'+hex(pc),z3.Or(v.read('sp')!=sp+delta,v.read(pair[0])!=pointer,v.read(pair[1])!=biased))
    # The comparison is exact modulo u64 even when n<4. Restrict the ordinary
    # index interpretation to n>=4 so n-4 has its mathematical value.
    s=z3.Solver();s.set(timeout=30000);s.add(z3.UGE(n,4));assert s.check()==z3.sat
    s.add(z3.ULT(z3.ZeroExt(32,i),z3.ZeroExt(32,n)-4)!=z3.ULT(z3.ZeroExt(32,i)+4,z3.ZeroExt(32,n)))
    assert s.check()==z3.unsat
    out.append({'label':'word_gate_integer_interpretation_requires_count_at_least_four','premises_nonvacuous':True,
                'result':'unsat','query':s.to_smt2()})
    assert len(out)==16
    return out


def audit():
    e=json.loads(read(ROOT/(R.P+'_checks.json')))
    for p,h in R.PINS.items():assert sha(ROOT/p)==h
    parent=json.loads(read(ROOT/'daemon_record_extension_checks.json'));totals=Counter();cases=[]
    for c in e['cases']:
        ci=c['class_index'];f=c['context_fields'];n=f['count_input32'];assert n==6
        assert f['count_read']['address']==hex(R.C+28) and f['count_read']['bytes_hex']=='06000000'
        assert f['advanced_pointer']==hex(R.C+32)
        assert int(f['prepared_q32'],16)==int(f['extension_q64'],16)&0xffffffff
        assert int(f['extended_count_X10'],16)==n+0x0d38177c and int(f['biased_count_X1'],16)==n+0x4a2cb691c686c716
        for ir in c['intervals']:
            ii=ir['interval_index'];item=parent['classes'][ci]['intervals'][ii]
            assert ir['parent_interval_sha256']==item['interval_packed']['decoded_sha256'] and ir['API_return_premise']==item['API_return_premise']
            row=unpack(item['interval_packed'])
            for p in ir['chunks']:
                lo,hi=p['start_visit'],p['end_visit_exclusive'];assert p['visits']==row['source_visits'][lo:hi]
                assert p['frames']==[{k:v for k,v in x.items() if k!='Q_registers32'} for x in row['source_frames'][lo:hi+1]]
                assert all(x['Q_registers32']==p['Q_registers32_preserved'] for x in row['source_frames'][lo:hi+1])
                for a,b in [('reads','source_reads'),('writes','source_writes'),('edges','logical_edges')]:
                    assert p[a]==[x for x in row[b] if lo<=x['source_visit_index']<hi]
                totals.update(replay(p))
            totals.update({'selected_read_'+k:v for k,v in independent_origins(row,ir).items()})
            for name,(address,expected) in R.CELLS.items():
                # Independent forward fold includes every write, not only the
                # source events selected into replay chunks.
                values={}
                for kind in ['initial_private_fixtures','initial_image_fixtures']:
                    for fixture in row[kind]:
                        a=int(fixture['address'],16);raw=bytes.fromhex(fixture['bytes_hex'])
                        for k in range(max(address,a),min(address+8,a+len(raw))):
                            value=raw[k-a];assert k not in values or values[k]==value;values[k]=value
                if ii>1:
                    assert bytes(values[address+k] for k in range(8)).hex()==expected
                    assert ir['saved_cell_epochs'][name]['incoming_bytes_hex']==expected
                    spans=list(item['API_return_premise']['invalidated_spans'])
                    for key in ['allocated_owner_premise','retired_owner_premise']:
                        if item['API_return_premise'].get(key):spans.append(item['API_return_premise'][key])
                    assert all(not(int(s['address'],16)<address+8 and address<int(s['address'],16)+s['size_bytes']) for s in spans)
                    totals['saved_boundary_bytes_checked']+=8
                cut=None if ii<3 else (85736 if name=='count' else 100249);overlaps=[]
                for w in row['source_writes']:
                    if cut is not None and w['source_visit_index']>=cut:continue
                    a=int(w['address'],16);raw=bytes.fromhex(w['after_hex'])
                    if a<address+8 and address<a+len(raw):
                        overlaps.append(w)
                        for k in range(max(address,a),min(address+8,a+len(raw))):values[k]=raw[k-a]
                assert bytes(values[address+k] for k in range(8)).hex()==expected
                if ii>1:assert not overlaps and ir['saved_cell_epochs'][name]['overlapping_writes_before_cut']==[]
            if ii==1:
                for reg,lo,hi,value in [('x10',87611,87694,n+0x0d38177c),('x12',87611,87694,0x4a2cb691b94eaf9a),
                                      ('x1',87695,87829,n+0x4a2cb691c686c716)]:
                    assert all(int(x['registers31'][int(reg[1:])],16)==value for x in row['source_frames'][lo:hi+1])
                    for v in row['source_visits'][lo:hi]:
                        ins=instruction(int(v['pc'],16));assert not any(ins.reg_name(r) in [reg,'w'+reg[1:]] for r in ins.regs_access()[1])
                    totals['preserved_register_frame_checks']+=hi-lo+1
            if ii==3:
                for g in c['loop_inputs']['word_gates']:
                    j=g['start_visit'];regs=[int(x,16) for x in row['source_frames'][j]['registers31']]
                    assert regs[23]==n+0x4a2cb691c686c716 and (regs[22]-0x4a384b6e)&0xffffffff==g['logical_index']
                    totals['word_gates_checked']+=1
                for t in c['loop_inputs']['tail_iterations']:
                    j=t['start_visit'];index=t['logical_index'];r,w=t['read'],t['write']
                    assert index in [4,5] and int(r['address'],16)==R.C+32+index
                    assert int(w['address'],16)==0x680005fe23+index-4 and r['bytes_hex']==w['after_hex']=='00'
                    assert r in row['source_reads'] and w in row['source_writes'] and t['edge'] in row['logical_edges']
                    assert t['edge']['target']==('0x100a39694' if index==4 else '0x100bd8394')
                    totals['tail_iterations_checked']+=1
            print(json.dumps({'audit_class':ci,'interval':ii,'visits':totals['source_visits']}),flush=True)
            del row;gc.collect()
        totals['count_data_pairs_checked']+=1
        cases.append({'class_index':ci,'count32':6,'data_pointer':hex(R.C+32),'word_indices':[0,4],
                      'tail_copy_indices':[4,5],'encoded_count64':hex(n+0x4a2cb691c686c716)})
    proofs=obligations();totals['new_source_queries_unsat']=len(proofs)
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
            'parent_pins':R.PINS,'dependencies':{p:sha(ROOT/p) for p in DEPS},'cases':cases,'independent_totals':dict(totals),
            'source_proofs':proofs,'retained_count_data_flow_established':True,'native_constructor_epoch_join_established':False,
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'full_goal_complete':False}


if __name__=='__main__':
    x=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(x,indent=2)+'\n');print(json.dumps(x['independent_totals']),flush=True)
