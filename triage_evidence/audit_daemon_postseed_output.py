#!/usr/bin/env python3
"""Independent source replay and post-seed cleanup/twist/output contracts.

O(receipts+visits*(register state+byte effects)+N+query DAG) time;
O(receipt collection+largest interval+N) space, N=624;30 s/query.
Snapshot continuation is conditional; no native API/IPC/PAC/ownership runs.
"""
import json,struct
from collections import Counter
from hashlib import sha256
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,TABLE,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_daemon_readiness_arena import Lift
from audit_daemon_network_record import state_bytes,fixture_bytes,join
from recover_daemon_return_bank_origins import Algebra
from lskd_values_symbolic import mem,cell
import recover_daemon_postseed_output as R

MASK=(1<<32)-1
def u32(x):return x&MASK
def word(s,a,n=4):return int.from_bytes(bytes(s[a+j] for j in range(n)),'little')
def raw(s,a,n):return bytes(s[a+j] for j in range(n))
def joined(before,after,effects=()):
    join(before,after,effects);assert before['boundary']['Q_registers32']==after['entry_Q_registers32']
    assert before['boundary']['pc']==after['entry_PC'] and before['foreign_owners']==after['foreign_owners']
def selected(row,pc,kind='source_reads'):
    return [x for x in row[kind] if x['pc']==hex(pc)]
def at(row,pc):
    return [f for f in row['source_frames'] if f['pc']==hex(pc)]
def reg(f,n):return int(f['registers31'][n],16)

def comparison(row):
    assert len(row['source_calls'])==1;call=row['source_calls'][0]
    assert (call['pc'],call['target'])==('0x100a3c13c','0x100427514');a=int(call['arguments8'][0],16)
    s=fixture_bytes(row,'private')|fixture_bytes(row,'image')
    for w in row['source_writes']:
        if w['source_visit_index']<call['source_visit_index']:s.update({int(w['address'],16)+j:b for j,b in enumerate(bytes.fromhex(w['after_hex']))})
    key=((((0x5a2dd95b7f1fcb68|((a<<1)&((1<<64)-1)))-a+0xd2e9135240701a4c)&((1<<64)-1))^0x2c6f16a258bd37d6)*0xba209ef7&((1<<64)-1);k=key&MASK
    left=(word(s,a,8)+key)&((1<<64)-1);right=word(s,a+24,8)^key;mode=word(s,a+8)^k
    yes,no,mask=word(s,a+16)^k,u32(word(s,a+20)+k),word(s,a+32)^k
    assert (left,right,mode)==(5119,0,0);index=mask^(yes if left<right else no);assert index==0x16a1
    result=selected(row,0x1004275ac,'source_writes');assert len(result)==1 and result[0]['address']==hex(a+12) and int.from_bytes(bytes.fromhex(result[0]['after_hex']),'little')==index
    return {'record_address':hex(a),'A64':left,'B64':right,'mode32':mode,'predicate':left<right,'index':hex(index),'target':hex(FIXUPS[TABLE+8*index]['target'])}

def codec(row):
    s=fixture_bytes(row,'private')|fixture_bytes(row,'image');f=row['source_frames'][0]
    output=reg(f,4);remaining=reg(f,2);shift=reg(f,8);tempered=reg(f,9);phase=reg(f,10)
    assert (remaining,shift,phase)==(32,0,0xbc66)
    a=output+remaining-1;cache=word(s,word(s,int(row['caller_SP'],16)+0x168,8),8)
    cacheindex=word(s,word(s,int(row['caller_SP'],16)+0x160,8));ca=cache+(cacheindex&0x0ba3ccc8)
    cached=word(s,ca);r=u32(cached+(a&MASK));mask=word(s,0x1010c6800,8)^0xa7a730ec
    text=word(s,0x1010ca2a8,8)^0x12af5504870a589f
    prekey=(u32(phase+0xe3064333)&0x1cf9b3ff)^0x0ba37f51
    aa=text+(u32(r+prekey)&mask);ba=text+(u32(r+0x0ba3ccca)&mask)
    ta,tb=IMAGE.read(aa,1)[0],IMAGE.read(ba,1)[0]
    candidate=((tempered>>(shift&31))^u32(31*(a&MASK))^ta^tb)&255
    stored=candidate^0xd7
    assert (cacheindex,cache,cached,mask,aa,ba,ta,tb)==(255,0x6500115d6c,0xa0018891,0xfff0c01200007fff,0x100823b60,0x100823b62,6,0xb8)
    for pc,address,value,n in [(0x100a0c9d8,ca,cached,4),(0x100a0ca30,aa,ta,1),(0x100a0ca54,ba,tb,1)]:
        rr=selected(row,pc);assert len(rr)==1 and rr[0]['address']==hex(address) and int.from_bytes(bytes.fromhex(rr[0]['bytes_hex']),'little')==value and rr[0]['size_bytes']==n
    assert row['source_writes']==[{'pc':'0x100a0ca74','source_visit_index':59,'address':hex(a),'size_bytes':1,'after_hex':bytes([stored]).hex()}]
    assert all(output+j not in s for j in range(32));final=state_bytes(row)
    assert [output+j for j in range(32) if output+j in final]==[a]
    b=row['boundary'];assert int(b['registers31'][2],16)==remaining-int(stored!=0) and int(b['registers31'][8],16)==8
    return {'tempered_u32':hex(tempered),'output_base':hex(output),'address':hex(a),'cached_word_address':hex(ca),'cached_word32':hex(cached),
            'address_low32':hex(a&MASK),'r32':hex(r),'prekey32':hex(prekey),'mask64':hex(mask),'text_base':hex(text),
            'text_addresses':[hex(aa),hex(ba)],'text_bytes_hex':bytes([ta,tb]).hex(),'candidate8':hex(candidate),'stored8_hex':bytes([stored]).hex(),
            'remaining_before':remaining,'remaining_after':remaining-int(stored!=0),'defined_output_bytes':1,'unknown_output_bytes':31}

def audit_case(c,parent):
    before=R.Parent.Parent.unpack(parent['exit_intervals_packed'][-1]);initial=state_bytes(before);sp=int(before['boundary']['SP'],16)
    mt=list(struct.unpack('<624I',raw(initial,R.G,2496)));payload=raw(initial,R.PAYLOAD,64);counts=Counter();model=Counter();lifts=[];rows=[]
    assert raw(initial,R.G,2496).hex()==c['entry_state2496_hex'] and payload.hex()==c['entry_payload64_hex']
    assert len(c['intervals'])==13
    for j,packed in enumerate(c['intervals']):
        row=R.Parent.Parent.unpack(packed['packed']);effects=[c['snapshot_neighbor_effect']] if j==4 else []
        if j==4:
            a=int(effects[0]['address'],16);assert all(a+k not in state_bytes(before) for k in range(8))
        joined(before,row,effects);result=Lift(row).run();assert result['all_checks_pass'];lifts.append(result);counts.update(result['verified_counts']);rows.append(row)
        state=state_bytes(row)
        if j<6:assert raw(state,R.G,2496)==struct.pack('<624I',*mt);model['unchanged_cleanup_state_words_checked']+=624
        if j in [6,7,8]:
            indices=range(227) if j==6 else range(227,623) if j==7 else range(623,624)
            pc=0x100a5e93c if j==6 else 0x100b312a4 if j==7 else 0x100a2f634
            ww=selected(row,pc,'source_writes');assert len(ww)==len(indices)
            for i,w in zip(indices,ww):
                nxt=mt[(i+1)%624];y=(mt[i]&0x80000000)|(nxt&0x7fffffff)
                mt[i]=u32(mt[(i+397)%624]^(y>>1)^(0x9908b0df if nxt&1 else 0))
                assert w['address']==hex(R.G+4*i) and w['size_bytes']==4 and w['after_hex']==struct.pack('<I',mt[i]).hex()
                model['twist_word_updates_checked']+=1;model['odd_table_choices' if nxt&1 else 'even_table_choices']+=1
            assert raw(state,R.G,2496)==struct.pack('<624I',*mt);model['complete_twist_boundary_words_checked']+=624
        before=row
    assert [len(r['source_visits']) for r in rows]==[46,14,24,1048,1820,27,4540,7933,30,7,96,56,71]
    strict=rows[3];control=R.Parent.Parent.unpack(c['missing_neighbor_control_packed']);joined(strict,control)
    missing=Lift(control).run();counts.update(missing['verified_counts']);assert missing['all_checks_pass'] and not control['source_visits']
    assert control['boundary']['kind']=='before_undefined_foreign_owner_read' and control['boundary']['detail']=={'address':hex(R.Arena.MARKER+8),'size_bytes':8}
    for k in [0,1,2]:assert not rows[k]['source_writes']
    route=rows[0];assert selected(route,0x100a38830)[0]['bytes_hex']=='01' and selected(route,0x100a388a4)[0]['address']=='0x1010b6cb8' and selected(route,0x100a388a4)[0]['bytes_hex']=='01000000'
    ww=selected(strict,0x1009f2984,'source_writes');assert len(ww)==54
    for i,w in enumerate(ww):
        f=strict['source_frames'][w['source_visit_index']];a=R.PAYLOAD+63-i
        # These are store-entry operands; independently replayed source computes them.
        assert w['address']==hex(a) and w['after_hex']==bytes([reg(f,13)&255]).hex()
    end=state_bytes(strict);assert raw(end,R.PAYLOAD,10)==payload[:10]
    ledger=0x1010b5f18;assert word(end,ledger,8)==(word(initial,ledger,8)-88)&((1<<64)-1)
    assert word(end,R.Arena.H+8,8)==word(initial,R.Arena.H+8,8)+88==R.Arena.M+86620
    tail=rows[4];ww=selected(tail,0x100b7c0d0,'source_writes');assert len(ww)==86
    for i,w in enumerate(ww):assert w['address']==hex(R.Arena.H+0x179-i) and w['size_bytes']==1
    assert word(state_bytes(tail),R.Arena.MARKER,8)==R.Arena.M+86620
    assert selected(tail,0x100c0cec8,'source_writes')[0]['address']==hex(R.Arena.MARKER)
    gate=R.Parent.GATE_WORD;assert word(initial,gate)==0xa94ef
    assert word(state_bytes(rows[4]),gate)==0xa94ef and word(state_bytes(rows[5]),gate)==0x5d96
    assert selected(rows[5],0x100bde608,'source_writes')[0]['after_hex']=='965d0000'
    table=int(rows[6]['entry_registers31'][1],16);assert raw(fixture_bytes(rows[6],'private'),table,8)==struct.pack('<2I',0,0x9908b0df)
    assert word(state_bytes(rows[8]),sp+0x1ec)==624 and word(state_bytes(rows[9]),sp+0x1ec)==0
    compare=comparison(rows[10]);selectedraw=int(rows[10]['boundary']['registers31'][19],16);assert selectedraw==mt[0]
    s=state_bytes(rows[10]);assert word(s,sp+0x1ec)==word(s,0x1010c67dc)==1
    temp=mt[0]^(mt[0]>>11);temp=u32(temp^((temp<<7)&0x9d2c5680));temp=u32(temp^((temp<<15)&0xefc60000));temp^=temp>>18
    assert int(rows[11]['boundary']['registers31'][9],16)==temp and word(state_bytes(rows[11]),0x1010c8258)==1
    encoded=codec(rows[12]);assert encoded['tempered_u32']==hex(temp) and encoded['stored8_hex']==c['output_first_byte_hex']
    final=state_bytes(rows[-1]);assert raw(final,R.G,2496).hex()==c['final_state2496_hex'] and raw(final,R.PAYLOAD,64).hex()==c['final_payload64_hex']
    assert c['final_boundary']==rows[-1]['boundary'] and c['final_NZCV']==rows[-1]['boundary_NZCV']
    model.update(payload_overwrite_bytes_checked=54,arena_head_overwrite_bytes_checked=86,snapshot_added_bytes_checked=8,strict_missing_field_controls_checked=1,
                 gate_releases_checked=1,index_resets_checked=1,selected_words_checked=1,tempered_words_checked=1,encoded_output_bytes_checked=1)
    print(json.dumps({'independently_checked_case':c['parent_case_index'],'source_visits':counts['source_visits']}),flush=True)
    return {'parent_case_index':c['parent_case_index'],'independent_lifts':lifts,'missing_field_lift':missing,'independent_totals':dict(counts),'model_checks':dict(model),
            'comparison':compare,'codec':encoded,'raw_selected_u32':hex(selectedraw),'final_state_sha256':sha256(struct.pack('<624I',*mt)).hexdigest(),'all_checks_pass':True}

def obligations():
    out=[]
    def prove(label,bad,premise=z3.BoolVal(True)):
        s=z3.Solver();s.set(timeout=30000);s.add(premise);assert s.check()==z3.sat;s.add(z3.simplify(bad));assert s.check()==z3.unsat,label
        out.append({'label':label,'query':s.to_smt2(),'premises_nonvacuous':True,'result':'unsat'})
    sp=0x71000000;ready=z3.BitVec('po_ready8',8);flag=z3.BitVec('po_flag32',32)
    v=Algebra();v.seed('sp',sp);v.seed('w10',0xcbb6);mem(v,sp+0x80,8,0x72000000);mem(v,0x72000000,1,ready)
    v.run_block(R.ENTRY,0x100a38838);v.seed('x11',0x72000008);mem(v,0x72000008,4,flag);v.run_block(0x100a388a4,0x100a388c0)
    prove('all_readiness8_flag32_original_route',z3.Or(v.read('w10')!=z3.If(z3.And(ready==1,flag!=0),z3.BitVecVal(0xcbc1,32),z3.BitVecVal(0xcbb6,32)),v.read('w9')!=0))
    pointer=z3.BitVec('po_saved_pointer64',64);v=Algebra();v.seed('w8',0x5ae9);v.seed('x7',pointer);v.run_block(R.POINTER,0x100c21ae4)
    prove('all_saved_pointer64_original_null_partition',z3.Or(v.read('w8')!=z3.If(pointer==0,z3.BitVecVal(0x5aeb,32),z3.BitVecVal(0x5ae9,32)),v.read('w10')!=0x24f4,v.read('w9')!=0))
    header=z3.BitVec('po_extent64',64);v=Algebra();v.seed('w10',0x24f4);v.seed('x7',0x73000010);mem(v,0x73000000,8,header);v.run_block(R.EXTENT,0x100abb114)
    prove('all_encoded_extent64_original_signed_partition',v.read('w8')!=z3.If(header+0x2178739ec47edc16>=0,z3.BitVecVal(0x75f8,32),z3.BitVecVal(0x24f4,32)))
    n,x=z3.BitVecs('po_count64 po_counter64',64);a,b=z3.BitVecs('po_maskA32 po_maskB32',32)
    v=Algebra();v.seed('sp',sp);v.seed('x12',n);v.seed('x8',x);v.seed('w15',a);v.seed('w10',b);v.seed('x7',0x74000000)
    v.run_block(0x1009f296c,0x1009f298c)
    expected=(z3.Extract(31,0,x)^a^b)*(z3.Extract(31,0,x)+17)
    prove('all_payload_loop_operands_original_byte_count_increment',z3.Or(cell(v,sp+0x1d8,8)!=n-1,v.stores[-1]['address']!=0x74000000+n-1,
          v.stores[-1]['value']!=z3.Extract(7,0,expected),v.read('x8')!=x+1))
    v=Algebra();v.seed('sp',sp);v.seed('x13',n);v.seed('x10',x);v.seed('w11',0x24f4);v.seed('x8',0x74000000)
    v.run_block(0x100b7c0b8,0x100b7c0e8)
    prove('all_arena_head_loop_operands_original_byte_count_increment',z3.Or(cell(v,sp+0x200,8)!=n-1,v.stores[-1]['address']!=0x74000000+n-1,
          v.stores[-1]['value']!=z3.Extract(7,0,(z3.Extract(31,0,x)^0xba)*(z3.Extract(31,0,x)+17)),v.read('x10')!=x+1))
    old,nxt,far=z3.BitVecs('po_current32 po_next32 po_far32',32);offset=z3.BitVec('po_offset64',64);table=0x75000000
    class Twist(Algebra):
        def __init__(self,pc):super().__init__();self.table_pc=pc;self.table_address=None
        def load(self,a,n):
            if self.pc==self.table_pc:
                assert n==4;self.table_address=a;return z3.If(nxt&1!=0,z3.BitVecVal(0x9908b0df,32),z3.BitVecVal(0,32))
            return super().load(a,n)
    equation=far^z3.LShR((old&0x80000000)|(nxt&0x7fffffff),1)^z3.If(nxt&1!=0,z3.BitVecVal(0x9908b0df,32),z3.BitVecVal(0,32))
    for label,start,end,pc,currentreg,offsetreg,nd,fd,sd in [
        ('first',R.TWIST1,0x100a5e940,0x100a5e930,'w11','x9',4,0x634,0),
        ('second',0x100b31278,0x100b312a8,0x100b31298,'w12','x10',0x390,0,0x38c)]:
        v=Twist(pc);v.seed('x20',R.G);v.seed(offsetreg,offset);v.seed(currentreg,old);v.seed('x1',table);v.seed('w8',0x7ffffffe)
        mem(v,R.G+offset+nd,4,nxt);mem(v,R.G+offset+fd,4,far);v.run_block(start,end)
        prove('all_words_offsets_original_'+label+'_twist_equation_and_table_address',z3.Or(v.stores[-1]['value']!=equation,
              v.stores[-1]['address']!=R.G+offset+sd,v.table_address!=table+((z3.ZeroExt(32,nxt)&1)<<2)))
    v=Twist(0x100a2f628);v.seed('sp',sp);v.seed('x20',R.G);v.seed('w9',0x6d0e);v.seed('x1',table)
    mem(v,R.G+2492,4,old);mem(v,R.G,4,nxt);mem(v,R.G+1584,4,far);v.run_block(R.TWIST_LAST,0x100a2f638)
    prove('all_words_original_last_twist_equation_and_table_address',z3.Or(cell(v,R.G+2492,4)!=equation,v.table_address!=table+((z3.ZeroExt(32,nxt)&1)<<2),v.read('w10')!=0xb399))
    index=z3.BitVec('po_index32',32);mem(v,sp+0x1ec,4,index);v.run_block(0x100a2f638,0x100a2f650)
    prove('all_index32_original_reset_partition',v.read('w9')!=z3.If(z3.UGT(index,623),z3.BitVecVal(0x6d1a,32),z3.BitVecVal(0x6d0e,32)))
    v=Algebra();v.seed('w19',old);v.seed('w11',1);v.run_block(0x100a7ccb8,0x100a7ccf0)
    t=old^z3.LShR(old,11);t=t^((t<<7)&0x9d2c5680);t=t^((t<<15)&0xefc60000);t=t^z3.LShR(t,18)
    prove('all_raw_words_original_phase1_tempering',v.read('w9')!=t)
    candidate=z3.BitVec('po_candidate32',32);address=z3.BitVec('po_output_address64',64);remaining=z3.BitVec('po_remaining32',32);shift=z3.BitVec('po_shift32',32)
    v=Algebra();v.seed('w14',candidate);v.seed('w13',0);v.seed('w16',0);v.seed('x15',address);v.seed('w17',0);v.seed('w11',0x26d1);v.seed('w8',shift);v.seed('w2',remaining);v.seed('w10',0xbc66)
    v.run_block(0x100a0ca5c,0x100a0ca98);stored=z3.Extract(7,0,candidate)^0xd7;left=remaining-z3.If(stored!=0,z3.BitVecVal(1,32),z3.BitVecVal(0,32))
    prove('all_candidates_addresses_counts_original_store_reject_zero_and_transfer',z3.Or(v.stores[-1]['address']!=address,v.stores[-1]['value']!=stored,
          v.read('w2')!=left,v.read('w8')!=shift+8,v.read('w10')!=z3.If(left==0,z3.BitVecVal(0xc4da,32),z3.BitVecVal(0xbc66,32))))
    return out

def build():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e['generator_sha256']==sha(R.__file__) and e['dependencies']=={n:sha(ROOT/n) for n in R.DEPS}
    assert e['snapshot_neighbor']==R.neighbor() and e['source_regions']==R.source()
    parent=json.loads(read(ROOT/(R.Parent.P+'_checks.json')));cases=[audit_case(c,parent['cases'][c['parent_case_index']]) for c in e['cases']];counts=Counter();model=Counter()
    for c in cases:counts.update(c['independent_totals']);model.update(c['model_checks'])
    proofs=obligations()
    return {'scope':__doc__,'generator_sha256':sha(R.__file__),'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':sha(SOURCE),
            'dependencies':e['dependencies'],'verified_counts':e['verified_counts'],'cases':cases,'independent_totals':dict(counts),'model_checks':dict(model),
            'source_proofs':proofs,'source_queries_unsat':len(proofs),'all_checks_pass':True,'native_API_executed':False,
            'native_daemon_kext_pairing_established':False,'native_epoch_join_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps({'replay':e['independent_totals'],'model':e['model_checks'],'source_queries_unsat':e['source_queries_unsat'],'results':[c['codec'] for c in e['cases']]}),flush=True)
