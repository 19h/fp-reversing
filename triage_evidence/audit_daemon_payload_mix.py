#!/usr/bin/env python3
"""Independent packed-source replay and compact first-pass state composition.

O(receipts+visits*(state+byte effects)+iterations*N+query DAG) time;
O(largest interval+N+audit summaries) space, N=624. Solver limit 30 s/query.
No native API/IPC, allocation/free, hardware PAC or IDB mutation executes.
"""
import json,struct
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,TABLE
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_daemon_arena_split import Lift as ParentLift,ConsumerEquation
from audit_daemon_network_record import fixture_bytes,state_bytes,join
from audit_daemon_environment_outputs import DEC
from recover_daemon_return_bank_origins import Algebra
from lskd_values_symbolic import mem,cell
import recover_daemon_payload_mix as R

class Lift(ParentLift):
    def __init__(self,row):
        super().__init__(row)
        if row['entry_PC']=='0x100aaf008':
            slot=TABLE+8*0xa559;target=FIXUPS[slot]['target'];assert target==0x100abba18
            assert row['entry_registers31'][9]==hex(target)
            self.last_authenticated_load=(slot,target);self.counts['inherited_exit_origins_checked']+=1

def joined(a,b):
    join(a,b);assert a['boundary']['Q_registers32']==b['entry_Q_registers32']
    assert a['boundary']['pc']==b['entry_PC'] and a['foreign_owners']==b['foreign_owners']

def masks(payload):
    out=[R.Parent.PAYLOAD&0xffffffff]
    for j in [1,2,3]:
        a=R.Parent.PAYLOAD+4*j;t=0x100822c80+4*j
        word=int.from_bytes(payload[4*j:4*j+4],'little');text0=int.from_bytes(IMAGE.read(t,4),'little');text2=int.from_bytes(IMAGE.read(t+2,4),'little')
        out.append(((a*0xc40ba787)&0xffffffff)^word^(3&0xc68e91c5)^0x1bbdced5^text0^text2^0xe2715a91)
    return out

def comparisons(row):
    out=[];mask64=(1<<64)-1;initial=fixture_bytes(row,'private')|fixture_bytes(row,'image')
    for call in row['source_calls']:
        at=int(call['arguments8'][0],16);state=initial.copy()
        for w in row['source_writes']:
            if w['source_visit_index']<call['source_visit_index']:state.update({int(w['address'],16)+j:b for j,b in enumerate(bytes.fromhex(w['after_hex']))})
        raw=bytes(state[at+j] for j in range(40));u=lambda o,n:int.from_bytes(raw[o:o+n],'little')
        if call['target']=='0x100427514':
            key=((at^0x0179fa0fe732d262)*0xba209ef7)&mask64;k=key&0xffffffff
            a,b=(u(0,8)+key)&mask64,u(24,8)^key;mode=u(8,4)^k
            yes,no,mask=u(16,4)^k,(u(20,4)+k)&0xffffffff,u(32,4)^k
            assert (a,b,mode)==(623,int(row['entry_registers31'][19],16)+1,0)
            choose=a<b;writer='0x1004275ac';off=12
        else:
            assert call['target']=='0x100444d6c'
            key=((at^0x823819558515cfbd)*0xc7f6dca7)&mask64;k=key&0xffffffff
            a,b=(u(16,8)+key)&mask64,u(32,8)^key;mode=u(12,4)^k
            yes,no,mask=u(28,4)^k,(u(8,4)-k)&0xffffffff,(u(4,4)+k)&0xffffffff
            assert (a,b,mode)==(int(row['entry_registers31'][27],16)+1,3,1)
            choose=a>b;writer='0x100444df4';off=0
        result=mask^(yes if choose else no);w=[w for w in row['source_writes'] if w['pc']==writer];assert len(w)==1
        assert w[0]['address']==hex(at+off) and w[0]['after_hex']==struct.pack('<I',result).hex()
        out.append({'call_site':call['pc'],'A64':a,'B64':b,'mode32':mode,'predicate':choose,'index32':hex(result),'target':hex(FIXUPS[TABLE+8*result]['target'])})
    assert len(out)==2;return out

def audit_case(c,parent):
    before=parent['intervals'][-1];initial=state_bytes(before);sp=int(before['boundary']['SP'],16);q=sp+0x220
    payload=bytes(initial[R.Parent.PAYLOAD+j] for j in range(64));d=masks(payload)
    mt=list(struct.unpack('<624I',bytes.fromhex(c['entry_state2496_hex'])));keys=list(struct.unpack('<4I',bytes.fromhex(c['entry_key16_hex'])))
    assert bytes(initial[R.G+j] for j in range(2496)).hex()==c['entry_state2496_hex']
    assert bytes(initial[q+j] for j in range(16)).hex()==c['entry_key16_hex']
    i=2;j=1;remaining=623;lifts=[];totals=Counter();control=Counter();model=Counter();all_comparisons=[]
    for k,(packed,record) in enumerate(zip(c['intervals_packed'],c['iteration_records'])):
        row=R.unpack(packed);joined(before,row)
        assert [int(row['entry_registers31'][r],16) for r in [19,27,24]]==[i,j,remaining]
        mt[i]=((mt[i]^((mt[i-1]^(mt[i-1]>>30))*1664525&0xffffffff))+keys[j]+j)&0xffffffff;i+=1
        if i==624:mt[0]=mt[623];i=1;model['state_wraps_checked']+=1
        j=(j+1)%4;keys[j]^=d[j];model['key_'+str(j)+'_mutations_checked']+=1
        if k<622:remaining-=1
        assert [int(row['boundary']['registers31'][r],16) for r in [19,27,24]]==[i,j,remaining]
        actual=state_bytes(row);assert bytes(actual[R.G+a] for a in range(2496))==struct.pack('<624I',*mt)
        assert bytes(actual[q+a] for a in range(16))==struct.pack('<4I',*keys)==bytes.fromhex(record['key16_hex'])
        assert [int(record[key]) for key in ['exit_i32','exit_j32','exit_remaining32']]==[i,j,remaining]
        contract=comparisons(row);all_comparisons.append(contract)
        for t in contract:control[t['call_site']+('_true' if t['predicate'] else '_false')]+=1
        payload_reads=[x for x in row['source_reads'] if R.Parent.PAYLOAD<=int(x['address'],16)<R.Parent.PAYLOAD+64]
        if j:
            assert len(payload_reads)==1 and payload_reads[0]['address']==hex(R.Parent.PAYLOAD+4*j)
            f=row['source_frames'][payload_reads[0]['source_visit_index']];gp=f['registers31']
            assert gp[12]=='0x3' and int(gp[13],16)&1==0 and int(gp[14],16)==0x100822c80+4*j and int(gp[11],16)==0x100822c82+4*j
        else:assert not payload_reads
        assert not any(R.Parent.PAYLOAD<=int(w['address'],16)<R.Parent.PAYLOAD+64 for w in row['source_writes'])
        result=Lift(row).run();result['iteration']=k+2;lifts.append(result);totals.update(result['verified_counts'])
        model.update(complete_state_words_checked=624,complete_key_words_checked=4,exact_intermediate_joins_checked=1)
        before=row
        if k%64==0:print(json.dumps({'parent_seed_case_index':c['parent_seed_case_index'],'iteration':k+2,'source_visits':totals['source_visits']}),flush=True)
    assert remaining==1 and before['boundary']['pc']==hex(R.EXIT) and i==2 and j==0
    for packed in c['exit_intervals_packed']:
        row=R.unpack(packed);joined(before,row);result=Lift(row).run();lifts.append(result);totals.update(result['verified_counts']);before=row
    assert before['boundary']['pc']=='0x100abba18' and before['boundary']['registers31'][24]=='0x0'
    assert c['final_boundary']==before['boundary'] and c['final_NZCV']==before['boundary_NZCV']
    assert bytes.fromhex(c['final_state2496_hex'])==struct.pack('<624I',*mt) and bytes.fromhex(c['final_key16_hex'])==struct.pack('<4I',*keys)
    assert keys==[0xffffffff,0,0,0]
    return {'parent_seed_case_index':c['parent_seed_case_index'],'mutation_masks32':[hex(x) for x in d],
            'independent_lifts':lifts,'independent_totals':dict(totals),'model_checks':dict(model),'control_checks':dict(control),
            'comparison_records':all_comparisons,'all_checks_pass':True}

def obligations():
    qs=[]
    def prove(label,bad,premise=z3.BoolVal(True)):
        s=z3.Solver();s.set(timeout=30000);s.add(premise);assert s.check()==z3.sat;s.add(z3.simplify(bad));assert s.check()==z3.unsat,label
        qs.append({'label':label,'query':s.to_smt2(),'premises_nonvacuous':True,'result':'unsat'})
    i,j,old,prev,key=z3.BitVecs('pm_i32 pm_j32 pm_old32 pm_previous32 pm_key32',32);sp=0x71000000;q=0x72000000
    v=Algebra();v.seed('x20',R.G);v.seed('w19',i);v.seed('w27',j);v.seed('sp',sp)
    ia=z3.ZeroExt(32,i)<<2;pa=z3.ZeroExt(32,i-1)<<2;ja=z3.ZeroExt(32,j)<<2
    mem(v,R.G+ia,4,old);mem(v,R.G+pa,4,prev);mem(v,sp+0x1c0,8,q);mem(v,q+ja,4,key)
    v.run_block(R.ENTRY,0x1009c4714);domain=z3.And(z3.UGE(i,1),z3.ULE(i,623),z3.ULE(j,3))
    prove('all_indexed_words_original_first_mix_equation',cell(v,R.G+ia,4)!=((old^((prev^z3.LShR(prev,30))*1664525))+key+j),domain)
    prove('all_valid_first_mix_indices_original_increment',v.read('w19')!=i+1,domain)
    r=z3.BitVec('pm_record32',32)
    prove('algebraic_source_record_affine_transform_is_XOR',r-((r<<1)&0x377b9daa)+0x1bbdced5!=(r^0x1bbdced5))
    w,phase,flag=z3.BitVecs('pm_payload32 pm_phase32 pm_flag32',32);address=z3.BitVec('pm_address64',64);text=z3.BitVec('pm_text48',48)
    v=ConsumerEquation();v.payload_word=w;v.seed('x10',address);v.seed('w12',phase);v.seed('w13',flag);v.seed('sp',sp);v.seed('x8',4);v.seed('x14',0x100822c84);v.seed('x11',0x100822c86)
    mem(v,sp+0x1c0,8,q);mem(v,q+4,4,r);mem(v,0x100822c84,4,z3.Extract(31,0,text));mem(v,0x100822c86,4,z3.Extract(47,16,text))
    v.run_block(R.Parent.STOP,0x100a07710)
    delta=z3.Extract(31,0,address)*0xc40ba787^w^(phase&0xc68e91c5)^(flag&1)^0x1bbdced5^z3.Extract(31,0,text)^z3.Extract(47,16,text)^0xe2715a91
    prove('all_nonwrap_inputs_original_consumer_is_old_record_XOR_delta',cell(v,q+4,4)!=(r^delta))
    pointer=z3.BitVec('pm_pointer64',64);v=Algebra();v.seed('sp',sp);v.seed('w27',4);v.seed('w25',0xb399)
    mem(v,sp+0x1c0,8,q);mem(v,q,4,r);mem(v,sp+0x140,4,3);mem(v,sp+0x13c,4,1);mem(v,sp+0x190,8,pointer)
    v.run_block(0x100a7d924,0x100a7d970)
    prove('all_record_pointer_words_original_wrapped_key_XOR_low_pointer',cell(v,q,4)!=(r^z3.Extract(31,0,pointer)))
    v=Algebra();v.seed('x20',R.G);v.seed('sp',sp);v.seed('w19',624);mem(v,R.G+623*4,4,old);mem(v,sp+0x15c,4,623)
    v.run_block(0x100c0bb74,0x100c0bba4);v.run_block(0x100c0bbb8,0x100c0bbbc)
    prove('all_last_words_original_state_wrap_copy_and_index_reset',z3.Or(cell(v,R.G,4)!=old,v.read('w19')!=1))
    n=z3.BitVec('pm_remaining32',32);v=Algebra();v.seed('w9',0x1a22);v.seed('w24',n);v.run_block(R.EXIT,0x100aaeffc)
    prove('all_u32_remaining_values_original_decrement_and_exit_partition',z3.Or(v.read('w24')!=n-1,
        v.read('w9')!=z3.If(n==1,z3.BitVecVal(0xa559,32),z3.BitVecVal(0x1a22,32))))
    d=z3.BitVec('pm_delta32',32);restored=r
    for _ in range(156):restored=restored^d
    prove('algebraic_156_identical_key_mutations_restore_every_word',restored!=r)
    return qs

def build():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e['generator_sha256']==sha(R.__file__) and e['dependencies']=={n:sha(ROOT/n) for n in R.DEPS}
    p=json.loads(read(ROOT/(R.Parent.P+'_checks.json')));cases=[audit_case(c,p['seed_cases'][c['parent_seed_case_index']]) for c in e['cases']]
    totals=Counter();model=Counter();control=Counter()
    for c in cases:totals.update(c['independent_totals']);model.update(c['model_checks']);control.update(c['control_checks'])
    queries=obligations()
    return {'scope':__doc__,'generator_sha256':sha(R.__file__),'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
            'source_sha256':sha(SOURCE),'dependencies':e['dependencies'],'verified_counts':e['verified_counts'],
            'cases':cases,'independent_totals':dict(totals),'model_checks':dict(model),'control_checks':dict(control),
            'source_proofs':queries,'source_queries_unsat':len(queries),'all_checks_pass':True,'native_API_executed':False,
            'native_daemon_kext_pairing_established':False,'native_epoch_join_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps({'replay':e['independent_totals'],'model':e['model_checks'],'control':e['control_checks']}),flush=True)
