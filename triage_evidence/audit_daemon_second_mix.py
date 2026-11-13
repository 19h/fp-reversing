#!/usr/bin/env python3
"""Independent second-pass replay, compact recurrence and gate value proofs.

O(receipts+visits*(state+effects)+iterations*N+query DAG) time;
O(receipt collection+largest interval+N) space, N=624. Solver limit30 s/query.
CAS is a sequential value transition; no native concurrency/PAC/API executes.
"""
import json,struct
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,TABLE,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_daemon_readiness_arena import Lift as ParentLift
from audit_daemon_network_record import state_bytes,fixture_bytes,join
from recover_daemon_return_bank_origins import Algebra
from lskd_values_symbolic import mem,cell
import recover_daemon_second_mix as R

class Lift(ParentLift):
    def one(self,i):
        if i.mnemonic=='casal' and i.address==R.GATE+4:
            assert i.op_str=='w8, w12, [x5]';a=self.address(i,i.operands[2]);old=self.load(a,4)
            match=self.projected(old)==self.projected(self.read('w8'))
            self.store(a,4,self.read('w12') if match else old,i.address);self.write('w8',old)
            self.counts['gate_CAS_value_transitions_checked']+=1;return
        return super().one(i)

class GateEquation(Algebra):
    def one(self,i):
        if i.mnemonic=='casal':
            assert i.address==R.GATE+4 and i.op_str=='w8, w12, [x5]'
            a=self.address(i,i.operands[2]);old=self.load(a,4)
            self.store(a,4,z3.If(old==self.read('w8'),self.read('w12'),old),i.address);self.write('w8',old);return
        return super().one(i)

def joined(before,after):
    join(before,after);assert before['boundary']['Q_registers32']==after['entry_Q_registers32']
    assert before['boundary']['pc']==after['entry_PC'] and before['foreign_owners']==after['foreign_owners']

def comparison(row):
    assert len(row['source_calls'])==1;call=row['source_calls'][0]
    assert call['pc']=='0x100abbb2c' and call['target']=='0x100444d6c'
    at=int(call['arguments8'][0],16);state=fixture_bytes(row,'private')|fixture_bytes(row,'image')
    for w in row['source_writes']:
        if w['source_visit_index']<call['source_visit_index']:state.update({int(w['address'],16)+j:b for j,b in enumerate(bytes.fromhex(w['after_hex']))})
    raw=bytes(state[at+j] for j in range(40));u=lambda o,n:int.from_bytes(raw[o:o+n],'little');mask64=(1<<64)-1
    key=((at^0x823819558515cfbd)*0xc7f6dca7)&mask64;k=key&0xffffffff
    a,b,mode=(u(16,8)+key)&mask64,u(32,8)^key,u(12,4)^k
    assert (a,b,mode)==(int(row['entry_registers31'][19],16)+1,623,1)
    yes,no,mask=u(28,4)^k,(u(8,4)-k)&0xffffffff,(u(4,4)+k)&0xffffffff
    choice=a>b;index=mask^(yes if choice else no);assert index==(0x1770 if choice else 0x17bd)
    w=[x for x in row['source_writes'] if x['pc']=='0x100444df4'];assert len(w)==1 and w[0]['address']==hex(at) and w[0]['after_hex']==struct.pack('<I',index).hex()
    return {'A64':a,'B64':b,'mode32':mode,'predicate':choice,'index32':hex(index),'target':hex(FIXUPS[TABLE+8*index]['target'])}

def audit_case(c,parent):
    before=R.Parent.unpack(parent['exit_intervals_packed'][-1]);initial=state_bytes(before);q=int(before['boundary']['SP'],16)+0x220
    mt=list(struct.unpack('<624I',bytes(initial[R.G+j] for j in range(2496))));key=bytes(initial[q+j] for j in range(16))
    payload=bytes(initial[R.Parent.Parent.PAYLOAD+j] for j in range(64));assert struct.pack('<624I',*mt).hex()==c['entry_state2496_hex'] and key.hex()==c['entry_key16_hex']
    i=2;remaining=623;lifts=[];totals=Counter();model=Counter();comparisons=[]
    assert len(c['intervals_packed'])==len(c['iteration_records'])==623
    for k,(packed,record) in enumerate(zip(c['intervals_packed'],c['iteration_records'])):
        row=R.Parent.unpack(packed);joined(before,row)
        assert [int(row['entry_registers31'][r],16) for r in [19,25]]==[i,remaining]
        mt[i]=((mt[i]^((mt[i-1]^(mt[i-1]>>30))*1566083941&0xffffffff))-i)&0xffffffff;i+=1
        if i==624:mt[0]=mt[623];i=1;model['state_wraps_checked']+=1
        if k<622:remaining-=1
        actual=state_bytes(row);assert bytes(actual[R.G+j] for j in range(2496))==struct.pack('<624I',*mt)
        assert bytes(actual[q+j] for j in range(16))==key and bytes(actual[R.Parent.Parent.PAYLOAD+j] for j in range(64))==payload
        assert [int(row['boundary']['registers31'][r],16) for r in [19,25]]==[i,remaining]
        assert record['iteration']==k+1 and [record['exit_i32'],record['exit_remaining32']]==[i,remaining]
        assert not any(R.Parent.Parent.PAYLOAD<=int(x['address'],16)<R.Parent.Parent.PAYLOAD+64 for x in row['source_reads']+row['source_writes'])
        comparisons.append(comparison(row));result=Lift(row).run();lifts.append(result);totals.update(result['verified_counts'])
        model.update(complete_state_words_checked=624,unchanged_key_words_checked=4,unchanged_payload_bytes_checked=64,exact_iteration_joins_checked=1)
        before=row
        if k%128==0:print(json.dumps({'parent_case_index':c['parent_case_index'],'iteration':k+1,'source_visits':totals['source_visits']}),flush=True)
    assert i==2 and remaining==1 and c['second_pass_boundary']==before['boundary'] and c['second_pass_NZCV']==before['boundary_NZCV']
    assert c['second_pass_state2496_hex']==struct.pack('<624I',*mt).hex()
    extras=[]
    for packed in c['exit_intervals_packed']:
        row=R.Parent.unpack(packed);joined(before,row);result=Lift(row).run();lifts.append(result);totals.update(result['verified_counts']);before=row;extras.append(row)
    counter,force,gate=extras
    assert [len(x['source_visits']) for x in extras]==[17,20,10]
    assert counter['boundary']['registers31'][25]=='0x0' and counter['boundary']['pc']==hex(R.FORCE)
    assert force['source_writes']==[{'pc':'0x100b2a20c','source_visit_index':3,'address':hex(R.G),'size_bytes':4,'after_hex':'00000080'}]
    mt[0]=0x80000000;final=state_bytes(gate);assert bytes(final[R.G+j] for j in range(2496))==struct.pack('<624I',*mt)==bytes.fromhex(c['final_state2496_hex'])
    assert bytes(final[q+j] for j in range(16))==key==bytes.fromhex(c['final_key16_hex'])
    assert c['entry_gate32_hex']=='965d0000' and c['final_gate32_hex']=='ef940a00'
    assert gate['source_reads'][0]['pc']=='0x100b3a84c' and gate['source_reads'][0]['address']==hex(R.GATE_WORD) and gate['source_reads'][0]['bytes_hex']=='965d0000'
    assert gate['source_writes']==[{'pc':'0x100b3a84c','source_visit_index':1,'address':hex(R.GATE_WORD),'size_bytes':4,'after_hex':'ef940a00'}]
    assert bytes(final[R.GATE_WORD+j] for j in range(4)).hex()==c['final_gate32_hex']
    assert c['final_boundary']==gate['boundary'] and c['final_NZCV']==gate['boundary_NZCV'] and gate['boundary']['pc']==hex(R.NEXT)
    model.update(final_word_forces_checked=1,same_gate_reacquisitions_checked=1)
    assert sum(x['predicate'] for x in comparisons)==1
    return {'parent_case_index':c['parent_case_index'],'independent_lifts':lifts,'independent_totals':dict(totals),
            'model_checks':dict(model),'comparison_records':comparisons,'final_state_sha256':__import__('hashlib').sha256(struct.pack('<624I',*mt)).hexdigest(),'all_checks_pass':True}

def obligations():
    out=[]
    def prove(label,bad,premise=z3.BoolVal(True)):
        s=z3.Solver();s.set(timeout=30000);s.add(premise);assert s.check()==z3.sat;s.add(z3.simplify(bad));assert s.check()==z3.unsat,label
        out.append({'label':label,'query':s.to_smt2(),'premises_nonvacuous':True,'result':'unsat'})
    i,old,prev=z3.BitVecs('sm_i32 sm_old32 sm_previous32',32);sp=0x71000000
    v=Algebra();v.seed('x20',R.G);v.seed('w19',i);ia=z3.ZeroExt(32,i)<<2;pa=z3.ZeroExt(32,i-1)<<2
    mem(v,R.G+ia,4,old);mem(v,R.G+pa,4,prev);v.run_block(R.ENTRY,0x100abba44)
    domain=z3.And(z3.UGE(i,1),z3.ULE(i,623))
    prove('all_valid_indices_original_second_mix_equation',cell(v,R.G+ia,4)!=((old^((prev^z3.LShR(prev,30))*1566083941))-i),domain)
    prove('all_valid_indices_original_increment',v.read('w22')!=i+1,domain)
    v=Algebra();v.seed('sp',sp);v.seed('x20',R.G);v.seed('w19',623);mem(v,sp+0x150,4,0xd831fa4f);mem(v,sp+0x1cc,4,0xb399);mem(v,R.G+623*4,4,old)
    v.run_block(0x1009f0478,0x1009f04c8);v.run_block(0x1009f04d0,0x1009f04d4)
    prove('all_last_words_original_wrap_copy_reset_and_counter_phase',z3.Or(cell(v,R.G,4)!=old,v.read('w19')!=1,v.read('w9')!=1,v.read('w10')!=1))
    v=Algebra();v.seed('sp',sp);v.seed('w19',i);v.seed('w22',i+1);mem(v,sp+0x148,4,0xa73ca7a3);mem(v,sp+0x1cc,4,0xb399)
    v.run_block(0x100a6c638,0x100a6c670);v.run_block(0x100a6c674,0x100a6c678)
    prove('all_nonwrap_indices_original_index_and_counter_phase',z3.Or(v.read('w19')!=i+1,v.read('w9')!=1,v.read('w10')!=1),z3.And(z3.UGE(i,1),z3.ULE(i,622)))
    n=z3.BitVec('sm_remaining32',32);v=Algebra();v.seed('w9',1);v.seed('w10',1);v.seed('w25',n);v.run_block(R.COUNTER,0x100a0775c)
    prove('all_u32_remaining_original_decrement_and_exit_partition',z3.Or(v.read('w25')!=n-1,v.read('w9')!=z3.If(n==1,z3.BitVecVal(0x1cdc,32),z3.BitVecVal(0x1c60,32))))
    gate,aux=z3.BitVecs('sm_gate_pointer64 sm_aux_pointer64',64);v=Algebra();v.seed('sp',sp);v.seed('x20',R.G);v.seed('x26',TABLE);v.seed('w8',0xb399)
    mem(v,TABLE+8*0x5a78,8,R.GATE);mem(v,sp+0xc0,8,gate);mem(v,sp+0x128,8,aux);v.run_block(R.FORCE,0x100b2a248)
    prove('all_saved_pointers_original_force_and_gate_setup',z3.Or(cell(v,R.G,4)!=0x80000000,v.read('x5')!=gate,v.read('x4')!=aux,v.read('w12')!=0xa94ef,v.read('w2')!=0x5d96,v.read('w10')!=0xcbb6,v.read('w9')!=0x5a78))
    word=z3.BitVec('sm_gate_word32',32);v=GateEquation();v.seed('x5',R.GATE_WORD);v.seed('w12',0xa94ef);mem(v,R.GATE_WORD,4,word);v.run_block(R.GATE,R.GATE+8)
    prove('all_u32_original_CAS_old_value_and_conditional_replacement',z3.Or(v.read('w8')!=word,cell(v,R.GATE_WORD,4)!=z3.If(word==0x5d96,z3.BitVecVal(0xa94ef,32),word)))
    v.seed('w2',0x5d96);v.seed('w10',0xcbb6);v.seed('w9',0x5a78);v.run_block(R.GATE+8,0x100b3a864)
    prove('all_u32_original_CAS_success_or_self_retry_index',v.read('w8')!=z3.If(word==0x5d96,z3.BitVecVal(0x8106,32),z3.BitVecVal(0x5a78,32)))
    return out

def build():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e['generator_sha256']==sha(R.__file__) and e['dependencies']=={n:sha(ROOT/n) for n in R.DEPS}
    p=json.loads(read(ROOT/(R.Parent.P+'_checks.json')));cases=[audit_case(c,p['cases'][c['parent_case_index']]) for c in e['cases']];totals=Counter();model=Counter()
    for c in cases:totals.update(c['independent_totals']);model.update(c['model_checks'])
    qs=obligations()
    return {'scope':__doc__,'generator_sha256':sha(R.__file__),'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
            'source_sha256':sha(SOURCE),'dependencies':e['dependencies'],'verified_counts':e['verified_counts'],
            'cases':cases,'independent_totals':dict(totals),'model_checks':dict(model),'source_proofs':qs,'source_queries_unsat':len(qs),
            'all_checks_pass':True,'native_API_executed':False,'native_daemon_kext_pairing_established':False,'native_epoch_join_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps({'replay':e['independent_totals'],'model':e['model_checks'],'final_states':[c['final_state_sha256'] for c in e['cases']]}),flush=True)
