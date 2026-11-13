#!/usr/bin/env python3
"""Independent full stream/refill/caller replay and ABI separation checks.

O(receipts+visits*(register state+effects)+intervals*N+query DAG) time;
O(receipt collection+largest interval+N) space,N=624;30 s/query.
Logical returns and sequential byte flow do not prove a native caller epoch.
"""
import json,struct
from collections import Counter
from hashlib import sha256
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,TABLE,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_daemon_readiness_arena import Lift as ParentLift
from audit_daemon_network_record import state_bytes,fixture_bytes,join
from recover_daemon_return_bank_origins import Algebra
from lskd_values_symbolic import mem,cell
import recover_daemon_generated_stream as R

class Lift(ParentLift):
    SAVED_ORIGINS={0x1005068ac:(0x1007c9a6c,0x1010433a0,0x1007cf718,0x1007cf720,0x10059cd50,'x0'),
                   0x1005ae1fc:(0x1005bf60c,0x101042268,0x1009a1028,0x1009a1030,0x1005ae1d4,'x13')}
    def __init__(self,row):
        super().__init__(row);self.saved_origins_checked=set()
    def integer(self,value):
        result=super().integer(value)
        origins=self.SAVED_ORIGINS
        if self.pc in origins and result==origins[self.pc][0]:
            target,slot,op,wp,rp,register=origins[self.pc];row=self.c;assert FIXUPS[slot]['target']==result
            origin=selected(row,op);saved=selected(row,wp,'source_writes');reloaded=selected(row,rp)
            assert len(origin)==len(saved)==len(reloaded)==1;o,w,r=origin[0],saved[0],reloaded[0]
            assert o['address']==hex(slot) and o['bytes_hex']==w['after_hex']==r['bytes_hex']==struct.pack('<Q',result).hex()
            assert w['address']==r['address'] and w['size_bytes']==r['size_bytes']==8
            assert o['source_visit_index']<w['source_visit_index']<r['source_visit_index']
            a=int(w['address'],16)
            assert not any(int(x['address'],16)<a+8 and a<int(x['address'],16)+x['size_bytes'] for x in row['source_writes'] if w['source_visit_index']<x['source_visit_index']<=r['source_visit_index'])
            for visit in row['source_visits'][r['source_visit_index']+1:]:
                if visit['pc']==hex(self.pc):break
                from audit_daemon_environment_outputs import DEC
                i=next(DEC.disasm(IMAGE.read(int(visit['pc'],16),4),int(visit['pc'],16)))
                assert not any(i.reg_name(x) in [register,'w'+register[1:]] for x in i.regs_access()[1])
            self.last_authenticated_load=(slot,result)
            if self.pc not in self.saved_origins_checked:self.counts['reloaded_saved_origins_checked']+=1;self.saved_origins_checked.add(self.pc)
        return result

MASK32=(1<<32)-1;MASK64=(1<<64)-1
def u32(v):return v&MASK32
def raw(s,a,n):return bytes(s[a+j] for j in range(n))
word=R.word
def selected(row,pc,kind='source_reads'):return [x for x in row[kind] if x['pc']==hex(pc)]
def joined(before,after,effects=()):
    join(before,after,effects);assert before['boundary']['Q_registers32']==after['entry_Q_registers32']
    assert before['boundary']['pc']==after['entry_PC'] and before['foreign_owners']==after['foreign_owners']
def comparison(row,kind):
    assert len(row['source_calls'])==1;c=row['source_calls'][0];a=int(c['arguments8'][0],16);s=fixture_bytes(row,'private')|fixture_bytes(row,'image')
    for w in row['source_writes']:
        if w['source_visit_index']<c['source_visit_index']:s.update({int(w['address'],16)+j:b for j,b in enumerate(bytes.fromhex(w['after_hex']))})
    if kind=='refill':
        assert (c['pc'],c['target'])==('0x100b33030','0x10041a5e0')
        k=((a^0xee9763edb3ce6674^0xa374c17f4a1aff00)*0xda51a827)&MASK64;lo=k&MASK32
        left=(word(s,a+8,8)-k)&MASK64;right=word(s,a+32,8)^k;mode=u32(word(s,a)-lo)
        yes,no,mask=word(s,a+44)^lo,u32(word(s,a+40)+lo),u32(word(s,a+20)-lo)
        assert right==0 and mode==0;predicate=left==right;index=mask^(yes if predicate else no)
        assert index==(0x177c if predicate else 0x1782);pc=0x10041a668;offset=16
    else:
        assert (c['pc'],c['target'])==('0x100a3c13c','0x100427514')
        k=((((0x5a2dd95b7f1fcb68|((a<<1)&MASK64))-a+0xd2e9135240701a4c)&MASK64)^0x2c6f16a258bd37d6)*0xba209ef7&MASK64;lo=k&MASK32
        left=(word(s,a,8)+k)&MASK64;right=word(s,a+24,8)^k;mode=word(s,a+8)^lo
        yes,no,mask=word(s,a+16)^lo,u32(word(s,a+20)+lo),word(s,a+32)^lo
        assert left==5119 and mode==0;predicate=left<right;index=mask^(yes if predicate else no)
        assert index==0x16a1;pc=0x1004275ac;offset=12
    writes=selected(row,pc,'source_writes');assert len(writes)==1 and writes[0]['address']==hex(a+offset) and writes[0]['after_hex']==struct.pack('<I',index).hex()
    return {'kind':kind,'record':hex(a),'A64':left,'B64':right,'mode32':mode,'predicate':predicate,'index':hex(index),'slot':hex(TABLE+8*index),'target':hex(FIXUPS[TABLE+8*index]['target'])}

def codec(row):
    s=fixture_bytes(row,'private')|fixture_bytes(row,'image');regs=list(map(lambda x:int(x,16),row['entry_registers31']));sp=int(row['caller_SP'],16)
    remaining,shift,word32,phase,output=[regs[i] for i in [2,8,9,10,4]];assert phase==0xbc66 and 0<remaining<=32 and shift in [0,8,16,24]
    a=output+remaining-1;ci=word(s,word(s,sp+0x160,8));cache=word(s,word(s,sp+0x168,8),8);ca=cache+(ci&0x0ba3ccc8);cached=word(s,ca)
    r=u32(cached+(a&MASK32));mask=word(s,0x1010c6800,8)^0xa7a730ec;text=word(s,0x1010ca2a8,8)^0x12af5504870a589f
    aa=text+(u32(r+0x0ba3ccc8)&mask);ba=text+(u32(r+0x0ba3ccca)&mask);ta,tb=IMAGE.read(aa,1)[0],IMAGE.read(ba,1)[0]
    candidate=((word32>>(shift&31))^u32(31*(a&MASK32))^ta^tb)&255;stored=candidate^0xd7
    assert len(row['source_writes'])==1;w=row['source_writes'][0];assert w['pc']=='0x100a0ca74' and w['address']==hex(a) and w['size_bytes']==1 and w['after_hex']==bytes([stored]).hex()
    for pc,address,value,n in [(0x100a0c9d8,ca,cached,4),(0x100a0ca30,aa,ta,1),(0x100a0ca54,ba,tb,1)]:
        rr=selected(row,pc);assert len(rr)==1 and rr[0]['address']==hex(address) and rr[0]['size_bytes']==n and int.from_bytes(bytes.fromhex(rr[0]['bytes_hex']),'little')==value
    b=row['boundary'];assert int(b['registers31'][2],16)==remaining-int(stored!=0) and int(b['registers31'][8],16)==shift+8
    return {'address':hex(a),'remaining_before':remaining,'remaining_after':remaining-int(stored!=0),'shift_before':shift,'shift_after':shift+8,
            'word32':hex(word32),'candidate8':hex(candidate),'stored8_hex':bytes([stored]).hex(),'text_addresses':[hex(aa),hex(ba)],'text_bytes_hex':bytes([ta,tb]).hex()}

def caller(row,completed,output):
    initial=fixture_bytes(row,'private')|fixture_bytes(row,'image');final=state_bytes(row)
    status=selected(row,0x100a6d390,'source_writes');assert len(status)==1 and status[0]['address']=='0x6800070db8' and status[0]['after_hex']=='51c63d8b'
    adapter=selected(row,0x100add7d8);assert len(adapter)==1 and adapter[0]['address']=='0x6800060010' and adapter[0]['bytes_hex']=='57c220ab'
    assert word(initial,0x6800060010)==word(final,0x6800060010)==0xab20c257
    assert not any(int(w['address'],16)<0x6800060014 and 0x6800060010<int(w['address'],16)+w['size_bytes'] for w in row['source_writes'])
    assert selected(row,0x100add7e4,'source_writes')[0]['after_hex']=='00'*8
    returns=[e for e in row['logical_edges'] if e['kind']=='retab'];assert [(e['pc'],e['target']) for e in returns]==[('0x100a6d3c8','0x100add7d8'),('0x100add7f8','0x100605f1c')]
    reads=selected(row,0x100576f10);writes=selected(row,0x100576f28,'source_writes');assert len(reads)==len(writes)==32
    for j,(rr,w) in enumerate(zip(reads,writes)):
        k=31-j;assert rr['address']==hex(output+k) and rr['bytes_hex']==bytes([completed[k]]).hex()
        assert w['address']==hex(0x6500115b54+k) and w['after_hex']==bytes([completed[k]^0x98]).hex()
    assert raw(final,0x6500115b54,32)==bytes(b^0x98 for b in completed)
    overwrite=selected(row,0x10054b73c,'source_writes');assert len(overwrite)==32
    for j,w in enumerate(overwrite):assert w['address']==hex(output+31-j) and w['size_bytes']==1
    assert max(w['source_visit_index'] for w in writes)<min(w['source_visit_index'] for w in overwrite)
    for a,value in [(0x6500115ba8,0x78f07ded),(0x6500115be4,4),(0x6500115be8,2)]:assert word(final,a)==value
    assert row['boundary']['pc']==hex(R.NEXT) and row['boundary']['detail']['symbol']=='libSystem/_malloc' and row['boundary']['registers31'][0]=='0x68'
    return {'status_output_pointer':status[0]['address'],'status32':'0x8b3dc651','adapter_input_pointer':adapter[0]['address'],
            'adapter_input32':'0xab20c257','status_pointers_alias':False,'adapter_delta64':0,'logical_returns':returns,
            'arena_base':'0x6500115b20','arena_output_offset_bytes':52,'arena_output32_hex':raw(final,0x6500115b54,32).hex(),
            'private_overwrite32_hex':raw(final,output,32).hex(),'pending_malloc_bytes':104}

def audit_case(c,parent):
    before=R.unpack(parent['intervals'][-1]['packed']);initial=state_bytes(before);sp=int(before['boundary']['SP'],16);output=int(c['output_pointer'],16)
    mt=list(struct.unpack('<624I',raw(initial,R.G,2496)));counts=Counter();model=Counter();lifts=[];attempts=[];comparisons=[];selections=[];rows=[]
    completed=None;generation=1;index=1
    assert len(c['intervals'])==105
    for k,p in enumerate(c['intervals']):
        row=R.unpack(p['packed']);joined(before,row);lift=Lift(row).run();assert lift['all_checks_pass'];lifts.append(lift);counts.update(lift['verified_counts']);rows.append(row)
        label=p['label'];s=state_bytes(row)
        if label.startswith('refill_first_twist') or label.startswith('refill_second_twist') or label=='refill_last_twist_and_retained_index':
            part=0 if label.startswith('refill_first') else 1 if label.startswith('refill_second') else 2
            indices=[range(227),range(227,623),range(623,624)][part];pc=[0x100a5e93c,0x100b312a4,0x100a2f634][part]
            ww=selected(row,pc,'source_writes');assert len(ww)==len(indices)
            for i,w in zip(indices,ww):
                nxt=mt[(i+1)%624];y=(mt[i]&0x80000000)|(nxt&0x7fffffff)
                mt[i]=u32(mt[(i+397)%624]^(y>>1)^(0x9908b0df if nxt&1 else 0));assert w['address']==hex(R.G+4*i) and w['after_hex']==struct.pack('<I',mt[i]).hex()
                model['twist_word_updates_checked']+=1
        if label=='counter_record_refill_to_twist':
            q=comparison(row,'refill');assert q['A64']==generation and not q['predicate'];comparisons.append(q);model['full_twist_refills_checked']+=1
        if label=='refill_selection_and_counter_comparison':
            q=comparison(row,'selection');assert q['B64']==generation and not q['predicate'];comparisons.append(q)
            assert int(row['boundary']['registers31'][19],16)==mt[index];selections.append({'index':index,'raw_u32':hex(mt[index])});index+=1
            assert word(s,sp+0x1ec)==word(s,0x1010c67dc)==index;model['selected_words_checked']+=1
        if label=='refill_counter_and_temper':
            r=int(row['entry_registers31'][19],16);t=r^(r>>11);t=u32(t^((t<<7)&0x9d2c5680));t=u32(t^((t<<15)&0xefc60000));t^=t>>18
            generation+=1;assert word(s,R.COUNTER)==generation and int(row['boundary']['registers31'][9],16)==t;model['tempered_words_checked']+=1
        if label=='encoded_byte_attempt':attempts.append(codec(row));model['encoded_byte_attempts_checked']+=1
        if label=='status_epilogues_arena_copy_scratch_overwrite_to_malloc':
            completed=raw(fixture_bytes(row,'private'),output,32);assert completed.hex()==c['completed_output32_hex'] and all(completed)
        assert raw(s,R.G,2496)==struct.pack('<624I',*mt);model['complete_state_boundary_words_checked']+=624
        assert word(s,R.Parent.Parent.GATE_WORD)==0x5d96
        before=row
        if k%24==0:print(json.dumps({'case':c['parent_case_index'],'interval':k+1,'source_visits':counts['source_visits']}),flush=True)
    assert generation==index==8 and len(attempts)==31 and all(x['stored8_hex']!='00' for x in attempts)
    assert [x['address'] for x in attempts]==[hex(output+j) for j in range(30,-1,-1)]
    assert [x['shift_before'] for x in attempts]==[8,16,24]+[0,8,16,24]*7
    contract=caller(rows[-1],completed,output);model.update(arena_copy_bytes_checked=32,private_overwrite_bytes_checked=32,status_pointer_mismatches_checked=1,logical_caller_returns_checked=2)
    assert contract['arena_output32_hex']==c['arena_output32_hex'] and contract['private_overwrite32_hex']==c['final_private_output32_hex']
    assert struct.pack('<624I',*mt).hex()==c['final_generated_array2496_hex'] and c['final_boundary']==before['boundary'] and c['final_NZCV']==before['boundary_NZCV']
    return {'parent_case_index':c['parent_case_index'],'independent_lifts':lifts,'independent_totals':dict(counts),'model_checks':dict(model),
            'byte_attempts':attempts,'comparisons':comparisons,'selections':selections,'caller_contract':contract,'final_array_sha256':sha256(struct.pack('<624I',*mt)).hexdigest(),'all_checks_pass':True}

def controls(e):
    zero=[];counters=[];totals=Counter();model=Counter()
    for c in e['zero_controls']:
        main=e['cases'][c['parent_case_index']];origin=R.unpack(main['intervals'][c['parent_main_interval_index']]['packed']);before=R.entry(origin)
        change=c['entry_register_effect'];assert change['register']=='x9' and before['boundary']['registers31'][9]==change['before']
        before['boundary']['registers31']=before['boundary']['registers31'].copy();before['boundary']['registers31'][9]=change['after'];lifts=[];attempts=[]
        for p in c['intervals_packed']:
            row=R.unpack(p);joined(before,row);lift=Lift(row).run();lifts.append(lift);totals.update(lift['verified_counts'])
            if row['entry_PC']==hex(R.BYTE):
                a=codec(row);assert a['stored8_hex']=='00' and a['remaining_before']==a['remaining_after']==31;attempts.append(a)
            before=row
        assert len(attempts)==3 and len({a['address'] for a in attempts})==1 and [a['shift_before'] for a in attempts]==[8,16,24]
        assert before['boundary']['pc']==hex(R.REFILL) and int(before['boundary']['registers31'][8],16)==32
        model.update(forced_zero_attempts_checked=3,forced_zero_refills_checked=1);zero.append({'parent_case_index':c['parent_case_index'],'independent_lifts':lifts,'attempts':attempts,'all_checks_pass':True})
    for c in e['counter_controls']:
        main=e['cases'][c['parent_case_index']];origin=R.unpack(main['intervals'][c['parent_main_interval_index']]['packed']);before=R.entry(origin);row=R.unpack(c['intervals_packed'][0])
        joined(before,row,[c['effect']]);lift=Lift(row).run();totals.update(lift['verified_counts']);q=comparison(row,'refill');assert q['A64']==c['counter32'] and q['predicate']==(c['counter32']==0)
        assert row['boundary']['pc']==hex(R.ADMISSION if c['counter32']==0 else R.TWIST_ENTRY)
        model['separate_counter_partitions_checked']+=1;counters.append({'parent_case_index':c['parent_case_index'],'counter32':c['counter32'],'independent_lift':lift,'comparison':q,'all_checks_pass':True})
    return {'zero_controls':zero,'counter_controls':counters,'independent_totals':dict(totals),'model_checks':dict(model),'all_checks_pass':True}

def obligations():
    out=[]
    def prove(label,bad,premise=z3.BoolVal(True)):
        s=z3.Solver();s.set(timeout=30000);s.add(premise);assert s.check()==z3.sat;s.add(z3.simplify(bad));assert s.check()==z3.unsat,label
        out.append({'label':label,'query':s.to_smt2(),'premises_nonvacuous':True,'result':'unsat'})
    shift=z3.BitVec('gs_shift32',32);v=Algebra()
    for n,value in [('w11',0x26d1),('w3',0x7269d8ad),('w5',0x8d96bce7),('w7',0xffff43ba),('w6',0x8cc8),('w19',0xb248),('w8',shift)]:v.seed(n,value)
    v.run_block(R.ENTRY,0x100bf6d64)
    prove('all_shift32_original_word_exhaustion_partition',z3.Or(v.read('w10')!=0xbc66,v.read('w11')!=z3.If(shift==32,z3.BitVecVal(0x2700,32),z3.BitVecVal(0x26d1,32))))
    record,left,right=z3.BitVecs('gs_record64 gs_left64 gs_right64',64);mode,mask,yes,no=z3.BitVecs('gs_mode32 gs_mask32 gs_yes32 gs_no32',32)
    v=Algebra();v.seed('x0',record);v.run_block(0x10041a5e0,0x10041a61c);key=v.read('x8');lo=z3.Extract(31,0,key)
    for off,n,value in [(0,4,mode+lo),(8,8,left+key),(20,4,mask+lo),(32,8,right^key),(40,4,no-lo),(44,4,yes^lo)]:mem(v,record+off,n,value)
    v.run_block(0x10041a61c,0x10041a66c);predicate=z3.If(mode&1!=0,z3.UGT(left,right),left==right)
    prove('all_records_original_equality_or_unsigned_greater_leaf',z3.Or(cell(v,record+16,4)!=(mask^z3.If(predicate,yes,no)),v.read('x0')!=record,v.stores[-1]['address']!=record+16))
    counter=z3.BitVec('gs_counter32',32);sp=0x680005fce0;fp=0x6800060000;at=fp-0x90;k=((at^0xee9763edb3ce6674^0xa374c17f4a1aff00)*0xda51a827)&MASK64
    v=Algebra();v.seed('sp',sp);v.seed('x29',fp);v.seed('w12',0xb399);v.seed('x13',z3.ZeroExt(32,counter));mem(v,sp+0x98,8,k)
    v.run_block(0x100b32f60,0x100b32fb4);v.seed('x0',at);v.run_block(0x10041a5e0,0x10041a66c)
    prove('all_counter32_original_refill_record_selects_admission_only_at_zero',z3.Or(cell(v,at+16,4)!=z3.If(counter==0,z3.BitVecVal(0x177c,32),z3.BitVecVal(0x1782,32)),cell(v,sp+0xc8,8)!=z3.ZeroExt(32,counter)))
    byte=z3.BitVec('gs_byte8',8);address=z3.BitVec('gs_address64',64);v=Algebra();v.seed('w17',byte);v.seed('x0',address);v.run_block(0x100576f18,0x100576f2c)
    prove('all_byte8_original_arena_copy_transform',z3.Or(v.stores[-1]['address']!=address,v.stores[-1]['value']!=(byte^0x98)))
    count,x=z3.BitVecs('gs_count64 gs_overwrite_counter64',64);control=z3.BitVec('gs_overwrite_control32',32);v=Algebra();v.seed('sp',sp);v.seed('x8',count);v.seed('x10',x);v.seed('w2',control);v.seed('x20',address)
    v.run_block(0x10054b728,0x10054b744)
    prove('all_operands_original_private_scratch_overwrite',z3.Or(cell(v,sp+0x3668,8)!=count-1,v.stores[-1]['address']!=address+count-1,
          v.stores[-1]['value']!=z3.Extract(7,0,(z3.Extract(31,0,x)^control)*(z3.Extract(31,0,x)+17)),v.read('x10')!=x+1))
    phase=z3.BitVec('gs_completion_phase32',32);v=Algebra();v.seed('sp',sp);v.seed('w12',phase);mem(v,sp+0x40,8,address);v.run_block(R.DONE,0x100a6d394)
    prove('all_phases_saved_pointer_original_status_store',z3.Or(v.stores[-1]['address']!=address,v.stores[-1]['value']!=phase-((phase<<1)&0x167a84a2)+0x8b3dc651))
    inp,output=z3.BitVecs('gs_adapter_input64 gs_adapter_output64',64);value,expected=z3.BitVecs('gs_adapter_word32 gs_adapter_expected32',32)
    v=Algebra();v.seed('x20',inp);v.seed('x19',output);v.seed('w21',expected);mem(v,inp,4,value);v.run_block(0x100add7d8,0x100add7e8)
    prove('all_adapter_values_pointers_original_low16_delta_store',z3.Or(v.stores[-1]['address']!=output,v.stores[-1]['value']!=z3.ZeroExt(48,z3.Extract(15,0,value-expected))<<4))
    return out

def assemble(e,cases):
    assert e['generator_sha256']==sha(R.__file__) and e['dependencies']=={n:sha(ROOT/n) for n in R.DEPS} and e['source_regions']==R.source()
    assert len(cases)==len(e['cases'])==2 and all(c['all_checks_pass'] for c in cases)
    extra=controls(e);counts=Counter(extra['independent_totals']);model=Counter(extra['model_checks'])
    for c in cases:counts.update(c['independent_totals']);model.update(c['model_checks'])
    proofs=obligations()
    return {'scope':__doc__,'generator_sha256':sha(R.__file__),'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':sha(SOURCE),
            'dependencies':e['dependencies'],'verified_counts':e['verified_counts'],'cases':cases,'controls':extra,'independent_totals':dict(counts),'model_checks':dict(model),
            'source_proofs':proofs,'source_queries_unsat':len(proofs),'all_checks_pass':True,'native_API_executed':False,'native_daemon_kext_pairing_established':False,'native_epoch_join_established':False,'full_goal_complete':False}

def build():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));parent=json.loads(read(ROOT/(R.Parent.P+'_checks.json')))
    return assemble(e,[audit_case(c,parent['cases'][c['parent_case_index']]) for c in e['cases']])

if __name__=='__main__':
    e=build();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps({'replay':e['independent_totals'],'model':e['model_checks'],'source_queries_unsat':e['source_queries_unsat']}),flush=True)
