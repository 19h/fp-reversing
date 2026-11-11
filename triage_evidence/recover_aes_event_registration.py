#!/usr/bin/env python3
"""Original AES event hashing, interruptible registration and mutex sleep paths.

Source/ABI certificates with declared register, thread, atomic and call snapshots.
No native wait queue, mutex, scheduler, device, key, IPC or IDB operation executes.
O(B+I+P) collection/source/path time and space; SMT cost separate.
"""
import argparse
import json

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
import z3

from kernel_native_reader import Kernel
from kext_port_tools import ROOT
from recover_kext_aes_handoff import function
from recover_kext_cold_init import pointer
from recover_aes_trace_wakeup import TraceLift
from recover_aes_configuration_commands import fork
from lskd_values_symbolic import resize, part
from verify_daemon_reader_record_payloads_publication import read, sha

F=0xfffffe0053000000
TABLE_ROOT=0xfffffe0007e66df8
TABLE_COUNT=0xfffffe0007e66e00
POLICY=0xfffffe000cb0bc50
FUNCTIONS={'gate_sleep':0xfffffe000c51e1d4,'gate_wake':0xfffffe000c51e19c,'event_sleep':0xfffffe000c51c928,
 'loop_sleep':0xfffffe000c519a8c,'loop_wake':0xfffffe000c519a78,'mutex_sleep':0xfffffe000bd0c8f4,
 'assert_wait':0xfffffe000bd28394,'wake_primitive':0xfffffe000bd2b480,'register_wrapper':0xfffffe000bd6dfdc,
 'wake_wrapper':0xfffffe000bd6e22c,'mark_wait':0xfffffe000bd28280,'register_core':0xfffffe000bd6bc48,
 'counter_cleanup':0xfffffe000bd561fc}


class EventLift(TraceLift):
    def run(self,label):
        saved=self.c;row=next(r for r in saved['spans']if r['label']==label)
        cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
        raw=bytes.fromhex(row['bytes_hex']);insns=list(cs.disasm(raw,int(row['start'],16)));assert len(insns)*4==len(raw)
        for ins in insns:
            self.pc=ins.address;o=ins.operands
            if ins.mnemonic=='mrs':
                assert ins.op_str.endswith(', tpidr_el1')
                self.write(ins.reg_name(o[0].reg),self.declared_thread);self.count+=1
            elif ins.mnemonic in ['casl','casa']:
                expected_reg=ins.reg_name(o[0].reg);n=self.width(expected_reg)//8
                address=self.address(ins,o[2]);old=self.load(address,n)
                expected=self.read(expected_reg);desired=self.read(ins.reg_name(o[1].reg))
                self.store(address,n,z3.If(old==expected,desired,old),ins.address)
                self.write(expected_reg,old);self.count+=1
            else:
                self.c={'spans':[{'label':label,'start':hex(ins.address),'bytes_hex':bytes(ins.bytes).hex()}]}
                super().run(label)
        self.c=saved;return self


def forest(capture,name,entry,stops,seeds,cells=(),writes=()):
    row=next(r for r in capture['spans']if int(r['start'],16)<=entry<int(r['end'],16))
    cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
    code={i.address:i for i in cs.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16))}
    obj=EventLift({'spans':[]})
    for reg,value in seeds.items():obj.seed(reg,value)
    for at,n,value in cells:obj.fixed[(z3.simplify(resize(at,64)).sexpr(),n)]=resize(value,n*8)
    for at,n in writes:obj.fixed_stores.add((z3.simplify(resize(at,64)).sexpr(),n))
    pending=[(entry,obj,z3.BoolVal(True),[])];leaves=[]
    while pending:
        pc,obj,predicate,visits=pending.pop();predicate=z3.simplify(predicate)
        if z3.is_false(predicate):continue
        assert len(visits)<64
        if pc in stops:leaves.append((pc,obj,predicate,visits));continue
        ins=code[pc];m,o=ins.mnemonic,ins.operands;visits=visits+[pc]
        if m=='b':pending.append((o[0].imm&((1<<64)-1),obj,predicate,visits));continue
        condition=None
        if m.startswith('b.'):condition=obj.condition(m[2:])
        elif m in ['cbz','cbnz']:
            condition=obj.read(ins.reg_name(o[0].reg))==0
            if m=='cbnz':condition=z3.Not(condition)
        elif m in ['tbz','tbnz']:
            condition=(obj.read(ins.reg_name(o[0].reg))&(1<<o[1].imm))==0
            if m=='tbnz':condition=z3.Not(condition)
        if condition is not None:
            pending.append((o[-1].imm&((1<<64)-1),fork(obj),z3.And(predicate,condition),visits))
            pending.append((pc+4,fork(obj),z3.And(predicate,z3.Not(condition)),visits))
        else:
            assert m in ['mov','ldr','ldrh','and','cmp','cmn','ccmp','csel','str']
            obj.c={'spans':[{'label':name,'start':hex(pc),'bytes_hex':bytes(ins.bytes).hex()}]}
            obj.run(name);pending.append((pc+4,obj,predicate,visits))
    return leaves


def prove(capture):
    queries,pieces,counts={}, {}, {}
    E,B,T,M=z3.BitVecs('event64 table_base64 thread64 mutex64',64)
    N,HASH,IP,FLAGS,STATUS=z3.BitVecs('bucket_count32 abstract_hash32 interruptibility32 abort_flags32 wait_status32',32)
    CAP,COUNTER=z3.BitVecs('thread_cap16 thread_counter16',16)
    WORD32=z3.BitVec('mutex_observation32',32)
    WORD64=z3.BitVec('mutex_observation64',64);TID=z3.BitVec('thread_id32',32);POL=z3.BitVec('policy32',32)
    def run(name,a,z,seeds,cells=(),writes=()):
        obj=EventLift(part(capture,name,a,z));obj.declared_thread=T
        for reg,value in seeds.items():obj.seed(reg,value)
        for at,n,value in cells:obj.fixed[(z3.simplify(resize(at,64)).sexpr(),n)]=resize(value,n*8)
        for at,n in writes:obj.fixed_stores.add((z3.simplify(resize(at,64)).sexpr(),n))
        obj.run(name);assert obj.count==(z-a)//4
        pieces[name]={'start':hex(a),'end':hex(z),'instructions':obj.count};counts[name]=obj.count
        return obj
    def cell(obj,at,n):return obj.fixed[(z3.simplify(resize(at,64)).sexpr(),n)]
    # Hash cuts include the original table globals and checked address formation.
    aw=run('assert_hash',0xfffffe000bd283c0,0xfffffe000bd28434,{'x20':E,'x19':resize(IP,64)},
           [(TABLE_ROOT,8,B),(TABLE_COUNT,4,N)])
    wk=run('wake_hash',0xfffffe000bd2b4ac,0xfffffe000bd2b51c,{'x8':E},[(TABLE_ROOT,8,B),(TABLE_COUNT,4,N)])
    h=(E^z3.LShR(E,31))*0x7fb5d329728ea185;h=(h^z3.LShR(h,27))*0x81dadef4bc2dd44d
    low=resize(h^z3.LShR(h,33),32);index=low&(N-1);off=z3.ZeroExt(32,index)*24
    for name,obj,reg in [('assert',aw,'x9'),('wake',wk,'x10')]:
        queries[name+'_scaled_hash']=obj.read(reg)!=off
        queries[name+'_pointer']=z3.And(z3.ULE(index,0x7fffffff//24),obj.read('x0')!=B+off)
        queries[name+'_event']=obj.read('x1')!=E
    queries['hash_queue_join']=aw.read('x0')!=wk.read('x0')
    queries['assert_interruptibility']=aw.read('x2')!=z3.ZeroExt(32,IP)
    power2=z3.And(N!=0,(N&(N-1))==0)
    queries['masked_index_bound']=z3.And(power2,z3.UGE(HASH&(N-1),N))
    queries['scaled_index_sign_fit']=z3.And(power2,z3.ULE(N,1<<26),z3.UGT(z3.ZeroExt(32,HASH&(N-1))*24,0x7fffffff))
    queries['scaled_index_table_extent']=z3.And(power2,z3.UGT(z3.ZeroExt(32,HASH&(N-1))*24+24,z3.ZeroExt(32,N)*24))
    obj=run('register_core_arguments',0xfffffe000bd6e064,0xfffffe000bd6e080,
            {'x19':B,'x23':E,'x22':resize(IP,64),'x20':0,'x21':T})
    queries['register_core_arguments']=z3.Or(obj.read('x0')!=B,obj.read('x1')!=E,obj.read('x2')!=resize(IP,64),
                       obj.read('w3')!=0,obj.read('x4')!=0,obj.read('x5')!=0,obj.read('x6')!=T)
    mark=forest(capture,'mark',0xfffffe000bd282a0,{0xfffffe000bd282e4,0xfffffe000bd282f0},
                {'x0':T,'x1':resize(IP,64)},[(T+0xc8,2,CAP),(T+0x210,4,FLAGS)],[(T+0x210,4)])
    i=IP&3;c=resize(CAP&3,32);effective=z3.If(z3.ULT(i,c),i,c)
    aborted=z3.And(effective!=0,(FLAGS&16)!=0,z3.Or(effective==2,(FLAGS&32)==0))
    queries['mark_abort_partition']=z3.Or(*[p for pc,_,p,_ in mark if pc==0xfffffe000bd282e4])!=aborted
    for j,(pc,obj,predicate,_)in enumerate(mark):
        queries['mark_effective_'+str(j)]=z3.And(predicate,obj.read('w21')!=effective)
        if pc==0xfffffe000bd282e4:
            expected=z3.If((FLAGS&32)!=0,FLAGS&0xffffffcf,FLAGS)
            queries['abort_flag_effect_'+str(j)]=z3.And(predicate,cell(obj,T+0x210,4)!=expected)
    queries['zero_interruptibility_cannot_abort']=z3.And(IP==0,aborted)
    queries['two_interruptibility_bounded']=z3.And(IP==2,z3.UGT(effective,2))
    obj=run('abort_result',0xfffffe000bd282e4,0xfffffe000bd282ec,{'x19':T},writes=[(T+0x58d,1)])
    queries['abort_result']=z3.Or(cell(obj,T+0x58d,1)!=0,obj.read('w0')!=2)
    obj=run('wait_mask',0xfffffe000bd282f8,0xfffffe000bd28304,{'w21':effective})
    state_bits=z3.If(effective==0,resize(9,32),resize(1,32))
    queries['wait_mask']=obj.read('w22')!=state_bits
    state,hint=z3.BitVec('thread_state32',32),z3.BitVec('wait_hint8',8)
    obj=run('wait_publication',0xfffffe000bd28338,0xfffffe000bd28364,{'x19':T,'w21':effective,'w22':state_bits},
       [(T+0x1f8,4,state),(T+0x58d,1,hint)],[(T+0x1f8,4),(T+0xcb,1),(T+0x58e,1),(T+0x58d,1),(T+0xd8,4)])
    queries['wait_publication']=z3.Or(cell(obj,T+0x1f8,4)!=(state|state_bits),cell(obj,T+0xcb,1)!=z3.If(effective==2,resize(1,8),resize(0,8)),
                                    cell(obj,T+0x58e,1)!=hint,cell(obj,T+0x58d,1)!=0,cell(obj,T+0xd8,4)!=0xffffffff)
    loop,depth=z3.BitVec('loop64',64),z3.BitVec('recursive_depth32',32)
    obj=run('loop_sleep_arguments',0xfffffe000c519b14,0xfffffe000c519b34,{'x19':loop,'x21':E,'x20':resize(IP,64)},
            [(loop+0x10,8,M),(M+0x20,4,depth)],[(M+0x20,4),(M+0x18,8)])
    queries['loop_sleep_arguments']=z3.Or(obj.read('x0')!=M,obj.read('w1')!=16,obj.read('x2')!=E,obj.read('x3')!=resize(IP,64),
                                         cell(obj,M+0x20,4)!=0,cell(obj,M+0x18,8)!=0,obj.read('w23')!=depth)
    obj=run('assert_wait_arguments',0xfffffe000bd0c938,0xfffffe000bd0c940,{'x2':E,'x3':resize(IP,64)})
    queries['assert_wait_arguments']=z3.Or(obj.read('x0')!=E,obj.read('x1')!=resize(IP,64))
    obj=run('counter_increment',0xfffffe000bd0c924,0xfffffe000bd0c938,{'sp':F},[(T+0x21e,2,COUNTER)],[(T+0x21e,2)])
    queries['counter_increment']=z3.Or(cell(obj,T+0x21e,2)!=resize(COUNTER+1,16),cell(obj,F+0x18,8)!=T)
    sleep=forest(capture,'sleep_result',0xfffffe000bd0c944,{0xfffffe000bd0c990,0xfffffe000bd0ca70},
                 {'w0':STATUS,'w19':16})
    queries['sleep_result_partition']=z3.Or(*[p for pc,_,p,_ in sleep if pc==0xfffffe000bd0c990])!=(STATUS==0xffffffff)
    obj=run('unlock_RMW',0xfffffe000bd0c990,0xfffffe000bd0c9b4,{'x20':M},
            [(POLICY,4,POL),(T+0x518,4,TID),(M+8,4,WORD32)],[(M+8,4)])
    queries['unlock_RMW']=z3.Or(obj.read('w2')!=WORD32,cell(obj,M+8,4)!=z3.If(WORD32==TID,resize(0,32),WORD32))
    queries['unlock_fast_condition']=obj.equal!=z3.And(WORD32==TID,POL==0)
    obj=run('block_arguments',0xfffffe000bd0c9b8,0xfffffe000bd0c9c4,{})
    queries['block_arguments']=z3.Or(obj.read('x0')!=0,obj.read('x1')!=0,obj.read('w2')!=0)
    obj=run('relock_RMW',0xfffffe000bd0c9e0,0xfffffe000bd0c9f0,{'x20':M,'x9':resize(TID,64),'x8':resize(POL,64)},
            [(M+8,8,WORD64)],[(M+8,8)])
    queries['relock_RMW']=z3.Or(obj.read('x2')!=WORD64,cell(obj,M+8,8)!=z3.If(WORD64==0,resize(TID,64),WORD64))
    queries['relock_fast_condition']=(obj.read('x8')==0)!=z3.And(WORD64==0,POL==0)
    obj=run('cleanup_arguments',0xfffffe000bd0ca70,0xfffffe000bd0ca78,{'sp':F,'x0':resize(STATUS,64)})
    queries['cleanup_arguments']=z3.Or(obj.read('x19')!=resize(STATUS,64),obj.read('x0')!=F+0x18)
    obj=run('cleanup_counter',0xfffffe000bd56214,0xfffffe000bd56224,{},[(T+0x21e,2,COUNTER)],[(T+0x21e,2)])
    queries['cleanup_counter']=z3.Or(cell(obj,T+0x21e,2)!=resize(COUNTER-1,16),obj.equal!=(COUNTER==1))
    queries['counter_pair_modular_balance']=resize(resize(COUNTER+1,16)-1,16)!=COUNTER
    obj=run('sleep_result_preserved',0xfffffe000bd0ca7c,0xfffffe000bd0ca80,{'x19':resize(STATUS,64)})
    queries['sleep_result_preserved']=obj.read('x0')!=resize(STATUS,64)
    obj=run('wake_primitive_arguments',0xfffffe000c519a7c,0xfffffe000c519a88,{'x1':E,'x2':0})
    queries['wake_primitive_arguments']=z3.Or(obj.read('x0')!=E,obj.read('x1')!=0,obj.read('w2')!=0)
    for label,a,value in [('wake_all_count',0xfffffe000bd2b4a8,0xffffffff),('wake_one_count',0xfffffe000bd2b49c,1)]:
        obj=run(label,a,a+4,{});queries[label]=obj.read('w4')!=value
    count_result=z3.BitVec('wake_helper_result32',32)
    obj=run('wake_result_translation',0xfffffe000bd2b524,0xfffffe000bd2b530,{'w0':count_result})
    queries['wake_result_translation']=obj.read('w0')!=z3.If(count_result==0,resize(48,32),resize(0,32))
    # The empty/FIFO insertion suffix publishes event and outer queue identity.
    Q=z3.BitVec('selected_queue64',64)
    obj=run('empty_membership',0xfffffe000bd6be34,0xfffffe000bd6be44,{'x20':T,'x24':Q,'x25':E,'x19':B},
            writes=[(T,8),(T+8,8),(Q+8,8),(T+0x18,8),(T+0x28,8)])
    queries['empty_membership']=z3.Or(cell(obj,T,8)!=T,cell(obj,T+8,8)!=T,cell(obj,Q+8,8)!=T,
                                    cell(obj,T+0x18,8)!=E,cell(obj,T+0x28,8)!=B)
    other_base=z3.BitVec('other_table_base64',64)
    controls={'queue_join_requires_epoch':z3.And(N==1,B!=other_base,aw.read('x0')!=z3.substitute(wk.read('x0'),(B,other_base))),'input_two_can_abort':z3.And(IP==2,aborted),
              'nonzero_wait_status_need_not_block':z3.And(STATUS!=0,STATUS!=0xffffffff)}
    proofs={}
    for label,leaves in [('mark',mark),('sleep',sleep)]:
        predicates=[p for _,_,p,_ in leaves]
        queries[label+'_coverage']=z3.Not(z3.Or(*predicates))
        queries[label+'_disjoint']=z3.Or(*[z3.And(a,b)for j,a in enumerate(predicates)for b in predicates[j+1:]])
    for name,query in queries.items():
        solver=z3.Solver();solver.set(timeout=15000);solver.add(query);result=solver.check()
        assert result==z3.unsat,(name,str(result),solver.reason_unknown())
        proofs[name]={'result':'unsat','query':solver.sexpr()};print(name,result,flush=True)
    negative={}
    for name,query in controls.items():
        solver=z3.Solver();solver.set(timeout=15000);solver.add(query);assert solver.check()==z3.sat
        negative[name]={'result':'sat','query':solver.sexpr(),'scope':'Abstract premise control; no native input/reachability claim.'}
    paths={};feasible=0
    for label,leaves in [('mark',mark),('sleep',sleep)]:
        paths[label]=[]
        for pc,_,predicate,visits in leaves:
            solver=z3.Solver();solver.set(timeout=15000);solver.add(predicate);result=solver.check();assert result in [z3.sat,z3.unsat]
            feasible+=result==z3.sat
            paths[label].append({'frontier':hex(pc),'path':[hex(a)for a in visits],'path_condition':predicate.sexpr(),
                                 'feasibility':str(result),'feasibility_query':solver.sexpr()})
    return {'proofs':proofs,'negative_controls':negative,'source_pieces':pieces,'source_lift_counts':counts,'source_paths':paths,
            'verified_counts':{'queries_unsat':len(proofs),'controls_sat':len(negative),'source_pieces':len(pieces),
               'source_lifted_instances':sum(counts.values()),'mark_source_paths':len(mark),'sleep_source_paths':len(sleep),
               'feasible_source_paths':int(feasible)}}


def sleep_return_frontiers(configure, sites):
    """Trace old X0/W0 only until its first overwrite, over original CFG edges."""
    cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
    code={i.address:i for i in cs.disasm(bytes.fromhex(configure['bytes_hex']),int(configure['start'],16))}
    result=[]
    for site in sites:
        call=int(site['sleep_call'],16);pending=[call+4];visited=set();overwrites=[]
        while pending:
            pc=pending.pop()
            if pc in visited:continue
            visited.add(pc);ins=code[pc]
            reads,writes=ins.regs_access()
            assert not {'x0','w0'}&{ins.reg_name(r)for r in reads},('sleep-result use',hex(pc),ins.op_str)
            if {'x0','w0'}&{ins.reg_name(r)for r in writes}:overwrites.append(hex(pc));continue
            assert ins.mnemonic not in ['bl','blr','blraa','braa','ret','retab']
            if ins.mnemonic=='b':pending.append(ins.operands[0].imm&((1<<64)-1))
            elif ins.mnemonic.startswith('b.')or ins.mnemonic in ['cbz','cbnz','tbz','tbnz']:
                pending.extend([pc+4,ins.operands[-1].imm&((1<<64)-1)])
            else:pending.append(pc+4)
        result.append({'sleep_call':hex(call),'visited':[hex(a)for a in sorted(visited)],'first_return_register_overwrites':sorted(overwrites),
                       'reads_before_overwrite':0})
    return result


def build():
    k=Kernel();spans=[]
    for label,address in FUNCTIONS.items():
        r=k.function(address);r['label']=label;r['bytes_hex']=r.pop('bytes');spans.append(r)
    hw=next(e for e in k.entries if e['name']=='com.apple.driver.AppleS8000AES')
    r=function(k,hw,0xfffffe0009d4fcf8);r['label']='configure';spans.append(r)
    result=prove({'spans':spans})
    previous=json.loads(read(ROOT/'aes_trace_wakeup_checks.json'))
    result['configuration_sleep_returns']=sleep_return_frontiers(r,previous['configuration_sleep_sites'])
    result['verified_counts']['untested_configuration_sleep_returns']=len(result['configuration_sleep_returns'])
    slots={hex(a):pointer(k,a)for a in [TABLE_ROOT,0xfffffe0007f3fdb0,0xfffffe0007f3fdb8,
               0xfffffe0007f3f7e8,0xfffffe0007f3f7f0]}
    result['verified_counts'].update(spans=len(spans),instructions=sum(len(r['instructions'])for r in spans),
                                    code_B=sum(len(bytes.fromhex(r['bytes_hex']))for r in spans),original_slots=len(slots))
    return {'scope':__doc__,'generator_sha256':sha(__file__),'kernel_collection_sha256':k.sha256,'spans':spans,'slots':slots,
       'exact_symbols':k.symbols(list(FUNCTIONS.values())+[int(r['target'],16)for r in slots.values()]),
       'file_table_count':{'address':hex(TABLE_COUNT),'bytes_hex':k.read(TABLE_COUNT,4).hex()},
       'file_table_prefix':{'address':slots[hex(TABLE_ROOT)]['target'],'bytes_hex':k.read(int(slots[hex(TABLE_ROOT)]['target'],16),24).hex()},
       'file_policy':{'address':hex(POLICY),'bytes_hex':k.read(POLICY,4).hex()},
       'dependencies':{p:sha(ROOT/p)for p in ['recover_aes_trace_wakeup.py','aes_trace_wakeup_checks.json',
          'aes_synchronous_wait_source.json','kernel_waitq_enqueue_source.json','kernel_native_reader.py',
          'recover_kext_aes_handoff.py','recover_kext_cold_init.py','lskd_values_symbolic.py','verify_daemon_reader_record_payloads_publication.py']},
       'new_IDA_access':False,'new_native_execution':False,'new_IDB_mutations':False,'full_goal_complete':False,**result}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--verify',action='store_true');args=parser.parse_args()
    result=build();path=ROOT/'aes_event_registration_checks.json'
    if args.verify:assert json.loads(read(path))==result
    else:path.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result['verified_counts']))
