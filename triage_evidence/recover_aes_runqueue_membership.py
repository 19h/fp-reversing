#!/usr/bin/env python3
"""Original placement routing, compact priority rings and auxiliary-record joins.

Disjoint fixed cells and valid priority/ring snapshots only. Native queue
ownership, lifetime, locking and scheduling are unobserved. O(B+I+P) source
time/space; SMT cost separate. No native target or IDB operation executes.
"""
import argparse
import json
import z3
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from kernel_native_reader import Kernel
from kext_port_tools import ROOT
from recover_aes_block_wake_handshake import HandshakeLift
from lskd_values_symbolic import resize, part, mem, cell
from verify_daemon_reader_record_payloads_publication import read, sha

FUNCTIONS={'backend':0xfffffe000bd207c4,'enqueue':0xfffffe000bd2d5cc,
 'weights':0xfffffe000bd2173c,'placement':0xfffffe000bd27054}
DEPS=['kernel_native_reader.py','kext_port_tools.py','recover_aes_block_wake_handshake.py',
 'recover_aes_event_wake_selection.py','recover_event_wait_table.py','lskd_values_symbolic.py',
 'aes_block_wake_handshake_checks.json','aes_event_wake_selection_checks.json',
 'verify_daemon_reader_record_payloads_publication.py']


class QueueLift(HandshakeLift):
    def run(self,label):
        saved=self.c;row=next(r for r in saved['spans']if r['label']==label)
        cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
        for i in cs.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
            self.pc=i.address;m,o=i.mnemonic,i.operands
            if m=='ldrsh':
                dest=i.reg_name(o[0].reg);v=self.load(self.address(i,o[1]),2)
                self.write(dest,z3.SignExt(self.width(dest)-16,v));self.count+=1
            elif m=='ldr'and i.writeback:
                assert i.op_str=='w12, [x11], #8'
                self.write('w12',self.load(self.read('x11'),4));self.write('x11',self.read('x11')+8);self.count+=1
            elif m=='ldaddh':
                at=self.address(i,o[2]);old=self.load(at,2)
                self.store(at,2,old+resize(self.read(i.reg_name(o[0].reg)),16),i.address)
                self.write(i.reg_name(o[1].reg),old);self.count+=1
            else:
                self.c={'spans':[{'label':label,'start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run(label)
        self.c=saved;return self


def prove(c):
    q={};pieces={};Q,T,H,P,R,A=z3.BitVecs('runqueue64 thread64 head64 previous64 candidate64 auxiliary64',64)
    K=z3.BitVec('priority16',16);FLAGS,MAX,COUNT,SPECIAL=z3.BitVecs('source_flags32 previous_max32 count32 special_count32',32)
    MASK=z3.BitVec('bitmap64',64);CLASS=z3.BitVec('class8',8)
    priority=z3.SignExt(48,K);bank=z3.LShR(resize(priority,32),6)
    valid=z3.ULE(K,127);slot=Q+0x20+(priority<<3)
    def run(name,a,z,seeds,cells=()):
        o=QueueLift(part(c,name,a,z))
        for r,v in seeds.items():o.seed(r,v)
        for at,n,v in cells:mem(o,at,n,v)
        o.run(name);assert o.count==(z-a)//4;pieces[name]={'start':hex(a),'end':hex(z),'instructions':o.count};return o
    o=run('backend_identity_store',0xfffffe000bd20818,0xfffffe000bd20820,
          {'x19':R,'x20':T},[(T+0x2a0,8,A)])
    q['backend_identity_store']=z3.Or(cell(o,T+0x20,8)!=R,o.read('x8')!=A)
    o=run('bound_backend_arguments',0xfffffe000bd20824,0xfffffe000bd20830,
          {'x19':R,'x20':T,'x25':resize(FLAGS,64)})
    q['bound_backend_arguments']=z3.Or(o.read('x0')!=R+0x2a0,o.read('x1')!=T,o.read('x2')!=resize(FLAGS,64))
    o=run('priority_head_load',0xfffffe000bd2d5d0,0xfffffe000bd2d5dc,{'x0':Q,'x1':T},[(T+0x214,2,K),(slot,8,H)])
    q['signed_priority_and_head']=z3.Or(o.read('x12')!=priority,o.read('x11')!=Q+0x20,o.read('x10')!=H)
    q['valid_priority_head_extent']=z3.And(valid,z3.Or(z3.ULT(priority*8+0x20,0x20),z3.UGT(priority*8+0x20+8,0x420)))
    o=run('empty_ring',0xfffffe000bd2d60c,0xfffffe000bd2d614,{'x1':T,'x11':Q+0x20,'x12':priority})
    q['empty_ring']=z3.Or(cell(o,T,8)!=T,cell(o,T+8,8)!=T,cell(o,slot,8)!=T)
    for name,a,z,head_store in [('prepend',0xfffffe000bd2d5f4,0xfffffe000bd2d608,True),
                               ('append',0xfffffe000bd2d654,0xfffffe000bd2d664,False)]:
        o=run(name,a,z,{'x1':T,'x10':H,'x8':P,'x11':Q+0x20,'x12':priority})
        q[name+'_links']=z3.Or(cell(o,T,8)!=H,cell(o,T+8,8)!=P,cell(o,P,8)!=T,cell(o,H+8,8)!=T,o.read('w9')!=0)
        q[name+'_store_ledger']=len(o.stores)!=(5 if head_store else 4)
        if head_store:q[name+'_head']=cell(o,slot,8)!=T
    o=run('empty_bitmap',0xfffffe000bd2d614,0xfffffe000bd2d638,
          {'x1':T,'x0':Q},[(T+0x214,2,K),(Q,4,MAX),(Q+8+(resize(bank,64)<<3),8,MASK)])
    bit=resize(1,64)<<(priority&63)
    q['empty_bitmap_OR']=cell(o,Q+8+(resize(bank,64)<<3),8)!=(MASK|bit)
    q['empty_bitmap_bank_bound']=z3.And(valid,z3.UGT(bank,1))
    q['empty_bitmap_contains_priority']=(cell(o,Q+8+(resize(bank,64)<<3),8)&bit)!=bit
    o=run('highest_priority_comparison',0xfffffe000bd2d638,0xfffffe000bd2d640,{'x1':T,'w12':MAX},[(T+0x214,2,K)])
    q['signed_highest_comparison']=z3.Or(o.cmp_left!=MAX,o.cmp_right!=z3.SignExt(16,K))
    o=run('highest_priority_store',0xfffffe000bd2d644,0xfffffe000bd2d64c,{'x0':Q,'w8':z3.SignExt(16,K)})
    q['new_highest_publication']=z3.Or(cell(o,Q,4)!=z3.SignExt(16,K),o.read('w9')!=1)
    global_mask=0xfffffe000cad06a8
    o=run('classification_bitmap',0xfffffe000bd2d66c,0xfffffe000bd2d684,{'x1':T},
          [(T+0x214,2,K),(global_mask+(resize(bank,64)<<3),8,MASK)])
    q['classification_bit']=(o.read('x8')&1)!=z3.LShR(MASK,priority&63)&1
    o=run('special_count',0xfffffe000bd2d688,0xfffffe000bd2d694,{'x0':Q},[(Q+0x1c,4,SPECIAL)])
    q['special_count_modular']=cell(o,Q+0x1c,4)!=SPECIAL+1
    RET=z3.BitVec('highest_increased64',64)
    o=run('total_and_return',0xfffffe000bd2d694,0xfffffe000bd2d6a4,{'x0':Q,'x9':RET},[(Q+0x18,4,COUNT)])
    q['total_and_return']=z3.Or(cell(o,Q+0x18,4)!=COUNT+1,o.read('x0')!=RET)
    returned=o.read('x0');incremented=cell(o,Q+0x18,4)
    o=run('same_class_auxiliary_record',0xfffffe000bd209e4,0xfffffe000bd209fc,{'x20':T},[(T+0x298,8,A),(T+0x204,1,CLASS)])
    record=A+0x60+resize(CLASS,64)*112
    q['same_class_auxiliary_record']=o.read('x8')!=record
    q['same_class_pair_join']=o.read('x8')+0x20!=A+0x80+resize(CLASS,64)*112
    q['same_class_elapsed_join']=o.read('x8')+0x58!=A+0xb8+resize(CLASS,64)*112
    o=run('cached_class_runqueue',0xfffffe000bd209ac,0xfffffe000bd209c4,{'x26':R,'x20':T},[(T+0x204,1,CLASS)])
    q['cached_class_runqueue']=o.read('x23')+8!=R+0x2510+resize(CLASS,64)*0x458
    BASE=z3.BitVec('per_context_array64',64);INDEX=z3.BitVec('context_index8',8)
    o=run('uncached_class_context_record',0xfffffe000bd20ac4,0xfffffe000bd20af4,{'x20':T,'x26':R,'sp':0x61000000},
          [(T+0x298,8,A),(T+0x204,1,CLASS),(record+0x60,8,BASE),(R+0x85e,1,INDEX)])
    q['uncached_class_context_record']=o.read('x22')!=BASE+resize(INDEX,64)*200
    # Six class entries fall through to a suffix of six u16 increments.
    HCOUNT=z3.BitVec('class_counter16',16)
    o=run('class_counter_increment',0xfffffe000bd208c0,0xfffffe000bd208cc,{'x26':R},[(R+0xae8,2,HCOUNT)])
    q['class_counter_increment']=cell(o,R+0xae8,2)!=HCOUNT+1
    out={};negative={}
    for name,query in q.items():
        solver=z3.Solver();solver.set(timeout=15000);solver.add(query);result=solver.check();assert result==z3.unsat,(name,str(result))
        out[name]={'result':'unsat','query':solver.to_smt2()}
    controls={'count_can_wrap':z3.And(COUNT==0xffffffff,COUNT+1==0),
      'class_record_requires_epoch':z3.And(A!=R,A+0x60+resize(CLASS,64)*112!=R+0x60+resize(CLASS,64)*112),
      'zero_result_with_count_increment':z3.And(RET==0,COUNT==7,returned==0,incremented==8)}
    for name,query in controls.items():
        solver=z3.Solver();solver.set(timeout=15000);solver.add(query);assert solver.check()==z3.sat
        negative[name]={'result':'sat','query':solver.to_smt2(),'scope':'Abstract contract-domain control; no native reachability claim.'}
    return out,negative,pieces


def build():
    k=Kernel();spans=[]
    for name,a in FUNCTIONS.items():
        r=k.function(a);r['label']=name;r['bytes_hex']=r.pop('bytes');spans.append(r)
    proofs,controls,pieces=prove({'spans':spans})
    counts={'queries_unsat':len(proofs),'controls_sat':len(controls),'source_pieces':len(pieces),
      'source_lifted_instances':sum(r['instructions']for r in pieces.values()),'spans':len(spans),
      'instructions':sum(len(r['instructions'])for r in spans)};counts['code_B']=counts['instructions']*4
    return {'scope':__doc__,'generator_sha256':sha(__file__),'kernel_collection_sha256':k.sha256,
      'dependencies':{p:sha(ROOT/p)for p in DEPS},'spans':spans,'exact_symbols':k.symbols(FUNCTIONS.values()),
      'proofs':proofs,'negative_controls':controls,'source_pieces':pieces,'verified_counts':counts,
      'new_IDA_access':False,'new_native_execution':False,'new_IDB_mutations':False,'full_goal_complete':False}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--verify',action='store_true');args=parser.parse_args()
    out=build();p=ROOT/'aes_runqueue_membership_checks.json'
    if args.verify:assert json.loads(read(p))==out
    else:p.write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps(out['verified_counts']),flush=True)
