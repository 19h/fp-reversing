#!/usr/bin/env python3
"""Original hashed-event summary, full waiter matching and wake handoff ABI.

Source scalar certificates only; native locking, scheduler effects, table/thread
epochs and liveness remain unobserved. O(B+I+P) source time/space; SMT cost is
separate. No target, device, Mach IPC, native atomic or IDB operation executes.
"""
import argparse
import json
import z3
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from kernel_native_reader import Kernel
from kext_port_tools import ROOT
from recover_event_wait_table import StartupLift
from lskd_values_symbolic import resize, part, mem, cell
from verify_daemon_reader_record_payloads_publication import read, sha

FUNCTIONS={'register':0xfffffe000bd6bc48,'wake_wrapper':0xfffffe000bd6e22c,
 'request':0xfffffe000bd6c59c,'select':0xfffffe000bd6c660,'fifo':0xfffffe000bd6ce44,
 'stage':0xfffffe000bd6cbcc,'drain':0xfffffe000bd6bad0}
DEPS=['kernel_native_reader.py','kext_port_tools.py','recover_event_wait_table.py',
 'lskd_values_symbolic.py','verify_daemon_reader_record_payloads_publication.py',
 'aes_event_registration_checks.json','event_wait_table_checks.json','kernel_waitq_receiver_source.json']


class WakeLift(StartupLift):
    def width(self,name):return 128 if name in ['q0','v0']else super().width(name)
    def key(self,name):return 'v0'if name=='q0'else super().key(name)
    def run(self,label):
        saved=self.c;row=next(r for r in saved['spans']if r['label']==label)
        cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
        for i in cs.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
            if i.mnemonic=='movi':
                assert i.op_str=='v0.2d, #0000000000000000';self.write('q0',resize(0,128));self.count+=1
            elif i.op_str=='v0.d[0], v0.d[0]':
                assert i.mnemonic=='mov';self.count+=1
            else:
                self.c={'spans':[{'label':label,'start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run(label)
        self.c=saved;return self


def prove(c):
    queries={};pieces={};Q,T,R=z3.BitVecs('queue64 thread64 request64',64)
    E,OTHER,ID=z3.BitVecs('event64 other_event64 stored_identity64',64)
    H,A,STATE,RESULT,COUNT=z3.BitVecs('header32 accumulator32 state32 result32 selected32',32)
    IDENT,MORE=z3.BitVecs('identify8 more8',8);S=0x61000000
    def run(name,a,z,seeds,cells=()):
        o=WakeLift(part(c,name,a,z))
        for reg,v in seeds.items():o.seed(reg,v)
        for at,n,v in cells:mem(o,at,n,v)
        o.run(name);assert o.count==(z-a)//4
        pieces[name]={'start':hex(a),'end':hex(z),'instructions':o.count};return o
    o=run('direct_summary_input',0xfffffe000bd6bcec,0xfffffe000bd6bcf4,{'x25':E,'x19':Q})
    queries['direct_summary_input']=z3.Or(o.read('x28')!=E,o.read('x24')!=Q)
    o=run('registration_summary',0xfffffe000bd6bec4,0xfffffe000bd6becc,{'w8':H,'x28':E,'x24':Q})
    updated=cell(o,Q,4);summary=z3.LShR(H,5);low=resize(E,32)&0x7ffffff
    queries['registration_summary_store']=updated!=(H|(resize(E,32)<<5))
    queries['registration_preserves_low5']=(updated&31)!=(H&31)
    queries['registration_contains_event']=(low&~z3.LShR(updated,5))!=0
    o=run('summary_filter',0xfffffe000bd6c82c,0xfffffe000bd6c834,{'w8':H,'x9':E})
    passed=o.equal
    queries['source_summary_filter']=passed!=((low&~summary)==0)
    queries['summary_containment_admits_match']=z3.And((low&~summary)==0,z3.Not(passed))
    previous=z3.BitVec('previous_event64',64);oldlow=resize(previous,32)&0x7ffffff
    queries['summary_insert_preserves_previous']=z3.And((oldlow&~summary)==0,(oldlow&~z3.LShR(updated,5))!=0)
    o=run('identity_comparison',0xfffffe000bd6ce98,0xfffffe000bd6cea0,{'x1':T,'x21':Q},[(T+0x28,8,ID)])
    queries['full_identity_comparison']=o.equal!=(ID==Q)
    identity=o.equal
    o=run('event_comparison',0xfffffe000bd6cea4,0xfffffe000bd6ceb0,{'x1':T,'x19':R},[(T+0x18,8,OTHER),(R,8,E)])
    queries['full_event_comparison']=o.equal!=(OTHER==E)
    queries['full_match_conjunction']=z3.And(identity,o.equal)!=z3.And(ID==Q,OTHER==E)
    o=run('unmatched_accumulation',0xfffffe000bd6ce78,0xfffffe000bd6ce80,{'x8':OTHER,'w20':A})
    queries['unmatched_low27_OR']=o.read('w20')!=(A|(resize(OTHER,32)&0x7ffffff))
    o=run('summary_replacement',0xfffffe000bd6c888,0xfffffe000bd6c88c,{'w8':H,'w0':A})
    queries['summary_replacement']=o.read('w8')!=((H&31)|(A<<5))
    o=run('empty_summary',0xfffffe000bd6c9a8,0xfffffe000bd6c9b0,{'w8':H,'x21':Q})
    queries['empty_summary']=cell(o,Q,4)!=(H&31)
    o=run('wake_request',0xfffffe000bd6c5b8,0xfffffe000bd6c5d4,
          {'sp':S,'x1':E,'w2':0,'w3':4,'w4':0xffffffff})
    queries['request_fields']=z3.Or(cell(o,S+8,8)!=E,cell(o,S+0x10,4)!=0,cell(o,S+0x14,4)!=4,
                                    cell(o,S+0x18,4)!=0xffffffff,cell(o,S+0x1c,4)!=0,
                                    cell(o,S+0x20,16)!=0,o.read('x1')!=S+8)
    o=run('stage_publication',0xfffffe000bd6cc18,0xfffffe000bd6cc40,{'x19':T,'x20':R},
          [(R+8,4,RESULT),(R+0x14,1,IDENT),(T+0x1f8,4,STATE)])
    queries['stage_wait_identity_clear']=z3.Or(cell(o,T+0x28,8)!=0,cell(o,T+0x18,8)!=0)
    queries['stage_state_and_result']=z3.Or(cell(o,T+0x1f8,4)!=(STATE|0x100),cell(o,T+0xd8,4)!=RESULT,
                                           cell(o,T+0xcb,1)!=0,cell(o,T+0x58e,1)!=0)
    queries['stage_tests_old_state']=z3.Or(o.read('w8')!=STATE,o.read('w9')!=resize(IDENT,32))
    o=run('immediate_scheduler_argument',0xfffffe000bd6cc74,0xfffffe000bd6cc78,{'x19':T})
    queries['immediate_scheduler_argument']=o.read('x0')!=T
    o=run('deferred_scheduler_argument',0xfffffe000bd6bb80,0xfffffe000bd6bb84,{'x20':T})
    queries['deferred_scheduler_argument']=o.read('x0')!=T
    o=run('count_return',0xfffffe000bd6c640,0xfffffe000bd6c650,{'sp':S},[(S+0x20,4,COUNT),(S+0x1d,1,MORE)])
    queries['selected_plus_more_return']=o.read('w0')!=COUNT+resize(MORE&1,32)
    controls={
      'same_low27_is_not_full_event_equality':z3.And(E!=OTHER,(resize(E,32)&0x7ffffff)==(resize(OTHER,32)&0x7ffffff)),
      'summary_can_pass_without_any_full_match':z3.And(E==3,OTHER==1,previous==2,H==((3<<5)|9),passed,E!=OTHER,E!=previous),
      'missing_summary_bit_can_hide_a_match':z3.And(E==1,H==9,z3.Not(passed))}
    out={};negative={}
    for name,query in queries.items():
        solver=z3.Solver();solver.set(timeout=15000);solver.add(query);result=solver.check();assert result==z3.unsat,(name,str(result))
        out[name]={'result':str(result),'query':solver.to_smt2()}
    for name,query in controls.items():
        solver=z3.Solver();solver.set(timeout=15000);solver.add(query);assert solver.check()==z3.sat
        negative[name]={'result':'sat','query':solver.to_smt2(),'scope':'Abstract invariant/discrimination control, not native reachability.'}
    return out,negative,pieces


def build():
    k=Kernel();spans=[]
    for name,a in FUNCTIONS.items():
        r=k.function(a);r['label']=name;r['bytes_hex']=r.pop('bytes');spans.append(r)
    proofs,controls,pieces=prove({'spans':spans})
    counts={'queries_unsat':len(proofs),'controls_sat':len(controls),'source_pieces':len(pieces),
      'source_lifted_instances':sum(r['instructions']for r in pieces.values()),'spans':len(spans),
      'instructions':sum(len(r['instructions'])for r in spans)}
    counts['code_B']=counts['instructions']*4
    return {'scope':__doc__,'generator_sha256':sha(__file__),'kernel_collection_sha256':k.sha256,
      'dependencies':{n:sha(ROOT/n)for n in DEPS},'spans':spans,'exact_symbols':k.symbols(FUNCTIONS.values()),
      'proofs':proofs,'negative_controls':controls,'source_pieces':pieces,'verified_counts':counts,
      'new_IDA_access':False,'new_native_execution':False,'new_IDB_mutations':False,'full_goal_complete':False}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--verify',action='store_true');args=parser.parse_args()
    result=build();path=ROOT/'aes_event_wake_selection_checks.json'
    if args.verify:assert json.loads(read(path))==result
    else:path.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result['verified_counts']),flush=True)
