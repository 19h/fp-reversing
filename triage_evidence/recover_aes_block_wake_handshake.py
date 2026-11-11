#!/usr/bin/env python3
"""Original block/wake state, counter-pair and placement handoff contracts.

Disjoint fixed symbolic cells and declared single-RMW observations only. Native
switching, locking, scheduling, time calibration and interleavings are unknown.
O(B+I+P) source time/space; SMT cost separate. No target or IDB operation.
"""
import argparse
import json
import z3
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from kernel_native_reader import Kernel
from kext_port_tools import ROOT
from recover_aes_event_wake_selection import WakeLift
from lskd_values_symbolic import resize, part, mem, cell
from verify_daemon_reader_record_payloads_publication import read, sha

G=0xfffffe000cad06a0
FUNCTIONS={'wake_state':0xfffffe000bd26ba8,'placement':0xfffffe000bd27054,'block':0xfffffe000bd28f6c,
 'invoke':0xfffffe000bd2a064,'post_switch':0xfffffe000bd2a8b8,'count_increment':0xfffffe000bd22370,
 'count_decrement':0xfffffe000bd1e688,'mark_wait':0xfffffe000bd28280}
DEPS=['kernel_native_reader.py','kext_port_tools.py','recover_aes_event_wake_selection.py',
 'recover_event_wait_table.py','lskd_values_symbolic.py','aes_event_wake_selection_checks.json',
 'aes_event_registration_checks.json','verify_daemon_reader_record_payloads_publication.py']


class HandshakeLift(WakeLift):
    def write(self,name,value):
        if name in ['q0','v0']:
            self.regs['v0']=resize(value,128);self.values[(getattr(self,'pc',0),name)]=resize(value,128)
        else:super().write(name,value)

    def condition_value(self,name):
        if name in ['eq','ne']:return self.equal if name=='eq'else z3.Not(self.equal)
        return {'hi':z3.UGT,'hs':z3.UGE,'lo':z3.ULT,'ls':z3.ULE}[name](self.cmp_left,self.cmp_right)

    def run(self,label):
        saved=self.c;row=next(r for r in saved['spans']if r['label']==label)
        cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
        for i in cs.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
            self.pc=i.address;m,o=i.mnemonic,i.operands
            if m in ['csel','csinv','cset']:
                cond=self.condition_value(i.op_str.rsplit(',',1)[1].strip());dest=i.reg_name(o[0].reg)
                if m=='cset':value=z3.If(cond,resize(1,self.width(dest)),resize(0,self.width(dest)))
                else:
                    a=self.read(i.reg_name(o[1].reg));b=self.read(i.reg_name(o[2].reg))
                    value=z3.If(cond,a,b if m=='csel'else ~b)
                self.write(dest,value);self.count+=1
            elif m=='subs':
                dest=i.reg_name(o[0].reg);n=self.width(dest);a=self.operand(i,o[1],n);b=self.operand(i,o[2],n)
                self.write(dest,a-b);self.cmp_left=a;self.cmp_right=b;self.equal=a==b;self.count+=1
            elif m=='ldadd':
                src=i.reg_name(o[0].reg);dest=i.reg_name(o[1].reg);n=self.width(src)//8;at=self.address(i,o[2])
                old=self.load(at,n);self.store(at,n,old+self.read(src),i.address);self.write(dest,old);self.count+=1
            elif m=='casp':
                assert i.op_str in ['x4, x5, x6, x7, [x10]','x4, x5, x2, x3, [x12]']
                at=self.address(i,o[4]);old=self.load(at,16)
                expected=z3.Concat(self.read(i.reg_name(o[1].reg)),self.read(i.reg_name(o[0].reg)))
                desired=z3.Concat(self.read(i.reg_name(o[3].reg)),self.read(i.reg_name(o[2].reg)))
                self.store(at,16,z3.If(old==expected,desired,old),i.address)
                self.write(i.reg_name(o[0].reg),z3.Extract(63,0,old));self.write(i.reg_name(o[1].reg),z3.Extract(127,64,old));self.count+=1
            elif m=='movi'and i.op_str=='v0.2d, #0xffffffffffffffff':
                self.write('q0',resize(-1,128));self.count+=1
            else:
                self.c={'spans':[{'label':label,'start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run(label)
        self.c=saved;return self


def prove(c):
    q={};pieces={};T,U,P=z3.BitVecs('thread64 cpu_context64 pair_cell64',64)
    S,G0=z3.BitVecs('thread_state32 scheduler_count32',32)
    C,H,NOW,OLD,TOTAL=z3.BitVecs('pair_count64 pair_epoch64 raw_now64 old_epoch64 accumulated64',64)
    def run(name,a,z,seeds,cells=()):
        o=HandshakeLift(part(c,name,a,z))
        for r,v in seeds.items():o.seed(r,v)
        for at,n,v in cells:mem(o,at,n,v)
        o.run(name);assert o.count==(z-a)//4;pieces[name]={'start':hex(a),'end':hex(z),'instructions':o.count};return o
    wake=run('wake_state_store',0xfffffe000bd26c30,0xfffffe000bd26c44,{'x19':T},[(T+0x1f8,4,S)])
    W=cell(wake,T+0x1f8,4);expected=(S&0xfffffeb2)|4
    q['wake_state_rewrite']=W!=expected
    q['wake_clears_bits_0_3_6_8']=(W&0x149)!=0
    q['wake_sets_bit2']=(W&4)!=4
    q['wake_preserves_other_bits']=(W&0xfffffeb2)!=(S&0xfffffeb2)
    q['wake_branch_uses_old_state']=wake.read('w23')!=S
    dispatch=run('block_state_choice',0xfffffe000bd2ac88,0xfffffe000bd2ac9c,{'w8':S})
    D=z3.If((S&0x30)==0x10,S|0x20,S)&0xfffffffb
    q['post_switch_state_choice']=z3.Or(dispatch.read('w27')!=z3.If((S&0x30)==0x10,S|0x20,S),
                                              dispatch.read('w22')!=z3.If((S&0x30)==0x10,resize(1,32),resize(0,32)))
    o=run('block_state_publication',0xfffffe000bd2ac9c,0xfffffe000bd2acc8,{'x19':U,'x21':T,'w27':dispatch.read('w27')},
          [(U+0x70,8,NOW),(T+0x328,8,OLD),(T+0x330,8,TOTAL)])
    q['post_switch_clear_bit2']=cell(o,T+0x1f8,4)!=D
    q['post_switch_retains_wait_bit']=(cell(o,T+0x1f8,4)&1)!=(S&1)
    q['post_switch_runtime_accumulation']=cell(o,T+0x330,8)!=TOTAL+NOW-OLD
    q['post_switch_timestamp_sentinel']=z3.Or(cell(o,T+0x270,16)!=resize(-1,128),cell(o,T+0x2b0,8)!=0)
    inc=run('global_increment',0xfffffe000bd22374,0xfffffe000bd22384,{},{(G,4,G0)})
    dec=run('global_decrement',0xfffffe000bd1e68c,0xfffffe000bd1e69c,{},{(G,4,G0)})
    q['global_increment']=z3.Or(cell(inc,G,4)!=G0+1,inc.read('w8')!=G0)
    q['global_decrement']=z3.Or(cell(dec,G,4)!=G0-1,dec.read('w8')!=G0)
    q['global_decrement_increment_balance']=(G0-1)+1!=G0
    q['positive_global_pair_no_wrap']=z3.And(G0!=0,z3.Or(z3.UGT(G0-1,G0),z3.UGT(z3.ZeroExt(32,G0-1)+1,0xffffffff)))
    o=run('pair_increment_desired',0xfffffe000bd223bc,0xfffffe000bd223d0,{'x4':C,'x5':H})
    q['pair_increment_desired']=z3.Or(o.read('x6')!=C+1,o.read('x7')!=z3.If(C!=0,H,resize(-1,64)))
    o=run('pair_decrement_desired',0xfffffe000bd1e6e8,0xfffffe000bd1e6f4,{'x12':P,'x10':NOW},[(P,8,C),(P+8,8,H)])
    q['pair_decrement_desired']=z3.Or(o.read('x2')!=C-1,o.read('x3')!=z3.If(C==1,NOW,H))
    LO,HI,OBS_LO,OBS_HI,NEW_LO,NEW_HI=z3.BitVecs('expected_low64 expected_high64 observed_low64 observed_high64 desired_low64 desired_high64',64)
    for name,a,z,addr,seeds in [
      ('increment_casp',0xfffffe000bd223d4,0xfffffe000bd223e0,'x10',{'x2':LO,'x3':HI,'x6':NEW_LO,'x7':NEW_HI}),
      ('decrement_casp',0xfffffe000bd1e708,0xfffffe000bd1e714,'x12',{'x0':LO,'x1':HI,'x2':NEW_LO,'x3':NEW_HI})]:
        o=run(name,a,z,{addr:P,**seeds},[(P,16,z3.Concat(OBS_HI,OBS_LO))])
        expected=z3.If(z3.And(LO==OBS_LO,HI==OBS_HI),z3.Concat(NEW_HI,NEW_LO),z3.Concat(OBS_HI,OBS_LO))
        q[name+'_write']=cell(o,P,16)!=expected
        q[name+'_observations']=z3.Or(o.read('x4')!=OBS_LO,o.read('x5')!=OBS_HI)
    d_hi=z3.If(C==1,NOW,H);reinc_hi=z3.If(C-1!=0,d_hi,resize(-1,64))
    q['pair_count_balance']=(C-1)+1!=C
    q['pair_last_stop_then_start_epoch']=z3.And(C==1,reinc_hi!=resize(-1,64))
    q['pair_nonlast_epoch_preserved']=z3.And(C!=1,reinc_hi!=H)
    # Source state cuts compose only over a matched, disjoint, no-writer epoch.
    waitmask=z3.BitVec('normal_wait_mask32',32);ordinary=z3.Or(waitmask==1,waitmask==9)
    marked=resize(4,32)|waitmask
    first_wake=(marked|0x100)&0xfffffeb2|4
    blocked=z3.If((marked&0x30)==0x10,marked|0x20,marked)&0xfffffffb
    later_wake=(blocked|0x100)&0xfffffeb2|4
    q['ordinary_before_switch_state4']=z3.And(ordinary,first_wake!=4)
    q['ordinary_after_switch_state4']=z3.And(ordinary,later_wake!=4)
    q['ordinary_early_wake_selects_requeue']=z3.And(ordinary,(first_wake&1)!=0)
    q['ordinary_blocked_state_bit2_clear']=z3.And(ordinary,z3.Or((blocked&1)==0,(blocked&4)!=0))
    q['ordinary_wake_epoch_join']=z3.And(ordinary,first_wake!=later_wake)
    o=run('block_continuation_store',0xfffffe000bd29008,0xfffffe000bd29010,{'x19':T,'x21':0,'x23':0},[(T+0x1f8,4,S)])
    q['null_block_continuations']=z3.Or(cell(o,T+0xe0,8)!=0,cell(o,T+0xe8,8)!=0)
    o=run('block_result_load',0xfffffe000bd29054,0xfffffe000bd29058,{'x19':T},[(T+0xd8,4,G0)])
    q['block_returns_wait_result']=o.read('w0')!=G0
    o=run('immediate_placement_arguments',0xfffffe000bd6cc80,0xfffffe000bd6cc88,{'x19':T})
    q['immediate_placement_arguments']=z3.Or(o.read('x0')!=T,o.read('w1')!=5)
    o=run('deferred_placement_arguments',0xfffffe000bd6bb8c,0xfffffe000bd6bb94,{'x20':T})
    q['deferred_placement_arguments']=z3.Or(o.read('x0')!=T,o.read('w1')!=5)
    CALLBACK=z3.BitVec('thread_callback64',64)
    for name,a,z,reg,code in [('block_callback',0xfffffe000bd2ad18,0xfffffe000bd2ad28,'x21',1),
                             ('wake_callback',0xfffffe000bd26ca8,0xfffffe000bd26cb8,'x19',2)]:
        o=run(name,a,z,{reg:T},[(T+0x2d8,8,CALLBACK)])
        q[name+'_ABI']=z3.Or(o.read('x8')!=CALLBACK,o.read('w0')!=code,o.read('x1')!=T,o.read('x17')!=0xae56)
    controls={
      'auxiliary_state_can_distinguish_orders':z3.And((S&5)==5,(S&0x30)==0x10,
          ((S|0x100)&0xfffffeb2|4)!=((D|0x100)&0xfffffeb2|4)),
      'decrement_zero_wraps':z3.And(G0==0,G0-1==0xffffffff),
      'pair_compare_requires_epoch':z3.And(LO==OBS_LO,HI!=OBS_HI,z3.Concat(LO,HI)!=z3.Concat(OBS_LO,OBS_HI)),
      'wake_state_not_enough_for_placement':z3.And((S&4)==0,W==4)}
    proofs={};negative={}
    for name,query in q.items():
        solver=z3.Solver();solver.set(timeout=15000);solver.add(query);result=solver.check();assert result==z3.unsat,(name,str(result))
        proofs[name]={'result':'unsat','query':solver.to_smt2()}
    for name,query in controls.items():
        solver=z3.Solver();solver.set(timeout=15000);solver.add(query);assert solver.check()==z3.sat,(name,solver.reason_unknown())
        negative[name]={'result':'sat','query':solver.to_smt2(),'scope':'Abstract premise/discrimination control; no native reachability claim.'}
    return proofs,negative,pieces


def build():
    k=Kernel();spans=[]
    for name,a in FUNCTIONS.items():
        r=k.function(a);r['label']=name;r['bytes_hex']=r.pop('bytes');spans.append(r)
    # The preceding source archive also pins the two wake callers and stage ABI.
    old=json.loads(read(ROOT/'aes_event_wake_selection_checks.json'))
    for name in ['stage','drain']:spans.append(next(r for r in old['spans']if r['label']==name))
    proofs,controls,pieces=prove({'spans':spans})
    counts={'queries_unsat':len(proofs),'controls_sat':len(controls),'source_pieces':len(pieces),
      'source_lifted_instances':sum(r['instructions']for r in pieces.values()),'spans':len(spans),
      'instructions':sum(len(r['instructions'])for r in spans)}
    counts['code_B']=counts['instructions']*4
    return {'scope':__doc__,'generator_sha256':sha(__file__),'kernel_collection_sha256':k.sha256,
      'dependencies':{p:sha(ROOT/p)for p in DEPS},'spans':spans,'exact_symbols':k.symbols(int(r['start'],16)for r in spans),
      'proofs':proofs,'negative_controls':controls,'source_pieces':pieces,'verified_counts':counts,
      'new_IDA_access':False,'new_native_execution':False,'new_IDB_mutations':False,'full_goal_complete':False}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--verify',action='store_true');args=parser.parse_args()
    out=build();p=ROOT/'aes_block_wake_handshake_checks.json'
    if args.verify:assert json.loads(read(p))==out
    else:p.write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps(out['verified_counts']),flush=True)
