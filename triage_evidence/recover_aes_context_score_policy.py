#!/usr/bin/env python3
"""Original context-score policy arithmetic, paired updates and wake producer.

Fixed cells, stable scalar snapshots and one CASP observation per source cut.
Loop liveness, native clock units, scheduling and concurrent ordering remain
unknown. O(B+I+P) source time/space; SMT cost separate. No target or IDB runs.
"""
import argparse
import json
import z3
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from kernel_native_reader import Kernel
from kext_port_tools import ROOT
from recover_aes_uncached_context_queue import ContextLift
from lskd_values_symbolic import resize, part, mem, cell
from verify_daemon_reader_record_payloads_publication import read, sha

SCORE=0xfffffe000bd1ec40
FUNCTIONS={'score':SCORE,'count_increment':0xfffffe000bd22370,
 'backend':0xfffffe000bd207c4,'context_rekey':0xfffffe000bd1ea3c,
 'configuration':0xfffffe000bd24c94,'time_table_converter':0xfffffe000bd21468}
GLOBAL_EXTENTS={0xfffffe000cb62868:8,0xfffffe000cb62870:48,
 0xfffffe000cb62900:48,0xfffffe000cb62930:24,0xfffffe000ca9068c:1,
 0xfffffe000ca90690:24,0xfffffe000ca906a8:24,0xfffffe000ca906c0:24,
 0xfffffe000ca906d8:24,0xfffffe000ca8c000:4,0xfffffe000704ec40:42}
PUBLIC_SOURCE={'url':'https://raw.githubusercontent.com/apple-oss-distributions/xnu/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/sched_clutch.c',
 'sha256':'0a4c7c24704ebc0dc1f3e950103b3896a4a6308ccee31d2783818f53e6b405c0','size_B':241161,
 'scope':'Primary-source semantic comparison only. Exact compiled version, configuration and symbol identity are unknown.'}
DEPS=['kernel_native_reader.py','kext_port_tools.py','recover_aes_uncached_context_queue.py',
 'recover_aes_cached_class_queue.py','recover_aes_runqueue_membership.py',
 'recover_aes_block_wake_handshake.py','recover_aes_event_wake_selection.py',
 'recover_event_wait_table.py','lskd_values_symbolic.py','aes_uncached_context_queue_checks.json',
 'aes_block_wake_handshake_checks.json','verify_daemon_reader_record_payloads_publication.py']


def udiv(a,b):return z3.If(b==0,resize(0,a.size()),z3.UDiv(a,b))


class PolicyLift(ContextLift):
    def run(self,label):
        saved=self.c;row=next(r for r in saved['spans']if r['label']==label)
        cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
        for i in cs.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
            self.pc=i.address;m,o=i.mnemonic,i.operands
            if m=='sxtw':
                self.write(i.reg_name(o[0].reg),z3.SignExt(32,resize(self.read(i.reg_name(o[1].reg)),32)));self.count+=1
            elif m=='udiv':
                self.write(i.reg_name(o[0].reg),udiv(self.read(i.reg_name(o[1].reg)),self.read(i.reg_name(o[2].reg))));self.count+=1
            else:
                self.c={'spans':[{'label':label,'start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run(label)
        self.c=saved;return self


def prove(c):
    q={};pieces={};A,X,T,D=z3.BitVecs('auxiliary64 context64 thread64 owner64',64)
    N=z3.BitVec('active_count32',32);P=z3.BitVec('policy8',8)
    U,V,E,NOW,PERIOD,BASE,SCALE,DELTA,CACHED,STAMP,LIMIT=z3.BitVecs(
      'account_u64 account_v64 epoch64 now64 period64 period_base64 period_scale64 delta64 cached_offset64 cache_stamp64 threshold64',64)
    K,DIV=z3.BitVecs('elapsed_periods8 divisor8',8);C=z3.BitVec('queue_count64',64)
    def run(name,a,z,seeds,cells=()):
        o=PolicyLift(part(c,name,a,z))
        for r,v in seeds.items():o.seed(r,v)
        for at,n,v in cells:mem(o,at,n,v)
        o.run(name);assert o.count==(z-a)//4;pieces[name]={'start':hex(a),'end':hex(z),'instructions':o.count};return o
    o=run('empty_context_return',0xfffffe000bd1ecf4,0xfffffe000bd1ecf8,{})
    q['empty_context_return']=o.read('w19')!=0
    o=run('active_counter_read',0xfffffe000bd1ec74,0xfffffe000bd1ec80,{'w11':resize(P,32)},[(0xfffffe000cb62930+(resize(P,64)<<2),4,N)])
    q['active_counter_read']=o.read('w12')!=N
    o=run('active_counter_sign_extension',0xfffffe000bd1ec84,0xfffffe000bd1ec88,{'w12':N})
    q['active_counter_sign_extension']=o.read('x12')!=z3.SignExt(32,N)
    o=run('period_formula',0xfffffe000bd1eca4,0xfffffe000bd1ecb0,
      {'x13':0xfffffe000cb62900,'x14':0xfffffe000cb62870,'x11':resize(P,64),'x12':z3.SignExt(32,N)},
      [(0xfffffe000cb62900+(resize(P,64)<<3),8,BASE),(0xfffffe000cb62870+(resize(P,64)<<3),8,SCALE)])
    q['period_formula_modular']=o.read('x16')!=BASE+SCALE*z3.SignExt(32,N)
    o=run('elapsed_comparison',0xfffffe000bd1ec9c,0xfffffe000bd1eca0,{'x1':NOW,'x3':E})
    q['elapsed_subtraction']=z3.Or(o.read('x15')!=NOW-E,o.condition_value('ls')!=z3.ULE(NOW,E))
    o=run('period_quantization',0xfffffe000bd1ecb8,0xfffffe000bd1ecc8,{'x15':DELTA,'x16':PERIOD,'x3':E,'x4':C})
    low=resize(resize(udiv(DELTA,PERIOD),8),64)
    q['period_quotient_low8']=z3.Or(o.read('x15')!=udiv(DELTA,PERIOD),o.read('x17')!=low)
    q['period_epoch_uses_low8']=z3.Or(o.read('x5')!=E+low*PERIOD,o.read('x2')!=C)
    for name,pc,atreg,expected_regs,desired_regs in [
      ('period_pair',0xfffffe000bd1ecd4,'x16',('x6','x7'),('x4','x5')),
      ('account_pair',0xfffffe000bd1ed88,'x15',('x6','x7'),('x4','x5')),
      ('cache_pair',0xfffffe000bd1edf8,'x12',('x4','x5'),('x0','x1'))]:
        OBS=z3.BitVec(name+'_observed128',128);L0,L1,R0,R1=z3.BitVecs(name+'_expected_low64 '+name+'_expected_high64 '+name+'_desired_low64 '+name+'_desired_high64',64)
        seeds={atreg:A,expected_regs[0]:L0,expected_regs[1]:L1,desired_regs[0]:R0,desired_regs[1]:R1}
        o=run(name,pc,pc+4,seeds,[(A,16,OBS)])
        q[name+'_full_casp']=z3.Or(cell(o,A,16)!=z3.If(OBS==z3.Concat(L1,L0),z3.Concat(R1,R0),OBS),
          o.read(expected_regs[0])!=z3.Extract(63,0,OBS),o.read(expected_regs[1])!=z3.Extract(127,64,OBS))
    o=run('account_inputs',0xfffffe000bd1ed08,0xfffffe000bd1ed14,{'x10':A},
      [(A+0x50,8,U),(A+0x58,8,V),(0xfffffe000cb62868,8,LIMIT)])
    q['account_pair_and_threshold_inputs']=z3.Or(o.read('x2')!=U,o.read('x3')!=V,o.read('x12')!=LIMIT)
    o=run('account_setup',0xfffffe000bd1ed14,0xfffffe000bd1ed2c,
      {'w11':resize(K,32),'x2':U,'x3':V},[(0xfffffe000ca9068c,1,DIV)])
    q['account_setup_literal_divisor_sum']=z3.Or(o.read('x13')!=resize(K,64),o.read('x14')!=0xcccccccccccccccd,
      o.read('w11')!=resize(DIV,32),o.read('x15')!=U+V)
    o=run('account_normalization',0xfffffe000bd1ed38,0xfffffe000bd1ed54,
      {'x2':U,'x3':V,'x14':0xcccccccccccccccd,'x15':U+V,'x12':LIMIT})
    high=lambda x:z3.Extract(127,64,z3.ZeroExt(64,x)*resize(0xcccccccccccccccd,128))
    normalized_u=z3.If(z3.ULT(U+V,LIMIT),U,z3.LShR(high(U),3))
    normalized_v=z3.If(z3.ULT(U+V,LIMIT),V,z3.LShR(high(V),3))
    q['account_normalization']=z3.Or(o.read('x15')!=normalized_u,o.read('x5')!=normalized_v)
    iq,ir=z3.Ints('divide10_quotient divide10_remainder');ix=10*iq+ir;magic=0xcccccccccccccccd;power=1<<67
    q['divide10_identity_lemma']=z3.And(iq>=0,ir>=0,ir<10,ix<(1<<64),z3.Or(ix*magic<iq*power,ix*magic>=(iq+1)*power))
    o=run('account_update_candidate',0xfffffe000bd1ed54,0xfffffe000bd1ed7c,
      {'x15':U,'x5':V,'x13':resize(K,64),'x11':resize(DIV,64)})
    sub=udiv(V*resize(K,64),resize(DIV,64));sat=z3.If(z3.ULT(U,sub),resize(0,64),U-sub)
    weighted=udiv((V*resize(DIV,64))*U,U*resize(K,64)+V*resize(DIV,64))
    q['account_subtraction_saturates']=o.read('x16')!=sat
    q['account_weighted_candidate']=o.read('x17')!=weighted
    q['account_candidate_selection']=o.read('x4')!=z3.If(z3.UGE(V,U),sat,weighted)
    o=run('offset_v_larger',0xfffffe000bd1edb4,0xfffffe000bd1edc0,{'x14':V-U,'x11':resize(DIV,64),'x12':V})
    q['offset_v_larger']=o.read('w11')!=resize(resize(DIV,64)+udiv((V-U)*resize(DIV,64),V),32)
    o=run('offset_u_at_least_v',0xfffffe000bd1edcc,0xfffffe000bd1edd4,{'x12':V,'x13':U,'x11':resize(DIV,64)})
    q['offset_u_at_least_v']=o.read('x11')!=udiv(V*resize(DIV,64),U)
    o=run('offset_both_zero',0xfffffe000bd1edc4,0xfffffe000bd1edc8,{'x10':A},[(A+0x40,1,DIV)])
    q['offset_both_zero_uses_cached_byte']=o.read('w11')!=resize(DIV,32)
    o=run('cache_timestamp_comparison',0xfffffe000bd1edd4,0xfffffe000bd1ede0,
      {'x10':A,'x11':resize(K,64),'x1':NOW},[(A+0x40,8,CACHED),(A+0x48,8,STAMP)])
    q['cache_timestamp_comparison']=z3.Or(o.read('x2')!=CACHED,o.read('x3')!=STAMP,o.condition_value('hs')!=z3.UGE(STAMP,NOW))
    o=run('cache_first_stamp_selection',0xfffffe000bd1ede4,0xfffffe000bd1edec,{'x3':STAMP,'x2':CACHED,'x11':resize(K,64)})
    q['cache_first_stamp_selection']=o.read('x0')!=z3.If(STAMP==0,CACHED,resize(K,64))
    B=z3.BitVec('root_priority8',8)
    o=run('score_addition',0xfffffe000bd1ee10,0xfffffe000bd1ee18,{'w9':resize(B,32),'w0':resize(CACHED,32),'x8':X},[(X+0xc1,1,K)])
    o=run('score_byte_return',0xfffffe000bd1ee2c,0xfffffe000bd1ee30,{'w19':o.read('w19')})
    q['score_return_low8']=o.read('w0')!=resize(B+resize(CACHED,8),32)
    o=run('wake_record_selection',0xfffffe000bd223a0,0xfffffe000bd223b8,{'x0':T},[(T+0x204,1,P),(T+0x298,8,D)])
    q['wake_uses_same_auxiliary_record']=o.read('x9')!=D+0x60+112*resize(P,64)
    o=run('wake_time_addition',0xfffffe000bd22428,0xfffffe000bd22440,{'x10':DELTA,'x9':A},[(0xfffffe000cb62868,8,LIMIT),(A+0x58,8,V)])
    q['wake_updates_policy_v']=cell(o,A+0x58,8)!=V+z3.If(z3.ULT(DELTA,LIMIT),DELTA,LIMIT)
    o=run('configuration_option_arguments',0xfffffe000bd24ca0,0xfffffe000bd24cc4,{},[(0xfffffe0007f8b6e8,8,A)])
    q['configuration_option_arguments']=z3.Or(o.read('x0')!=A+0x6c,o.read('x1')!=0xfffffe000704ec40,
      o.read('x2')!=0xfffffe000ca9068c,o.read('w3')!=1,o.read('w4')!=0)
    o=run('configuration_default_divisor',0xfffffe000bd24ccc,0xfffffe000bd24cd8,{})
    q['configuration_default_divisor']=cell(o,0xfffffe000ca9068c,1)!=8
    F=z3.BitVec('frequency_scalar32',32)
    o=run('configuration_threshold',0xfffffe000bd24d18,0xfffffe000bd24d30,{},[(0xfffffe000ca8c000,4,F)])
    q['configuration_threshold']=cell(o,0xfffffe000cb62868,8)!=z3.LShR(resize(F,64),1)
    for name,pc,source,dest in [('deadline',0xfffffe000bd24cdc,0xfffffe000ca90690,0xfffffe000cb628d0),
      ('warp',0xfffffe000bd24cf0,0xfffffe000ca906a8,0xfffffe000cb628a0),
      ('quantum',0xfffffe000bd24d04,0xfffffe000ca906c0,0xfffffe000cb62870),
      ('pending',0xfffffe000bd24d30,0xfffffe000ca906d8,0xfffffe000cb62900)]:
        o=run('configuration_'+name+'_arguments',pc,pc+16,{})
        q['configuration_'+name+'_arguments']=z3.Or(o.read('x0')!=source,o.read('x1')!=dest)
    proofs={};controls={}
    for name,query in q.items():
        s=z3.Solver();s.set(timeout=15000);s.add(query);result=s.check();assert result==z3.unsat,(name,str(result),s.reason_unknown())
        proofs[name]={'result':'unsat','query':s.to_smt2()}
    cases={'period_low8_is_not_full_advance':z3.And(DELTA==256,PERIOD==1,resize(resize(udiv(DELTA,PERIOD),8),64)*PERIOD!=DELTA),
      'zero_divisor_is_not_z3_total_division':z3.And(DELTA==7,PERIOD==0,udiv(DELTA,PERIOD)!=z3.UDiv(DELTA,PERIOD)),
      'normalization_gate_uses_modular_sum':z3.And(U==(1<<64)-1,V==1,LIMIT==10,z3.ULT(U+V,LIMIT)),
      'fresh_cache_can_override_candidate':z3.And(STAMP==NOW,CACHED==3,K==8,resize(CACHED,8)!=K)}
    for name,query in cases.items():
        s=z3.Solver();s.add(query);assert s.check()==z3.sat
        controls[name]={'result':'sat','query':s.to_smt2(),'scope':'Abstract arithmetic discriminator; no native reachability claim.'}
    return proofs,controls,pieces


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
      'file_global_observations':[{'address':hex(a),'size_B':n,'bytes_hex':k.read(a,n).hex()}for a,n in GLOBAL_EXTENTS.items()],
      'public_source_reference':PUBLIC_SOURCE,
      'proofs':proofs,'negative_controls':controls,'source_pieces':pieces,'verified_counts':counts,
      'new_IDA_access':False,'new_native_execution':False,'new_IDB_mutations':False,'full_goal_complete':False}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--verify',action='store_true');args=p.parse_args()
    out=build();path=ROOT/'aes_context_score_policy_checks.json'
    if args.verify:assert json.loads(read(path))==out
    else:path.write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps(out['verified_counts']),flush=True)
