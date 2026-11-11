#!/usr/bin/env python3
"""Original uncached placement lanes, embedded nodes and context accounting.

Fixed disjoint cells, declared policy-off epochs and scalar RMW observations
only. Native range admission, ownership, atomic ordering and scheduling are
unknown. O(B+I+P) source time/space; SMT cost separate. No target or IDB runs.
"""
import argparse
import json
import z3
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_EXT_UXTB
from kernel_native_reader import Kernel
from kext_port_tools import ROOT
from recover_aes_cached_class_queue import CachedLift
from lskd_values_symbolic import resize, part, mem, cell
from verify_daemon_reader_record_payloads_publication import read, sha

FUNCTIONS={'backend':0xfffffe000bd207c4,'paired_constructor':0xfffffe000bd212b0,
 'initializer':0xfffffe000bd2d3cc,'score':0xfffffe000bd1ec40,'generic_select':0xfffffe000bd1efa8,
 'refresh':0xfffffe000bd1ee74,'deadline_merge':0xfffffe000c48b7c0,
 'thread_merge':0xfffffe000c48bb48,'priority_merge':0xfffffe000c48b42c,
 'context_rekey':0xfffffe000bd1ea3c,'priority_raise':0xfffffe000c48b730}
DEPS=['kernel_native_reader.py','kext_port_tools.py','recover_aes_cached_class_queue.py',
 'recover_aes_runqueue_membership.py','recover_aes_block_wake_handshake.py',
 'recover_aes_event_wake_selection.py','recover_event_wait_table.py','lskd_values_symbolic.py',
 'aes_cached_class_queue_checks.json','aes_runqueue_membership_checks.json',
 'verify_daemon_reader_record_payloads_publication.py']


class ContextLift(CachedLift):
    def operand(self,i,o,n):
        if o.ext==ARM64_EXT_UXTB:
            assert not o.shift.type;return resize(self.read(i.reg_name(o.reg)),n)&255
        return super().operand(i,o,n)

    def run(self,label):
        saved=self.c;row=next(r for r in saved['spans']if r['label']==label)
        cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
        for i in cs.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
            self.pc=i.address;m,o=i.mnemonic,i.operands
            if m in ['str','stp']and i.writeback:
                index=1 if m=='str'else 2;base=i.reg_name(o[index].mem.base);at=self.address(i,o[index])
                for j in range(index):
                    src=i.reg_name(o[j].reg);n=self.width(src)//8;self.store(at+j*n,n,self.read(src),i.address)
                self.write(base,at);self.count+=1
            elif m=='sxth':
                dest=i.reg_name(o[0].reg);self.write(dest,z3.SignExt(self.width(dest)-16,resize(self.read(i.reg_name(o[1].reg)),16)));self.count+=1
            elif m=='ubfx':
                dest=i.reg_name(o[0].reg);v=self.read(i.reg_name(o[1].reg))
                self.write(dest,z3.Extract(o[2].imm+o[3].imm-1,o[2].imm,v));self.count+=1
            elif m=='ldset':
                at=self.address(i,o[2]);old=self.load(at,8);self.store(at,8,old|self.read(i.reg_name(o[0].reg)),i.address)
                self.write(i.reg_name(o[1].reg),old);self.count+=1
            elif m=='casp':
                at=self.address(i,o[4]);old=self.load(at,16)
                expected=z3.Concat(self.read(i.reg_name(o[1].reg)),self.read(i.reg_name(o[0].reg)))
                desired=z3.Concat(self.read(i.reg_name(o[3].reg)),self.read(i.reg_name(o[2].reg)))
                self.store(at,16,z3.If(old==expected,desired,old),i.address)
                self.write(i.reg_name(o[0].reg),z3.Extract(63,0,old));self.write(i.reg_name(o[1].reg),z3.Extract(127,64,old));self.count+=1
            else:
                self.c={'spans':[{'label':label,'start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run(label)
        self.c=saved;return self


def prove(c):
    q={};pieces={};X,T,R,A,G,TAIL=z3.BitVecs('context64 thread64 parent64 auxiliary64 generic_record64 tail64',64)
    L=z3.BitVec('lane32',32);CLASS,TYPE,MARK,BASE,OFFSET=z3.BitVecs('class8 type8 marker8 base_priority8 offset8',8)
    P=z3.BitVec('primary_priority16',16);FLAGS=z3.BitVec('flags32',32);NOW=z3.BitVec('raw_now64',64);SP=0x61000000
    def run(name,a,z,seeds,cells=()):
        o=ContextLift(part(c,name,a,z))
        for reg,v in seeds.items():o.seed(reg,v)
        for at,n,v in cells:mem(o,at,n,v)
        o.run(name);assert o.count==(z-a)//4;pieces[name]={'start':hex(a),'end':hex(z),'instructions':o.count};return o
    lane64=resize(L,64);raw_lane=resize((L<<3)|(L<<5),64)
    o=run('lane_node_geometry',0xfffffe000bd20b18,0xfffffe000bd20b30,{'x22':X,'w28':L},[(X+0x30+raw_lane,1,MARK)])
    q['lane_node_geometry']=z3.And(z3.ULE(L,2),z3.Or(o.read('x19')!=X+0x18,o.read('x21')!=0x20+40*lane64,o.read('w8')!=resize(MARK,32)))
    q['three_lane_extent']=z3.And(z3.ULE(L,2),z3.UGT(0x18+40*lane64+40,0x90))
    o=run('primary_node_pack',0xfffffe000bd20b54,0xfffffe000bd20b7c,{'x20':T,'x11':NOW,'sp':SP},[(T+0x214,2,P),(SP+0x3c,4,FLAGS)])
    key=(resize(P,64)&255)<<8|resize((FLAGS&1)^1,64)
    q['primary_node_zero_links']=z3.Or(cell(o,T+0x60,8)!=0,cell(o,T+0x68,8)!=0,o.read('x25')!=T+0x60)
    q['primary_node_key_time']=z3.Or(cell(o,T+0x70,8)!=key,cell(o,T+0x78,8)!=NOW)
    OLD=z3.BitVec('old_primary_rank32',32)
    o=run('primary_rank_comparison',0xfffffe000bd20b90,0xfffffe000bd20ba4,{'x9':key,'w27':OLD})
    q['primary_rank_extraction']=z3.And(z3.ULE(P,95),o.read('w10')!=resize(P,32))
    expected=z3.If(resize(P,32)<OLD,resize(-1,32),z3.If(resize(P,32)>OLD,resize(1,32),resize(0,32)))
    q['primary_rank_comparison']=z3.And(z3.ULE(P,95),o.read('w8')!=expected)
    o=run('parent_lane_bucket',0xfffffe000bd20bb4,0xfffffe000bd20bdc,{'x22':X,'x26':R,'w28':L,'sp':SP},[(X+0xc0,1,CLASS),(X+0xc4,1,TYPE)])
    bucket=R+0x878+168*lane64+56*resize(TYPE,64)
    q['parent_lane_bucket']=z3.Or(o.read('x26')!=bucket,o.read('w21')!=resize(CLASS,32))
    q['parent_lane_bucket_extent']=z3.And(z3.ULE(L,2),z3.ULE(TYPE,2),z3.ULE(CLASS,5),z3.UGT(0x878+168*lane64+56*resize(TYPE,64)+8*resize(CLASS,64)+8,0xa70))
    META=z3.BitVec('lane_metadata16',16);N=z3.BitVec('lane_node64',64)
    o=run('lane_node_prepare',0xfffffe000bd20c24,0xfffffe000bd20c30,{'x24':N},[(N+0x10,2,META)])
    q['lane_node_prepare']=z3.Or(cell(o,N,8)!=0,cell(o,N+8,8)!=0,cell(o,N+0x10,8)!=resize(META,64))
    BM,TM=z3.BitVecs('class_mask64 type_mask64',64)
    o=run('lane_bitmap_publication',0xfffffe000bd20c40,0xfffffe000bd20c64,
          {'x26':bucket,'x21':resize(CLASS,64),'x19':resize(TYPE,64),'x23':lane64,'sp':SP},
          [(bucket+0x30,8,BM),(SP+0x28,8,R),(R+0xa70+(lane64<<3),8,TM)])
    q['lane_class_bitmap']=cell(o,bucket+0x30,8)!=(BM|(resize(1,64)<<(resize(CLASS,64)&63)))
    q['lane_type_bitmap']=cell(o,R+0xa70+(lane64<<3),8)!=(TM|(resize(1,64)<<(resize(TYPE,64)&63)))
    W=z3.BitVec('thread_flags32',32);B=z3.BitVec('thread_aux_flag8',8)
    o=run('secondary_priority_gate',0xfffffe000bd20c7c,0xfffffe000bd20c8c,{'x20':T},[(T+0x210,4,W)])
    q['secondary_priority_gate']=o.equal!=((W&0x1894c6)==0)
    o=run('secondary_priority_fallback',0xfffffe000bd20c90,0xfffffe000bd20ca0,{'x20':T,'x25':T+0x214},[(T+0x53d,1,B)])
    q['secondary_priority_fallback']=o.read('x25')!=z3.If(B==0,T+0x216,T+0x214)
    AT=z3.BitVec('selected_priority_cell64',64)
    o=run('secondary_node_pack',0xfffffe000bd20ca0,0xfffffe000bd20cb4,{'x25':AT,'x20':T},[(AT,2,P)])
    q['secondary_node_pack']=z3.Or(cell(o,T+0x80,8)!=0,cell(o,T+0x88,8)!=0,cell(o,T+0x90,8)!=((resize(P,64)&255)<<8))
    o=run('waiter_list_append',0xfffffe000bd20cd4,0xfffffe000bd20ce0,{'x20':T,'x22':X,'x8':X+0xb0,'x9':TAIL})
    q['waiter_list_append']=z3.Or(cell(o,T+0x98,8)!=X+0xb0,cell(o,T+0xa0,8)!=TAIL,cell(o,TAIL,8)!=T+0x98,cell(o,X+0xb8,8)!=T+0x98)
    COUNT16=z3.BitVec('auxiliary_count16',16)
    o=run('auxiliary_count',0xfffffe000bd20d14,0xfffffe000bd20d24,{'sp':SP},[(SP+0x18,8,A),(A+0x50,2,COUNT16)])
    q['auxiliary_count_modular']=cell(o,A+0x50,2)!=COUNT16+1
    COUNT,EPOCH=z3.BitVecs('queue_count64 queue_epoch64',64)
    o=run('queue_pair_desired',0xfffffe000bd20d2c,0xfffffe000bd20d40,{'x0':COUNT,'x1':EPOCH,'x2':NOW})
    q['queue_pair_desired']=z3.Or(o.read('x6')!=COUNT+1,o.read('x7')!=z3.If(COUNT==0,NOW,EPOCH))
    OBS=z3.BitVec('observed_pair128',128)
    o=run('queue_pair_casp',0xfffffe000bd20d40,0xfffffe000bd20d44,{'x8':A,'x4':COUNT,'x5':EPOCH,'x6':COUNT+1,'x7':NOW},[(A,16,OBS)])
    q['queue_pair_casp']=z3.Or(cell(o,A,16)!=z3.If(OBS==z3.Concat(EPOCH,COUNT),z3.Concat(NOW,COUNT+1),OBS),o.read('x4')!=z3.Extract(63,0,OBS),o.read('x5')!=z3.Extract(127,64,OBS))
    o=run('context_placement_modifier',0xfffffe000bd20d58,0xfffffe000bd20d64,{'w10':FLAGS})
    q['context_placement_modifier']=o.read('w20')!=4-(FLAGS&2)
    o=run('generic_class_record',0xfffffe000bd20e0c,0xfffffe000bd20e1c,{'x26':R,'w21':resize(CLASS,32)})
    q['generic_class_record']=o.read('x24')!=R+0xaf8+1112*resize(CLASS,64)
    SCORE=z3.BitVec('context_score8',8)
    o=run('context_empty_ring',0xfffffe000bd20f2c,0xfffffe000bd20f38,{'x22':X,'x9':G+0x20,'x11':resize(SCORE,64)})
    q['context_ring_uses_embedded_node']=z3.Or(cell(o,X+0xa0,8)!=X+0xa0,cell(o,X+0xa8,8)!=X+0xa0,cell(o,G+0x20+(resize(SCORE,64)<<3),8)!=X+0xa0)
    o=run('score_policy_off_input',0xfffffe000bd1ecfc,0xfffffe000bd1ed00,{'x10':A},[(A+0x40,1,OFFSET)])
    q['score_policy_off_input']=o.read('w0')!=resize(OFFSET,32)
    o=run('score_addition',0xfffffe000bd1ee10,0xfffffe000bd1ee18,{'w9':resize(BASE,32),'w0':resize(OFFSET,32),'x8':X},[(X+0xc1,1,SCORE)])
    score_sum=o.read('w19');q['score_addition']=score_sum!=resize(BASE,32)+resize(OFFSET,32)
    o=run('score_byte_return',0xfffffe000bd1ee2c,0xfffffe000bd1ee30,{'w19':score_sum})
    q['score_byte_return']=o.read('w0')!=resize(BASE+OFFSET,32)
    K0,K1=z3.BitVecs('left_key16 right_key16',16);LEFT,RIGHT=z3.BitVecs('left_node64 right_node64',64)
    o=run('secondary_heap_winner',0xfffffe000c48b440,0xfffffe000c48b45c,{'x0':LEFT,'x1':RIGHT},[(LEFT+0x10,8,resize(K0,64)),(RIGHT+0x10,8,resize(K1,64))])
    q['secondary_heap_signed16_max']=o.read('x0')!=z3.If(K1>K0,RIGHT,LEFT)
    proofs={};negative={}
    for name,query in q.items():
        solver=z3.Solver();solver.set(timeout=15000);solver.add(query);result=solver.check();assert result==z3.unsat,(name,str(result))
        proofs[name]={'result':'unsat','query':solver.to_smt2()}
    AUXCLASS=z3.BitVec('auxiliary_class8',8)
    controls={'score_and_parent_priority_can_differ':z3.And(BASE==31,OFFSET==1,BASE+OFFSET!=BASE),
      'auxiliary_and_context_class_are_distinct':z3.And(AUXCLASS==1,CLASS==5,112*resize(AUXCLASS,64)!=112*resize(CLASS,64)),
      'counter_wrap_is_modular':z3.And(COUNT16==65535,COUNT16+1==0)}
    for name,query in controls.items():
        solver=z3.Solver();solver.set(timeout=15000);solver.add(query);assert solver.check()==z3.sat
        negative[name]={'result':'sat','query':solver.to_smt2(),'scope':'Abstract domain discriminator; no native reachability claim.'}
    return proofs,negative,pieces


def build():
    k=Kernel();spans=[]
    for name,a in FUNCTIONS.items():
        r=k.function(a);r['label']=name;r['bytes_hex']=r.pop('bytes');spans.append(r)
    proofs,negative,pieces=prove({'spans':spans})
    counts={'queries_unsat':len(proofs),'controls_sat':len(negative),'source_pieces':len(pieces),
      'source_lifted_instances':sum(r['instructions']for r in pieces.values()),'spans':len(spans),
      'instructions':sum(len(r['instructions'])for r in spans)};counts['code_B']=counts['instructions']*4
    return {'scope':__doc__,'generator_sha256':sha(__file__),'kernel_collection_sha256':k.sha256,
      'dependencies':{p:sha(ROOT/p)for p in DEPS},'spans':spans,'exact_symbols':k.symbols(FUNCTIONS.values()),
      'proofs':proofs,'negative_controls':negative,'source_pieces':pieces,'verified_counts':counts,
      'new_IDA_access':False,'new_native_execution':False,'new_IDB_mutations':False,'full_goal_complete':False}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--verify',action='store_true');args=parser.parse_args()
    out=build();p=ROOT/'aes_uncached_context_queue_checks.json'
    if args.verify:assert json.loads(read(p))==out
    else:p.write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps(out['verified_counts']),flush=True)
