#!/usr/bin/env python3
"""Original 96-head initialization, cached-class publication and heap ABI.

Fixed disjoint cells and returning source phases only. Native caller ranges,
queue ownership, class lifetimes, atomic ordering and scheduling are unknown.
O(B+I+P) source time/space; SMT cost separate. No target or IDB executes.
"""
import argparse
import json
import z3
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from kernel_native_reader import Kernel
from kext_port_tools import ROOT
from recover_aes_runqueue_membership import QueueLift
from lskd_values_symbolic import resize, part, mem, cell
from verify_daemon_reader_record_payloads_publication import read, sha

FUNCTIONS={'initializer':0xfffffe000bd2d3cc,'backend':0xfffffe000bd207c4,
 'enqueue':0xfffffe000bd2d5cc,'refresh':0xfffffe000bd1ee74,'deadline_merge':0xfffffe000c48b7c0,
 'paired_constructor':0xfffffe000bd212b0,'candidate_constructor':0xfffffe000bd174a4,
 'global_constructor':0xfffffe000c63a924}
DEPS=['kernel_native_reader.py','kext_port_tools.py','recover_aes_runqueue_membership.py',
 'recover_aes_block_wake_handshake.py','recover_aes_event_wake_selection.py',
 'recover_event_wait_table.py','lskd_values_symbolic.py','aes_runqueue_membership_checks.json',
 'verify_daemon_reader_record_payloads_publication.py']


class CachedLift(QueueLift):
    def condition_value(self,name):
        if name in ['gt','ge','lt','le']:
            return {'gt':lambda a,b:a>b,'ge':lambda a,b:a>=b,'lt':lambda a,b:a<b,'le':lambda a,b:a<=b}[name](self.cmp_left,self.cmp_right)
        return super().condition_value(name)

    def run(self,label):
        saved=self.c;row=next(r for r in saved['spans']if r['label']==label)
        cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
        for i in cs.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
            self.pc=i.address;m,o=i.mnemonic,i.operands;dest=i.reg_name(o[0].reg)
            if m=='ands':
                v=self.operand(i,o[1],self.width(dest))&self.operand(i,o[2],self.width(dest))
                self.write(dest,v);self.cmp_left=v;self.cmp_right=resize(0,v.size());self.equal=v==0;self.count+=1
            elif m=='rbit':
                v=self.read(i.reg_name(o[1].reg));self.write(dest,z3.Concat(*[z3.Extract(j,j,v)for j in range(v.size())]));self.count+=1
            elif m=='asr':
                self.write(dest,self.read(i.reg_name(o[1].reg))>>o[2].imm);self.count+=1
            else:
                self.c={'spans':[{'label':label,'start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run(label)
        self.c=saved;return self


def prove(c):
    q={};pieces={};Q,T,C,B,N,H=z3.BitVecs('queue64 thread64 class_record64 parent_header64 node64 heap_root64',64)
    P=z3.BitVec('priority16',16);FLAGS=z3.BitVec('flags32',32);COUNT=z3.BitVec('cached_count16',16)
    BITMAP=z3.BitVec('class_bitmap64',64);CLASS=z3.BitVec('class_id8',8);F=z3.BitVec('record_flags8',8)
    def run(name,a,z,seeds,cells=()):
        o=CachedLift(part(c,name,a,z))
        for reg,value in seeds.items():o.seed(reg,value)
        for at,n,value in cells:mem(o,at,n,value)
        o.run(name);assert o.count==(z-a)//4;pieces[name]={'start':hex(a),'end':hex(z),'instructions':o.count};return o
    init=run('initializer_stores',0xfffffe000bd2d3d0,0xfffffe000bd2d444,{'x0':Q})
    q['initializer_maximum']=cell(init,Q,4)!=0xffffffff
    q['initializer_bitmaps_counts']=z3.Or(cell(init,Q+8,16)!=0,cell(init,Q+0x18,8)!=0)
    q['initializer_96_heads_zero']=z3.Or(*[cell(init,Q+off,16)!=0 for off in range(0x20,0x320,16)])
    stores=[{'pc':hex(s['pc']),'offset_B':z3.simplify(s['address']-Q).as_long(),'size_B':s['size_bytes']}for s in init.stores]
    covered={j for s in stores for j in range(s['offset_B'],s['offset_B']+s['size_B'])}
    assert covered==set(range(4))|set(range(8,0x320))and len(stores)==51
    priority=z3.SignExt(48,P)
    q['initialized_head_extent']=z3.And(z3.ULE(P,95),z3.Or(z3.ULT(0x20+(priority<<3),0x20),z3.UGT(0x28+(priority<<3),0x320)))
    q['cached_head_heap_separation']=z3.And(z3.ULE(P,95),z3.UGT(8+0x28+(priority<<3),0x420))
    o=run('candidate_initializer_argument',0xfffffe000bd1750c,0xfffffe000bd17510,{'x19':B})
    q['candidate_initializer_argument']=o.read('x0')!=B+0x2a0
    o=run('global_initializer_argument',0xfffffe000c63a9c0,0xfffffe000c63a9c8,{})
    q['global_initializer_argument']=o.read('x0')!=0xfffffe000cac6e18+0x2a0
    INDEX=z3.BitVec('constructor_class64',64)
    o=run('generic_constructor_record',0xfffffe000bd21370,0xfffffe000bd2137c,{'x19':INDEX,'x22':1112,'x20':B+0x2a0})
    q['generic_constructor_record']=z3.Or(o.read('x9')!=B+0x2a0+1112*INDEX,cell(o,B+0x2a0+1112*INDEX,1)!=resize(INDEX,8))
    o=run('cached_constructor_arguments',0xfffffe000bd21408,0xfffffe000bd21418,
          {'x21':B+0x1cb0,'x8':1112*INDEX,'x19':INDEX,'w25':1})
    q['cached_constructor_record']=z3.Or(o.read('x26')!=B+0x1cb0+1112*INDEX,o.read('x0')!=B+0x1cb8+1112*INDEX,
      cell(o,B+0x1cb0+1112*INDEX,1)!=resize(INDEX,8),cell(o,B+0x1cb1+1112*INDEX,1)!=1)
    o=run('cached_count',0xfffffe000bd2099c,0xfffffe000bd209a8,{'x26':B},[(B+0x85a,2,COUNT)])
    q['cached_count_modular']=cell(o,B+0x85a,2)!=COUNT+1
    q['cached_count_overflow_bit']=((o.read('w8')>>16)&1)!=z3.If(COUNT==65535,resize(1,32),resize(0,32))
    o=run('cached_membership_flag',0xfffffe000bd209dc,0xfffffe000bd209e4,{'x20':T})
    q['cached_membership_flag']=cell(o,T+0x50,1)!=1
    offset=z3.If((F&1)!=0,resize(0x270,64),resize(0x260,64));word=(z3.LShR(resize(CLASS,64),3))&0x18
    o=run('cached_class_bitmap',0xfffffe000bd20fa8,0xfffffe000bd20fe0,{'x23':C,'x24':B},
          [(C+1,1,F),(C,1,CLASS),(B+offset+word,8,BITMAP)])
    q['cached_class_bitmap']=cell(o,B+offset+word,8)!=(BITMAP|(resize(1,64)<<(resize(CLASS,64)&63)))
    q['class0to5_first_bitmap_word']=z3.And(z3.ULE(CLASS,5),word!=0)
    NOW,OFFSET,DURATION=z3.BitVecs('raw_clock64 cpu_offset64 duration64',64)
    o=run('cached_deadline',0xfffffe000bd20fec,0xfffffe000bd21004,{'x23':C,'x11':resize(CLASS,64),'x9':NOW,'x8':OFFSET},
          [(0xfffffe000cb628d0+(resize(CLASS,64)<<3),8,DURATION)])
    q['cached_deadline_modular']=cell(o,C+0x438,8)!=NOW+OFFSET+DURATION
    KEY=z3.BitVec('heap_key16',16)
    o=run('cached_heap_node',0xfffffe000bd21014,0xfffffe000bd21024,{'x23':C},[(C+0x430,2,KEY)])
    q['cached_heap_node_links']=cell(o,C+0x420,16)!=0
    q['cached_heap_node_key']=cell(o,C+0x430,8)!=resize(KEY,64)
    o=run('cached_heap_arguments',0xfffffe000bd21024,0xfffffe000bd2102c,{'x23':C,'x24':B,'x19':0x288},[(B+0x288,8,H)])
    q['cached_heap_arguments']=z3.Or(o.read('x0')!=H,o.read('x1')!=C+0x420)
    ROOT=z3.BitVec('returned_root64',64)
    o=run('cached_heap_root_publication',0xfffffe000bd21030,0xfffffe000bd21034,{'x23':C,'x24':B,'x19':0x288,'x0':ROOT})
    q['cached_heap_root_publication']=cell(o,B+0x288,8)!=ROOT
    o=run('cached_refresh_arguments',0xfffffe000bd20a8c,0xfffffe000bd20a94,{'x24':B},[(B,2,P)])
    q['cached_refresh_arguments']=z3.Or(o.read('w19')!=z3.SignExt(16,P),o.read('x0')!=B)
    OLD,NEW=z3.BitVecs('old_maximum32 new_maximum32',32)
    o=run('backend_return',0xfffffe000bd21130,0xfffffe000bd21138,{'w8':NEW,'w19':OLD})
    q['backend_returns_aggregate_increase']=o.read('w0')!=z3.If(NEW>OLD,resize(1,32),resize(0,32))
    MASK=z3.BitVec('cached_class_mask64',64)
    o=run('cached_class_selection',0xfffffe000bd1eebc,0xfffffe000bd1eecc,{'x9':MASK})
    chosen=o.read('x9')
    expected=resize(-1,64)
    for j in range(5,0,-1):expected=z3.If((MASK&(1<<j))!=0,resize(j,64),expected)
    q['cached_class_lowest_nonzero_bit']=z3.And((MASK&~resize(63,64))==0,chosen!=expected)
    o=run('cached_selected_record',0xfffffe000bd1eecc,0xfffffe000bd1eed8,{'x8':B,'x9':resize(CLASS,64)})
    q['cached_selected_record']=o.read('x10')!=B+resize(CLASS,64)*1112
    AMAX,BMAX=z3.BitVecs('cached_maximum32 generic_maximum32',32)
    o=run('aggregate_maximum_store',0xfffffe000bd1ef8c,0xfffffe000bd1ef98,{'x19':B,'w20':AMAX,'w8':BMAX})
    q['aggregate_signed_maximum']=cell(o,B,2)!=resize(z3.If(AMAX>BMAX,AMAX,BMAX),16)
    X,Y,KX,KY=z3.BitVecs('left_node64 right_node64 left_deadline64 right_deadline64',64)
    o=run('heap_unsigned_winner',0xfffffe000c48b7d4,0xfffffe000c48b7ec,{'x0':X,'x1':Y},[(X+0x18,8,KX),(Y+0x18,8,KY)])
    q['heap_unsigned_min_winner']=z3.Or(o.read('x0')!=z3.If(z3.ULT(KX,KY),X,Y),o.read('x8')!=z3.If(z3.ULT(KX,KY),Y,X))
    META=z3.BitVec('winner_metadata64',64)
    o=run('heap_loser_links',0xfffffe000c48b7ec,0xfffffe000c48b7f8,{'x0':X,'x8':Y},[(X+0x10,8,META)])
    q['heap_loser_links']=z3.Or(cell(o,Y,8)!=(META>>16),cell(o,Y+8,8)!=X)
    o=run('heap_old_child_backlink',0xfffffe000c48b804,0xfffffe000c48b810,{'x0':X,'x8':Y,'x9':META},[(X+0x10,2,KEY)])
    q['heap_old_child_backlink']=cell(o,(META>>16)+8,8)!=Y
    o=run('heap_root_links',0xfffffe000c48b810,0xfffffe000c48b81c,{'x0':X,'x8':Y,'x9':resize(KEY,64)})
    packed=(resize(KEY,64)&65535)|((Y&((1<<48)-1))<<16)
    q['heap_root_packed_child']=cell(o,X+0x10,8)!=packed
    q['heap_root_parent_sibling_zero']=z3.Or(cell(o,X,8)!=0,cell(o,X+8,8)!=0)
    PTR=z3.BitVec('canonical_pointer64',64)
    q['packed_child_round_trip']=z3.And(PTR==z3.SignExt(16,z3.Extract(47,0,PTR)),
       ((resize(KEY,64)&65535)|((PTR&((1<<48)-1))<<16))>>16!=PTR)
    proofs={};negative={}
    for name,query in q.items():
        solver=z3.Solver();solver.set(timeout=15000);solver.add(query);result=solver.check();assert result==z3.unsat,(name,str(result))
        proofs[name]={'result':'unsat','query':solver.to_smt2()}
    controls={'upper_priority_not_initialized':z3.And(P==127,0x20+(priority<<3)>=0x320),
      'priority127_aliases_heap_node_if_admitted':z3.And(P==127,8+0x20+(priority<<3)==0x420),
      'unmatched_header_epoch_changes_return':z3.And(NEW==20,OLD==30,NEW<OLD),
      'pointer_requires_canonical48':z3.And(PTR!=z3.SignExt(16,z3.Extract(47,0,PTR)),
        ((PTR&((1<<48)-1))<<16)>>16!=PTR)}
    for name,query in controls.items():
        solver=z3.Solver();solver.set(timeout=15000);solver.add(query);assert solver.check()==z3.sat
        negative[name]={'result':'sat','query':solver.to_smt2(),'scope':'Abstract domain discriminator; no native reachability or defect claim.'}
    return proofs,negative,pieces,stores


def build():
    k=Kernel();spans=[]
    for name,a in FUNCTIONS.items():
        r=k.function(a);r['label']=name;r['bytes_hex']=r.pop('bytes');spans.append(r)
    proofs,negative,pieces,stores=prove({'spans':spans})
    counts={'queries_unsat':len(proofs),'controls_sat':len(negative),'source_pieces':len(pieces),
      'source_lifted_instances':sum(r['instructions']for r in pieces.values()),'spans':len(spans),
      'instructions':sum(len(r['instructions'])for r in spans)};counts['code_B']=counts['instructions']*4
    return {'scope':__doc__,'generator_sha256':sha(__file__),'kernel_collection_sha256':k.sha256,
      'dependencies':{p:sha(ROOT/p)for p in DEPS},'spans':spans,'exact_symbols':k.symbols(FUNCTIONS.values()),
      'proofs':proofs,'negative_controls':negative,'source_pieces':pieces,'initializer_stores':stores,
      'verified_counts':counts,'new_IDA_access':False,'new_native_execution':False,
      'new_IDB_mutations':False,'full_goal_complete':False}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--verify',action='store_true');args=parser.parse_args()
    out=build();p=ROOT/'aes_cached_class_queue_checks.json'
    if args.verify:assert json.loads(read(p))==out
    else:p.write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps(out['verified_counts']),flush=True)
