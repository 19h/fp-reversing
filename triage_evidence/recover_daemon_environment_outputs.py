#!/usr/bin/env python3
"""Conditional clock-success helper, cache and notification-output interfaces.

Strict original-source execution stops before every import. Private entry,
controller/cache/notification states are premises, not native observations.
Three verified pure copies preserve unknown-byte origin and definedness.
O(cases*(visits+effects)+source+queries) time/space;30 s/query.
No native API, IPC, allocation, free or PAC executes.
"""
import itertools,json,struct
import z3
from collections import Counter
from unicorn import arm64_const as ar
import probe_daemon_descriptor_producers as Base
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,TABLE,FIXUPS,qword,selected,verify_original_fixups
from verify_daemon_reader_record_payloads_publication import read,sha
from recover_daemon_return_bank_origins import Algebra
from lskd_values_symbolic import mem,cell,resize
from daemon_import_bindings import binding

P='daemon_environment_outputs';ENTRY=0x100e1e5ec;RETURN=0x100701a7c
CLOCK_SUCCESS=0x1007019b0
POOL=0x1010b1720;DISPATCH=0x1010abb60;CACHE=0x1010ca2c8;FLAG=0x1010ca320;TOKEN=0x1010ca324
OUTPUTS=[(1,0x8950,8),(2,0x78b8,4),(3,0x73c0,8),(4,0x630c,4)]
COPIES={0x100e1f1e8:(0xe8,0x240),0x100e1f1f0:(0xd0,0x248),0x100e1f1f8:(0xa0,0x250)}

class Run(Base.Run):
    def __init__(self,c):
        Base.SOURCE_CAPTURE=json.loads(read(ROOT/'daemon_descriptor_producers_source.json'))
        super().__init__({'placement':c['placement'],'nonnull':True,'counter64':0,'probe':'fast','pattern':c['pattern'],'controllers':[0,0]})
        self.known=bytearray(Base.SIZE);self.initial=[];self.image_fixtures=[];self.unknown_copies=[];self.copy_pending=None;self.frames=[];self.checkpoints=[]
        self.fixture(Base.GUARD,struct.pack('<Q',0x123456789abcdef0))
        for j in range(31):self.set(j,((j+1)*0x0102030405060708)&((1<<64)-1))
        self.set(0,c['argument64']);self.set(30,RETURN)
        for j,off,n in OUTPUTS:
            self.set(j,0 if c['null_mask']&(1<<(j-1)) else self.C+off)
        self.u.reg_write(ar.UC_ARM64_REG_SP,self.C)
        if c['kind']=='caller':
            assert c['argument64']==0xfffffffffffffffe and c['null_mask']==0
            self.set(0,0)
            for off,x in [(0x9c8,0x1010b8dc8),(0x9c0,0x1010c4670),(0x9a8,0x101031fa0),(0x9b0,0x100fc4230),(0x9d8,TABLE)]:
                self.fixture(self.C+off,struct.pack('<Q',x))
            self.set(19,0x79ea);self.set(22,0xa6);self.set(23,0xa5cd4cf)
        for at,n,x,role in [(0x1010c54d8,8,c['controllers'][0],'controller_pair0'),(0x1010c54a8,8,c['controllers'][1],'controller_pair1'),
                             (FLAG,1,c['flag8'],'declared_notification_flag'),(TOKEN,4,0x5034,'declared_notification_token'),
                             (0x1010ca2c0,4,0x5035,'declared_general_notification_token'),(0x1010ca31c,4,0x5036,'declared_minus1_notification_token'),
                             (0x1010b8dc8,8,c['controllers'][0],'caller_controller0'),(0x1010c4670,8,c['controllers'][1],'caller_controller1')]:
            self.ensure(at,n);raw=x.to_bytes(n,'little');self.u.mem_write(at,raw)
            self.image_fixtures.append({'address':hex(at),'bytes_hex':raw.hex(),'provenance':role})
        raw=bytearray(80)
        if c['cache_mode']!='miss':
            j=0 if c['cache_mode']=='hit0' else 1
            struct.pack_into('<QQI4xQI',raw,j*40,c['argument64'],Base.P+0x1000,17,Base.P+0x2000,31)
            struct.pack_into('<I',raw,j*40+36,12345)
        self.ensure(CACHE,80);self.u.mem_write(CACHE,bytes(raw))
        self.image_fixtures.append({'address':hex(CACHE),'bytes_hex':bytes(raw).hex(),'provenance':'declared_two_record_cache'})
        self.entry_regs=[hex(self.reg(j)) for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))

    def preflight(self,i):
        if i.address in COPIES:
            src,dst=COPIES[i.address];f=self.C-0x4a0
            assert i.mnemonic=='ldr' and i.op_str==f'x11, [sp, #{hex(src)}]'
            follow=next(CS.disasm(IMAGE.read(i.address+4,4),i.address+4))
            assert follow.mnemonic=='str' and follow.op_str==f'x11, [x10, #{hex(dst-0x1e0)}]'
            assert self.u.reg_read(ar.UC_ARM64_REG_SP)==f and self.reg(10)==f+0x1e0
            self.copy_pending={'load_pc':hex(i.address),'store_pc':hex(i.address+4),'source':hex(f+src),'destination':hex(f+dst),
                               'size_bytes':8,'origin_offsets':list(range(src,src+8)),
                               'known_mask_hex':self.known[f+src-Base.P:f+src-Base.P+8].hex()}
            assert self.copy_pending['known_mask_hex']=='00'*8
            return True
        return super().preflight(i)

    def read(self,u,t,a,n,v,d):
        pc=u.reg_read(ar.UC_ARM64_REG_PC)
        if pc in COPIES:
            assert self.copy_pending and hex(a)==self.copy_pending['source'] and n==8
            self.reads.append({'pc':hex(pc),'source_visit_index':self.seq-1,'address':hex(a),'size_bytes':n,
                               'bytes_hex':bytes(u.mem_read(a,n)).hex(),'known_mask_hex':'00'*8,'unknown_copy_only':True})
            return
        return super().read(u,t,a,n,v,d)

    def write(self,u,t,a,n,v,d):
        pc=u.reg_read(ar.UC_ARM64_REG_PC);pending=self.copy_pending
        super().write(u,t,a,n,v,d)
        if pending and pc==int(pending['store_pc'],16):
            assert hex(a)==pending['destination'] and n==8
            self.known[a-Base.P:a-Base.P+8]=bytes(8);self.writes[-1]['known_mask_hex']='00'*8
            self.writes[-1]['unknown_origins']=pending['origin_offsets'];self.unknown_copies.append(pending);self.copy_pending=None

    def code(self,u,a,n,d):
        if a==RETURN:self.flush();return self.stop('before_original_caller_return_consumer')
        frame={'pc':hex(a),'registers31':[hex(self.reg(j)) for j in range(31)],
               'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'NZCV':hex(u.reg_read(ar.UC_ARM64_REG_NZCV))}
        before=self.seq;result=super().code(u,a,n,d)
        if self.seq>before:self.frames.append(frame)
        if a==ENTRY:self.checkpoints.append({'role':'internal_callee_entry',**frame})
        return result

    def run(self):
        start=CLOCK_SUCCESS if self.caller_configuration['kind']=='caller' else ENTRY
        self.ensure(start);self.u.emu_start(start,0,count=10000);self.flush();assert self.reason and self.copy_pending is None
        assert len(self.frames)==len(self.visits)
        return {'configuration':self.caller_configuration,'entry_PC':hex(start),'caller_SP':hex(self.C),
                'entry_registers31':self.entry_regs,'entry_NZCV':self.entry_NZCV,'initial_private_fixtures':self.initial,
                'initial_image_fixtures':self.image_fixtures,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,
                'logical_edges':self.edges,'source_calls':[{k:v for k,v in row.items() if k!='record'} for row in self.calls],
                'unknown_copy_effects':self.unknown_copies,'boundary':self.boundary,
                'source_frames':self.frames,'checkpoints':self.checkpoints,'boundary_NZCV':hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV)),
                'counts':{'source_visits':len(self.visits),'read_events':len(self.reads),'write_events':len(self.writes),'logical_edges':len(self.edges)},
                'native_target_executed':False}

def probe(c):
    v=Run(c);v.caller_configuration=c;return v.run()

def configurations():
    for placement,mode,flag,controllers in itertools.product([0,0x100],['miss','hit0','hit1'],[0,1,2,3],[(0,0),(0xffffffff,0x87654321)]):
        yield {'placement':placement,'pattern':0x35 if placement==0 else 0xca,'cache_mode':mode,'flag8':flag,
               'controllers':list(controllers),'argument64':0xfffffffffffffffe,'null_mask':0,'kind':'caller'}
    for mask in range(1,16):
        yield {'placement':0,'pattern':0x35,'cache_mode':'miss','flag8':0,'controllers':[0,0],
               'argument64':0xfffffffffffffffe,'null_mask':mask,'kind':'direct'}
    for argument in [-8,-7,-6,-5,-4,-3,-1,0,1]:
        yield {'placement':0,'pattern':0x35,'cache_mode':'miss','flag8':1,'controllers':[0,0],
               'argument64':argument&((1<<64)-1),'null_mask':0,'kind':'direct'}

def banks():
    rows=[]
    for name,l,r,k,add,base in [
        ('caller_constant_leaf',0x100fc4230,0x101031fa0,0xe4,0xcc0f,TABLE),
        ('caller_output_helper',0x100fc4230,0x101031fa0,0xe4,0xcbc0,TABLE),
        ('mutable_controller0',0x101033700,0x101033a30,0x6a,-0x45,POOL),
        ('mutable_controller1',0x1010330e0,0x101033500,0xfb,0x1e,POOL),
        ('dispatch_pointer',0x101033700,0x101033a30,0x6a,-0x61,POOL),
        ('notification_flag',0x101033700,0x101033a30,0x1d,-0x1e,POOL),
        ('common_notification_token',0x101033700,0x101033a30,0x1d,-0xe,POOL),
        ('cache_plus8',0x101033930,0x101032e80,0x8d,-0xb,POOL),
        ('general_notification_token',0x101032d80,0x101032fe0,8,-0xa0,POOL),
        ('minus1_notification_token',0x101032d80,0x101032fe0,0xe0,-0x45,POOL),
        ('allocate24',0x1010332e0,0x101033800,8,0xa07,DISPATCH),
        ('cache_clock',0x1010330e0,0x101033500,0xa0,0xabd,DISPATCH),
        ('common_notify_check',0x1010331e0,0x101033600,0xba,0xadb,DISPATCH),
        ('general_notify_check',0x101032d80,0x101032fe0,8,0xabd,DISPATCH),
        ('minus1_notify_check',0x1010332e0,0x101033800,0x3e,0xaad,DISPATCH)]:
        row=selected(l,r,k,add,base=base);left=IMAGE.read(l,256);right=IMAGE.read(r,256)
        row.update(name=name,left256_hex=left.hex(),right256_hex=right.hex(),
                   XOR_outputs_256=[j^right[left[j]^k] for j in range(256)])
        assert len(set(row['XOR_outputs_256']))==1;rows.append(row)
    return rows

def source():
    spans=[('clock_success_caller',CLOCK_SUCCESS,0x100701ac4),('constant_negative2_leaf',0x100001e0c,0x100001e14),
           ('helper_entry_and_output_validation',ENTRY,0x100e1e7c0),('output_clear_and_cache_setup',0x100e1e7c0,0x100e1e984),
           ('cache_key_loop',0x100e1ed80,0x100e1ede0),('cache_clock',0x100e1ede0,0x100e1ee5c),
           ('cache_miss_and_argument_classes',0x100e1f170,0x100e1f49c),('helper_return',0x100e25080,0x100e250bc)]
    return [{'name':n,'start':hex(a),'end':hex(b),'bytes_hex':IMAGE.read(a,b-a).hex(),
             'instructions':[{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str}
                              for i in CS.disasm(IMAGE.read(a,b-a),a)]} for n,a,b in spans]

def obligations():
    S,F,A,B,C,D,V=z3.BitVecs('deo_SP64 deo_frame64 deo_A64 deo_B64 deo_C64 deo_D64 deo_value64',64)
    status,index=z3.BitVecs('deo_result32 deo_index32',32);flag=z3.BitVec('deo_flag8',8);qs=[]
    def prove(label,bad):
        q=z3.Solver();q.set(timeout=30000);assert q.check()==z3.sat;q.add(z3.simplify(bad));assert q.check()==z3.unsat,label
        qs.append({'label':label,'query':q.to_smt2(),'result':'unsat','premises_nonvacuous':True})
    v=Algebra();v.run_block(0x100001e0c,0x100001e10)
    prove('constant_leaf_returns_full_negative_two',v.read('x0')!=0xfffffffffffffffe)
    v=Algebra();v.seed('sp',S-0x60);v.run_block(0x100e1e608,0x100e1e610)
    prove('fixed_frame_after_original_save_push',z3.Or(v.read('sp')!=S-0x4a0,v.read('x29')!=S-0x10))
    v=Algebra();v.seed('sp',F)
    for name,x in [('x1',A),('x2',B),('x3',C),('x4',D)]:v.seed(name,x)
    v.run_block(0x100e1e738,0x100e1e768);valid=z3.And(A!=0,B!=0,C!=0,D!=0)
    prove('all_four_pointer_validation_and_saved_arguments',z3.Or(v.read('w11')!=z3.If(valid,z3.BitVecVal(0x17e,32),z3.BitVecVal(0x1b2,32)),
          cell(v,F+0x110,8)!=A,cell(v,F+0xf0,8)!=B,cell(v,F+0x108,8)!=C,cell(v,F+0xb8,8)!=D))
    v=Algebra();v.seed('sp',F)
    for off,x in [(0x110,A),(0xf0,B),(0x108,C),(0xb8,D)]:mem(v,F+off,8,x)
    v.run_block(0x100e1e7c0,0x100e1e7fc)
    prove('four_output_stores_are_two_u64_two_u32_zeros',z3.Or(cell(v,A,8)!=0,cell(v,B,4)!=0,cell(v,C,8)!=0,cell(v,D,4)!=0))
    class Flag(Algebra):
        def load(self,at,n):
            if self.pc==0x100e1ed50:assert n==1;return flag
            return super().load(at,n)
    v=Flag();v.seed('sp',F);mem(v,F+0x80,8,A);v.run_block(0x100e1ed20,0x100e1ed74)
    zero=z3.simplify(z3.substitute(v.read('w8'),(flag,z3.BitVecVal(0,8)))).as_long()
    prove('notification_flag_selection_uses_only_low_bit',v.read('w8')!=z3.If(flag&1!=0,z3.BitVecVal(0xff,32),z3.BitVecVal(zero,32)))
    class Key(Algebra):
        def __init__(self):super().__init__();self.key_address=None
        def one(self,i):
            if i.mnemonic=='sxtw':self.write(i.reg_name(i.operands[0].reg),z3.SignExt(32,self.read(i.reg_name(i.operands[1].reg))));return
            return super().one(i)
        def load(self,at,n):
            if self.pc==0x100e1edb4:assert n==8;self.key_address=at;return V
            return super().load(at,n)
    v=Key();v.seed('w19',index);v.seed('x13',A);v.seed('sp',F);mem(v,F+0x138,8,B)
    v.run_block(0x100e1edac,0x100e1edc4)
    prove('signed_index_cache_key_stride_and_equality',z3.Or(v.key_address!=A+40*z3.SignExt(32,index),v.read('w11')!=z3.If(B!=V,z3.BitVecVal(1,32),z3.BitVecVal(0,32))))
    v=Algebra();v.seed('sp',F);v.seed('x10',F+0x1e0)
    for off,x in [(0xe8,A),(0xd0,B),(0xa0,C)]:mem(v,F+off,8,x)
    v.run_block(0x100e1f1e8,0x100e1f200)
    prove('three_complete_copy_slices_preserve_arbitrary_u64_values',z3.Or(cell(v,F+0x240,8)!=A,cell(v,F+0x248,8)!=B,cell(v,F+0x250,8)!=C))
    v=Algebra();v.seed('sp',F);mem(v,F+0x138,8,V);v.run_block(0x100e1f250,0x100e1f25c)
    in_range=z3.Or(*[V==z3.BitVecVal(n&((1<<64)-1),64) for n in [-6,-5,-4,-3,-2]])
    w=Algebra();w.seed('x9',V);w.run_block(0x100e1f354,0x100e1f358);minus1=w.z
    w.run_block(0x100e1f35c,0x100e1f360);minus8=w.z
    prove('complete_negative_argument_class_tests',z3.Or(z3.Not(v.condition('hs'))!=in_range,minus1!=(V==0xffffffffffffffff),minus8!=(V==0xfffffffffffffff8)))
    v=Algebra();v.seed('w27',0x720);v.seed('w4',0xde109bd7);v.seed('w19',index)
    v.run_block(0x100e1f170,0x100e1f1b8);more=(index+1)<z3.BitVecVal(2,32)
    prove('cache_loop_signed_two_record_bound',z3.Or(v.read('w19')!=index+1,v.read('w10')!=(0x720^z3.If(more,z3.BitVecVal(0,32),z3.BitVecVal(0x13,32)))))
    v=Algebra();v.seed('sp',S);v.seed('x0',0xfffffffffffffffe);v.run_block(0x100701a54,0x100701a78)
    prove('caller_four_output_pointer_arguments',z3.Or(v.read('x0')!=0xfffffffffffffffe,v.read('x1')!=S+0x8950,v.read('x2')!=S+0x78b8,
          v.read('x3')!=S+0x73c0,v.read('x4')!=S+0x630c,v.read('x17')!=0xde8e))
    v=Algebra();v.seed('w19',0x79ea);v.run_block(0x1007019b4,0x1007019c4);v.run_block(0x1007019fc,0x100701a04)
    prove('caller_saved_shift_basis',v.read('w21')!=0x1cb7)
    v=Algebra();v.seed('w0',status);v.seed('w21',0x1cb7);v.seed('w19',0x79ea);v.run_block(0x100701a7c,0x100701ab8)
    difference=status-((status<<1)&0x167b8ca2)
    prove('caller_return_transform_has_only_zero_success',z3.Or((difference==0)!=(status==0),v.read('w28')!=difference+0x8b3dc651,
          v.read('w8')!=z3.If(status==0,z3.BitVecVal(0x79ea,32),z3.BitVecVal(0x7a10,32))))
    return qs

def fixups(addresses):
    ordinary={a for a in addresses if FIXUPS[a]['kind']=='bind'}
    out=verify_original_fixups(set(addresses)-ordinary)
    for a in sorted(ordinary):
        row=binding(a);row.pop('library_path');assert not row['authenticated']
        out['records'].append(row)
    return out

def build():
    cases=[probe(c) for c in configurations()];counts=Counter();pool={};used=set()
    for c in cases:
        counts.update(c['counts'])
        for row in c['source_visits']:
            a=int(row['pc'],16);i=next(CS.disasm(IMAGE.read(a,4),a));pool[row['pc']]={'pc':row['pc'],'bytes_hex':row['bytes_hex'],'mnemonic':i.mnemonic,'operands':i.op_str}
        for r in c['source_reads']:
            a=int(r['address'],16)
            if r['size_bytes']==8 and a in FIXUPS:used.add(a)
    b=banks();used.update(int(r['slot'],16) for r in b)
    deps=['probe_daemon_descriptor_producers.py','daemon_descriptor_producers_source.json','daemon_receive_tools.py',
          'daemon_receive_fixups.txt','daemon_import_bindings.py','daemon_scratch_pointer_origin_checks.json',
          'daemon_scratch_pointer_origin_audit.json','recover_daemon_scratch_pointer_origin.py']
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n) for n in deps},
            'source_regions':source(),'source_pool':pool,'source_fixups':fixups(used),'bank_rules':b,
            'source_proofs':obligations(),'cases':cases,'verified_counts':{'cases':len(cases),**counts},
            'image_backing_premise':'Original file-backed image bytes with logical fixups and declared initial zero-fill for file-unbacked image spans; listed image fixtures and source writes override them. This is a private environment, not native state.',
            'parent_entry_premise':'Caller entry is a separate clock-success cut. Live premises are W19=0x79ea,W22=0xa6,W23=0x0a5cd4cf,the five listed source-compatible frame roots and an ABI-compatible zero X0. Other entry scalars are explicit fixtures. No clock API/output model or uninterrupted reservation-to-entry lifetime join is added.',
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
