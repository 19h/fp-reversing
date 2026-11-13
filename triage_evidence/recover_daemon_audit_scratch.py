#!/usr/bin/env python3
"""Caller audit-token scratch reservation and PID-extraction boundary.

Retained caller evidence stops on undefined bytes. Separate component cases
declare pointer/cursor/bank premises and stop before the BSM import. O(text
words+cases*(visits+effects)+queries) time/space; 30 s/query. No native API,
IPC, allocation/free, hardware PAC or IDB mutation executes.
"""
import itertools,json,struct
from collections import Counter
from hashlib import sha256
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64_const import ARM64_OP_MEM,ARM64_OP_REG
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,TABLE,FIXUPS,qword,selected
from verify_daemon_reader_record_payloads_publication import read,sha
from recover_daemon_iokit_census import text_section
from recover_daemon_return_bank_origins import Algebra
from lskd_values_symbolic import mem,cell
import recover_daemon_notification_failure as Parent

P='daemon_audit_scratch';ENTRY=0x1006cdaf8;RESERVE=0x1006e6114
RESTORE=0x10079af48;NEXT=0x1006f7720;COPY=0x10046f89c
BSM=0x100810240;MASK=(1<<64)-1
SPECS=[('caller_bridge',ENTRY,0x1006cdb2c),('reservation',RESERVE,0x1006e61a0),
       ('null_restoration',RESTORE,0x10079af64),('nonnull_copy_and_BSM',0x100810154,0x100810244),
       ('saved_continuation',NEXT,0x1006f776c),('copy_helper',COPY,0x10046faf8)]
DEPS=['daemon_receive_tools.py','daemon_receive_fixups.txt','recover_daemon_iokit_census.py',
      'recover_daemon_return_bank_origins.py','recover_daemon_notification_failure.py',
      'daemon_notification_failure_checks.json','daemon_notification_failure_audit.json',
      'recover_daemon_notification_registration.py','recover_daemon_environment_outputs.py',
      'probe_daemon_descriptor_producers.py','audit_daemon_environment_outputs.py']

class Run(Parent.Run):
    def __init__(self,c):
        super().__init__({'placement':c['placement'],'pattern':c['pattern'],'controllers':c['controllers'],'flag8':0})
        self.cfg=c;self.cut_stops={NEXT};self.allow_consumer=True

def configuration():
    for placement,controllers,pointer,cursor in itertools.product([0,0x100],[(0,0),(0xffffffff,0x87654321)],
             ['null']+['alignment_'+str(j) for j in range(8)],[0,0x80]):
        yield {'placement':placement,'controllers':list(controllers),'pointer':pointer,'cursor64':cursor,
               'pattern':0x35 if placement==0 else 0xca}

def component(c):
    v=Run(c);s=v.C;p=0 if c['pointer']=='null' else Parent.Parent.Base.P+0x3000+int(c['pointer'].split('_')[1])
    for off,x in [(0x9b8,p),(0x16d0,c['cursor64']),(0x600,0x100e99a00),(0x5f8,0x100f4e390)]:
        v.fixture(s+off,struct.pack('<Q',x))
    token=bytes((j*7+c['pattern'])&255 for j in range(32))
    if p:v.fixture(p,token)
    row=v.interval(ENTRY,'separate_audit_component_entry')
    assert row['boundary']['pc']==hex(BSM if p else NEXT),row['boundary']
    r=(s+0xc070+c['cursor64'])&MASK
    if p:
        assert row['boundary']['kind']=='before_unmodeled_import_call'
        assert row['boundary']['detail']['symbol']=='libbsm/_audit_token_to_au32'
        assert bytes(v.u.mem_read(r,32))==token
        assert int.from_bytes(v.u.mem_read(s+0x16d0,8),'little')==c['cursor64']+0x420
    else:assert int.from_bytes(v.u.mem_read(s+0x16d0,8),'little')==c['cursor64']
    return {'configuration':c,'pointer64':hex(p),'scratch_base64':hex(r),'trace':row,
            'final_cursor64':hex(int.from_bytes(v.u.mem_read(s+0x16d0,8),'little')),
            'copied32_hex':bytes(v.u.mem_read(r,32)).hex() if p else None,
            'separate_entry_premises':True,'native_target_executed':False}

def retained():
    parent=json.loads(read(ROOT/(Parent.P+'_checks.json')));rows=[]
    for ix,c in enumerate(parent['cases']):
        before=c['caller_consumer'];v=Run(c['configuration'])
        for j,x in enumerate(before['boundary']['registers31']):v.set(j,int(x,16))
        v.u.reg_write(ar.UC_ARM64_REG_SP,int(before['boundary']['SP'],16))
        v.u.reg_write(ar.UC_ARM64_REG_NZCV,int(before['boundary_NZCV'],16))
        # No unknown-byte substitutions: reconstruct the retained source writes.
        for row in Parent.intervals(c):
            for f in row['initial_private_fixtures']:v.fixture(int(f['address'],16),bytes.fromhex(f['bytes_hex']))
            for w in row['source_writes']:
                a=int(w['address'],16)
                if Parent.Parent.Base.P<=a<a+w['size_bytes']<=Parent.Parent.Base.P+Parent.Parent.Base.SIZE:
                    assert 'known_mask_hex' not in w or '00' not in w['known_mask_hex']
                    v.fixture(a,bytes.fromhex(w['after_hex']))
        row=v.interval(ENTRY,'retained_failure_caller_suffix')
        assert row['boundary']['pc']=='0x1006e6148' and row['boundary']['kind']=='before_unknown_private_read'
        detail=row['boundary']['detail'];assert detail['address']==hex(v.C+0x16d0) and detail['size_bytes']==8
        assert not any(v.known[v.C+0x16d0-Parent.Parent.Base.P:v.C+0x16d8-Parent.Parent.Base.P])
        ww=[w for old in Parent.intervals(c) for w in old['source_writes']
            if int(w['address'],16)<v.C+0x9c0 and v.C+0x9b8<int(w['address'],16)+w['size_bytes']]
        assert len(ww)==1 and ww[0]['pc']=='0x1007019b0' and ww[0]['size_bytes']==8
        assert ww[0]['after_hex']==int(c['root_prefix']['entry_registers31'][26],16).to_bytes(8,'little').hex()
        rows.append({'parent_case_index':ix,'trace':row,'unknown_cursor_bytes':8,
                     'saved_X26_writer':ww[0],'reservation_stores_before_cursor_read':3,
                     'native_pointer_origin_established':False})
    return rows

def banks():
    out=[]
    for name,l,r,k,add in [('copy',0x100e99a00,0x100f4e390,0x78,0xcb12),
                          ('BSM',0x100fc4230,0x101031fa0,0xf3,0xcc7f)]:
        row=selected(l,r,k,add);left=IMAGE.read(l,256);right=IMAGE.read(r,256)
        row.update(name=name,left256_hex=left.hex(),right256_hex=right.hex(),
                   XOR_outputs_256=[j^right[left[j]^k] for j in range(256)]);out.append(row)
    assert [r['target'] for r in out]==[hex(COPY),'libbsm/_audit_token_to_au32'];return out

def source():
    return [{'name':n,'start':hex(a),'end':hex(b),'bytes_hex':IMAGE.read(a,b-a).hex(),
             'instructions':[{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str}
                             for i in CS.disasm(IMAGE.read(a,b-a),a)]} for n,a,b in SPECS]

def census():
    a,n=text_section();raw=IMAGE.read(a,n);cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
    hits=[];unsupported=[];examined=0;widths={'b':1,'h':2,'s':4,'w':4,'d':8,'x':8,'q':16}
    for j,(word,) in enumerate(struct.iter_unpack('<I',raw)):
        if (word>>5)&31!=31:continue
        examined+=1
        for i in cs.disasm(raw[4*j:4*j+4],a+4*j):
            for op in i.operands:
                if op.type!=ARM64_OP_MEM or i.reg_name(op.mem.base)!='sp' or op.mem.index:continue
                names=[i.reg_name(o.reg) for o in i.operands if o.type==ARM64_OP_REG]
                if not names:continue
                width=8 if names[0] in ['fp','lr'] else widths.get(names[0][0]);m=i.mnemonic
                if m.endswith('b'):width=1
                elif m.endswith('h'):width=2
                elif m.endswith('sw'):width=4
                if m in ['stp','ldp','stnp','ldnp']:width=2*width if width else None
                for off in [0x9b8,0x16d0]:
                    if width is None:
                        if off-32<=op.mem.disp<off+8:unsupported.append(hex(i.address))
                    elif op.mem.disp<off+8 and off<op.mem.disp+width:
                        hits.append({'field_offset':hex(off),'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),
                                     'mnemonic':m,'operands':i.op_str,'access_bytes':width,
                                     'offset_bytes':op.mem.disp,'writes':m.startswith('st')})
    assert not unsupported
    return {'text_start':hex(a),'text_bytes':n,'text_sha256':sha256(raw).hexdigest(),
            'aligned_words_checked':n//4,'base_field31_words_decoded':examined,
            'overlapping_literal_SP_accesses':hits,'unclassified_nearby_widths':unsupported,
            'scope':'Fixed-immediate explicit SP memory operands and conventional scalar/vector/pair widths only. Computed aliases, register indexing, other sections and SP-epoch equality excluded.'}

def obligations():
    s,u,p=z3.BitVecs('as_SP64 as_cursor64 as_pointer64',64);qs=[]
    def prove(label,bad):
        q=z3.Solver();q.set(timeout=30000);assert q.check()==z3.sat;q.add(z3.simplify(bad));assert q.check()==z3.unsat,label
        qs.append({'label':label,'query':q.to_smt2(),'result':'unsat','premises_nonvacuous':True})
    class Inputs(Algebra):
        def load(self,a,n):
            if self.pc==0x1006cdb10:assert n==8;self.slot=a;return z3.BitVecVal(RESERVE,64)
            if self.pc==0x1006e6128:assert n==8;self.saved_slot=a;return z3.BitVecVal(NEXT,64)
            if self.pc==0x1006e618c:assert n==8;self.branch_slot=a;return z3.BitVecVal(0,64)
            return super().load(a,n)
    v=Inputs();v.seed('sp',s);v.seed('w19',0x79ea);mem(v,s+0x9d8,8,TABLE);mem(v,s+0x9b8,8,p)
    v.run_block(ENTRY,0x1006cdb28)
    prove('caller_bridge_exact_index_arguments_and_diversity',z3.Or(v.slot!=TABLE+8*0x2895,v.read('w8')!=0x6cf4,
          v.read('w11')!=0x5e,v.read('x0')!=p,v.read('x9')!=s+0xf0c,v.read('x10')!=s+0x7820,v.read('x17')!=0xafb5))
    mem(v,s+0x16d0,8,u);v.run_block(RESERVE,0x1006e619c)
    r=s+0xc070+u
    prove('reservation_exact_views_and_modular_cursor',z3.Or(v.saved_slot!=TABLE+8*0x5e,cell(v,s+0x4ec8,8)!=NEXT,
          cell(v,s+0xa7f8,8)!=s+0x7820,cell(v,s+0xa800,8)!=s+0xf0c,cell(v,s+0xa808,8)!=r+0x20,
          v.read('x21')!=r,cell(v,s+0x16d0,8)!=u+0x420,v.read('w23')!=0x86a,v.read('w8')!=0,v.read('x17')!=0xb6fd))
    prove('full_u64_pointer_zero_selects_restore',v.branch_slot!=TABLE+8*z3.If(p==0,z3.BitVecVal(0x6a27,64),z3.BitVecVal(0x6a1f,64)))
    # Cursor restoration occurs only on the null component branch.
    class Restore(Algebra):
        def load(self,a,n):
            if self.pc==0x10079af58:assert n==8;return z3.BitVecVal(NEXT,64)
            return super().load(a,n)
    v=Restore();v.seed('sp',s);v.seed('w8',0);v.seed('w15',0x74c29d88);mem(v,s+0x16d0,8,u+0x420)
    v.run_block(RESTORE,0x10079af60)
    prove('null_restores_all_u64_cursors_and_encodes_result',z3.Or(cell(v,s+0x16d0,8)!=u,v.read('w28')!=0x74c29d88,
          v.read('x8')!=NEXT,v.read('x17')!=0xb335))
    v=Algebra();v.seed('sp',s);v.seed('x26',p);v.run_block(0x1007019b0,0x1007019b4)
    prove('retained_saved_pointer_is_entry_X26',cell(v,s+0x9b8,8)!=p)
    c0,c1=z3.BitVecs('as_controller0_32 as_controller1_32',32)
    b0,b1=z3.BitVecs('as_bank_byte0 as_bank_byte1',8);lo,hi=z3.BitVecs('as_left64 as_right64',64)
    a0,a1=z3.BitVecs('as_controller_root0 as_controller_root1',64)
    class Banks(Algebra):
        def load(self,a,n):
            if self.pc in [0x100810198,0x1008101f0]:assert n==1;self.bank0=a;return b0
            if self.pc in [0x1008101a4,0x100810200]:assert n==1;self.bank1=a;return b1
            if self.pc in [0x1008101bc,0x100810210]:assert n==8;self.target_slot=a;return z3.BitVecVal(0,64)
            return super().load(a,n)
    v=Banks()
    for name,x in [('sp',s),('x0',p),('x9',s+0xf0c),('x10',s+0x7820),('x11',r+32),('x21',r),('w23',0x86a)]:v.seed(name,x)
    for off,x in [(0x9c8,a0),(0x9c0,a1),(0x600,lo),(0x5f8,hi),(0x9d8,TABLE)]:mem(v,s+off,8,x)
    mem(v,a0,4,c0);mem(v,a1,4,c1);v.run_block(0x100810154,0x1008101d0)
    mix=((c0^c1)^0xa6)*0xa5cd4cf;byte=z3.Extract(7,0,mix)
    prove('copy_bank_addresses_and_source_first_32_byte_ABI',z3.Or(v.bank0!=lo+z3.ZeroExt(56,byte),v.bank1!=hi+z3.ZeroExt(56,b0^0x78),
          v.target_slot!=TABLE+8*(z3.BitVecVal(0xcb12,64)+z3.ZeroExt(56,byte^b1)),
          v.read('x0')!=p,v.read('x1')!=r,v.read('x2')!=32,v.read('x17')!=0x34a1,
          cell(v,s+0x7820,8)!=0,cell(v,s+0xf0c,4)!=0x8b3dc651,v.read('w24')!=0x6cf4))
    v=Banks()
    for name,x in [('sp',s),('x26',a0),('x20',a1),('w22',0xa6),('w25',0xa5cd4cf),('x21',r),('x27',TABLE)]:v.seed(name,x)
    mem(v,a0,4,c0);mem(v,a1,4,c1);mem(v,s+0x9b0,8,lo);mem(v,s+0x9a8,8,hi)
    v.run_block(0x1008101d4,BSM);mix=((c1-c0)^0xa6)*0xa5cd4cf;byte=z3.Extract(7,0,mix)
    prove('BSM_bank_addresses_and_PID_only_output_ABI',z3.Or(v.bank0!=lo+z3.ZeroExt(56,byte),v.bank1!=hi+z3.ZeroExt(56,b0^0xf3),
          v.target_slot!=TABLE+8*(z3.BitVecVal(0xcc7f,64)+z3.ZeroExt(56,byte^b1)),v.read('x0')!=r,
          *[v.read('x'+str(j))!=0 for j in [1,2,3,4,5,7]],v.read('x6')!=s+0x571c,cell(v,s,8)!=0,v.read('x17')!=0xdc55))
    result=z3.BitVec('as_result32',32)
    class Selector(Algebra):
        def load(self,a,n):
            if self.pc==0x1006f7760:assert n==8;self.slot=a;return z3.BitVecVal(0,64)
            return super().load(a,n)
    v=Selector();v.seed('sp',s);v.seed('w28',result);mem(v,s+0x9d0,8,0x6cf4);mem(v,s+0x9d8,8,TABLE)
    v.run_block(NEXT,0x1006f7768)
    prove('conditional_saved_continuation_complete_u32_result_gate',z3.Or(v.slot!=TABLE+8*z3.If(result==0x8b3dc651,
          z3.BitVecVal(0xa424,64),z3.BitVecVal(0x7a10,64)),v.read('w21')!=0x1cb7,v.read('x17')!=0x4113))
    return qs

def build():
    cases=[component(c) for c in configuration()];old=retained();counts=Counter()
    for row in [c['trace'] for c in cases+old]:
        counts.update(source_visits=len(row['source_visits']),reads=len(row['source_reads']),
                      writes=len(row['source_writes']),logical_edges=len(row['logical_edges']))
    used={int(x['address'],16) for c in cases+old for x in c['trace']['source_reads'] if int(x['address'],16) in FIXUPS}
    used.update(TABLE+8*j for j in [0x2895,0x5e,0x6a1f,0x6a27,0xa424,0x7a10]);used.update(int(r['slot'],16) for r in banks())
    return {'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n) for n in DEPS},
            'source_sha256':sha(SOURCE),'source_regions':source(),'bank_rules':banks(),
            'source_fixups':Parent.Parent.fixups(used),'source_proofs':obligations(),'bounded_census':census(),
            'retained_cases':old,'cases':cases,'verified_counts':{'component_cases':len(cases),'retained_cases':len(old),**counts},
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
