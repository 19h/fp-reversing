#!/usr/bin/env python3
"""Independent original-record/nested-admission replay and source audit.

Reconstructs all declared entry bytes and diagnostic controls independently;
never imports the new producer. Full CPU, source read/write, final RAM and
source/IDA identities are checked. No native API or protected result supplied.
O(C*(B+F+V+P*J+R)+256*K) time and O(B+F+C*(V+J+P+R)) space;
P counts modeled PAC sites and J source journal entries. SMT cost separate.
"""
import base64,json,zlib,struct
from collections import Counter
from hashlib import sha256
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
import unicorn as uc
from unicorn import arm64_const as A
import z3
from verify_daemon_reader_record_payloads_publication import read

ROOT=Path(__file__).resolve().parent;CS=Cs(CS_ARCH_ARM64,CS_MODE_ARM);CS.detail=True
SHA=lambda b:sha256(b).hexdigest()
STACK=0x71000000;OWNER=0x73000000;CONTEXT=OWNER+0x2000;HALT=0x7f000000
SP=STACK+0x8000;FP=STACK+0xc000;RECORD=FP-0xb8;OUT=SP+0x978
GLOB=0x1d33000;RAM=[(STACK,65536),(OWNER,16384),(GLOB,0x11000)]


def unpack(p):
    b=zlib.decompress(base64.b64decode(p['zlib_base64'],validate=True));assert len(b)==p['size_bytes']and SHA(b)==p['sha256'];return b


class Replay:
    def __init__(self,p,code,banks,D):
        self.p=p;self.c=p['configuration'];self.D=D;self.phase='constructor';self.v=self.r=self.w=self.pi=self.ci=0
        self.pending=[];self.stats=Counter();self.used=set();self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM)
        for a,n in [(0x8f3000,4096),(0x981000,8192),(0x181000,4096),(0x174f000,4096),
          (0x18ac000,4096),(0x1ac1000,4096),(0x1c78000,4096),(0x1c80000,0xa0000),(HALT,4096)]+RAM:self.u.mem_map(a,n)
        self.ranges=[]
        for r in code:
            a=int(r['start'],16);b=bytes.fromhex(r['bytes_hex']);self.u.mem_write(a,b);self.ranges.append((a,a+len(b)))
        for a,b in banks.items():self.u.mem_write(a,b)
        for a,row in D.items():
            if 0x1c80000<=a<a+8<=0x1d20000 and not row['bind']:self.u.mem_write(a,int(row['target'],16).to_bytes(8,'little'))
        self.u.mem_write(0x1d1c578,(0x1d43300).to_bytes(8,'little'))
        for a,n in RAM:self.u.mem_write(a,b'\xa5'*n)
        c=self.c
        entries={0x1d356f0:c['global1_u64'],0x1d37f68:c['global2_u64'],0x1d333e8:c['global3_u64'],
          0x1d358c8:c['global4_u64'],0x1d43500:c['seed_u64'],0x1d43300:0xb39a4e0cf582617d,
          SP+0x1b8:OWNER+0x880,SP+0x398:0x1d43500}
        for a,v in entries.items():self.u.mem_write(a,v.to_bytes(8,'little'))
        self.u.mem_write(CONTEXT+0x294,(0x4b0cf052).to_bytes(4,'little'))
        for j in range(31):self.setreg(j,((j+1)*0x13579bdf02468ace)&((1<<64)-1))
        for j,v in {12:CONTEXT,22:0x7bd0,29:FP}.items():self.setreg(j,v)
        self.u.reg_write(A.UC_ARM64_REG_SP,SP);self.u.reg_write(A.UC_ARM64_REG_PC,0x8f3448)
        self.u.reg_write(A.UC_ARM64_REG_NZCV,0);self.u.reg_write(A.UC_ARM64_REG_CPACR_EL1,3<<20)
        for j in range(32):self.u.reg_write(A.UC_ARM64_REG_Q0+j,int.from_bytes(bytes([j])*16,'little'))
        self.frame(p['initial']);assert len(p['initial_RAM'])==3
        for row,(a,n)in zip(p['initial_RAM'],RAM):assert row['address']==hex(a)and unpack(row['payload'])==self.ram(a,n)
        self.u.hook_add(uc.UC_HOOK_CODE,self.hook);self.u.hook_add(uc.UC_HOOK_MEM_READ,self.readhook);self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.writehook)
    def reg(self,j):return self.u.reg_read(getattr(A,'UC_ARM64_REG_X'+str(j)))
    def setreg(self,j,v):self.u.reg_write(getattr(A,'UC_ARM64_REG_X'+str(j)),v)
    def ram(self,a,n):return bytes(self.u.mem_read(a,n))
    def frame(self,f):
        assert f=={'pc':hex(self.u.reg_read(A.UC_ARM64_REG_PC)),'sp':hex(self.u.reg_read(A.UC_ARM64_REG_SP)),
          'registers31':[hex(self.reg(j))for j in range(31)],'NZCV':hex(self.u.reg_read(A.UC_ARM64_REG_NZCV)),
          'Q32':[hex(self.u.reg_read(A.UC_ARM64_REG_Q0+j))for j in range(32)]};self.stats['complete_CPU_frames_checked']+=1
    def flush(self):
        for e in self.pending:assert self.ram(int(e['address'],16),e['size_B']).hex()==e['after_hex']
        self.pending=[]
    def readhook(self,u,access,a,n,value,data):
        assert self.p['source_reads'][self.r]=={'phase':self.phase,'visit':self.v-1,'address':hex(a),'size_B':n,'bytes_hex':self.ram(a,n).hex()};self.r+=1
        if a in self.D:self.used.add(a)
    def writehook(self,u,access,a,n,value,data):
        assert any(lo<=a<a+n<=lo+m for lo,m in RAM)
        e=self.p['source_writes'][self.w];self.w+=1
        assert {k:e[k]for k in ['phase','visit','address','size_B','before_hex']}=={'phase':self.phase,'visit':self.v-1,'address':hex(a),'size_B':n,'before_hex':self.ram(a,n).hex()};self.pending.append(e)
    def hook(self,u,pc,n,data):
        self.flush()
        if pc==HALT:self.frame(self.p['terminal']);self.stop='returned';u.emu_stop();return
        assert any(lo<=pc<hi for lo,hi in self.ranges)
        raw=self.ram(pc,4);i=next(CS.disasm(raw,pc));target=mod=None
        if pc in [0x981104,0x981218,0x981520]:
            point=self.p['CPU_points'][self.ci];self.ci+=1;assert point['pc']==hex(pc);self.frame(point['CPU'])
            if pc in [0x981104,0x981218]:
                cursor=int.from_bytes(self.ram(self.reg(1),8),'little');want=self.c['seed_u64']-(0xe0 if pc==0x981104 else 0)
                assert point['cursor_pointer']==hex(self.reg(1))and point['cursor_u64']==hex(cursor)and cursor==want&((1<<64)-1)
            else:
                at=self.u.reg_read(A.UC_ARM64_REG_SP)+0x48;d=self.ram(at,16)
                assert point['descriptor16_address']==hex(at)and point['descriptor16_hex']==d.hex()
                assert int.from_bytes(d[:8],'little')==0x4b0cf05100000001
                payload=int.from_bytes(d[8:],'little')
                scalar=(0x0c9700c5+0xf369ff3c)&0xffffffff;assert scalar==65537
                encoded=(scalar-(0x358e1de4&(scalar<<1))+0x1ac70ef2)&0xffffffff
                assert int.from_bytes(self.ram(payload,4),'little')==encoded==0x1ac60ef3
                self.stats['selected_65537_initializers_checked']+=1
        if i.mnemonic in ['braa','blraa']:
            regs=i.op_str.upper().replace(' ','').split(',');target=self.u.reg_read(getattr(A,'UC_ARM64_REG_'+regs[0]));mod=self.u.reg_read(getattr(A,'UC_ARM64_REG_'+regs[1]))
            if i.mnemonic=='blraa'and not any(lo<=target<hi for lo,hi in self.ranges):
                e=self.p['frontier'];self.frame(self.p['terminal']);self.stop='unretained_callee'
                assert e=={'pc':hex(pc),'target':hex(target),'modifier':hex(mod),'original_slot':'0x1d03900','instruction':i.mnemonic+' '+i.op_str,'instruction_executed':False,'argument_record80_hex':self.ram(self.reg(0),80).hex()}
                assert (pc,target,mod)==(0x981754,0x17bbb8,0xc2d9);self.used.add(0x1d03900);u.emu_stop();return
        assert self.p['source_visits'][self.v]=={'phase':self.phase,'pc':hex(pc),'bytes_hex':raw.hex(),'instruction':i.mnemonic+' '+i.op_str};self.v+=1
        if i.mnemonic in ['pacibsp','retab','braa','blraa']:
            e=self.p['PAC_models'][self.pi];self.pi+=1;self.frame(e['before']);assert e['pc']==hex(pc)and e['kind']==i.mnemonic
            if target is not None:
                slot=int(e['original_slot'],16);row=self.D[slot]
                assert e['target']==hex(target)and e['modifier']==hex(mod)and row['target']==hex(target)and row['diversity']==hex(mod)and row['key']=='IA'and row['address_diversity']==0
                assert int.from_bytes(self.ram(slot,8),'little')==target
                assert any(r['address']==hex(slot)and r['size_B']==8 and int(r['bytes_hex'],16)!=0 for r in self.p['source_reads'][:self.r])
                if i.mnemonic=='blraa':self.setreg(30,pc+4)
                u.reg_write(A.UC_ARM64_REG_PC,target)
            else:u.reg_write(A.UC_ARM64_REG_PC,self.reg(30)if i.mnemonic=='retab'else pc+4)
    def run(self):
        self.u.emu_start(0x8f3448,0x8f34f8,count=10000);self.flush();self.frame(self.p['constructor_terminal'])
        before=self.ram(RECORD,80);assert before.hex()==self.p['record80_before_controls_hex']
        ptr=RECORD&0xffffffff;mask=((((ptr&0x55860eb0)*2-ptr+0x2a79f14c)&0xffffffff)^0x84f565d4)*0x9e8a2055&0xffffffff
        want=bytearray(b'\xa5'*80)
        for off,v,n in [(0,0,8),(8,mask^0x5a617ac0,4),(0x10,SP+0x5c4,8),(0x18,CONTEXT+0x290,8),
          (0x20,OWNER+0x880,8),(0x28,CONTEXT+0x3a0,8),(0x38,CONTEXT,8),(0x40,0,8),(0x48,(mask+0x9265)&0xffffffff,4)]:want[off:off+n]=v.to_bytes(n,'little')
        assert before==want and int.from_bytes(self.ram(SP+0x5c4,4),'little')==128
        control=self.c['control'];patches=[]
        off={'null_context':0x38,'null_count':0x10,'null_input':0x20,'null_auxiliary':0x28}.get(control)
        if off is not None:patches=[(RECORD+off,b'\0'*8)]
        elif control=='compare_equal':patches=[(RECORD+8,((mask^0x5a617ac0)^0x80).to_bytes(4,'little'))]
        else:assert control=='as_staged'
        actual=[]
        for a,b in patches:actual.append({'address':hex(a),'before_hex':self.ram(a,len(b)).hex(),'after_hex':b.hex()});self.u.mem_write(a,b)
        assert actual==self.p['record_controls']and self.ram(RECORD,80).hex()==self.p['record80_after_controls_hex']
        self.phase='nested';self.setreg(0,RECORD);self.setreg(1,OUT);self.setreg(30,HALT);self.u.reg_write(A.UC_ARM64_REG_PC,0x981c38);self.frame(self.p['nested_entry'])
        self.u.emu_start(0x981c38,0,count=10000);self.flush();assert self.stop==self.p['stop_reason']
        assert self.v==len(self.p['source_visits'])and self.r==len(self.p['source_reads'])and self.w==len(self.p['source_writes'])and self.pi==len(self.p['PAC_models'])and self.ci==len(self.p['CPU_points'])
        assert self.p['used_original_pointer_rows']==[self.D[a]for a in sorted(self.used)]
        for row in self.p['used_original_pointer_rows']:
            if row['bind']:assert row['import']['name']=='___stack_chk_guard';continue
            word=int(row['word'],16);decoded=word&0xffffffff if word>>63 else(word&((1<<43)-1))|(((word>>43)&255)<<56)
            assert decoded==int(row['target'],16)
            if word>>63:assert word>>49&3==0 and word>>32&65535==int(row['diversity'],16)and word>>48&1==row['address_diversity']
            self.stats['original_pointer_profile_associations_checked']+=1
        seed=self.c['seed_u64'];value=int.from_bytes(self.ram(OUT,8),'little');status=int.from_bytes(self.ram(RECORD+0x30,4),'little')
        complete=control not in ['as_staged','null_auxiliary']
        assert self.stop==('returned'if complete else'unretained_callee')and value==(0 if complete else seed)
        assert status==(0x45e2a202 if complete else 0xa5a5a5a5)
        assert self.p['final_delta_cell_u64']==hex(value)and self.p['final_status_u32']==hex(status)
        output_writes=[w for w in self.p['source_writes']if w['phase']=='nested'and int(w['address'],16)<OUT+8 and OUT<int(w['address'],16)+w['size_B']]
        assert len(output_writes)==(1 if complete else 0)
        if complete:assert self.p['source_visits'][output_writes[0]['visit']]['pc']=='0x981e54'and output_writes[0]['after_hex']=='00'*8
        if complete:assert self.u.reg_read(A.UC_ARM64_REG_SP)==SP
        for k in ['source_reads','source_writes']:assert not any(int(e['address'],16)<OWNER+0x900 and OWNER+0x880<int(e['address'],16)+e['size_B']for e in self.p[k])
        assert self.ram(OWNER+0x880,128)==b'\xa5'*128
        assert len(self.p['final_RAM'])==3
        for row,(a,n)in zip(self.p['final_RAM'],RAM):assert row['address']==hex(a)and unpack(row['payload'])==self.ram(a,n);self.stats['complete_final_RAM_bytes_checked']+=n
        assert not self.p['native_effects'];self.stats.update({'original_visits_checked':self.v,'original_reads_checked':self.r,'original_writes_checked':self.w,'PAC_models_checked':self.pi,'cursor_checkpoints_checked':sum(p['pc']in ['0x981104','0x981218']for p in self.p['CPU_points'])})
        return self.stats


def source_and_proofs(e):
    old=json.loads(read(ROOT/'fpsd1201_caller_ida_readback.json'));att=json.loads(read(ROOT/'fpsd1201_record_ida_readback.json'))
    assert att['input_sha256']==old['input_sha256']=='68d2f0a29c63b442f60622f539357db91d4e2a4b1d775e136c40fd8effc5aa2f'
    assert not att['IDB_mutated']and not att['native_target_executed']
    assert len(att['spans'])==2 and sum(r['size_B']for r in att['spans'])==3368
    starts=[int(a,16)for a in json.loads(read(ROOT/'corefp_library_inventory.json'))['compiler_function_starts']]
    for row in att['spans']:
        a=int(row['start'],16);n=row['size_B'];b=bytes.fromhex(row['bytes_hex'])
        assert starts[starts.index(a)+1]==a+n and len(b)==n and SHA(b)==row['sha256']==row['original_sha256']and row['current_equals_IDA_original_bytes']
    main=next(r for r in old['spans']if r['role']=='parent');m=bytes.fromhex(main['bytes_hex']);helper=next(r for r in old['spans']if r['role']=='stack_helper')
    assert main['sha256']=='4e0ebb4383ce0f3d074358e851dd1bdfff67e77d675e0cfa9e73b4a03ff9a94e'and SHA(m)==main['sha256']
    assert [r['start']for r in e['code_spans']]==['0x8f3448','0x981c38','0x981104','0x181b00']
    assert bytes.fromhex(e['code_spans'][0]['bytes_hex'])==m[0x8f3448-0x8e81c8:0x8f34f8-0x8e81c8]
    assert e['code_spans'][1]=={**helper,'role':'helper'}
    for i,r in enumerate(att['spans']):assert e['code_spans'][i+2]=={**r,'role':'child'if i==0 else'initializer'}
    ins={i.address:i for r in e['code_spans']for i in CS.disasm(bytes.fromhex(r['bytes_hex']),int(r['start'],16))}
    exact={0x8f3474:('mov','w10, #0xeb0'),0x8f3478:('movk','w10, #0x5586, lsl #16'),
      0x8f347c:('and','w10, w11, w10'),0x8f3480:('lsl','w10, w10, #1'),0x8f3488:('sub','w10, w10, w11'),
      0x8f348c:('mov','w11, #0xf14c'),0x8f3490:('movk','w11, #0x2a79, lsl #16'),0x8f3494:('add','w10, w10, w11'),
      0x8f3498:('mov','w11, #0x65d4'),0x8f349c:('movk','w11, #0x84f5, lsl #16'),0x8f34a0:('eor','w10, w10, w11'),
      0x8f34a4:('mov','w11, #0x2055'),0x8f34a8:('movk','w11, #0x9e8a, lsl #16'),0x8f34ac:('mul','w10, w10, w11'),
      0x981c50:('mov','x19, x1'),0x981d30:('ldr','x21, [x1]'),0x981da4:('sub','x15, x21, #0xe0'),0x981da8:('str','x15, [x20]'),
      0x981e3c:('mov','x1, x20'),0x981e40:('mov','x17, #0x3f61'),0x981e44:('blraa','x8, x17'),
      0x98120c:('ldr','x9, [x1]'),0x981210:('add','x9, x9, #0xe0'),0x981214:('str','x9, [x1]'),
      0x981228:('orr','w10, w0, w9'),0x98122c:('and','w9, w0, w9'),0x981230:('orn','w9, w9, w10'),
      0x98123c:('eor','w9, w9, w10'),0x981248:('mul','w9, w9, w10'),0x981260:('eor','w15, w11, w9'),
      0x9812d0:('orr','x11, x28, x26'),0x9812d4:('cmp','x11, #0'),0x9812e0:('ccmp','w15, w11, #4, ne'),
      0x9812e4:('cset','w11, eq'),0x9812ec:('sub','w10, w10, w9'),0x9812f0:('eor','w9, w10, w12'),
      0x9812f8:('mul','w9, w9, w12'),0x9812fc:('eor','w11, w9, w11'),0x981300:('and','w11, w11, #1'),
      0x981304:('orr','w11, w11, w11, lsl #1'),0x981308:('eor','w10, w11, w10'),
      0x9813a4:('orr','x11, x16, x1'),0x9813a8:('cmp','x13, #0'),0x9813ac:('ccmp','x11, #0, #4, ne'),
      0x9813b0:('cset','w11, eq'),0x9813b4:('eor','w10, w8, w10'),0x9813bc:('eor','w10, w10, w12'),
      0x9813c0:('mul','w10, w11, w10'),0x9813c4:('eor','w9, w10, w9'),
      0x981bf8:('str','w10, [x0, #0x30]'),0x981e48:('ldr','w8, [x20]'),0x981e4c:('sub','w8, w8, w21'),
      0x981e50:('ubfiz','x8, x8, #4, #0x10'),0x981e54:('str','x8, [x19]')}
    for pc,want in exact.items():assert (ins[pc].mnemonic,ins[pc].op_str)==want
    lookup=json.loads(read(ROOT/'corefp_lookup_contracts.json'));banks={}
    for row in lookup['banks']:
        for a,k in [('first_address','first_bytes'),('second_address','second_bytes')]:
            address=int(row[a],16);b=bytes.fromhex(row[k]);assert len(b)==256
            assert address not in banks or banks[address]==b;banks[address]=b
    values=[]
    for a,b,k,c in [(0x174f320,0x18ac370,0xe4,0xec),(0x1ac1bc0,0x1c78140,0x4c,0x35),
      (0x18ac070,0x1ac18c0,7,0x61),(0x1ac19c0,0x1c78040,0x20,0x94),(0x1ac19c0,0x1c78040,0x27,0x18),
      (0x174f220,0x18ac170,0xa5,0xd6),(0x1ac19c0,0x1c78040,0x78,0x2e),(0x174f320,0x18ac370,0xe5,0xaa)]:
        assert set(j^banks[b][banks[a][j]^k]for j in range(256))=={c};values.append(c)
    D={int(r['address'],16):r for r in json.loads(read(ROOT/'corefp_fixups_inventory.json'))['fixups']};B=0x1d05fa0;T=0x1c81940
    for index,target in [(0x8d4+0xec,0x1d356f0),(0x17ec+0x35,0x1d37f68),
      (0xa55+0x61,0x1d435c4),(0x1511+0x18,T+4),(0x57e+0xec,0x1d333ec),(0x174b+0xd6,0x1d37f68),(0x14fb+0x2e,T+4)]:assert D[B+index*8]['target']==hex(target)
    assert D[T+(0x1079d+0x94)*8]['target']=='0x981104'and D[T+(0x1079d+0x94)*8]['diversity']=='0x3f61'
    for p in e['proofs']:
        s=z3.Solver();s.set(timeout=30000);s.add(z3.parse_smt2_string(p['query']));assert str(s.check())==p['result']=='unsat'
    # Independent local obligations use the pinned source primitives above.
    x=z3.BitVec('independent_pointer',32)
    lhs=(((2*(x&0x55860eb0)-x+0x2a79f14c)^0x84f565d4)*0x9e8a2055)
    rhs=(~(x^0x4014fca6)^0x116797c1)*0x9e8a2055
    seed=z3.BitVec('independent_seed',64)
    flag=z3.Bool('independent_nonnull');word=z3.BitVec('independent_compare',32)
    idx=z3.BitVecVal(0x9265,32)^z3.If(z3.And(flag,word!=0x5a617a40),z3.BitVecVal(3,32),z3.BitVecVal(0,32))
    ptrs=[z3.BitVec('independent_p'+str(j),64)for j in range(3)];good=z3.And(ptrs[0]!=0,z3.Or(ptrs[1]!=0,ptrs[2]!=0))
    guard=z3.And(ptrs[0]!=0,(ptrs[1]|ptrs[2])!=0)
    for assertion in [z3.Implies((x&7)==0,lhs==rhs),(seed-z3.BitVecVal(224,64))+224==seed,
      (idx==0x9266)==z3.And(flag,word!=0x5a617a40),good==guard]:
        s=z3.Solver();s.set(timeout=30000);s.add(z3.Not(assertion));assert s.check()==z3.unsat
    s=z3.Solver();s.add(x==1,lhs!=rhs);assert s.check()==z3.sat
    return banks,D,{'fresh_IDA_spans':2,'fresh_IDA_bytes':3368,'compiler_bounded_bodies':2,
      'exact_source_instructions_checked':len(exact),'exhaustive_bank_inputs':8*256,'retained_queries_unsat':4,
      'independent_local_queries_unsat':4,'unaligned_pointer_counterexamples':1}


def main():
    e=json.loads(read(ROOT/'fpsd1201_record_checks.json'))
    assert e['generator_sha256']==SHA((ROOT/'recover_fpsd1201_record.py').read_bytes())
    for name,value in e['dependencies'].items():assert SHA(read(ROOT/name).encode())==value
    assert e['IDA_readback_sha256']==SHA(read(ROOT/'fpsd1201_record_ida_readback.json').encode())
    banks,D,source=source_and_proofs(e);totals=Counter()
    controls=['as_staged','null_context','null_count','null_input','compare_equal','null_auxiliary']
    expected=[(seed,control)for seed in [0,1,0xffffffffffffffff,0x0123456789abcdef]for control in controls]
    assert [(p['configuration']['seed_u64'],p['configuration']['control'])for p in e['profiles']]==expected
    for p in e['profiles']:totals.update(Replay(p,e['code_spans'],banks,D).run())
    assert e['entry_register_and_context_fixtures_are_declared']and not any(e[k]for k in ['whole_parent_replayed','native_target_executed','IDB_edit_operations_requested','full_goal_complete'])
    result={'source':source,'fresh_replay':dict(totals),'profiles':len(e['profiles']),'completed_rejections':16,
      'unretained_call_frontiers':8,'candidate_inline128_reads_or_writes':0,'whole_parent_replayed':False,
      'complete_as_staged_return_established':False,'native_target_executed':False,'full_goal_complete':False,'all_checks_pass':True}
    receipt={'result':result,'dependencies':e['dependencies'],'checks_sha256':SHA(read(ROOT/'fpsd1201_record_checks.json').encode()),
      'IDA_readback_sha256':e['IDA_readback_sha256'],'auditor_sha256':SHA(Path(__file__).read_bytes()),
      'fresh_replay_completed':True,'process_exit_code':0,'native_target_executed':False}
    (ROOT/'fpsd1201_record_audit.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(result))


if __name__=='__main__':main()
