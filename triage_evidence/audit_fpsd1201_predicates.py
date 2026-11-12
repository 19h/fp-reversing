#!/usr/bin/env python3
"""Independent sparse-RAM replay, frozen prefix refresh and leaf contracts.

Does not import the new producer. Prefix refresh shares only the frozen
declared API/PAC models; continuation uses a separate original-byte engine.
O(B+F+C*(V+J+R)+L*K) time/space, finite cases bounded; SMT is separate.
No target, native API, Mach message or IDB operation executes.
"""
import base64,json,struct,zlib
from pathlib import Path
from hashlib import sha256
from collections import Counter
import unicorn as U
from unicorn import arm64_const as A
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
import z3
import corefp_library_reader as L
L.SOURCE=Path(__file__).resolve().parent.parent/'CoreFP'
from corefp_fixups_reader import Pointers,ROOT
from probe_corefp_client_flow import Flow
from probe_corefp_exports import BASE
from verify_daemon_reader_record_payloads_publication import read

SHA=lambda b:sha256(b).hexdigest();CS=Cs(CS_ARCH_ARM64,CS_MODE_ARM);CS.detail=True
M32=(1<<32)-1;M64=(1<<64)-1


def unpack(d):
    b=zlib.decompress(base64.b64decode(d['zlib_base64'],validate=True));assert len(b)==d['size_bytes']and SHA(b)==d['sha256'];return b


def frame(u):
    out={'X31':[hex(u.reg_read(getattr(A,'UC_ARM64_REG_X'+str(i))))for i in range(31)],
      'Q32':[hex(u.reg_read(A.UC_ARM64_REG_Q0+i))for i in range(32)]}
    for n in ['SP','PC','NZCV','FPCR','FPSR','CPACR_EL1']:out[n]=hex(u.reg_read(getattr(A,'UC_ARM64_REG_'+n)))
    return out


def restore(u,f):
    for i,v in enumerate(f['X31']):u.reg_write(getattr(A,'UC_ARM64_REG_X'+str(i)),int(v,16))
    for i,v in enumerate(f['Q32']):u.reg_write(A.UC_ARM64_REG_Q0+i,int(v,16))
    for n in ['SP','PC','NZCV','FPCR','FPSR','CPACR_EL1']:u.reg_write(getattr(A,'UC_ARM64_REG_'+n),int(f[n],16))
    assert frame(u)==f


class Prefix(Flow):
    def code(self,u,pc,n,d):
        if pc==BASE+0x8ea14c:return self.stop('before_original_request1200_call')
        return super().code(u,pc,n,d)


class Replay:
    def __init__(self,p,spans):
        self.p=p;self.v=self.r=self.w=self.pac=0;self.pending=[];self.u=U.Uc(U.UC_ARCH_ARM64,U.UC_MODE_ARM)
        pages={int(r['address'],16)for r in p['initial_RAM']}
        for s in spans:
            lo,hi=BASE+int(s['start'],16),BASE+int(s['end'],16);pages.update(range(lo&~4095,(hi+4095)&~4095,4096))
        for a in sorted(pages):self.u.mem_map(a,4096)
        for s in spans:self.u.mem_write(BASE+int(s['start'],16),bytes.fromhex(s['bytes']))
        for r in p['initial_RAM']:self.u.mem_write(int(r['address'],16),unpack(r['payload']))
        restore(self.u,p['initial_CPU']);self.u.hook_add(U.UC_HOOK_CODE,self.code)
        self.u.hook_add(U.UC_HOOK_MEM_READ,self.memory);self.u.hook_add(U.UC_HOOK_MEM_WRITE,self.memory)
    def ram(self,a,n):return bytes(self.u.mem_read(a,n))
    def flush(self):
        for e in self.pending:assert self.ram(int(e['address'],16),e['size_B']).hex()==e['after_hex']
        self.pending=[]
    def memory(self,u,access,a,n,v,d):
        if access==U.UC_MEM_READ:
            e={'visit':self.v-1,'address':hex(a),'size_B':n,'bytes_hex':self.ram(a,n).hex()};assert e==self.p['reads'][self.r];self.r+=1
        else:
            e=self.p['writes'][self.w];self.w+=1
            assert {k:e[k]for k in ['visit','address','size_B','before_hex']}=={'visit':self.v-1,'address':hex(a),'size_B':n,'before_hex':self.ram(a,n).hex()}
            assert any(int(r['address'],16)<=a<a+n<=int(r['address'],16)+4096 for r in self.p['initial_RAM']);self.pending.append(e)
    def code(self,u,pc,n,d):
        self.flush();at=pc-BASE
        if at==int(self.p['frontier']['pc'],16):
            assert frame(u)==self.p['frontier']['CPU'];self.done=True;u.emu_stop();return
        raw=self.ram(pc,4);i=next(CS.disasm(raw,at));assert self.p['visits'][self.v]=={'pc':hex(at),'bytes_hex':raw.hex(),'instruction':i.mnemonic+' '+i.op_str};self.v+=1
        if i.mnemonic in ['braa','blraa']:
            rn,mn=i.op_str.split(', ');target=u.reg_read(getattr(A,'UC_ARM64_REG_'+rn.upper()));modifier=u.reg_read(getattr(A,'UC_ARM64_REG_'+mn.upper()))
            e=self.p['PAC_models'][self.pac];self.pac+=1;assert e['visit']==self.v-1 and e['pc']==hex(at)and e['target']==hex(target-BASE)and e['modifier']==hex(modifier)and e['CPU']==frame(u)
            r=e['original_pointer_row'];assert r['address']==e['slot']and r['key']=='IA'and not r['address_diversity']and int(r['diversity'],16)==modifier and BASE+int(r['target'],16)==target
            assert self.ram(BASE+int(e['slot'],16),8)==target.to_bytes(8,'little')
            if i.mnemonic=='blraa':u.reg_write(A.UC_ARM64_REG_LR,pc+4)
            u.reg_write(A.UC_ARM64_REG_PC,target)
        elif i.mnemonic.startswith(('pac','aut')):u.reg_write(A.UC_ARM64_REG_PC,pc+4)
        elif i.mnemonic in ['retab','retaa']:u.reg_write(A.UC_ARM64_REG_PC,u.reg_read(A.UC_ARM64_REG_LR))
        for e in self.p['record_points']:
            if e['visit']==self.v-1:assert e['pc']==hex(at)and e['CPU']==frame(u)and self.ram(int(e['record_pointer'],16),44).hex()==e['record44_hex']
    def run(self):
        self.u.emu_start(int(self.p['initial_CPU']['PC'],16),0,count=30001);self.flush();assert self.done
        assert [self.v,self.r,self.w,self.pac]==[len(self.p[k])for k in ['visits','reads','writes','PAC_models']]
        total=0
        for r in self.p['final_RAM']:assert self.ram(int(r['address'],16),4096)==unpack(r['payload']);total+=4096
        return {'visits_checked':self.v,'reads_checked':self.r,'writes_checked':self.w,'PAC_models_checked':self.pac,'final_RAM_B_checked':total}


def leaf_contract(entry,p,b):
    I=lambda off:int.from_bytes(b[off:off+4],'little');Q=lambda off:int.from_bytes(b[off:off+8],'little')
    if entry==0x274ed0:
        h=(((p^0x83d2a2b8ac4eec68)^0x4c51ef0102c278f0)*0x9e8a2055)&M64
        a=(Q(16)-h)&M64;c=(Q(32)+h)&M64;mode=(I(24)-h)&M32
        truth=c>a if mode&1 else c==a
        return ((((I(8)-h)&M32)if truth else((I(28)+h)&M32))^((I(0)+h)&M32)),40
    h=((~(p^0x43e21bde5aac752d)^0xa8964ff1d5102928)*0x4ecee2ad)&M64
    a=(Q(16)+h)&M64;c=(Q(24)+h)&M64;mode=(I(0)-h)&M32
    truth=a>c if mode&1 else Q(16)==Q(24)
    return (((I(12)^(h&M32))if truth else((I(8)+h)&M32))^((I(4)-h)&M32)),32


def leaf_cases(spans):
    cases=[];pairs=[(0,0),(0,1),(1,0),(M64,M64),(M64,0),(0,M64),(1<<63,(1<<63)-1),((1<<63)-1,1<<63)]
    for s in spans[1:]:
        entry=int(s['start'],16);u=U.Uc(U.UC_ARCH_ARM64,U.UC_MODE_ARM);u.mem_map(entry&~4095,4096);u.mem_write(entry,bytes.fromhex(s['bytes']));u.mem_map(0x60000000,8192);u.mem_map(0x70000000,4096)
        for delta in [0x100,0x108,0x1f8,0xff8]:
            p=0x60000000+delta
            for mode in [0,1,2,M32]:
                for a,c in pairs:
                    t=0x92abcdef;f=0x76543210;mask=0xfedcba98;b=bytearray(b'\xa5'*48)
                    if entry==0x274ed0:
                        h=(((p^0x83d2a2b8ac4eec68)^0x4c51ef0102c278f0)*0x9e8a2055)&M64
                        for off,v in {0:mask-h,8:t+h,24:mode+h,28:f-h}.items():struct.pack_into('<I',b,off,v&M32)
                        struct.pack_into('<Q',b,16,(a+h)&M64);struct.pack_into('<Q',b,32,(c-h)&M64);truth=c>a if mode&1 else c==a
                    else:
                        h=((~(p^0x43e21bde5aac752d)^0xa8964ff1d5102928)*0x4ecee2ad)&M64
                        for off,v in {0:mode+h,4:mask+h,8:f-h,12:t^(h&M32)}.items():struct.pack_into('<I',b,off,v&M32)
                        struct.pack_into('<Q',b,16,(a-h)&M64);struct.pack_into('<Q',b,24,(c-h)&M64);truth=a>c if mode&1 else a==c
                    expected=(t if truth else f)^mask;model,off=leaf_contract(entry,p,b);assert model==expected
                    u.mem_write(p,bytes(b));u.reg_write(A.UC_ARM64_REG_X0,p);u.reg_write(A.UC_ARM64_REG_LR,0x70000000);u.reg_write(A.UC_ARM64_REG_SP,0x60001000)
                    u.emu_start(entry,0x70000000,count=64);assert u.reg_read(A.UC_ARM64_REG_PC)==0x70000000 and u.reg_read(A.UC_ARM64_REG_X0)==p and u.reg_read(A.UC_ARM64_REG_SP)==0x60001000
                    result=bytes(u.mem_read(p,48));wanted=bytearray(b);struct.pack_into('<I',wanted,off,expected);assert result==wanted
                    cases.append({'entry':hex(entry),'record_pointer':hex(p),'mode_u32':mode,'left_u64':hex(a),'right_u64':hex(c),
                      'before48_hex':b.hex(),'after48_hex':result.hex(),'expected_result_u32':hex(expected),'store_offset_B':off})
    assert len(cases)==256
    return cases


def lifted_leaf_proofs(spans):
    """Lift every instruction of each complete pure leaf to bitvectors."""
    proofs=[]
    for span in spans[1:]:
        entry=int(span['start'],16);p=z3.BitVec('record_address_'+str(entry),64)
        mem=[z3.BitVec('byte_'+str(entry)+'_'+str(j),8)for j in range(48)];regs={0:p};flags={};stores=[];count=0
        def load(off,bits):return z3.Concat(*reversed(mem[off:off+bits//8]))
        def reg(n):
            bits=32 if n.startswith('w')else 64
            value=z3.BitVecVal(0,64)if n.endswith('zr')else regs[int(n[1:])]
            return z3.Extract(31,0,value)if bits==32 else value
        def put(n,v):regs[int(n[1:])]=z3.ZeroExt(32,v)if n.startswith('w')else v
        def val(i,o,bits):
            if o.type==1:return reg(i.reg_name(o.reg))
            assert o.type==2;return z3.BitVecVal(o.imm,bits)
        for i in CS.disasm(bytes.fromhex(span['bytes']),entry):
            count+=1;m=i.mnemonic;ops=i.operands;n=i.reg_name(ops[0].reg)if ops and ops[0].type==1 else None;bits=32 if n and n.startswith('w')else 64
            if m=='ret':continue
            if m=='mov':put(n,val(i,ops[1],bits));continue
            if m=='movk':
                shift=ops[1].shift.value;mask=((1<<bits)-1)^(65535<<shift);put(n,(reg(n)&mask)|(z3.BitVecVal(ops[1].imm,bits)<<shift));continue
            if m in ['ldr','ldp']:
                o=ops[-1];assert o.type==3 and i.reg_name(o.mem.base)=='x0'and not o.mem.index
                put(n,load(o.mem.disp,bits))
                if m=='ldp':put(i.reg_name(ops[1].reg),load(o.mem.disp+bits//8,bits))
                continue
            if m=='str':
                o=ops[1];assert o.type==3 and i.reg_name(o.mem.base)=='x0'and not o.mem.index;stores.append((o.mem.disp,reg(n)));continue
            if m in ['cmp','tst']:
                a,b=val(i,ops[0],bits),val(i,ops[1],bits)
                flags={'eq':a==b,'hi':z3.UGT(a,b),'ne':a!=b}if m=='cmp'else{'eq':a&b==0,'ne':a&b!=0};continue
            if m=='cset':put(n,z3.If(flags[i.op_str.split(', ')[-1]],z3.BitVecVal(1,bits),z3.BitVecVal(0,bits)));continue
            if m=='csel':put(n,z3.If(flags[i.op_str.split(', ')[-1]],val(i,ops[1],bits),val(i,ops[2],bits)));continue
            if m=='mvn':put(n,~val(i,ops[1],bits));continue
            a,b=val(i,ops[1],bits),val(i,ops[2],bits)
            assert m in ['add','sub','mul','and','orr','eor','bic'],m
            v={'add':lambda:a+b,'sub':lambda:a-b,'mul':lambda:a*b,'and':lambda:a&b,'orr':lambda:a|b,'eor':lambda:a^b,'bic':lambda:a&~b}[m]()
            put(n,v)
        assert count==len(bytes.fromhex(span['bytes']))//4 and len(stores)==1
        if entry==0x274ed0:
            a=z3.BitVecVal(0x83d2a2b8ac4eec68,64);h=(((p|a)-(p|~a)+~a)^0x4c51ef0102c278f0)*0x9e8a2055;h32=z3.Extract(31,0,h)
            left=load(16,64)-h;right=load(32,64)+h;mode=load(24,32)-h32
            truth=z3.If(mode&1!=0,z3.UGT(right,left),right==left)
            wanted=z3.If(truth,load(8,32)-h32,load(28,32)+h32)^(load(0,32)+h32);off=40
        else:
            a=z3.BitVecVal(0x43e21bde5aac752d,64);h=(((~p&~a)|(p&a))^0xa8964ff1d5102928)*0x4ecee2ad;h32=z3.Extract(31,0,h)
            truth=z3.If((load(0,32)-h32)&1!=0,z3.UGT(load(16,64)+h,load(24,64)+h),load(16,64)==load(24,64))
            wanted=z3.If(truth,load(12,32)^h32,load(8,32)+h32)^(load(4,32)-h32);off=32
        assert stores[0][0]==off and stores[0][1].size()==32 and z3.eq(regs[0],p)
        solver=z3.Solver();solver.set(timeout=30000);solver.add(stores[0][1]!=wanted);assert solver.check()==z3.unsat
        proofs.append({'entry':hex(entry),'source_instructions_lifted':count,'store_offset_B':off,'query':solver.to_smt2(),'result':'unsat'})
    return proofs


def main():
    e=json.loads(read(ROOT/'fpsd1201_predicates_checks.json'));assert e['generator_sha256']==SHA((ROOT/'recover_fpsd1201_predicates.py').read_bytes())
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h
    s=Pointers();assert s.function(0x8e81c8)==e['source_spans'][0]
    for span in e['source_spans']:assert s.function(int(span['start'],16))==span
    p=Prefix(s,e['fixture']);row=p.run_caller();assert row==e['prefix']['result']and frame(p.u)==e['prefix']['CPU']
    fp=int(e['prefix']['CPU']['X31'][29],16);sp=int(e['prefix']['CPU']['SP'],16);owner=int(e['prefix']['CPU']['X31'][20],16)
    assert(sp,fp,owner)==(0x7a036190,0x7a037ff0,0x7a036b50)and int.from_bytes(p.u.mem_read(sp+0x5c8,8),'little')==0x9a0
    assert int.from_bytes(p.u.mem_read(sp+0x308,8),'little')==((((fp-0xb8)^0x83d2a2b8ac4eec68)^0x4c51ef0102c278f0)*0x9e8a2055)&M64
    assert [q['global_control_u32']for q in e['profiles']]==[0,1,2,M32]
    total=Counter()
    for q in e['profiles']:
        flag=q['global_control_u32'];assert q['control']=={'address':hex(BASE+0x1d45f6c),'before_hex':'00000000','after_hex':flag.to_bytes(4,'little').hex()}
        p.u.mem_write(BASE+0x1d45f6c,flag.to_bytes(4,'little'));start=frame(p.u);start['PC']=hex(BASE+0x8ea164);assert start==q['initial_CPU']
        for r in q['initial_RAM']:assert bytes(p.u.mem_read(int(r['address'],16),4096))==unpack(r['payload']);total['initial_RAM_B_checked']+=4096
        total.update(Replay(q,e['source_spans']).run())
        assert q['owner']==hex(owner)and q['context']==hex(sp+0x1340)and q['context128_hex']=='006664706300000001'+'00'*119 and q['SP_1f0_hex']==(sp+0x1340).to_bytes(8,'little').hex()
        assert not q['request1200_gap_executed']and not q['native_effects']
        f=q['frontier'];assert f['pc']==('0x8ea868'if flag==0 else'0x8ea3b4')
        if flag==0:assert f['CPU']['X31'][12]==hex(BASE+0x1d33108)and f['CPU']['X31'][8]=='0x5d96'
        else:assert f['CPU']['X31'][13]=='0x0'
        C=sp+0x1340
        context_stores=[(q['visits'][w['visit']]['pc'],w['address'],w['size_B'],w['after_hex'])for w in q['writes']if C<=int(w['address'],16)<C+128]
        assert context_stores==[('0x8ea1f8',hex(C),8,'0066647063000000'),('0x8ea200',hex(C+8),1,'01')]
        if flag:
            for pc,address,size in [('0x8ea398',0x1d45f60,8),('0x8ea3a0',0x1d44440,4)]:
                reaching=[r for r in q['reads']if q['visits'][r['visit']]['pc']==pc];assert reaching[-1]['address']==hex(BASE+address)and reaching[-1]['size_B']==size and reaching[-1]['bytes_hex']=='00'*size
        for event in q['PAC_models']:assert event['original_pointer_row']==s.decoded[int(event['slot'],16)]
        for point in q['record_points']:
            if point['pc']in ['0x274ed0','0x1abbe0']:
                entry=int(point['pc'],16);v,off=leaf_contract(entry,int(point['record_pointer'],16),bytes.fromhex(point['record44_hex']))
                ret=next(x for x in q['record_points']if x['visit']>point['visit']and x['pc']==('0x8ea7a8'if entry==0x274ed0 else'0x8ed05c'))
                assert int.from_bytes(bytes.fromhex(ret['record44_hex'])[off:off+4],'little')==v
    for proof in e['proofs']:
        solver=z3.Solver();solver.set(timeout=30000);solver.add(z3.parse_smt2_string(proof['query']));assert proof['result']=='unsat'and solver.check()==z3.unsat
    solver=z3.Solver();solver.add(z3.parse_smt2_string(e['ordering_countermodel']['query']));assert solver.check()==z3.sat
    counts={'prefix_engine_steps':row['steps'],'prefix_original_visits':len(row['visited_original_instructions']),'profiles':len(e['profiles']),**{k:sum(len(p[k])for p in e['profiles'])for k in ['visits','reads','writes','PAC_models','record_points']},
      'queries_unsat':len(e['proofs']),'ordering_countermodels_sat':1,'atomic_stops':1,'uninitialized_pointer_stops':3}
    assert counts==e['verified_counts']=={'prefix_engine_steps':19723,'prefix_original_visits':19717,'profiles':4,'visits':41357,'reads':7913,'writes':2077,'PAC_models':1911,'record_points':14,
      'queries_unsat':6,'ordering_countermodels_sat':1,'atomic_stops':1,'uninitialized_pointer_stops':3}
    cases=leaf_cases(e['source_spans']);lifted=lifted_leaf_proofs(e['source_spans'])
    result={'verified_counts':counts,'fresh_continuation':dict(total),'fresh_prefix_engine_steps':row['steps'],'fresh_prefix_original_visits':len(row['visited_original_instructions']),
      'original_leaf_bytes_checked':sum(len(bytes.fromhex(v['bytes']))for v in e['source_spans'][1:]),'independent_leaf_cases':len(cases),
      'source_lifted_leaf_proofs_unsat':len(lifted),'whole_parent_replayed':False,'native_target_executed':False,'all_checks_pass':True}
    out={'result':result,'leaf_cases':cases,'source_lifted_leaf_proofs':lifted,'checks_sha256':SHA(read(ROOT/'fpsd1201_predicates_checks.json').encode()),
      'auditor_sha256':SHA(Path(__file__).read_bytes()),'dependencies':e['dependencies'],'fresh_replay_completed':True,'process_exit_code':0}
    (ROOT/'fpsd1201_predicates_audit.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(result),flush=True)


if __name__=='__main__':main()
