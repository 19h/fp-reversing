#!/usr/bin/env python3
"""Independently replay keyed-state frontiers and lift the complete signed leaf.

No import of this increment's producer. Frozen prefix, receipt restores and
explicit selector controls remain premises. O(C*(B+F+V+J+R)+L*K) is a
conservative time/space bound including source setup;
SMT has a 30 s query limit. No native target/API/IPC or IDB mutation runs.
"""
import json,struct,copy
from pathlib import Path
from hashlib import sha256
from collections import Counter
import unicorn as U
from unicorn import arm64_const as A
import z3
from audit_fpsd1201_predicates import Prefix,Replay as Frozen,frame,restore,unpack,leaf_contract,CS,M32,M64
from corefp_fixups_reader import Pointers,ROOT
from probe_corefp_exports import BASE,BIND
from verify_daemon_reader_record_payloads_publication import read
SHA=lambda b:sha256(b).hexdigest();FLAG=0x1d44409;STATE=0x1d4551c


def signed(x):return x if x<1<<63 else x-(1<<64)


def contract(p,b):
    w=lambda o:int.from_bytes(b[o:o+4],'little');q=lambda o:int.from_bytes(b[o:o+8],'little')
    H=(((p^0x2f2e0531b9d8df3b)^0xab99749f60a72103)*0xfcf33521)&M64;h=H&M32
    a=(q(16)-H)&M64;c=(q(24)-H)&M64;mode=(w(12)+h)&M32
    truth=signed(c)<signed(a)if mode&1 else c<a
    out=(((w(32)^h)if truth else(w(4)-h)&M32)^((w(8)+h)&M32))
    return {'H':hex(H),'A':hex(a),'B':hex(c),'mode_u32':mode,'true_u32':w(32)^h,'false_u32':(w(4)-h)&M32,'mask_u32':(w(8)+h)&M32,'truth':truth,'result_u32':out}


class Replay(Frozen):
    def __init__(self,p,spans):
        super().__init__(p,spans);self.mi=self.pi=0;self.u.mem_map(BIND,0x2000)
    def code(self,u,pc,n,d):
        self.flush();at=pc-BASE
        while self.pi<len(self.p['points'])and self.p['points'][self.pi]['visit']==self.v:
            e=self.p['points'][self.pi];self.pi+=1;assert e['pc']==hex(at)and e['CPU']==frame(u)
            assert e['record_pointer']==hex(u.reg_read(A.UC_ARM64_REG_X0))
            if e['record44_hex']is not None:assert self.ram(int(e['record_pointer'],16),44).hex()==e['record44_hex']
        if pc==int(self.p['frontier']['CPU']['PC'],16):assert frame(u)==self.p['frontier']['CPU'];self.done=True;u.emu_stop();return
        raw=self.ram(pc,4);i=next(CS.disasm(raw,at));assert self.p['visits'][self.v]=={'pc':hex(at),'bytes_hex':raw.hex(),'instruction':i.mnemonic+' '+i.op_str};self.v+=1
        if i.mnemonic=='casal':
            assert at==0x8ea868 and i.op_str=='w8, w11, [x12]';e=self.p['models'][self.mi];self.mi+=1
            a=u.reg_read(A.UC_ARM64_REG_X12);assert a==BASE+0x1d33108 and self.ram(a,4)==bytes.fromhex('965d0000')
            assert u.reg_read(A.UC_ARM64_REG_W8)==0x5d96 and u.reg_read(A.UC_ARM64_REG_W11)==0xa94ef
            assert e=={'kind':'declared_sequential_CASAL','visit':self.v-1,'address':hex(a),'old_u32':0x5d96,'compare_u32':0x5d96,'replacement_u32':0xa94ef,
              'before':frame(u),'after':dict(copy.deepcopy(frame(u)),PC=hex(pc+4)),'after4_hex':'ef940a00'}
            u.mem_write(a,bytes.fromhex('ef940a00'));u.reg_write(A.UC_ARM64_REG_PC,pc+4);return
        if i.mnemonic in ['braa','blraa']:
            rn,mn=i.op_str.split(', ');target=u.reg_read(getattr(A,'UC_ARM64_REG_'+rn.upper()));mod=u.reg_read(getattr(A,'UC_ARM64_REG_'+mn.upper()))
            e=self.p['PAC_models'][self.pac];self.pac+=1;row=e['original_pointer_row']
            resolved=BIND+row['import']['ordinal']*16+row['pointer_addend']if row['bind']else BASE+int(row['target'],16)
            assert e['CPU']==frame(u)and e['visit']==self.v-1 and e['pc']==hex(at)and e['target']==hex(target)and e['modifier']==hex(mod)
            assert row['key']=='IA'and not row['address_diversity']and int(row['diversity'],16)==mod and resolved==target
            assert self.ram(BASE+int(e['slot'],16),8)==target.to_bytes(8,'little')
            if i.mnemonic=='blraa':u.reg_write(A.UC_ARM64_REG_LR,pc+4)
            u.reg_write(A.UC_ARM64_REG_PC,target)
        elif i.mnemonic.startswith(('pac','aut')):u.reg_write(A.UC_ARM64_REG_PC,pc+4)
        elif i.mnemonic in ['retab','retaa']:u.reg_write(A.UC_ARM64_REG_PC,u.reg_read(A.UC_ARM64_REG_LR))
    def run(self):
        self.u.emu_start(int(self.p['initial_CPU']['PC'],16),0,count=30001);self.flush();assert self.done
        assert [self.v,self.r,self.w,self.pac,self.mi,self.pi]==[len(self.p[k])for k in ['visits','reads','writes','PAC_models','models','points']]
        for r in self.p['final_RAM']:assert self.ram(int(r['address'],16),4096)==unpack(r['payload'])
        sp=int(self.p['initial_CPU']['SP'],16);assert self.ram(sp+0x1340,128).hex()==self.p['context128_hex']=='006664706300000001'+'00'*119
        assert self.ram(sp+0x1a30,32).hex()==self.p['tuple32_hex']
        return {'visits_checked':self.v,'reads_checked':self.r,'writes_checked':self.w,'PAC_models_checked':self.pac,'models_checked':self.mi,'points_checked':self.pi,
          'final_RAM_B_checked':4096*len(self.p['final_RAM'])}


def leaf_cases(span):
    lo=int(span['start'],16);u=U.Uc(U.UC_ARCH_ARM64,U.UC_MODE_ARM);u.mem_map(lo&~4095,4096);u.mem_write(lo,bytes.fromhex(span['bytes']))
    u.mem_map(0x60000000,8192);u.mem_map(0x70000000,4096);out=[]
    pairs=[(0,0),(0,1),(1,0),(M64,M64),(M64,0),(0,M64),(1<<63,(1<<63)-1),((1<<63)-1,1<<63)]
    for delta in [0x100,0x108,0x1f8,0xff8]:
        p=0x60000000+delta;H=(((p^0x2f2e0531b9d8df3b)^0xab99749f60a72103)*0xfcf33521)&M64;h=H&M32
        for mode in [0,1,2,M32]:
            for a,b in pairs:
                raw=bytearray(b'\xa5'*48);t,f,mask=0x92abcdef,0x76543210,0xfedcba98
                for off,v in {4:f+h,8:mask-h,12:mode-h,32:t^h}.items():struct.pack_into('<I',raw,off,v&M32)
                struct.pack_into('<Q',raw,16,(a+H)&M64);struct.pack_into('<Q',raw,24,(b+H)&M64)
                truth=signed(b)<signed(a)if mode&1 else b<a;want=(t if truth else f)^mask;decoded=contract(p,raw);assert decoded['result_u32']==want
                u.mem_write(p,bytes(raw));u.reg_write(A.UC_ARM64_REG_X0,p);u.reg_write(A.UC_ARM64_REG_LR,0x70000000);u.reg_write(A.UC_ARM64_REG_SP,0x60001000)
                u.emu_start(lo,0x70000000,count=64);assert u.reg_read(A.UC_ARM64_REG_PC)==0x70000000 and u.reg_read(A.UC_ARM64_REG_X0)==p and u.reg_read(A.UC_ARM64_REG_SP)==0x60001000
                wanted=bytearray(raw);struct.pack_into('<I',wanted,0,want);assert bytes(u.mem_read(p,48))==wanted
                out.append({'record_pointer':hex(p),'before48_hex':raw.hex(),'after48_hex':wanted.hex(),'decoded':decoded})
    assert len(out)==128;return out


def lifted(span):
    p=z3.BitVec('signed_leaf_R64',64);mem=[z3.BitVec('signed_leaf_byte_'+str(j),8)for j in range(36)];regs={0:p};flags={};stores=[];count=0;H=z3.BitVec('signed_leaf_abstract_key64',64);key_identity=None
    def load(o,b):return z3.Concat(*reversed(mem[o:o+b//8]))
    def reg(n):
        v=z3.BitVecVal(0,64)if n.endswith('zr')else regs[int(n[1:])]
        return z3.Extract(31,0,v)if n.startswith('w')else v
    def put(n,v):regs[int(n[1:])]=z3.ZeroExt(32,v)if n.startswith('w')else v
    def val(i,o,b):return reg(i.reg_name(o.reg))if o.type==1 else z3.BitVecVal(o.imm,b)
    for i in CS.disasm(bytes.fromhex(span['bytes']),int(span['start'],16)):
        count+=1;m=i.mnemonic;ops=i.operands;n=i.reg_name(ops[0].reg)if ops and ops[0].type==1 else None;b=32 if n and n.startswith('w')else 64
        if m=='ret':continue
        if m=='mov':put(n,val(i,ops[1],b));continue
        if m=='movk':
            sh=ops[1].shift.value;put(n,(reg(n)&(((1<<b)-1)^(65535<<sh)))|(z3.BitVecVal(ops[1].imm,b)<<sh));continue
        if m in ['ldp','ldr']:
            o=ops[-1];assert o.type==3 and i.reg_name(o.mem.base)=='x0'and not o.mem.index
            put(n,load(o.mem.disp,b))
            if m=='ldp':put(i.reg_name(ops[1].reg),load(o.mem.disp+b//8,b))
            continue
        if m=='str':assert i.op_str=='w8, [x0]';stores.append((0,reg(n)));continue
        if m in ['cmp','tst']:
            a,c=val(i,ops[0],b),val(i,ops[1],b);flags={'lo':z3.ULT(a,c),'lt':a<c,'ne':a!=c}if m=='cmp'else{'ne':a&c!=0};continue
        if m=='cset':put(n,z3.If(flags[i.op_str.split(', ')[-1]],z3.BitVecVal(1,b),z3.BitVecVal(0,b)));continue
        if m=='csel':put(n,z3.If(flags[i.op_str.split(', ')[-1]],val(i,ops[1],b),val(i,ops[2],b)));continue
        a,c=val(i,ops[1],b),val(i,ops[2],b);assert m in ['orr','and','sub','eor','mul','add']
        put(n,{'orr':lambda:a|c,'and':lambda:a&c,'sub':lambda:a-c,'eor':lambda:a^c,'mul':lambda:a*c,'add':lambda:a+c}[m]())
        if i.address==0x43976c:
            literal=z3.BitVecVal(0x2f2e0531b9d8df3b,64);other=z3.BitVecVal(0xab99749f60a72103,64)
            original=(((p|literal)-(p&literal))^other)*0xfcf33521
            assert z3.eq(z3.simplify(regs[8]),z3.simplify(original))
            solver=z3.Solver();solver.set(timeout=30000);solver.add((p|literal)-(p&literal)!=(p^literal));assert solver.check()==z3.unsat
            key_identity={'label':'source_address_key_XOR_identity','query':solver.to_smt2(),'result':'unsat','exact_multiplier_u32':0xfcf33521}
            regs[8]=H
    h=z3.Extract(31,0,H)
    a=load(16,64)-H;c=load(24,64)-H;mode=load(12,32)+h;truth=z3.If(mode&1!=0,c<a,z3.ULT(c,a))
    wanted=z3.If(truth,load(32,32)^h,load(4,32)-h)^(load(8,32)+h)
    assert count==35 and len(stores)==1 and stores[0][0]==0 and z3.eq(regs[0],p)
    solver=z3.Solver();solver.set(timeout=30000);solver.add(stores[0][1]!=wanted);assert solver.check()==z3.unsat
    assert key_identity is not None
    return {'source_instructions_lifted':count,'proofs':[key_identity,{'label':'complete_body_for_arbitrary_key','query':solver.to_smt2(),'result':'unsat'}],
      'compositional_key_abstraction':'After exact source key construction and proved XOR identity, body is checked for every independent u64 key.', 'accessed_extent_B':36,'output_offset_B':0}


def source_contracts(e,s,old):
    expected={0x8ea8b0:('ldrb','w8, [x8]'),0x8ea8b4:('cmp','w8, #1'),0x8ea8b8:('cset','w8, eq'),
      0x8ea8bc:('mov','w9, #-0x97ad'),0x8ea8c0:('add','w9, w11, w9'),0x8ea8c4:('add','w9, w9, w20'),
      0x8ea8c8:('mul','w8, w9, w8'),0x8ea8cc:('eor','w8, w8, w10'),
      0x8eb9b4:('mov','w8, #0x5f5c'),0x8eb9b8:('movk','w8, #0x7e2e, lsl #16'),0x8eb9bc:('ldr','x9, [sp, #0x438]'),
      0x8eb9c0:('and','w8, w8, w9, lsl #1'),0x8eb9c4:('sub','w8, w9, w8'),
      0x8eb9c8:('mov','w9, #0x6db7'),0x8eb9cc:('movk','w9, #0x3f16, lsl #16'),0x8eb9d0:('add','w9, w27, w9'),
      0x8eb9d4:('add','w8, w8, w9'),0x8eb9d8:('mov','w9, #0x2fae'),0x8eb9dc:('movk','w9, #0x3f17, lsl #16'),
      0x8eb9e0:('eor','w8, w8, w9'),0x8eb9e4:('str','w8, [sp, #0x428]'),
      0x8ebe90:('ldr','w11, [sp, #0x418]'),0x8ebe94:('mov','w8, #0xfff7'),0x8ebe98:('movk','w8, #0xe2b, lsl #16'),
      0x8ebe9c:('and','w8, w11, w8'),0x8ebea0:('mov','w9, #0xaa33'),0x8ebea4:('eor','w10, w23, w9'),
      0x8ebea8:('mov','w9, #0xe228'),0x8ebeac:('movk','w9, #0x61cd, lsl #16'),0x8ebeb0:('cmp','w22, w9'),
      0x8ebeb4:('cset','w9, hi'),0x8ebeb8:('eor','w11, w11, w10'),0x8ebebc:('eor','w9, w11, w9'),
      0x8ebec0:('mov','w11, #1'),0x8ebec4:('bic','w9, w11, w9'),0x8ebec8:('mov','w11, #0x76'),
      0x8ebecc:('mul','w9, w9, w11'),0x8ebed0:('mov','w11, #-0x66c6'),0x8ebed4:('add','w11, w23, w11'),
      0x8ebed8:('eor','w9, w9, w11'),0x8e89f4:('str','w10, [sp, #0x418]')}
    for a,want in expected.items():
        ins=next(CS.disasm(s.read(a,4),a));assert (ins.mnemonic,ins.op_str)==want
    assert '0x8e89f4' in old['prefix']['result']['visited_original_instructions']
    p=z3.BitVec('optional_key_pointer_low32',32);word,counter=z3.BitVecs('optional_control32 optional_counter32',32);flag=z3.BitVec('selector_byte8',8)
    source_pointer=(p-((p<<1)&0x7e2e5f5c)+(0xc1f7+0x3f166db7))^0x3f172fae
    t=z3.If(z3.UGT(counter,0x61cde228),z3.BitVecVal(1,32),z3.BitVecVal(0,32))
    selected=(~(word^(0xc1f7^0xaa33)^t)&1)*0x76^(z3.BitVecVal(0xc1f7-0x66c6,32))
    wanted=z3.If((word&1)==t,z3.BitVecVal(0x5b47,32),z3.BitVecVal(0x5b31,32))
    idx=z3.If(flag==1,z3.BitVecVal(1,32),z3.BitVecVal(0,32))*((-0x97ad+0x10a+0x971b)&M32)^0x892c
    claims=[('source_pointer_low32_identity',source_pointer==p),('source_optional_gate_partition',selected==wanted),
      ('source_selector_all_256_bytes',idx==z3.If(flag==1,z3.BitVecVal(0x8954,32),z3.BitVecVal(0x892c,32)))]
    proofs=[]
    for label,claim in claims:
        solver=z3.Solver();solver.set(timeout=30000);solver.add(z3.Not(claim));assert solver.check()==z3.unsat
        proofs.append({'label':label,'query':solver.to_smt2(),'result':'unsat'})
    rows=[]
    for index,target,div in [(0x8954,0x8ea8ec,0x1414),(0x892c,0x8eb7a4,0x1414),(0x5b47,0x8eba0c,0x7dd1),(0x5b31,0x8ebee8,0x7dd1)]:
        slot=0x1c81940+index*8;row=s.decoded[slot];assert row['target']==hex(target)and row['diversity']==hex(div)and row['key']=='IA'and not row['address_diversity']
        rows.append({'index':hex(index),'slot':hex(slot),'target':hex(target),'IA_diversity':hex(div),'original_pointer_row':row})
    return {'exact_instructions_checked':len(expected),'proofs':proofs,'dispatch_rows':rows,'source_phase_u32':0xc1f7}


def main():
    e=json.loads(read(ROOT/'fpsd1201_key_routes_checks.json'));assert e['generator_sha256']==SHA((ROOT/'recover_fpsd1201_key_routes.py').read_bytes())
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h
    old=json.loads(read(ROOT/'fpsd1201_predicates_checks.json'));seed=json.loads(read(ROOT/'fpsd1201_seed_checks.json'));s=Pointers()
    assert s.read(FLAG,1)==b'\0'and s.read(0x1d32e18,8)==bytes.fromhex('e3b46c1700000000')
    available=json.loads(read(ROOT/'fpsd1201_key_routes_ida_availability.json'));assert not available['target_database_available']and not available['IDB_mutated']
    assert available['requested_target']=='c3d025e56a86'and len(available['listed_databases'])==1
    for span in e['source_spans']:assert s.function(int(span['start'],16))==span
    prefix=Prefix(s,old['fixture']);r=prefix.run_caller();assert r==old['prefix']['result']and frame(prefix.u)==old['prefix']['CPU']
    originalflag=bytes(prefix.u.mem_read(BASE+FLAG,1));assert originalflag==b'\0';totals=Counter();helper_calls=[];mixes=[];routes=[]
    assert len(e['profiles'])==8
    for q in e['profiles']:
        c=q['configuration'];prefix.u.mem_write(BASE+FLAG,originalflag)
        for row in old['profiles'][0]['final_RAM']:prefix.u.mem_write(int(row['address'],16),unpack(row['payload']))
        restore(prefix.u,old['profiles'][0]['frontier']['CPU'])
        if c['kind']=='post_tuple':
            prior=next(v for v in seed['profiles']if v['configuration']['label']==c['label'])
            for row in prior['final_RAM']:prefix.u.mem_write(int(row['address'],16),unpack(row['payload']))
            restore(prefix.u,prior['frontier']['CPU']);assert q['controls']==[]
        else:
            assert c['selector_byte']in [0,1,2,255]and q['controls']==[{'address':hex(BASE+FLAG),'before_hex':'00','after_hex':bytes([c['selector_byte']]).hex(),'reason':'declared selector-byte sensitivity input'}]
        assert q['restored_CPU']==frame(prefix.u)==q['initial_CPU']
        if c['kind']=='selector':prefix.u.mem_write(BASE+FLAG,bytes([c['selector_byte']]))
        for row in q['initial_RAM']:assert bytes(prefix.u.mem_read(int(row['address'],16),4096))==unpack(row['payload']);totals['initial_RAM_B_checked']+=4096
        run=Replay(q,e['source_spans']);totals.update(run.run());sp=int(q['initial_CPU']['SP'],16)
        for edge in q['PAC_models']:assert edge['original_pointer_row']==s.decoded[int(edge['slot'],16)]
        if c['kind']=='post_tuple':
            assert q['frontier']['reason']=='before_optional_key_word_read'and q['frontier']['CPU']['X31'][12]=='0x4'
            stores=[v for v in q['writes']if BASE+STATE<=int(v['address'],16)<BASE+STATE+2496];assert len(stores)==1
            w=stores[0];assert w['address']==hex(BASE+STATE+4)and q['visits'][w['visit']]['pc']=='0x8ebbd4'and w['size_B']==4
            def initial(a,n):
                row=next(v for v in q['initial_RAM']if int(v['address'],16)<=a<a+n<=int(v['address'],16)+4096)
                return unpack(row['payload'])[a-int(row['address'],16):a-int(row['address'],16)+n]
            before=int.from_bytes(initial(BASE+STATE,4),'little');previous1=int.from_bytes(initial(BASE+STATE+4,4),'little');key0=int.from_bytes(initial(sp+0x1a30,4),'little')
            expected=((previous1^((before^(before>>30))*1664525))+key0)&M32;assert w['after_hex']==expected.to_bytes(4,'little').hex()
            mixes.append({'label':c['label'],'seed0_u32':before,'state1_before_u32':previous1,'key0_u32':key0,'state1_after_u32':expected})
            for entry,ret in [(0x1abbe0,0x8ebca4),(0x439734,0x8ebe38)]:
                a=next(v for v in q['points']if v['pc']==hex(entry));b=next(v for v in q['points']if v['pc']==hex(ret));raw=bytes.fromhex(a['record44_hex']);addr=int(a['record_pointer'],16)
                if entry==0x439734:d=contract(addr,raw);out=d['result_u32'];off=0
                else:out,off=leaf_contract(entry,addr,raw);d={'result_u32':out,'output_offset_B':off}
                want=bytearray(raw);struct.pack_into('<I',want,off,out);assert bytes.fromhex(b['record44_hex'])==want and a['record_pointer']==b['record_pointer']
                helper_calls.append({'label':c['label'],'entry':hex(entry),'return':hex(ret),'decoded':d})
            gate=next(v for v in q['points']if v['pc']=='0x8ebe90')['CPU'];assert gate['X31'][22]=='0x61cde226'and gate['X31'][23]=='0xc1f7'
            assert int.from_bytes(run.ram(sp+0x418,4),'little')==0xf1d46bcc and run.ram(sp+0x438,8)==b'\0'*8
            assert not q['models']and q['tuple32_hex']==prior['tuple32_hex']
        else:
            flag=c['selector_byte'];point=next(v for v in q['points']if v['pc']=='0x8ea8b0');assert point['CPU']['X31'][8]==hex(BASE+FLAG)
            positive=flag==1;reason='before_preparation_object_field_read'if positive else'before_first_entropy_call'
            assert q['frontier']['reason']==reason and len(q['models'])==1
            if positive:
                assert q['frontier']['CPU']['X31'][23]=='0x176cb4e3'and q['frontier']['CPU']['PC']==hex(BASE+0x8eaebc)
                producer=next(v for v in q['reads']if q['visits'][v['visit']]['pc']=='0x8eadfc')
                assert producer['address']==hex(BASE+0x1d32e18)and producer['bytes_hex']=='e3b46c1700000000'
            else:assert any(v['pc']=='0x8eb7a4'and v['CPU']['X31'][13]=='0x0'for v in q['points'])
            routes.append({'selector_byte':flag,'reason':reason,'frontier_CPU':q['frontier']['CPU']})
    span=e['source_spans'][2];cases=leaf_cases(span);proof=lifted(span);routesource=source_contracts(e,s,old)
    counts={'profiles':8,'post_tuple_profiles':4,'selector_profiles':4,'prefix_original_visits_per_refresh':19717,
      **{k:sum(len(p[k])for p in e['profiles'])for k in ['visits','reads','writes','PAC_models','models','points']}}
    assert counts==e['verified_counts'];result={'verified_counts':counts,'fresh_prefix_original_visits':19717,'fresh_continuation':dict(totals),
      'independent_leaf_cases':len(cases),'source_lifted_leaf_proofs_unsat':2,'source_route_proofs_unsat':3,'native_target_executed':False,'all_checks_pass':True}
    out={'result':result,'checks_sha256':SHA(read(ROOT/'fpsd1201_key_routes_checks.json').encode()),'auditor_sha256':SHA(Path(__file__).read_bytes()),
      'dependencies':e['dependencies'],'leaf_cases':cases,'leaf_proof':proof,'source_route_contracts':routesource,'helper_calls':helper_calls,'first_mixes':mixes,'selector_routes':routes,
      'fresh_replay_completed':True,'process_exit_code':0}
    (ROOT/'fpsd1201_key_routes_audit.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(result),flush=True)


if __name__=='__main__':main()
