#!/usr/bin/env python3
"""Independent input-producer replay, scalar frames and original-byte controls.

Does not import the new producer. O(C*(B+V*J+P*F+R)+3072*Kh+1024*Ks)
time; bounded private maps; 30 s/SMT query. No native API/IPC or IDB.
"""
import copy,json
from pathlib import Path
from hashlib import sha256
from collections import Counter
import z3
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM
from unicorn import arm64_const as U
from capstone.arm64_const import ARM64_SFT_LSL,ARM64_SFT_LSR,ARM64_EXT_SXTW
import audit_corefp_word_recurrence as R
from verify_daemon_reader_record_payloads_publication import read
ROOT=R.ROOT;C=R.C;SHA=R.SHA;MOD=2**64;M=2**32-1;BUF=0x7400000200;TABLE=0x7800000000
SPECS=[('first_setup',0x1b47cc,0x1b489c),('first_head',0x1b48a0,0x1b4900),('first_tail_setup',0x1b4d74,0x1b4e98),('first_tail',0x1b4e9c,0x1b4efc),('copy_a',0x1b51d4,0x1b51d8),('control_seed',0x1b54d0,0x1b54e0),
 ('second_meta',0x1b55b0,0x1b55e0),('second_setup',0x1b5620,0x1b56d4),('second_head',0x1b56d8,0x1b5738),('second_tail_setup',0x1b5c40,0x1b5d1c),('second_tail',0x1b5d20,0x1b5d84)]
HEADERS={'first_head':{'counter':9,'base':23,'bias':0x37a981c3,'kind':0,'word':28,'pointer':27},'first_tail':{'counter':20,'base':23,'bias':0x37a981c3,'kind':1,'word':3,'pointer':2},
 'second_head':{'counter':1,'base':25,'bias':0x20390963,'kind':2,'word':3,'pointer':3},'second_tail':{'counter':16,'base':25,'bias':0x20390963,'kind':3,'word':3,'pointer':3}}
FIRST={0:0x3079b42400000000,7:0xddaef339,11:0xd6aee21e48c104c1,13:0x25d80cb3b079b424,14:0x21480c8200000000,16:0x25d80cb300000000,12:R.H0,19:R.H0,24:R.A,25:R.B,21:0x37a981c3,9:0x37a981c3}
TAIL={0:0xeee6c51fe30eeb7d,8:0x75e63c31c1b5fc60,13:0x91182a693ce91cf0,14:0x7ffeef76dfe7f790,15:0x11193ae0,27:0xad09be712e6ef6a0,28:0x43ef7b6ecd601ddd,30:0x9b00f92e22bb1720}


class Replay(R.Replay):
    def __init__(self,*a):super().__init__(*a);self.input_components=[];self.current_input=None
    def code(self,u,pc,n,d):
        self.flush()
        for name,lo,hi in SPECS:
            if pc==C.BASE+lo:assert self.current_input is None;self.current_input={'name':name,'entry':R.W.E.F.F.A.capture(self)}
            if pc==C.BASE+hi and self.current_input is not None and self.current_input['name']==name:
                self.current_input['end']=R.W.E.F.F.A.capture(self);self.input_components.append(self.current_input);self.current_input=None
        return super().code(u,pc,n,d)


def scalar(b,s):
    cpu=copy.deepcopy(b['entry']['CPU']);regs=list(map(lambda x:int(x,16),cpu['X31']));sp=int(cpu['SP'],16);nzcv=int(cpu['NZCV'],16);stack=bytearray.fromhex(b['entry']['stack1312_hex']);memory={};reads=[];writes=[]
    for r in b['reads']:
        for j,v in enumerate(bytes.fromhex(r['bytes_hex'])):memory[int(r['address'],16)+j]=v
    def rr(n):
        n={'fp':'x29','lr':'x30'}.get(n,n)
        if n=='sp':return sp
        if n in ['xzr','wzr']:return 0
        return regs[int(n[1:])]%2**(32 if n[0]=='w'else 64)
    def put(n,v):n={'fp':'x29','lr':'x30'}.get(n,n);regs[int(n[1:])]=v%2**(32 if n[0]=='w'else 64)
    def val(i,o,bits):
        v=rr(i.reg_name(o.reg))if o.type==1 else o.imm
        if o.ext:assert o.ext==ARM64_EXT_SXTW;v%=2**32;v-=2**32 if v>=2**31 else 0
        if o.shift.type:
            if o.shift.type==ARM64_SFT_LSL:v*=2**o.shift.value
            else:assert o.shift.type==ARM64_SFT_LSR;v//=2**o.shift.value
        return v%2**bits
    def cc(i):
        c=bool(nzcv&(1<<29));z=bool(nzcv&(1<<30));return {'lo':not c,'hi':c and not z,'eq':z,'ne':not z}[i.op_str.rsplit(', ',1)[1]]
    _,lo,hi=next(v for v in SPECS if v[0]==b['name'])
    for serial,i in enumerate(C.CS.disasm(s.read(lo,hi-lo),lo)):
        m=i.mnemonic;o=i.operands;n=i.reg_name(o[0].reg);bits=32 if n.startswith('w')else 64
        if m in ['ldr','ldur','str','stur']:
            mem=o[1];at=rr(i.reg_name(mem.mem.base))+mem.mem.disp
            if mem.mem.index:
                v=rr(i.reg_name(mem.mem.index));v-=2**32 if mem.ext==ARM64_EXT_SXTW and v>=2**31 else 0;at+=v*2**mem.shift.value
            at%=MOD;width=bits//8;raw=bytes(stack[at-sp:at-sp+width])if sp<=at and at+width<=sp+len(stack)else bytes(memory[at+j]for j in range(width));row={'visit':b['entry']['source_visit']+serial,'address':hex(at),'size_B':width}
            if m.startswith('ld'):reads.append({**row,'bytes_hex':raw.hex()});put(n,int.from_bytes(raw,'little'))
            else:
                assert sp<=at and at+width<=sp+len(stack);after=rr(n).to_bytes(width,'little');stack[at-sp:at-sp+width]=after;writes.append({**row,'before_hex':raw.hex(),'after_hex':after.hex()})
            continue
        if m=='mov':put(n,val(i,o[1],bits));continue
        if m=='movk':put(n,(rr(n)&~(65535<<o[1].shift.value))|(o[1].imm<<o[1].shift.value));continue
        if m=='cmp':
            a,c=val(i,o[0],bits),val(i,o[1],bits);v=(a-c)%2**bits;nzcv=((v>>(bits-1))<<31)|(int(v==0)<<30)|(int(a>=c)<<29)|(int(bool(((a^c)&(a^v))>>(bits-1)))<<28);continue
        if m=='cset':put(n,int(cc(i)));continue
        if m=='csel':put(n,val(i,o[1]if cc(i)else o[2],bits));continue
        a,c=val(i,o[1],bits),val(i,o[2],bits)
        if m=='add':v=a+c
        elif m=='sub':v=a-c
        elif m=='and':v=a&c
        elif m=='orr':v=a|c
        elif m=='eor':v=a^c
        elif m=='lsl':v=a*2**(c%bits)
        else:assert m=='lsr';v=a//2**(c%bits)
        put(n,v)
    cpu.update({'X31':list(map(hex,regs)),'NZCV':hex(nzcv),'PC':hex(C.BASE+hi)});assert cpu==b['end']['CPU']and stack.hex()==b['end']['stack1312_hex']and reads==b['reads']and writes==b['writes']


class Component:
    def __init__(self,b,s):
        self.b=b;_,self.lo,self.hi=next(v for v in SPECS if v[0]==b['name']);self.u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);self.fixed=set();self.dynamic=set();self.source=s.read(self.lo,self.hi-self.lo)
        def fixed(at,raw):
            for page in range(at&~4095,(at+len(raw)+4095)&~4095,4096):
                if page not in self.fixed:self.u.mem_map(page,4096);self.fixed.add(page)
            self.u.mem_write(at,raw)
        fixed(C.BASE+self.lo,self.source);cpu=b['entry']['CPU'];self.sp=int(cpu['SP'],16);self.stack=bytes.fromhex(b['entry']['stack1312_hex']);fixed(self.sp,self.stack)
        for r in b['reads']:fixed(int(r['address'],16),bytes.fromhex(r['bytes_hex']))
        C.restore(self.u,cpu);self.context=self.u.context_save();frame,stack=self.run();assert frame==b['end']['CPU']and stack.hex()==b['end']['stack1312_hex']
    def run(self,regs=None,stack=None,supply=None,stop=None):
        for page in self.dynamic:self.u.mem_unmap(page,4096)
        self.dynamic.clear();self.u.context_restore(self.context);self.u.mem_write(self.sp,self.stack if stack is None else bytes(stack))
        for k,v in (regs or {}).items():self.u.reg_write(getattr(U,'UC_ARM64_REG_X'+str(k)),v)
        for at,raw in supply or []:
            for page in range(at&~4095,(at+len(raw)+4095)&~4095,4096):
                if page not in self.fixed and page not in self.dynamic:self.u.mem_map(page,4096);self.dynamic.add(page)
            self.u.mem_write(at,raw)
        end=stop or self.hi;self.u.emu_start(C.BASE+self.lo,C.BASE+end,count=(end-self.lo)//4+1);assert self.u.reg_read(U.UC_ARM64_REG_PC)==C.BASE+end
        return C.frame(self.u),bytes(self.u.mem_read(self.sp,len(self.stack)))
    def intact(self):assert bytes(self.u.mem_read(C.BASE+self.lo,len(self.source)))==self.source
    def header(self):
        d=HEADERS[self.b['name']];c=R.CONFIG[d['kind']];entry=list(map(lambda v:int(v,16),self.b['entry']['CPU']['X31']));word=int.from_bytes(bytes.fromhex(self.b['reads'][-1]['bytes_hex']),'little');counter=entry[d['counter']]&M;digest=sha256();cases=0
        def check(counter,word):
            nonlocal cases
            index=(counter-d['bias'])&M;at=BUF+8*index;frame,stack=self.run({d['counter']:counter,d['base']:BUF},supply=[(at,word.to_bytes(8,'little'))]);rr=list(map(lambda v:int(v,16),frame['X31']));assert stack==self.stack and rr[d['word']]==word
            assert all((rr[j]+v)%MOD==index for j,v in zip(c['idx'],c['offset']));digest.update(json.dumps(frame,sort_keys=True).encode());cases+=1
        for lane in range(4):
            for byte in range(256):check(((byte<<(lane*8))^0x9e3779b9)&M,word)
        for lane in range(8):
            for byte in range(256):check(counter,((byte<<(lane*8))^0x6a09e667f3bcc909)%MOD)
        bad=d['bias']^1;frame,stack=self.run({d['counter']:bad,21:bad,d['base']:BUF},stop=self.hi-4);rr=list(map(lambda v:int(v,16),frame['X31']));expected=(bad-d['bias'])&M;actual=(rr[c['idx'][0]]+c['offset'][0])%MOD;at=rr[d['pointer']]
        assert stack==self.stack and actual!=expected and at!=BUF+8*expected and actual==MOD-1 and expected==M and at==BUF-8
        control={'threshold_register':'X21','retained_threshold_u32':hex(d['bias']),'changed_threshold_u32':hex(bad),'counter_u32':hex(bad),'actual_index_u64':hex(actual),'candidate_index_u64':hex(expected),'actual_address_u64':hex(at),'candidate_address_u64':hex(BUF+8*expected),'stopped_before_word_load':True,'common_contract_rejected':True}
        assert cases==3072;self.intact();return {'name':self.b['name'],'cases':cases,'source_visits':cases*(self.hi-self.lo)//4,'ordered_frames_sha256':digest.hexdigest(),'off_premise_controls':[control],'source_bytes_preserved':True}
    def setup(self):
        name=self.b['name'];entry=list(map(lambda v:int(v,16),self.b['entry']['CPU']['X31']));digest=sha256();cases=0
        assert name in ['first_setup','first_tail_setup','control_seed','second_setup','second_tail_setup']
        for lane in range(4):
            for byte in range(256):
                x=((byte<<(lane*8))^0x9e3779b9)&M;regs={};stack=bytearray(self.stack);expected=bytearray(self.stack);supply=[];wanted={}
                if name=='first_setup':
                    regs={22:x};wanted={**FIRST,8:x^0x7d45};values=[(0x50,4,int.from_bytes(stack[0x340:0x344],'little')^3),(0x58,4,(entry[27]&M)>>8),(0x438,4,entry[7]&M),(0x90,4,(entry[7]&M)>>16),(0x104,4,(entry[26]&M)>>16),(0xec,4,(entry[26]&M)>>8)]
                elif name=='first_tail_setup':
                    regs={8:x};stack[0x488:0x490]=TABLE.to_bytes(8,'little');expected[:]=stack;raw=bytes.fromhex(self.b['reads'][-1]['bytes_hex']);supply=[(TABLE+8*x,raw)];t=(10*(((x-1)&M)^0x82d1))&M;wanted={**TAIL,11:(x-1)&M,16:(t+0xb8442f8ce72af7a5)%MOD,7:int.from_bytes(raw,'little')};values=[(0x348,8,t)]
                elif name=='control_seed':regs={10:x};wanted={13:(x+0x864e)&M,16:(x+0x218e)&M};values=[]
                elif name=='second_setup':
                    regs={13:x};g=((x+0x5ce82c08)&M)&0xa3177c8d;wanted={24:(g+0x1912e4b015aa7516)%MOD,20:0x1532dd4e00000000,23:R.B,1:0x20390963,25:int.from_bytes(bytes.fromhex(self.b['reads'][-1]['bytes_hex']),'little')};values=[(0x410,8,g)]
                else:
                    stack[0x410:0x418]=x.to_bytes(8,'little');stack[0x488:0x490]=TABLE.to_bytes(8,'little');expected[:]=stack;raw=bytes.fromhex(self.b['reads'][-1]['bytes_hex']);signed=x if x<2**31 else x-2**32;supply=[(TABLE+8*signed,raw)];s=x^0xc579;g=((s+0x46ae3c8e)&M)&0xb9515fbf
                    wanted={24:0x0fa973f3ac5bfc00,27:0x68c613f41a12cb00,8:(g+0x86aa3caf87653ad1)%MOD};values=[(0x450,4,x^0x1b64aff0),(0x458,4,s),(0x410,8,g)]
                for off,n,v in values:expected[off:off+n]=v.to_bytes(n,'little')
                frame,after=self.run(regs,stack,supply);rr=list(map(lambda v:int(v,16),frame['X31']));assert all(rr[k]==v for k,v in wanted.items())and after==expected
                digest.update(json.dumps(frame,sort_keys=True).encode());digest.update(after);cases+=1
        assert cases==1024;self.intact();return {'name':name,'cases':cases,'source_visits':cases*(self.hi-self.lo)//4,'ordered_frames_and_stack_sha256':digest.hexdigest(),'source_bytes_preserved':True}


def epochs(p):
    out=[];visits=p['visits']
    for writer,reader,n in [('0x1b4e0c','0x1b529c',8),('0x1b56ac','0x1b5c64',8),('0x1b5cd8','0x1b5d20',4),('0x1b5cf4','0x1b63c0',4)]:
        ws=[w for w in p['writes']if visits[w['visit']]['pc']==writer];rs=[r for r in p['reads']if visits[r['visit']]['pc']==reader];assert len(ws)==len(rs)==1;w,r=ws[0],rs[0]
        assert w['address']==r['address']and w['size_B']==r['size_B']==n and w['visit']<r['visit']and w['after_hex']==r['bytes_hex'];at=int(w['address'],16)
        assert not any(w['visit']<v['visit']<r['visit']and int(v['address'],16)<at+n and at<int(v['address'],16)+v['size_B']for v in p['writes'])
        out.append({'store_PC':writer,'read_PC':reader,'address':w['address'],'size_B':n,'store_visit':w['visit'],'read_visit':r['visit'],'value_hex':r['bytes_hex'],'no_intervening_overlapping_write':True})
    return out


def joins(p,blocks,pins):
    label=p['configuration']['label'];once={b['name']:b for b in blocks if b['name']not in HEADERS};get=lambda name,part='end':list(map(lambda v:int(v,16),once[name][part]['CPU']['X31']));first=get('first_setup');master=get('first_setup','entry')[22]&M;key=master^0x7d45;control_store=(10*(((key-1)&M)^0x82d1))&M;ctrl=((control_store+0x32f291f3)&M)&0xcd0d6df7;seed=(ctrl+0x864e)&M;one=((seed+0x5ce82c08)&M)&0xa3177c8d;s=one^0xc579;two=((s+0x46ae3c8e)&M)&0xb9515fbf
    assert master==0xf82c and [key,(key-1)&M,control_store,ctrl,seed,one,two]==[0x8569,0x8568,0x4d3a,0x4d25,0xd373,0x7c09,0x55be]
    assert all(first[k]==v for k,v in FIRST.items())and first[8]==key
    ft=get('first_tail_setup');assert ft[11]==(key-1)&M and ft[16]==control_store+0xb8442f8ce72af7a5 and all(ft[k]==v for k,v in TAIL.items())
    assert get('first_tail_setup','entry')[8]==key and get('control_seed','entry')[10]==ctrl and get('control_seed')[13]==seed and get('second_setup','entry')[13]==seed
    second=get('second_setup');last=get('second_tail_setup');assert second[24]==one+0x1912e4b015aa7516 and second[20]==0x1532dd4e00000000 and second[23]==R.B and second[12]==R.H0
    assert last[8]==two+0x86aa3caf87653ad1 and last[24]==0x0fa973f3ac5bfc00 and last[27]==0x68c613f41a12cb00
    assert get('copy_a','entry')[24]==get('copy_a')[28]==second[28]==R.A
    initializers=pins['corefp_scan_entry_checks.json']['blocks'];initializer=next(b for b in initializers if b['label']==label and b['name']=='first_initializer');assert int(initializer['end']['CPU']['X31'][10],16)==ctrl
    codec=pins['corefp_word_codec_checks.json'];rec=pins['corefp_word_recurrence_checks.json'];head=[b for b in blocks if b['name']in HEADERS];n=p['configuration']['length_u32']//8;indices=Counter();values=[]
    for b in head:
        d=HEADERS[b['name']];c=R.CONFIG[d['kind']];rr=list(map(lambda v:int(v,16),b['entry']['CPU']['X31']));end=list(map(lambda v:int(v,16),b['end']['CPU']['X31']));i=(rr[d['counter']]-d['bias'])&M;side='first'if d['kind']<2 else'second';assert rr[21]==d['bias']and i==indices[side];indices[side]+=1
        assert all((end[j]+v)%MOD==i for j,v in zip(c['idx'],c['offset']));r=b['reads'][-1];assert int(r['address'],16)==rr[d['base']]+8*i and r['size_B']==8
        old=next(o for o in codec['blocks']if o['label']==label and o['name']==b['name']and o['entry']['source_visit']==b['end']['source_visit']);assert b['end']==old['entry']
        body=next(o for o in rec['blocks']if o['label']==label and o['name']==b['name']and o['entry']==old['end']);assert body['normalized_index_u64']==hex(i)
        if b['name']=='first_head'and i==0:assert rr[19]==R.H0
        if b['name']=='second_head'and i==0:assert rr[12]==R.H0
        values.append({'name':b['name'],'index_u32':hex(i),'threshold_u32':hex(rr[21]),'buffer_u64':hex(rr[d['base']]),'read_address_u64':r['address'],'header_end_visit':b['end']['source_visit'],'recurrence_entry_visit':body['entry']['source_visit']})
    assert indices['first']==indices['second']==n and len({v['buffer_u64']for v in values})==1
    return {'label':label,'master_W22':hex(master),'control_chain_u32':list(map(hex,[key,(key-1)&M,control_store,ctrl,seed,one,two])),'initial_h_u64':hex(R.H0),'a_u64':hex(R.A),'b_u32':hex(R.B),'header_interfaces':values,'epochs':epochs(p),'same_retained_buffer':True}


def check_census(e,s):
    c=e['census'];lo,hi=map(lambda k:int(c[k],16),['start','end']);rows=[{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'instruction':i.mnemonic+' '+i.op_str}for i in C.CS.disasm(s.read(lo,hi-lo),lo)];assert rows==c['instructions']and len(rows)==1791 and len(c['contracts'])==16
    for contract in c['contracts']:
        lo,hi=map(lambda k:int(contract[k],16),['start','end']);ins=list(C.CS.disasm(s.read(lo,hi-lo),lo));names={str(prefix)+str(j)for j in contract['preserved_registers']for prefix in ['w','x']};branches=[]
        for i in ins:
            rr,ww=i.regs_access();assert not names&{i.reg_name(j)for j in ww}and not any(i.group(g)for g in [2,3])
            if i.group(1):assert i.mnemonic=='braa';branches.append(hex(i.address))
        assert contract['branch_sites']==branches and contract['instruction_count']==len(ins)


def main():
    raw=read(ROOT/'corefp_word_inputs_checks.json').encode();e=json.loads(raw);s=C.Pointers();assert e['generator_sha256']==SHA((ROOT/'recover_corefp_word_inputs.py').read_bytes())and e['thin_sha256']==C.THIN_SHA;pins={}
    for n,h in e['parent_pins'].items():
        rr=read(ROOT/n).encode();assert SHA(rr)==h;pins[n]=json.loads(rr)
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h
    assert len(e['source_regions'])==11
    for region,(name,lo,hi)in zip(e['source_regions'],SPECS):
        assert region['name']==name and region['start']==hex(lo)and region['end']==hex(hi)and region['instructions']==[{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'instruction':i.mnemonic+' '+i.op_str}for i in C.CS.disasm(s.read(lo,hi-lo),lo)]
    for region in e['threshold_resets']+e['counter_regions']:
        lo,hi=map(lambda k:int(region[k],16),['start','end']);assert region['instructions']==[{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'instruction':i.mnemonic+' '+i.op_str}for i in C.CS.disasm(s.read(lo,hi-lo),lo)]
    check_census(e,s);old=R.W.frozen(pins)+pins['corefp_word_codec_checks.json']['proofs']+pins['corefp_word_recurrence_checks.json']['source_checks']['proofs'];new=e['source_checks']['proofs'];assert len(old)==1192 and len(new)==42
    for proof in old+new:
        q=z3.Solver();q.set(timeout=30000);q.from_string(proof['query']);assert proof['result']=='unsat'and q.check()==z3.unsat,proof['label']
    print(json.dumps({'queries_unsat':1234}),flush=True);parent=pins['corefp_workspace_checks.json'];totals=Counter();oracles=[];controls=[];interfaces=[];offset=0
    for j,p in enumerate(parent['profiles']):
        totals.update(R.W.E.F.F.A.initial_checks(p,s));r=Replay(p,parent['source_spans'],s);totals.update(r.run());R.W.E.F.F.W.workspace_oracle(p,r,s,parent['workspace_constructions'][j]);R.W.E.F.F.W.preparation_oracle(p,r,s)
        assert r.current_input is None;start=offset
        for actual in r.input_components:
            b=e['blocks'][offset];offset+=1;assert b['name']==actual['name']and b['label']==p['configuration']['label']and all(b[t]==actual[t]for t in ['entry','end']);lo,hi=b['entry']['source_visit'],b['end']['source_visit'];assert b['visits']==p['visits'][lo:hi]
            for k in ['reads','writes','PAC_models']:assert b[k]==[v for v in p[k]if lo<=v['visit']<hi]
            scalar(b,s);c=Component(b,s)
            if b['name']in HEADERS:oracles.append({'label':b['label'],**c.header()})
            elif b['name']in ['first_setup','first_tail_setup','control_seed','second_setup','second_tail_setup']:oracles.append({'label':b['label'],**c.setup()})
        join=joins(p,e['blocks'][start:offset],pins);assert e['joins'][j]['label']==join['label']and int(e['joins'][j]['master_W22'],16)&M==int(join['master_W22'],16)and e['joins'][j]['control_chain_u32']==join['control_chain_u32'];interfaces.append(join);print(json.dumps({'audited':p['configuration']['label']}),flush=True)
    expected={'profiles':6,'regions':74,'source_instructions':339,'source_B':1356,'regional_visits':2226,'regional_reads':104,'regional_writes':66,'regional_PAC_models':0,'census_instructions':1791,'census_B':7164,'preservation_contracts':16,'new_queries_unsat':42}
    assert offset==74 and e['verified_counts']==expected and sum(len(b['visits'])for b in e['blocks'])==2226 and sum(len(b['reads'])for b in e['blocks'])==104 and sum(len(b['writes'])for b in e['blocks'])==66 and not any(b['PAC_models']for b in e['blocks'])
    assert dict(totals)==pins['corefp_word_recurrence_audit.json']['result']['independent_replay']and e['replay_totals']=={k:v for k,v in totals.items()if not k.startswith('initial_')}
    headers=[o for o in oracles if o['name']in HEADERS];setups=[o for o in oracles if o['name']not in HEADERS]
    result={'verified_counts':expected,'independent_replay':dict(totals),'actual_full_frames':74,'independent_scalar_frames':74,'finite_header_cases':sum(o['cases']for o in headers),'finite_setup_cases':sum(o['cases']for o in setups),
      'finite_source_visits':sum(o['source_visits']for o in oracles),'off_premise_prefixes':sum(len(o['off_premise_controls'])for o in headers),'off_premise_source_visits':sum(((next(hi-lo for name,lo,hi in SPECS if name==o['name']))//4-1)*len(o['off_premise_controls'])for o in headers),
      'stable_control_epochs':sum(len(j['epochs'])for j in interfaces),'header_handoffs':sum(len(j['header_interfaces'])for j in interfaces),'new_queries_unsat':42,'frozen_queries_unsat':1192,'total_queries_unsat':1234,'all_checks_pass':True,'native_target_executed':False}
    assert len(headers)==32 and len(setups)==30 and result['finite_header_cases']==98304 and result['finite_setup_cases']==30720 and result['finite_source_visits']==3784704 and result['off_premise_prefixes']==32 and result['off_premise_source_visits']==742 and result['stable_control_epochs']==24 and result['header_handoffs']==32
    out={'result':result,'checks_sha256':SHA(raw),'auditor_sha256':SHA(Path(__file__).read_bytes()),'generator_sha256':e['generator_sha256'],'parent_pins':e['parent_pins'],'dependencies':e['dependencies'],'component_oracles':oracles,'interface_joins':interfaces,
      'fresh_replay_completed':True,'process_exit_code':0,'native_API_executed':False,'IDB_mutated':False,'new_live_IDA_claim':False,'earlier_arithmetic_passes_universally_reduced':False,'general_raw_preparation_contract_established':False,'whole_transform_algorithm':'unknown','full_goal_complete':False}
    (ROOT/'corefp_word_inputs_audit.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(result),flush=True)


if __name__=='__main__':main()
