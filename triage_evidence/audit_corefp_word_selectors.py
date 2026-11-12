#!/usr/bin/env python3
"""Independent source-selector replay, cache epochs and original-byte tests.

Does not import the new producer. O(C*(B+V*J+P*F+R)+K*L) time/space;
bounded private maps; 30 s/SMT query. No native API/IPC or IDA.
"""
import copy,json
from pathlib import Path
from hashlib import sha256
from collections import Counter
import z3
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM
from unicorn import arm64_const as U
from capstone.arm64_const import ARM64_SFT_LSL,ARM64_SFT_LSR,ARM64_EXT_SXTW,ARM64_EXT_UXTB,ARM64_EXT_UXTW
import audit_corefp_word_traversal as R
from verify_daemon_reader_record_payloads_publication import read
ROOT=R.ROOT;C=R.C;SHA=R.SHA;MOD=2**64;M=2**32-1;MASK=MOD-1;KEY=0xcccccccccccccccc;PRIVATE=0x7300000000
SPECS=[('pointer_cache',0x1b2d68,0x1b2d84),('first_selector',0x1b45dc,0x1b46c0),('second_selector',0x1b54d0,0x1b55a4)]
SEEDS=[0x68f4137b,0x1d486d12];ADDS=[[0x4c536b54,0xc8b88f15,0x803e016b,0xa89af9c0],[0x2311ef95,0x700fa8fa,0x3ad4ce9e,0xe18eca0e]]
LOADS=[[0x1b461c,0x1b4634,0x1b468c,0x1b46a4],[0x1b5510,0x1b5540,0x1b5564,0x1b5588]]
DIVS=[[0x1b45fc,0x1b462c,0x1b4684,0x1b469c,0x1b46b4],[0x1b54ec,0x1b5530,0x1b5554,0x1b5578,0x1b559c]]


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
        if o.ext:
            if o.ext==ARM64_EXT_UXTB:v%=256
            elif o.ext==ARM64_EXT_UXTW:v%=2**32
            else:assert o.ext==ARM64_EXT_SXTW;v%=2**32;v-=2**32 if v>=2**31 else 0
        if o.shift.type:
            if o.shift.type==ARM64_SFT_LSL:v*=2**o.shift.value
            else:assert o.shift.type==ARM64_SFT_LSR;v//=2**o.shift.value
        return v%2**bits
    def cc(i):
        c=bool(nzcv&(1<<29));z=bool(nzcv&(1<<30));return {'lo':not c,'hi':c and not z,'eq':z,'ne':not z}[i.op_str.rsplit(', ',1)[1]]
    _,lo,hi=next(v for v in SPECS if v[0]==b['name'])
    for serial,i in enumerate(C.CS.disasm(s.read(lo,hi-lo),lo)):
        m=i.mnemonic;o=i.operands;n=i.reg_name(o[0].reg);bits=32 if n.startswith('w')else 64
        if m in ['ldr','ldur','str','stur','ldp','stp']:
            mem=o[2 if m in ['ldp','stp']else 1];at=rr(i.reg_name(mem.mem.base))+mem.mem.disp
            if mem.mem.index:
                v=rr(i.reg_name(mem.mem.index));v-=2**32 if mem.ext==ARM64_EXT_SXTW and v>=2**31 else 0;at+=v*2**mem.shift.value
            at%=MOD;width=bits//8
            targets=[n,i.reg_name(o[1].reg)]if m in ['ldp','stp']else[n]
            for lane,target in enumerate(targets):
                address=(at+lane*width)%MOD;raw=bytes(stack[address-sp:address-sp+width])if sp<=address and address+width<=sp+len(stack)else bytes(memory[address+j]for j in range(width));row={'visit':b['entry']['source_visit']+serial,'address':hex(address),'size_B':width}
                if m.startswith('ld'):reads.append({**row,'bytes_hex':raw.hex()});put(target,int.from_bytes(raw,'little'))
                else:
                    assert sp<=address and address+width<=sp+len(stack);after=rr(target).to_bytes(width,'little');stack[address-sp:address-sp+width]=after;writes.append({**row,'before_hex':raw.hex(),'after_hex':after.hex()})
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
        elif m=='mul':v=a*c
        elif m=='udiv':v=a//c if c else 0
        elif m=='msub':v=val(i,o[3],bits)-a*c
        elif m=='lsl':v=a*2**(c%bits)
        else:assert m=='lsr';v=a//2**(c%bits)
        put(n,v)
    cpu.update({'X31':list(map(hex,regs)),'NZCV':hex(nzcv),'PC':hex(C.BASE+hi)});assert cpu==b['end']['CPU']and stack.hex()==b['end']['stack1312_hex']and reads==b['reads']and writes==b['writes']


class Component(R.Component):
    def __init__(self,b,s):
        self.b=b;_,self.lo,self.hi=next(v for v in SPECS if v[0]==b['name']);self.u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);self.fixed=set();self.dynamic=set();self.source=s.read(self.lo,self.hi-self.lo)
        def fixed(at,raw):
            for page in range(at&~4095,(at+len(raw)+4095)&~4095,4096):
                if page not in self.fixed:self.u.mem_map(page,4096);self.fixed.add(page)
            self.u.mem_write(at,raw)
        fixed(C.BASE+self.lo,self.source);cpu=b['entry']['CPU'];self.sp=int(cpu['SP'],16);self.stack=bytes.fromhex(b['entry']['stack1312_hex']);fixed(self.sp,self.stack)
        for row in b['reads']:fixed(int(row['address'],16),bytes.fromhex(row['bytes_hex']))
        C.restore(self.u,cpu);self.context=self.u.context_save();frame,stack=self.run();assert frame==b['end']['CPU']and stack.hex()==b['end']['stack1312_hex']



def oracle(words,kind,control=0x4d25):
    n=len(words);index=SEEDS[kind]%n;steps=[];effective=(((control+0x864e)&M)^0xcccccccccccc1fbf)
    for j in range(4):
        value=words[index];decoded=value if kind==0 else value^(effective if j==0 else KEY);dividend=(decoded+ADDS[kind][j])&MASK
        steps.append({'index_u64':hex(index),'stored_word_u64':hex(value),'decoded_word_u64':hex(decoded),'dividend_u64':hex(dividend),'quotient_u64':hex(dividend//n),'remainder_u64':hex(dividend%n)})
        index=dividend%n
    return index,steps


def finite(b,s):
    a=Component(b,s);name=b['name'];entry=list(map(lambda v:int(v,16),b['entry']['CPU']['X31']));digest=sha256();cases=0
    def check(value,domain,override=None):
        nonlocal cases
        stack=bytearray(a.stack);expected=bytearray(stack);regs={};supply=[]
        if name=='pointer_cache':
            stack[0x450:0x458]=value.to_bytes(8,'little');expected[:]=stack;wanted=(value+0x41ee14e61969358b)&MASK;expected[0x70:0x78]=wanted.to_bytes(8,'little');target=12
        else:
            kind=int(name=='second_selector');n=(1,2,3,4,5,7,8,16)[cases%8]if domain=='word'else value if domain=='count'else 7;residual=cases%8;control=value if domain=='control'else 0x4d25
            if override is not None:n=4
            raw=[override if override is not None else ((value if domain=='word'else 0x6a09e667f3bcc909)+j*0x9e3779b97f4a7c15)&MASK for j in range(n)];words=[v^KEY if kind else v for v in raw]
            supply=[(PRIVATE,b''.join(v.to_bytes(8,'little')for v in words))];wanted,steps=oracle(words,kind,control);target=14 if kind else 10
            if kind:
                regs={10:control};stack[0x450:0x458]=n.to_bytes(8,'little');stack[0x70:0x78]=((PRIVATE-0xa22256c23a653713)&MASK).to_bytes(8,'little');expected[:]=stack
            else:
                encoded=((8*n+residual)^0x458e3e59);stack[0x3ec:0x3f0]=encoded.to_bytes(4,'little');stack[0x468:0x470]=PRIVATE.to_bytes(8,'little');expected[:]=stack
                for off,width,v in [(0x458,4,encoded>>3),(0x28c,4,entry[13]&M),(0x54,4,entry[16]&M),(0x270,4,entry[0]&M),(0x2a4,4,entry[17]&M),(0x258,4,entry[14]&M),(0x450,8,n)]:expected[off:off+width]=v.to_bytes(width,'little')
        frame,after=a.run(regs,stack,supply);rr=list(map(lambda v:int(v,16),frame['X31']));assert rr[target]==wanted and after==expected
        if name!='pointer_cache':assert rr[15 if kind else 1]==n and wanted<n and all(int(v['index_u64'],16)<n for v in steps)
        digest.update(json.dumps(frame,sort_keys=True).encode());digest.update(after);cases+=1
        return wanted
    if name=='pointer_cache':
        domains=[['biased_pointer',64]]
        for lane in range(8):
            for byte in range(256):check(((byte<<(8*lane))^0x6a09e667f3bcc909)&MASK,'pointer')
    else:
        domains=[['word_seed',64],['count',32,1,32]]
        for lane in range(8):
            for byte in range(256):check(((byte<<(8*lane))^0x6a09e667f3bcc909)&MASK,'word')
        for n in range(1,33):
            for residual in range(1 if name=='second_selector'else 8):check(n,'count')
        if name=='second_selector':
            domains.append(['control',32])
            for lane in range(4):
                for byte in range(256):check(((byte<<(8*lane))^0x9e3779b9)&M,'control')
    controls=[];positive_cases=cases
    if name!='pointer_cache':
        for value in range(4):controls.append({'all_raw_words_u64':hex(value),'N':4,'remainder_u32':hex(check(value,'control_fixture',value))})
    a.intact();return {'label':b['label'],'name':name,'domains':domains,'cases':positive_cases,'source_visits':positive_cases*len(b['visits']),'split_controls':controls,'control_cases':len(controls),'control_source_visits':len(controls)*len(b['visits']),'ordered_frames_and_stack_sha256':digest.hexdigest(),'source_bytes_preserved':True}


def zero_controls(b,s):
    a=Component(b,s);stack=bytearray(a.stack);stack[0x3ec:0x3f0]=(0x458e3e59).to_bytes(4,'little');frame,after=a.run(stack=stack,stop=0x1b461c);rr=list(map(lambda v:int(v,16),frame['X31']));assert rr[1]==0 and rr[11]==0x68f4137b
    expected=bytearray(stack);expected[0x458:0x45c]=(0x458e3e59>>3).to_bytes(4,'little');expected[0x28c:0x290]=(int(b['entry']['CPU']['X31'][13],16)&M).to_bytes(4,'little');assert after==expected;a.intact()
    raw=s.read(0x1b462c,4);assert next(C.CS.disasm(raw,0x1b462c)).mnemonic=='udiv';u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(C.BASE+0x1b4000,4096);u.mem_write(C.BASE+0x1b462c,raw);C.restore(u,b['entry']['CPU']);ctx=u.context_save();digest=sha256();cases=0
    values=[((byte<<(8*lane))^0x6a09e667f3bcc909)&MASK for lane in range(8)for byte in range(256)]+[0,1,MASK]
    for value in values:
        u.context_restore(ctx);u.reg_write(U.UC_ARM64_REG_X1,0);u.reg_write(U.UC_ARM64_REG_X11,value);u.emu_start(C.BASE+0x1b462c,C.BASE+0x1b4630,count=1);f=C.frame(u);assert int(f['X31'][12],16)==0 and int(f['X31'][11],16)==value;digest.update(json.dumps(f,sort_keys=True).encode());cases+=1
    assert bytes(u.mem_read(C.BASE+0x1b462c,4))==raw
    return {'label':b['label'],'prefix_stop_PC':'0x1b461c','first_index_u32':'0x68f4137b','buffer_read_executed':False,'u64_UDIV_PC':'0x1b462c','u64_cases':cases,'prefix_cases':1,'cases':cases+1,'source_visits':cases+16,'ordered_u64_frames_sha256':digest.hexdigest(),'source_bytes_preserved':True,'native_fault_established':False}


class Replay(R.Replay):
    def __init__(self,*a):super().__init__(*a);self.selector_components=[];self.current_selector=None
    def code(self,u,pc,n,d):
        self.flush()
        for name,lo,hi in SPECS:
            if pc==C.BASE+lo:assert self.current_selector is None;self.current_selector={'name':name,'entry':R.R.W.R.W.E.F.F.A.capture(self)}
            if pc==C.BASE+hi and self.current_selector is not None and self.current_selector['name']==name:self.current_selector['end']=R.R.W.R.W.E.F.F.A.capture(self);self.selector_components.append(self.current_selector);self.current_selector=None
        return super().code(u,pc,n,d)


def joins(p,blocks,pins):
    label=p['configuration']['label'];bs={b['name']:b for b in blocks};first=bs['first_selector'];second=bs['second_selector'];cache=bs['pointer_cache'];n=p['configuration']['length_u32']//8;sp=int(first['entry']['CPU']['SP'],16)
    value=lambda r:int.from_bytes(bytes.fromhex(r['bytes_hex']),'little');base=value(first['reads'][1]);encoded_base=value(second['reads'][1]);assert (encoded_base+0xa22256c23a653713)&MASK==base
    assert value(second['reads'][0])==n and int(second['entry']['CPU']['X31'][10],16)==0x4d25
    source=cache['reads'][0];assert source['address']==hex(sp+0x450)and (value(source)+0xe4106ba853ce6c9e)&MASK==base and cache['writes'][0]['after_hex']==second['reads'][1]['bytes_hex']
    epochs=[]
    for w,r in [(next(w for w in p['writes']if p['visits'][w['visit']]['pc']=='0x1af858'),source),(cache['writes'][0],second['reads'][1]),(first['writes'][-1],second['reads'][0])]:
        at=int(w['address'],16);assert w['address']==r['address']and w['size_B']==r['size_B']==8 and w['after_hex']==r['bytes_hex']and w['visit']<r['visit']
        assert not any(w['visit']<v['visit']<r['visit']and int(v['address'],16)<at+8 and at<int(v['address'],16)+v['size_B']for v in p['writes'])
        epochs.append({'store_PC':p['visits'][w['visit']]['pc'],'read_PC':p['visits'][r['visit']]['pc'],'store_visit':w['visit'],'read_visit':r['visit'],'address':w['address'],'size_B':8,'value_hex':r['bytes_hex'],'no_intervening_overlapping_write':True})
    chains=[];word_epochs=[]
    for kind,b in enumerate([first,second]):
        reads=b['reads'][2:];assert len(reads)==4;idx=SEEDS[kind]%n;steps=[]
        for j,r in enumerate(reads):
            at=base+8*idx;assert r['address']==hex(at)and r['size_B']==8 and p['visits'][r['visit']]['pc']==hex(LOADS[kind][j]);word=value(r);decoded=word if kind==0 else word^KEY;D=(decoded+ADDS[kind][j])&MASK
            if kind==0:
                consumer=next(v for v in p['reads']if v['visit']>r['visit']and v['address']==r['address']and p['visits'][v['visit']]['pc']in ['0x1b48fc','0x1b4ef8']);lo,hi=r['visit'],consumer['visit'];assert consumer['bytes_hex']==r['bytes_hex'];producer=r
            else:
                producer=next(v for v in p['writes']if v['address']==r['address']and p['visits'][v['visit']]['pc']in ['0x1b4930','0x1b4f00']);lo,hi=producer['visit'],r['visit'];assert producer['after_hex']==r['bytes_hex'];consumer=r
            assert not any(lo<v['visit']<hi and int(v['address'],16)<at+8 and at<int(v['address'],16)+v['size_B']for v in p['writes'])
            word_epochs.append({'kind':kind,'address':hex(at),'size_B':8,'from_visit':lo,'to_visit':hi,'value_hex':r['bytes_hex'],'no_intervening_overlapping_write':True})
            steps.append({'index_u64':hex(idx),'stored_word_u64':hex(word),'decoded_word_u64':hex(decoded),'dividend_u64':hex(D),'quotient_u64':hex(D//n),'remainder_u64':hex(D%n)});idx=D%n
        target=10 if kind==0 else 14;assert int(b['end']['CPU']['X31'][target],16)==idx and idx<n
        traversal=next(v for v in pins['corefp_word_traversal_checks.json']['blocks']if v['label']==label and v['name']==('first_bound'if kind==0 else'second_bound_encode'));assert b['end']==traversal['entry']
        chains.append({'kind':kind,'seed_index_u32':hex(SEEDS[kind]%n),'steps':steps,'final_remainder_u32':hex(idx),'bound_entry_visit':traversal['entry']['source_visit']})
    old=[b for b in pins['corefp_word_traversal_checks.json']['blocks']if b['label']==label];t=R.joins(p,old,pins['corefp_word_traversal_checks.json'],pins,R.C.Pointers());assert t['remainders_u32']==[c['final_remainder_u32']for c in chains]
    return {'label':label,'word_count_u32':hex(n),'buffer_u64':hex(base),'encoded_base_u64':hex(encoded_base),'cache_epochs':epochs,'word_epochs':word_epochs,'chains':chains,'same_buffer_both_selectors':True,'source_divisors_bound_to_word_count':True,'traversal_join_checked':True}


def inputs():
    raw=read(ROOT/'corefp_word_selectors_checks.json').encode();e=json.loads(raw);s=C.Pointers();pins={};assert e['generator_sha256']==SHA((ROOT/'recover_corefp_word_selectors.py').read_bytes())and e['thin_sha256']==C.THIN_SHA
    for n,h in e['parent_pins'].items():rr=read(ROOT/n).encode();assert SHA(rr)==h;pins[n]=json.loads(rr)
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h
    assert len(pins)==24 and len(e['dependencies'])==27 and len(e['source_regions'])==3
    for region,(name,lo,hi)in zip(e['source_regions'],SPECS):assert region=={'name':name,'start':hex(lo),'end':hex(hi),'instructions':[{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'instruction':i.mnemonic+' '+i.op_str}for i in C.CS.disasm(s.read(lo,hi-lo),lo)]}
    assert e['seed_u32']==list(map(hex,SEEDS))and e['word_addends_u32']==[[hex(v)for v in row]for row in ADDS]and e['word_load_sites']==[[hex(v)for v in row]for row in LOADS]and e['division_sites']==[[hex(v)for v in row]for row in DIVS]
    return raw,e,s,pins


def frozen(pins):return R.R.W.R.W.frozen(pins)+pins['corefp_word_codec_checks.json']['proofs']+pins['corefp_word_recurrence_checks.json']['source_checks']['proofs']+pins['corefp_word_inputs_checks.json']['source_checks']['proofs']+pins['corefp_input_lineage_checks.json']['source_checks']['proofs']+pins['corefp_word_traversal_checks.json']['source_checks']['proofs']


def main():
    raw,e,s,pins=inputs();old=frozen(pins);new=e['source_checks']['proofs'];assert len(old)==1301 and len(new)==28
    for proof in old+new:
        q=z3.Solver();q.set(timeout=30000);q.from_string(proof['query']);assert proof['result']=='unsat'and q.check()==z3.unsat,proof['label']
    print(json.dumps({'queries_unsat':1329}),flush=True);parent=pins['corefp_workspace_checks.json'];totals=Counter();oracles=[];zeros=[];interfaces=[];offset=0
    for j,p in enumerate(parent['profiles']):
        totals.update(R.R.W.R.W.E.F.F.A.initial_checks(p,s));r=Replay(p,parent['source_spans'],s);totals.update(r.run());R.R.W.R.W.E.F.F.W.workspace_oracle(p,r,s,parent['workspace_constructions'][j]);R.R.W.R.W.E.F.F.W.preparation_oracle(p,r,s);assert r.current_selector is None and len(r.selector_components)==3;start=offset
        for actual in r.selector_components:
            b=e['blocks'][offset];offset+=1;assert b['name']==actual['name']and b['label']==p['configuration']['label']and all(b[t]==actual[t]for t in ['entry','end']);lo,hi=b['entry']['source_visit'],b['end']['source_visit'];assert b['visits']==p['visits'][lo:hi]
            for k in ['reads','writes','PAC_models']:assert b[k]==[v for v in p[k]if lo<=v['visit']<hi]
            scalar(b,s);oracles.append(finite(b,s))
            if b['name']=='first_selector':zeros.append(zero_controls(b,s))
        interfaces.append(joins(p,e['blocks'][start:offset],pins));print(json.dumps({'audited':p['configuration']['label']}),flush=True)
    assert offset==18 and dict(totals)==pins['corefp_word_traversal_audit.json']['result']['independent_replay']and e['replay_totals']=={k:v for k,v in totals.items()if not k.startswith('initial_')}
    counts={'profiles':6,'regions':18,'source_instructions':117,'source_B':468,'regional_visits':702,'regional_reads':78,'regional_read_B':600,'regional_writes':48,'regional_write_B':240,'regional_PAC_models':0,'new_queries_unsat':28};assert e['verified_counts']==counts
    result={'verified_counts':counts,'independent_replay':dict(totals),'actual_full_frames':18,'independent_scalar_frames':18,'finite_cases':sum(o['cases']for o in oracles),'finite_source_visits':sum(o['source_visits']for o in oracles),'split_control_cases':sum(o['control_cases']for o in oracles),'split_control_source_visits':sum(o['control_source_visits']for o in oracles),'zero_divisor_cases':sum(o['cases']for o in zeros),'zero_divisor_source_visits':sum(o['source_visits']for o in zeros),'stable_cache_epochs':sum(len(j['cache_epochs'])for j in interfaces),'stable_word_epochs':sum(len(j['word_epochs'])for j in interfaces),'selector_chains_checked':sum(len(j['chains'])for j in interfaces),'new_queries_unsat':28,'frozen_queries_unsat':1301,'total_queries_unsat':1329,'all_checks_pass':True,'native_target_executed':False}
    assert [result[k]for k in ['finite_cases','finite_source_visits','split_control_cases','split_control_source_visits','zero_divisor_cases','zero_divisor_source_visits','stable_cache_epochs','stable_word_epochs','selector_chains_checked']]==[44736,1861056,48,2640,12312,12402,18,48,12]
    out={'result':result,'checks_sha256':SHA(raw),'auditor_sha256':SHA(Path(__file__).read_bytes()),'generator_sha256':e['generator_sha256'],'parent_pins':e['parent_pins'],'dependencies':e['dependencies'],'component_oracles':oracles,'zero_divisor_oracles':zeros,'interface_joins':interfaces,'fresh_replay_completed':True,'process_exit_code':0,'native_API_executed':False,'IDB_mutated':False,'new_live_IDA_claim':False,'earlier_arithmetic_passes_universally_reduced':False,'general_raw_preparation_contract_established':False,'whole_transform_algorithm':'unknown','full_goal_complete':False}
    (ROOT/'corefp_word_selectors_audit.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(result),flush=True)


if __name__=='__main__':main()
