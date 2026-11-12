#!/usr/bin/env python3
"""Independent entry-lineage replay, integer frames and original-byte controls.

Does not import the new producer. O(C*(B+V*J+P*F+R)+N*L) conservative
time/space; bounded private maps; 30 s/SMT query. No native API/IPC/IDA.
"""
import copy,json
from pathlib import Path
from hashlib import sha256
from collections import Counter
import z3
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM
from unicorn import arm64_const as U
from capstone.arm64_const import ARM64_SFT_LSL,ARM64_SFT_LSR,ARM64_EXT_SXTW
import audit_corefp_word_inputs as W
from verify_daemon_reader_record_payloads_publication import read
ROOT=W.ROOT;C=W.C;SHA=W.SHA;MOD=2**64;M=2**32-1;RECORD=0x7a00000200
SPECS=[('record_decode',0x1af7dc,0x1af874),('buffer_cache',0x1af8fc,0x1af90c),('control_first_store',0x1afc1c,0x1afc44),
 ('control_first_reload',0x1afd94,0x1afd98),('control_subtract',0x1afdb0,0x1afdc0),('control_mask',0x1afe3c,0x1afe54),('control_multiply',0x1afe9c,0x1afebc),
 ('control_second_store',0x1aff88,0x1aff8c),('master_store',0x1b0270,0x1b0290),('master_reload',0x1b41a0,0x1b41a4),('first_base',0x1b4618,0x1b461c),('second_base',0x1b56c4,0x1b56c8)]
AUX=[('forward_argument',0x1af940,0x1af94c),('forward_literals',0x1af970,0x1af980),('forward_update',0x1afa60,0x1afa68)]
CONTRACTS=[('operation_before_direction',0x1af81c,0x1af92c,[9]),('operation_reverse',0x1afaa4,0x1afc1c,[9]),('forward_argument',0x1af94c,0x1afa60,[14]),
 ('forward_literal_counter',0x1af980,0x1afa60,[9]),('forward_literal_mask',0x1af980,0x1afa64,[15]),('decoded_buffer',0x1af860,0x1af908,[25]),
 ('first_control_reload',0x1afd98,0x1afdbc,[10]),('subtracted_control',0x1afdc0,0x1afe3c,[9]),('masked_control',0x1afe54,0x1afe9c,[8]),('multiplied_control',0x1afebc,0x1aff88,[12]),
 ('master_loaded',0x1b41a4,0x1b47cc,[22]),('first_buffer_loaded',0x1b461c,0x1b48a0,[23]),('second_buffer_loaded',0x1b56c8,0x1b56d8,[25]),
 ('first_buffer_loop',0x1b48a0,0x1b51d4,[23]),('second_buffer_loop',0x1b56d8,0x1b63e4,[25])]


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
        elif m=='lsl':v=a*2**(c%bits)
        else:assert m=='lsr';v=a//2**(c%bits)
        put(n,v)
    cpu.update({'X31':list(map(hex,regs)),'NZCV':hex(nzcv),'PC':hex(C.BASE+hi)});assert cpu==b['end']['CPU']and stack.hex()==b['end']['stack1312_hex']and reads==b['reads']and writes==b['writes']


class Replay(W.Replay):
    def __init__(self,*a):super().__init__(*a);self.lineage_components=[];self.current_lineage=None
    def code(self,u,pc,n,d):
        self.flush()
        for name,lo,hi in SPECS:
            if pc==C.BASE+lo:assert self.current_lineage is None;self.current_lineage={'name':name,'entry':W.R.W.E.F.F.A.capture(self)}
            if pc==C.BASE+hi and self.current_lineage is not None and self.current_lineage['name']==name:
                self.current_lineage['end']=W.R.W.E.F.F.A.capture(self);self.lineage_components.append(self.current_lineage);self.current_lineage=None
        return super().code(u,pc,n,d)


class Component(W.Component):
    def __init__(self,b,s,auxiliary=False):
        self.b=b;_,self.lo,self.hi=next(v for v in SPECS+AUX if v[0]==b['name']);self.u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);self.fixed=set();self.dynamic=set();self.source=s.read(self.lo,self.hi-self.lo)
        def fixed(at,raw):
            for page in range(at&~4095,(at+len(raw)+4095)&~4095,4096):
                if page not in self.fixed:self.u.mem_map(page,4096);self.fixed.add(page)
            self.u.mem_write(at,raw)
        fixed(C.BASE+self.lo,self.source);cpu=b['entry']['CPU'];self.sp=int(cpu['SP'],16);self.stack=bytes.fromhex(b['entry']['stack1312_hex']);fixed(self.sp,self.stack)
        for row in b['reads']:fixed(int(row['address'],16),bytes.fromhex(row['bytes_hex']))
        C.restore(self.u,cpu);self.context=self.u.context_save()
        if not auxiliary:
            frame,stack=self.run();assert frame==b['end']['CPU']and stack.hex()==b['end']['stack1312_hex']
    def finite(self):
        name=self.b['name'];entry=list(map(lambda v:int(v,16),self.b['entry']['CPU']['X31']));digest=sha256();cases=0;domains=[]
        def value(raw):return int.from_bytes(raw,'little')
        def check(x,kind='value'):
            nonlocal cases
            regs={};stack=bytearray(self.stack);expected=bytearray(self.stack);supply=[];wanted={};writes=[]
            if name=='record_decode':
                raw=bytearray(48)
                for off,row in zip([0xc,0x18,0x20,0x28],self.b['reads']):raw[off:off+row['size_B']]=bytes.fromhex(row['bytes_hex'])
                record=RECORD
                if kind=='record':record+=x
                else:
                    off,n={'operation':(0xc,4),'buffer':(0x18,8),'source':(0x20,8),'length':(0x28,4)}[kind];raw[off:off+n]=x.to_bytes(n,'little')
                regs={0:record};supply=[(record,bytes(raw))];key=(((record&M)^0x542fbf9b)*0x4386951d)&M;d=value(raw[0xc:0x10])^key;buffer=(value(raw[0x18:0x20])+0xe4106ba853ce6c9e)%MOD;src=value(raw[0x20:0x28]);length=value(raw[0x28:0x2c])^key
                wanted={9:d,1:value(raw[0x18:0x20]),10:src,25:buffer,8:length,14:d|(0x12 if src>buffer else 0)};writes=[(0x430,4,length),(0x450,8,value(raw[0x18:0x20]))]
            elif name=='buffer_cache':
                companion=value(bytes.fromhex(self.b['reads'][0]['bytes_hex']));base=entry[25]
                if kind=='buffer':regs={25:x};base=x
                else:companion=x;supply=[(int(self.b['reads'][0]['address'],16),x.to_bytes(8,'little'))]
                writes=[(0x460,8,companion),(0x468,8,base)]
            elif name=='control_first_store':regs={9:x};wanted={10:x^0x92b7};writes=[(0x438,8,x^0x92b7)]
            elif name=='control_first_reload':stack[0x438:0x440]=x.to_bytes(8,'little');expected[:]=stack;wanted={10:x}
            elif name=='control_subtract':regs={10:x};wanted={9:(x-0x40fe)&M}
            elif name=='control_mask':regs={9:x};wanted={8:((x+0x7a57526e)&M)&0x85a87fd8}
            elif name=='control_multiply':regs={8:x};wanted={12:((((x-0x3484)&M)^0x4ac6)*0x6322)&M}
            elif name=='control_second_store':regs={12:x};writes=[(0x438,4,x)]
            elif name=='master_store':stack[0x438:0x43c]=x.to_bytes(4,'little');expected[:]=stack;writes=[(0x348,4,((x+0xc244327b)&M)&0x3dbbff6c)]
            elif name=='master_reload':stack[0x348:0x34c]=x.to_bytes(4,'little');expected[:]=stack;wanted={22:x}
            else:
                assert name in ['first_base','second_base'];stack[0x468:0x470]=x.to_bytes(8,'little');expected[:]=stack;wanted={23 if name=='first_base'else 25:x}
            for off,n,v in writes:expected[off:off+n]=v.to_bytes(n,'little')
            frame,after=self.run(regs,stack,supply);rr=list(map(lambda v:int(v,16),frame['X31']));assert all(rr[j]==v for j,v in wanted.items())and after==expected
            digest.update(json.dumps(frame,sort_keys=True).encode());digest.update(after);cases+=1
        if name=='record_decode':domains=[('record',4),('operation',4),('buffer',8),('source',8),('length',4)]
        elif name=='buffer_cache':domains=[('buffer',8),('companion',8)]
        else:domains=[('value',8 if name in ['control_first_reload','first_base','second_base']else 4)]
        for kind,width in domains:
            mask=2**(width*8)-1;pattern=0x9e3779b9 if width==4 else 0x6a09e667f3bcc909
            for lane in range(width):
                for byte in range(256):check(((byte<<(8*lane))^pattern)&mask,kind)
        self.intact();return {'label':self.b['label'],'name':name,'domains':[[k,8*n]for k,n in domains],'cases':cases,'source_visits':cases*(self.hi-self.lo)//4,
          'ordered_frames_and_stack_sha256':digest.hexdigest(),'source_bytes_preserved':True}


def auxiliary(template,s):
    components={name:Component({'name':name,'entry':template['entry'],'reads':[]},s,True)for name,_,_ in AUX};digest=sha256();cases=0
    def check(d):
        argument,stack=components['forward_argument'].run({9:d});rr=list(map(lambda v:int(v,16),argument['X31']));assert rr[14]==(d-0x4442)&M and stack==components['forward_argument'].stack
        literals,stack=components['forward_literals'].run();lr=list(map(lambda v:int(v,16),literals['X31']));assert lr[9]==0x189444c9 and lr[15]==0xe76bff78 and stack==components['forward_literals'].stack
        result,stack=components['forward_update'].run({14:rr[14],9:lr[9],15:lr[15]});actual=int(result['X31'][9],16);wanted=((d-0x4442+0x189444c9)&M)&0xe76bff78
        assert actual==wanted and stack==components['forward_update'].stack
        for frame in [argument,literals,result]:digest.update(json.dumps(frame,sort_keys=True).encode())
        return actual
    for lane in range(4):
        for byte in range(256):check(((byte<<(8*lane))^0x9e3779b9)&M);cases+=1
    selected=check(0x7f48);changed=check(0x7f49);assert selected==0x7f48 and changed!=0x7f49
    for component in components.values():component.intact()
    return {'finite_cases':cases,'source_visits':cases*9,'selected_operation_u32':'0x7f48','selected_result_u32':hex(selected),
      'off_operation_u32':'0x7f49','off_operation_result_u32':hex(changed),'general_identity_rejected':True,'two_control_cases':2,'control_source_visits':18,
      'ordered_frames_sha256':digest.hexdigest(),'source_bytes_preserved':True,'dispatch_executed':False}


def epochs(p):
    out=[];visits=p['visits'];sp=0x62017ad0
    for writer,reader,off,n in [('0x1afc40','0x1afd94',0x438,8),('0x1aff88','0x1b0280',0x438,4),('0x1b028c','0x1b41a0',0x348,4),
      ('0x1af908','0x1b4618',0x468,8),('0x1af908','0x1b56c4',0x468,8)]:
        ws=[w for w in p['writes']if visits[w['visit']]['pc']==writer and int(w['address'],16)==sp+off];rs=[r for r in p['reads']if visits[r['visit']]['pc']==reader];assert len(ws)==len(rs)==1;w,r=ws[0],rs[0]
        assert w['address']==r['address']and w['size_B']==r['size_B']==n and w['visit']<r['visit']and w['after_hex']==r['bytes_hex'];at=int(w['address'],16)
        assert not any(w['visit']<v['visit']<r['visit']and int(v['address'],16)<at+n and at<int(v['address'],16)+v['size_B']for v in p['writes'])
        out.append({'store_PC':writer,'read_PC':reader,'address':w['address'],'size_B':n,'store_visit':w['visit'],'read_visit':r['visit'],'value_hex':r['bytes_hex'],'no_intervening_overlapping_write':True})
    return out


def control_chain(d):
    a=d^0x92b7;b=(a-0x40fe)&M;c=((b+0x7a57526e)&M)&0x85a87fd8;e=((((c-0x3484)&M)^0x4ac6)*0x6322)&M;f=((e+0xc244327b)&M)&0x3dbbff6c
    return [a,b,c,e,f]


def joins(p,blocks,pins):
    label=p['configuration']['label'];bs={b['name']:b for b in blocks};assert len(bs)==12
    def rr(name,part='end'):return list(map(lambda v:int(v,16),bs[name][part]['CPU']['X31']))
    d=rr('record_decode')[9];assert d==0x7f48;a,b,c,e,m=control_chain(d);assert [a,b,c,e,m]==[0xedff,0xad01,0x7f48,0xc644,0xf82c]
    assert rr('control_first_store','entry')[9]==d and rr('control_first_store')[10]==a and rr('control_first_reload')[10]==a
    assert rr('control_subtract','entry')[10]&M==a and rr('control_subtract')[9]==b and rr('control_mask','entry')[9]==b and rr('control_mask')[8]==c
    assert rr('control_multiply','entry')[8]==c and rr('control_multiply')[12]==e and rr('control_second_store','entry')[12]==e and rr('master_store')[12]==m and rr('master_reload')[22]==m
    base=rr('record_decode')[25];assert rr('buffer_cache','entry')[25]==rr('first_base')[23]==rr('second_base')[25]==base
    record=int(bs['record_decode']['entry']['CPU']['X31'][0],16);reads=bs['record_decode']['reads'];k=(((record&M)^0x542fbf9b)*0x4386951d)&M
    assert [int(v['address'],16)-record for v in reads]==[0xc,0x18,0x20,0x28]and [v['size_B']for v in reads]==[4,8,8,4]
    raw_d=int.from_bytes(bytes.fromhex(reads[0]['bytes_hex']),'little');raw_b=int.from_bytes(bytes.fromhex(reads[1]['bytes_hex']),'little');assert raw_d^k==d and (raw_b+0xe4106ba853ce6c9e)%MOD==base
    old=[x for x in pins['corefp_word_inputs_checks.json']['blocks']if x['label']==label];word_join=W.joins(p,old,pins)
    setup=next(x for x in old if x['name']=='first_setup');assert int(setup['entry']['CPU']['X31'][22],16)&M==m
    assert all(int(h['buffer_u64'],16)==base for h in word_join['header_interfaces'])
    lo=bs['record_decode']['end']['source_visit'];hi=bs['control_first_store']['entry']['source_visit'];allowed=[(0x1af81c,0x1af92c),(0x1afaa4,0x1afc1c)]
    assert all(any(a<=int(v['pc'],16)<b for a,b in allowed)for v in p['visits'][lo:hi])
    assert not any(0x1af92c<=int(v['pc'],16)<0x1afaa4 for v in p['visits'][lo:hi])
    nonunique=control_chain(0x7f49)[-1];assert nonunique==m
    return {'label':label,'record_u64':hex(record),'address_key_u32':hex(k),'decoded_operation_u32':hex(d),'control_chain_u32':list(map(hex,[a,b,c,e,m])),
      'decoded_buffer_u64':hex(base),'raw_buffer_u64':hex(raw_b),'master_setup_entry_visit':setup['entry']['source_visit'],'downstream_control_chain_u32':word_join['control_chain_u32'],
      'header_handoffs':len(word_join['header_interfaces']),'epochs':epochs(p),'retained_direction':'reverse','retained_operation_corridor_visits':hi-lo,
      'other_operation_same_master':{'operation_u32':'0x7f49','master_u32':hex(nonunique),'native_admission_established':False}}


def check_census(e,s):
    expected={};contracts=e['census']['contracts'];assert len(contracts)==15
    for contract,(name,lo,hi,regs)in zip(contracts,CONTRACTS):
        assert contract['name']==name and contract['start']==hex(lo)and contract['end']==hex(hi)and contract['preserved_registers']==regs
        ins=list(C.CS.disasm(s.read(lo,hi-lo),lo));names={prefix+str(j)for j in regs for prefix in ['w','x']};branches=[]
        for i in ins:
            _,ww=i.regs_access();assert not names&{i.reg_name(j)for j in ww}and not any(i.group(g)for g in [2,3])
            if i.group(1):assert i.mnemonic=='braa';branches.append(hex(i.address))
            expected[i.address]={'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'instruction':i.mnemonic+' '+i.op_str}
        assert contract['instruction_count']==len(ins)and contract['branch_sites']==branches
    assert e['census']['instructions']==[expected[k]for k in sorted(expected)]and len(expected)==2216


def main():
    raw=read(ROOT/'corefp_input_lineage_checks.json').encode();e=json.loads(raw);s=C.Pointers();assert e['generator_sha256']==SHA((ROOT/'recover_corefp_input_lineage.py').read_bytes())and e['thin_sha256']==C.THIN_SHA;pins={}
    for n,h in e['parent_pins'].items():
        rr=read(ROOT/n).encode();assert SHA(rr)==h;pins[n]=json.loads(rr)
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h
    assert len(e['source_regions'])==12 and len(e['auxiliary_regions'])==3
    for region,(name,lo,hi)in zip(e['source_regions']+e['auxiliary_regions'],SPECS+AUX):
        assert region['name']==name and region['start']==hex(lo)and region['end']==hex(hi)and region['instructions']==[{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'instruction':i.mnemonic+' '+i.op_str}for i in C.CS.disasm(s.read(lo,hi-lo),lo)]
    check_census(e,s);old=W.R.W.frozen(pins)+pins['corefp_word_codec_checks.json']['proofs']+pins['corefp_word_recurrence_checks.json']['source_checks']['proofs']+pins['corefp_word_inputs_checks.json']['source_checks']['proofs'];new=e['source_checks']['proofs'];assert len(old)==1234 and len(new)==29
    for proof in old+new:
        q=z3.Solver();q.set(timeout=30000);q.from_string(proof['query']);assert proof['result']=='unsat'and q.check()==z3.unsat,proof['label']
    assert e['source_checks']['normalization_cut']=={'pc':'0x1af814','register':'W8','identity':'record_source_key','replacement':'(low32(record) XOR 0x542fbf9b)*0x4386951d mod 2^32'}
    print(json.dumps({'queries_unsat':1263}),flush=True);parent=pins['corefp_workspace_checks.json'];totals=Counter();oracles=[];interfaces=[];offset=0
    for j,p in enumerate(parent['profiles']):
        totals.update(W.R.W.E.F.F.A.initial_checks(p,s));r=Replay(p,parent['source_spans'],s);totals.update(r.run());W.R.W.E.F.F.W.workspace_oracle(p,r,s,parent['workspace_constructions'][j]);W.R.W.E.F.F.W.preparation_oracle(p,r,s)
        assert r.current_lineage is None and len(r.lineage_components)==12;start=offset
        for actual in r.lineage_components:
            b=e['blocks'][offset];offset+=1;assert b['name']==actual['name']and b['label']==p['configuration']['label']and all(b[t]==actual[t]for t in ['entry','end']);lo,hi=b['entry']['source_visit'],b['end']['source_visit'];assert b['visits']==p['visits'][lo:hi]
            for k in ['reads','writes','PAC_models']:assert b[k]==[v for v in p[k]if lo<=v['visit']<hi]
            scalar(b,s);oracles.append(Component(b,s).finite())
        interfaces.append(joins(p,e['blocks'][start:offset],pins));print(json.dumps({'audited':p['configuration']['label']}),flush=True)
    assert offset==72 and dict(totals)==pins['corefp_word_inputs_audit.json']['result']['independent_replay']and e['replay_totals']=={k:v for k,v in totals.items()if not k.startswith('initial_')}
    aux=auxiliary(e['blocks'][0],s);counts={'profiles':6,'regions':72,'primary_source_instructions':83,'primary_source_B':332,'auxiliary_source_instructions':9,'auxiliary_source_B':36,'regional_visits':498,
      'regional_reads':60,'regional_writes':42,'regional_PAC_models':0,'preservation_contracts':15,'census_instructions':2216,'census_B':8864,'unique_source_instructions':2273,'unique_source_B':9092,'new_queries_unsat':29}
    assert e['verified_counts']==counts and sum(len(b['visits'])for b in e['blocks'])==498 and sum(len(b['reads'])for b in e['blocks'])==60 and sum(len(b['writes'])for b in e['blocks'])==42 and not any(b['PAC_models']for b in e['blocks'])
    result={'verified_counts':counts,'independent_replay':dict(totals),'actual_full_frames':72,'independent_scalar_frames':72,'finite_component_cases':sum(o['cases']for o in oracles),
      'finite_source_visits':sum(o['source_visits']for o in oracles),'auxiliary_cases':aux['finite_cases'],'auxiliary_source_visits':aux['source_visits'],'stable_control_buffer_epochs':sum(len(j['epochs'])for j in interfaces),
      'word_header_handoffs':sum(j['header_handoffs']for j in interfaces),'new_queries_unsat':29,'frozen_queries_unsat':1234,'total_queries_unsat':1263,'all_checks_pass':True,'native_target_executed':False}
    assert result['finite_component_cases']==147456 and result['finite_source_visits']==2002944 and result['stable_control_buffer_epochs']==30 and result['word_header_handoffs']==32
    out={'result':result,'checks_sha256':SHA(raw),'auditor_sha256':SHA(Path(__file__).read_bytes()),'generator_sha256':e['generator_sha256'],'parent_pins':e['parent_pins'],'dependencies':e['dependencies'],
      'component_oracles':oracles,'auxiliary_oracle':aux,'interface_joins':interfaces,'fresh_replay_completed':True,'process_exit_code':0,'native_API_executed':False,'IDB_mutated':False,'new_live_IDA_claim':False,
      'earlier_arithmetic_passes_universally_reduced':False,'general_raw_preparation_contract_established':False,'whole_transform_algorithm':'unknown','full_goal_complete':False}
    (ROOT/'corefp_input_lineage_audit.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(result),flush=True)


if __name__=='__main__':main()
