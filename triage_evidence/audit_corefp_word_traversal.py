#!/usr/bin/env python3
"""Independent cyclic word-control replay, source frames and bounded tests.

Does not import the new producer. O(C*(B+V*J+P*F+R)+N*L) time/space;
bounded private maps; 30 s/SMT query. No native API/IPC or IDA.
"""
import copy,json
from pathlib import Path
from hashlib import sha256
from collections import Counter
import z3
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM
from unicorn import arm64_const as U
from capstone.arm64_const import ARM64_SFT_LSL,ARM64_SFT_LSR,ARM64_EXT_SXTW,ARM64_EXT_UXTB
import audit_corefp_input_lineage as R
from verify_daemon_reader_record_payloads_publication import read
ROOT=R.ROOT;C=R.C;SHA=R.SHA;MOD=2**64;M=2**32-1;TABLE=0x1c81940;PRIVATE_TABLE=0x7e00000000
SPECS=[('table_cache',0x1af8b0,0x1af8c4),('word_count',0x1b45dc,0x1b45f4),('first_bound',0x1b46c0,0x1b4738),('first_key',0x1b47d0,0x1b47d4),
 ('first_lower',0x1b4828,0x1b4838),('first_delta',0x1b4880,0x1b488c),('first_header',0x1b48a0,0x1b48a8),('first_dispatch',0x1b4d24,0x1b4d70),
 ('first_tail_bound',0x1b4d74,0x1b4de4),('first_tail_delta',0x1b4e8c,0x1b4e94),('first_tail_header',0x1b4e9c,0x1b4ea4),('first_tail_dispatch',0x1b5190,0x1b51d0),
 ('second_bound_encode',0x1b55a4,0x1b55f0),('second_bound_decode',0x1b5620,0x1b567c),('second_header',0x1b56d8,0x1b56e0),('second_dispatch',0x1b5be8,0x1b5c3c),
 ('second_tail_bound',0x1b5c64,0x1b5cdc),('second_tail_header',0x1b5d20,0x1b5d2c),('second_tail_dispatch',0x1b636c,0x1b63e0)]
CONFIG=[{'name':'first','header':'first_header','dispatch':'first_dispatch','counter':9,'next':9,'target':26,'index':9,'lo':4,'hi':10,'delta':22,'bias':0x37a981c3,'lower':0x7390ff4b,'step':0x3be77d89,'scale':0x6c,'key':0xf82c,'invert':True,'branch':0x1b4d70,'modifier':0x2883},
 {'name':'first_tail','header':'first_tail_header','dispatch':'first_tail_dispatch','counter':20,'next':20,'target':2,'index':17,'lo':10,'hi':9,'delta':4,'bias':0x37a981c3,'lower':0x722872e2,'step':0x3a7ef120,'scale':1,'key':0x8568,'invert':False,'branch':0x1b51d0,'modifier':0x5e63},
 {'name':'second','header':'second_header','dispatch':'second_dispatch','counter':1,'next':1,'target':2,'index':17,'lo':11,'hi':7,'delta':None,'bias':0x20390963,'lower':0x3076d59e,'step':0x103dcc3c,'scale':0xbd,'key':0xd373,'invert':False,'branch':0x1b5c3c,'modifier':0xe8d0},
 {'name':'second_tail','header':'second_tail_header','dispatch':'second_tail_dispatch','counter':16,'next':16,'target':2,'index':12,'lo':None,'hi':11,'delta':None,'bias':0x20390963,'lower':0x1b64d3f9,'step':0xfb2bca97,'scale':0xe4,'key':0xb970,'invert':False,'branch':0x1b63e0,'modifier':0xf3d5}]
CONTRACTS=[('first_predicate',0x1b48a8,0x1b4d24,[2,3,4,9,10,17,22]),('first_tail_predicate',0x1b4ea4,0x1b5190,[4,9,10,11,17,20]),
 ('second_predicate',0x1b56e0,0x1b5be8,[1,7,11,13,17]),('second_tail_predicate',0x1b5d2c,0x1b636c,[11,16,17]),
 ('first_bound',0x1b4738,0x1b48a0,[10]),('first_tail_bound',0x1b4de4,0x1b4e9c,[9,10,11]),('second_encoded_bound',0x1b55f0,0x1b5620,[17]),
 ('second_lower',0x1b55e0,0x1b56d8,[11]),('second_bound',0x1b567c,0x1b56d8,[7]),('second_tail_bound',0x1b5cdc,0x1b5d20,[11])]
ROWS=[('first_initial',0xc644,0x1b48a0,0x774e),('first_continue',0xf82c,0x1b48a0,0x2883),('first_exit',0xf840,0x1b4d74,0x2883),
 ('first_tail_initial',0x8569,0x1b4e9c,0x5e63),('first_tail_continue',0x8569,0x1b4e9c,0x5e63),('first_tail_exit',0x8568,0x1b51d4,0x5e63),
 ('second_initial',0x6eb3,0x1b56d8,0xb144),('second_continue',0xd3ce,0x1b56d8,0xe8d0),('second_exit',0xd373,0x1b5c40,0xe8d0),
 ('second_tail_initial',0x7c09,0x1b5d20,0x6ff1),('second_tail_continue',0xb994,0x1b5d20,0xf3d5),('second_tail_exit',0xb970,0x1b63e4,0xf3d5)]


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
        elif m=='lsl':v=a*2**(c%bits)
        else:assert m=='lsr';v=a//2**(c%bits)
        put(n,v)
    cpu.update({'X31':list(map(hex,regs)),'NZCV':hex(nzcv),'PC':hex(C.BASE+hi)});assert cpu==b['end']['CPU']and stack.hex()==b['end']['stack1312_hex']and reads==b['reads']and writes==b['writes']


class Replay(R.Replay):
    def __init__(self,*a):super().__init__(*a);self.traversal_components=[];self.current_traversal=None
    def code(self,u,pc,n,d):
        self.flush()
        for name,lo,hi in SPECS:
            if pc==C.BASE+lo:assert self.current_traversal is None;self.current_traversal={'name':name,'entry':R.W.R.W.E.F.F.A.capture(self)}
            if pc==C.BASE+hi and self.current_traversal is not None and self.current_traversal['name']==name:
                self.current_traversal['end']=R.W.R.W.E.F.F.A.capture(self);self.traversal_components.append(self.current_traversal);self.current_traversal=None
        return super().code(u,pc,n,d)


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


def branch_oracle(header,dispatch,d,s):
    h=Component(header,s);t=Component(dispatch,s);digest=sha256();entry=list(map(lambda v:int(v,16),header['entry']['CPU']['X31']));counter=entry[d['counter']]&M
    lower=entry[d['lo']]&M if d['lo']is not None else d['lower'];upper=entry[d['hi']]&M;cases=0
    def run(c,lo,hi,flip=False):
        hr={d['counter']:c,d['hi']:hi};tr={d['counter']:c,d['hi']:hi};hs=bytearray(h.stack);ts=bytearray(t.stack)
        if d['lo']is None:hs[0x450:0x454]=lo.to_bytes(4,'little')
        else:hr[d['lo']]=lo;tr[d['lo']]=lo
        frame,after=h.run(hr,hs);assert after==hs;flag=int(frame['X31'][17],16);assert flag==int(hi<lo);tr[17]=flag^int(flip)
        ts[0x488:0x490]=PRIVATE_TABLE.to_bytes(8,'little')
        if d['name']=='second_tail':ts[0x458:0x45c]=d['key'].to_bytes(4,'little')
        member=((c+d['step']-lo)&M)<((hi-lo)&M);index=(int(not member if d['invert']else member)*d['scale'])^d['key']
        indexes=[d['key'],d['key']^d['scale']];supply=[(PRIVATE_TABLE+8*i,i.to_bytes(8,'little'))for i in indexes]
        end,stack=t.run(tr,ts,supply);actual=int(end['X31'][d['target']],16);assert stack==ts and int(end['X31'][d['next']],16)==(c+1)&M
        if not flip:assert actual==index
        digest.update(json.dumps([frame,end],sort_keys=True).encode());return actual,index
    domains=['counter','upper']if d['lo']is None else['counter','lower','upper']
    for domain in domains:
        for lane in range(4):
            for byte in range(256):
                x=((byte<<(8*lane))^0x9e3779b9)&M;run(x if domain=='counter'else counter,x if domain=='lower'else lower,x if domain=='upper'else upper);cases+=1
    actual,want=run(d['bias'],d['lower'],d['lower']+1,True);assert actual!=want;h.intact();t.intact()
    return {'label':header['label'],'name':d['name'],'domains':domains,'cases':cases,'source_visits':cases*(len(header['visits'])+len(dispatch['visits'])),
      'ordered_frames_sha256':digest.hexdigest(),'source_bytes_preserved':True,'negative_flag_control':{'counter_u32':hex(d['bias']),'lower_u32':hex(d['lower']),'upper_u32':hex(d['lower']+1),
      'correct_wrap_flag':0,'supplied_wrap_flag':1,'actual_index_u32':hex(actual),'candidate_index_u32':hex(want),'contract_rejected':True,'branch_executed':False},
      'negative_source_visits':len(header['visits'])+len(dispatch['visits'])}


def bound_oracle(b,s,other=None):
    a=Component(b,s);c=Component(other,s)if other is not None else None;name=b['name'];digest=sha256();cases=0
    for lane in range(4):
        for byte in range(256):
            value=((byte<<(8*lane))^0x9e3779b9)&M;stack=bytearray(a.stack);expected=bytearray(stack)
            if name=='word_count':stack[0x3ec:0x3f0]=value.to_bytes(4,'little');expected[:]=stack;expected[0x458:0x45c]=(value>>3).to_bytes(4,'little');regs={};wanted=((value>>3)^0x08b1c7cb)
            elif name=='first_bound':value&=0x1fffffff;regs={10:value};wanted=(value+0x7390ff4b)&M
            elif name=='second_bound_encode':value&=0x1fffffff;regs={14:value};wanted=(value+0x3076d59e)&M
            elif name=='first_tail_bound':stack[0x458:0x45c]=(value^0x08b1c7cb).to_bytes(4,'little');expected[:]=stack;regs={8:0x8569};wanted=(value+0x722872e2)&M
            else:assert name=='second_tail_bound';stack[0x410:0x418]=(0x7c09).to_bytes(8,'little');stack[0x458:0x45c]=(value^0x08b1c7cb).to_bytes(4,'little');expected[:]=stack;expected[0x450:0x454]=(0x1b64d3f9).to_bytes(4,'little');regs={};wanted=(value+0x1b64d3f9)&M
            frame,after=a.run(regs,stack);assert after==expected;rr=list(map(lambda v:int(v,16),frame['X31']))
            if c:
                frame,after=c.run({17:rr[17]});assert after==c.stack;rr=list(map(lambda v:int(v,16),frame['X31']));assert rr[7]==wanted and rr[11]==0x3076d59e
            else:assert rr[{'word_count':1,'first_bound':10,'first_tail_bound':9,'second_tail_bound':11}[name]]==wanted
            digest.update(json.dumps(frame,sort_keys=True).encode());digest.update(after);cases+=1
    a.intact()
    if c:c.intact()
    return {'label':b['label'],'name':name,'cases':cases,'source_visits':cases*(len(b['visits'])+(len(other['visits'])if c else 0)),
      'ordered_frames_and_stack_sha256':digest.hexdigest(),'source_bytes_preserved':True}


def outside_oracles(e,s):
    blocks={b['name']:b for b in e['blocks']if b['label']=='separate_ramp16'};out=[]
    for control in e['source_checks']['outside_domain_controls']:
        value=int(control['remainder_u32'],16);name=control['name'];a=Component(blocks[name if name=='first_bound'else'second_bound_encode'],s)
        frame,stack=a.run({10 if name=='first_bound'else 14:value});assert stack==a.stack;visits=(a.hi-a.lo)//4
        if name=='second_bound':
            c=Component(blocks['second_bound_decode'],s);frame,stack=c.run({17:int(frame['X31'][17],16)});assert stack==c.stack;c.intact();visits+=(c.hi-c.lo)//4
        actual=int(frame['X31'][10 if name=='first_bound'else 7],16);assert value>0x1fffffff and actual==int(control['actual_upper_u32'],16)and actual!=int(control['candidate_upper_u32'],16);a.intact()
        out.append({'name':name,'remainder_u32':hex(value),'actual_upper_u32':hex(actual),'candidate_upper_u32':control['candidate_upper_u32'],'source_visits':visits,'outside_count_domain':True,'branch_executed':False})
    return out


def check_census(e,s):
    unique={};contracts=e['census']['contracts'];assert len(contracts)==len(CONTRACTS)==10
    for row,(name,lo,hi,regs)in zip(contracts,CONTRACTS):
        assert row['name']==name and row['start']==hex(lo)and row['end']==hex(hi)and row['preserved_registers']==regs;names={p+str(j)for j in regs for p in ['w','x']};ins=list(C.CS.disasm(s.read(lo,hi-lo),lo));branches=[]
        for i in ins:
            _,ww=i.regs_access();ww=[]if i.mnemonic in ['cmp','tst','ccmp']else ww
            assert not names&{i.reg_name(j)for j in ww}and not any(i.group(g)for g in [2,3])
            if i.group(1):assert i.mnemonic=='braa';branches.append(hex(i.address))
            unique[i.address]={'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'instruction':i.mnemonic+' '+i.op_str}
        assert row['instruction_count']==len(ins)and row['branch_sites']==branches
    assert e['census']['instructions']==[unique[k]for k in sorted(unique)]and len(unique)==1411


def joins(p,blocks,e,pins,s):
    label=p['configuration']['label'];N=p['configuration']['length_u32']//8;bs={b['name']:b for b in blocks if b['name']not in {x[k]for x in CONFIG for k in ['header','dispatch']}}
    def rr(name,part='end'):return list(map(lambda v:int(v,16),bs[name][part]['CPU']['X31']))
    assert rr('word_count')[1]==N and rr('first_key')[2]==0xf82c and rr('first_lower')[4]==0x7390ff4b and rr('first_delta')[22]==0x3be77d89 and rr('first_delta')[3]==0x6c
    r1=rr('first_bound','entry')[10]&M;r2=rr('second_bound_encode','entry')[14]&M;assert r1<N and r2<N and N>=2 and N<=0x1fffffff
    assert rr('first_bound')[10]==(0x7390ff4b+r1)&M and rr('first_tail_bound')[9]==(0x722872e2+N)&M and rr('first_tail_bound')[10]==0x722872e2
    assert rr('second_bound_decode')[7]==(0x3076d59e+r2)&M and rr('second_tail_bound')[11]==(0x1b64d3f9+N)&M
    assert rr('second_bound_encode')[17]==rr('second_bound_decode','entry')[17]
    cache=bs['table_cache'];assert int(cache['writes'][0]['address'],16)==int(cache['entry']['CPU']['SP'],16)+0x488 and int.from_bytes(bytes.fromhex(cache['writes'][0]['after_hex']),'little')==C.BASE+TABLE
    assert cache['reads'][0]['address']==hex(C.BASE+0x1d108e8)and int.from_bytes(bytes.fromhex(cache['reads'][0]['bytes_hex']),'little')==C.BASE+TABLE+4
    decisions=[];epochs=[];visits=p['visits'];cache_write=cache['writes'][0]
    for d in CONFIG:
        headers=[b for b in blocks if b['name']==d['header']];dispatches=[b for b in blocks if b['name']==d['dispatch']];start=0 if d['name']in ['first','second']else max(1,r1 if d['name']=='first_tail'else r2)
        stop=max(1,r1 if d['name']=='first'else r2)if d['name']in ['first','second']else N
        assert len(headers)==len(dispatches)==stop-start
        for index,h,t in zip(range(start,stop),headers,dispatches):
            hcpu=list(map(lambda v:int(v,16),h['entry']['CPU']['X31']));tcpu=list(map(lambda v:int(v,16),t['entry']['CPU']['X31']));assert (hcpu[d['counter']]-d['bias'])&M==index and h['end']['CPU']['X31'][17]==t['entry']['CPU']['X31'][17]
            c=tcpu[d['counter']]&M;lower=tcpu[d['lo']]&M if d['lo']is not None else d['lower'];upper=tcpu[d['hi']]&M;member=((c+d['step']-lower)&M)<((upper-lower)&M);continued=index+1<stop;assert member==continued
            selected=(int(not member if d['invert']else member)*d['scale'])^d['key'];load=t['reads'][-1];row=s.decoded[TABLE+8*selected];edge=next(x for x in p['PAC_models']if x['visit']==t['end']['source_visit'])
            assert load['address']==hex(C.BASE+TABLE+8*selected)and edge['pointer_row']==row and edge['pc']==hex(d['branch'])and edge['modifier']==hex(d['modifier'])and edge['target']==hex(C.BASE+int(row['target'],16))
            next_pc=int(visits[t['end']['source_visit']+1]['pc'],16);assert next_pc==int(row['target'],16)
            table_read=t['reads'][-2];assert table_read['address']==cache_write['address']and table_read['bytes_hex']==cache_write['after_hex']and table_read['size_B']==8
            at=int(table_read['address'],16);assert not any(cache_write['visit']<w['visit']<table_read['visit']and int(w['address'],16)<at+8 and at<int(w['address'],16)+w['size_B']for w in p['writes'])
            epochs.append({'store_visit':cache_write['visit'],'read_visit':table_read['visit'],'address':table_read['address'],'size_B':8,'no_intervening_overlapping_write':True})
            decisions.append({'name':d['name'],'logical_index_u32':hex(index),'continue':continued,'selector_index_u32':hex(selected),'pointer_row':row,'branch_PC':edge['pc'],'target_PC':hex(next_pc),'modifier':edge['modifier']})
    for pc,index,target,mod in [(0x1b489c,0xc644,0x1b48a0,0x774e),(0x1b4e98,0x8569,0x1b4e9c,0x5e63),(0x1b56d4,0x6eb3,0x1b56d8,0xb144),(0x1b5d1c,0x7c09,0x1b5d20,0x6ff1)]:
        edge=next(v for v in p['PAC_models']if v['pc']==hex(pc));assert edge['target']==hex(C.BASE+target)and edge['modifier']==hex(mod)and edge['pointer_row']==s.decoded[TABLE+8*index]
    old=[b for b in pins['corefp_input_lineage_checks.json']['blocks']if b['label']==label];origin=R.joins(p,old,pins);assert origin['decoded_operation_u32']=='0x7f48'
    return {'label':label,'word_count_u32':hex(N),'remainders_u32':list(map(hex,[r1,r2])),'head_lengths_u32':list(map(hex,[max(1,r1),max(1,r2)])),
      'decisions':decisions,'table_epochs':epochs,'initial_edges_checked':4,'same_entry_lineage':True,'conditional_bounded_traversal':True}


def inputs():
    raw=read(ROOT/'corefp_word_traversal_checks.json').encode();e=json.loads(raw);s=C.Pointers();pins={}
    assert e['generator_sha256']==SHA((ROOT/'recover_corefp_word_traversal.py').read_bytes())and e['thin_sha256']==C.THIN_SHA
    for n,h in e['parent_pins'].items():
        rr=read(ROOT/n).encode();assert SHA(rr)==h;pins[n]=json.loads(rr)
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h
    assert len(pins)==22 and len(e['dependencies'])==25 and len(e['source_regions'])==19
    for region,(name,lo,hi)in zip(e['source_regions'],SPECS):
        assert region['name']==name and region['start']==hex(lo)and region['end']==hex(hi)and region['instructions']==[{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'instruction':i.mnemonic+' '+i.op_str}for i in C.CS.disasm(s.read(lo,hi-lo),lo)]
    for region,(lo,hi)in zip(e['remainder_interfaces'],[(0x1b46b4,0x1b46c0),(0x1b559c,0x1b55a4)]):
        assert region['start']==hex(lo)and region['end']==hex(hi)and region['instructions']==[{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'instruction':i.mnemonic+' '+i.op_str}for i in C.CS.disasm(s.read(lo,hi-lo),lo)]
    assert len(e['remainder_interfaces'])==2 and len(e['target_rows'])==12 and e['table_cache_origin_row']==s.decoded[0x1d108e8]
    for row,(name,index,target,diversity)in zip(e['target_rows'],ROWS):
        actual=s.decoded[TABLE+8*index];assert row=={'name':name,'index_u32':hex(index),'row':actual}
        assert actual['target']==hex(target)and actual['diversity']==hex(diversity)and actual['authenticated']and actual['key']=='IA'and not actual['address_diversity']and actual['chain_membership_verified']
    check_census(e,s)
    return raw,e,s,pins


def main():
    raw,e,s,pins=inputs();old=R.W.R.W.frozen(pins)+pins['corefp_word_codec_checks.json']['proofs']+pins['corefp_word_recurrence_checks.json']['source_checks']['proofs']+pins['corefp_word_inputs_checks.json']['source_checks']['proofs']+pins['corefp_input_lineage_checks.json']['source_checks']['proofs'];new=e['source_checks']['proofs'];assert len(old)==1263 and len(new)==38
    for proof in old+new:
        q=z3.Solver();q.set(timeout=30000);q.from_string(proof['query']);assert proof['result']=='unsat'and q.check()==z3.unsat,proof['label']
    for control in e['source_checks']['outside_domain_controls']:
        q=z3.Solver();q.set(timeout=30000);q.from_string(control['query']);q.add(z3.BitVec('selector_remainder32',32)==int(control['remainder_u32'],16));assert control['result']=='sat'and q.check()==z3.sat
    print(json.dumps({'queries_unsat':1301,'queries_sat':2}),flush=True);parent=pins['corefp_workspace_checks.json'];totals=Counter();branches=[];bounds=[];interfaces=[];offset=0
    for j,p in enumerate(parent['profiles']):
        totals.update(R.W.R.W.E.F.F.A.initial_checks(p,s));r=Replay(p,parent['source_spans'],s);totals.update(r.run());R.W.R.W.E.F.F.W.workspace_oracle(p,r,s,parent['workspace_constructions'][j]);R.W.R.W.E.F.F.W.preparation_oracle(p,r,s)
        assert r.current_traversal is None;start=offset
        for actual in r.traversal_components:
            b=e['blocks'][offset];offset+=1;assert b['name']==actual['name']and b['label']==p['configuration']['label']and all(b[t]==actual[t]for t in ['entry','end']);lo,hi=b['entry']['source_visit'],b['end']['source_visit'];assert b['visits']==p['visits'][lo:hi]
            for k in ['reads','writes','PAC_models']:assert b[k]==[v for v in p[k]if lo<=v['visit']<hi]
            scalar(b,s)
        blocks=e['blocks'][start:offset];bs={b['name']:b for b in blocks}
        for d in CONFIG:
            for h,t in zip([b for b in blocks if b['name']==d['header']],[b for b in blocks if b['name']==d['dispatch']]):branches.append(branch_oracle(h,t,d,s))
        for name in ['word_count','first_bound','first_tail_bound','second_bound_encode','second_tail_bound']:bounds.append(bound_oracle(bs[name],s,bs['second_bound_decode']if name=='second_bound_encode'else None))
        interfaces.append(joins(p,blocks,e,pins,s));print(json.dumps({'audited':p['configuration']['label']}),flush=True)
    outside=outside_oracles(e,s);assert offset==130 and dict(totals)==pins['corefp_input_lineage_audit.json']['result']['independent_replay']and e['replay_totals']=={k:v for k,v in totals.items()if not k.startswith('initial_')}
    counts={'profiles':6,'regions':130,'source_instructions':245,'source_B':980,'regional_visits':1634,'regional_reads':106,'regional_writes':18,'regional_PAC_models':0,'preservation_contracts':10,'census_instructions':1411,'census_B':5644,'unique_source_instructions':1619,'unique_source_B':6476,'logical_target_rows':12,'distinct_target_rows':11,'new_queries_unsat':38}
    assert e['verified_counts']==counts and sum(len(b['visits'])for b in e['blocks'])==1634 and sum(len(b['reads'])for b in e['blocks'])==106 and sum(len(b['writes'])for b in e['blocks'])==18 and not any(b['PAC_models']for b in e['blocks'])
    result={'verified_counts':counts,'independent_replay':dict(totals),'actual_full_frames':130,'independent_scalar_frames':130,'branch_cases':sum(o['cases']for o in branches),'branch_source_visits':sum(o['source_visits']for o in branches),'bound_count_cases':sum(o['cases']for o in bounds),'bound_count_source_visits':sum(o['source_visits']for o in bounds),'finite_cases':sum(o['cases']for o in branches+bounds),'finite_source_visits':sum(o['source_visits']for o in branches+bounds),'negative_cases':len(branches)+len(outside),'negative_source_visits':sum(o['negative_source_visits']for o in branches)+sum(o['source_visits']for o in outside),'stable_table_epochs':sum(len(j['table_epochs'])for j in interfaces),'retained_decisions':sum(len(j['decisions'])for j in interfaces),'initial_edges_checked':sum(j['initial_edges_checked']for j in interfaces),'new_queries_unsat':38,'frozen_queries_unsat':1263,'total_queries_unsat':1301,'outside_domain_queries_sat':2,'all_checks_pass':True,'native_target_executed':False}
    assert [result[k]for k in ['branch_cases','branch_source_visits','bound_count_cases','bound_count_source_visits','finite_cases','finite_source_visits','negative_cases','negative_source_visits','stable_table_epochs','retained_decisions','initial_edges_checked']]==[92160,2039808,30720,835584,122880,2875392,34,800,32,32,24]
    out={'result':result,'checks_sha256':SHA(raw),'auditor_sha256':SHA(Path(__file__).read_bytes()),'generator_sha256':e['generator_sha256'],'parent_pins':e['parent_pins'],'dependencies':e['dependencies'],'branch_oracles':branches,'bound_count_oracles':bounds,'outside_domain_oracles':outside,'interface_joins':interfaces,'fresh_replay_completed':True,'process_exit_code':0,'native_API_executed':False,'IDB_mutated':False,'new_live_IDA_claim':False,'earlier_arithmetic_passes_universally_reduced':False,'general_raw_preparation_contract_established':False,'whole_transform_algorithm':'unknown','full_goal_complete':False}
    (ROOT/'corefp_word_traversal_audit.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(result),flush=True)


if __name__=='__main__':main()
