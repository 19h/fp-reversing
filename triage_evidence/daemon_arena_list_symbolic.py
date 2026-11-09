#!/usr/bin/env python3
"""Byte-symbolic arena-list consumer; frame bytes stay unconstrained.
O(instructions + effects + BV expressions) time/space plus optional solver
resources. No native target or concrete value for an unavailable byte.
"""
import json
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64_const import ARM64_OP_REG,ARM64_EXT_SXTW,ARM64_EXT_SXTX,ARM64_EXT_UXTW
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from capture_daemon_record720 import sha
from prove_daemon_record720_fingerprint import FingerprintLift
from lskd_values_symbolic import resize
from recover_daemon_object_clock import sections
from recover_daemon_descriptor_producers import verify_used_fixups
from daemon_digest_output_access import key
from replay_daemon_descriptor_producers import IMPORTS
from daemon_import_bindings import binding

CS=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);CS.detail=True
class ListFlags(FingerprintLift):
    def set_flags(self,a,b,add=False):
        n=a.size();r=a+b if add else a-b;sa=z3.Extract(n-1,n-1,a);sb=z3.Extract(n-1,n-1,b);sr=z3.Extract(n-1,n-1,r);self.equal=r==0;self.carry=(z3.Extract(n,n,z3.ZeroExt(1,a)+z3.ZeroExt(1,b))==1)if add else z3.UGE(a,b);self.negative=sr==1;self.overflow=z3.And(sa==sb if add else sa!=sb,sr!=sa);self.cmp_left=a;self.cmp_right=b
    def condition(self,cc):
        e=self.equal;c=self.carry;n=self.negative;v=self.overflow;table={'eq':e,'ne':z3.Not(e),'lo':z3.Not(c),'hs':c,'hi':z3.And(c,z3.Not(e)),'ls':z3.Or(z3.Not(c),e),'gt':z3.And(z3.Not(e),n==v),'le':z3.Or(e,n!=v),'ge':n==v,'lt':n!=v,'mi':n,'pl':z3.Not(n),'vs':v,'vc':z3.Not(v)};assert cc in table,cc;return table[cc]
    def run(self,label):
        row=next(r for r in self.c['spans']if r['label']==label);old=self.c
        for i in CS.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
            self.pc=i.address;o=i.operands;m=i.mnemonic
            if m in ['cmp','cmn']:
                n=self.width(i.reg_name(o[0].reg));self.set_flags(self.operand(i,o[0],n),self.operand(i,o[1],n),m=='cmn');self.count+=1
            elif m=='subs':
                dest=i.reg_name(o[0].reg);n=self.width(dest);a=self.operand(i,o[1],n);b=self.operand(i,o[2],n);self.set_flags(a,b);self.write(dest,a-b);self.count+=1
            elif m=='ccmp':
                n=self.width(i.reg_name(o[0].reg));a=self.operand(i,o[0],n);b=self.operand(i,o[1],n);take=self.condition(i.op_str.rsplit(',',1)[1].strip());self.set_flags(a,b);self.equal=z3.If(take,self.equal,z3.BoolVal(bool(o[2].imm&4)));self.carry=z3.If(take,self.carry,z3.BoolVal(bool(o[2].imm&2)));self.negative=z3.If(take,self.negative,z3.BoolVal(bool(o[2].imm&8)));self.overflow=z3.If(take,self.overflow,z3.BoolVal(bool(o[2].imm&1)));self.count+=1
            elif m=='cset':
                cc=i.op_str.rsplit(',',1)[1].strip();self.write(i.reg_name(o[0].reg),z3.If(self.condition(cc),z3.BitVecVal(1,32),z3.BitVecVal(0,32)));self.count+=1
            else:
                self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run('one')
        self.c=old;return self
class Frontier(Exception):
    def __init__(self,detail):self.detail=detail
def numeric(value,role,pc):
    value=z3.simplify(value)
    if not z3.is_bv_value(value):raise Frontier({'pc':hex(pc),'kind':'symbolic_'+role,'expression':value.sexpr()})
    return value.as_long()

def analyze(source):
    ctx=source['context'];ram={};effects=[];unknown={};steps=[];edges=[];observables=[];origins={};memory_origins={int(a,16):int(v,16)for a,v in ctx.get('memory_pointer_origins',{}).items()};fix=set();stores=[];pc=int(ctx['entry_PC'],16);owner=ctx['frame_owner'];lo=int(owner['address'],16);hi=lo+owner['size_bytes'];WRITABLE=[s for s in sections()if s['segment']=='__DATA']
    for g in ctx['known_byte_groups']:
        for j,b in enumerate(bytes.fromhex(g['bytes_hex'])):ram[int(g['address'],16)+j]=z3.BitVecVal(b,8)
    def address_value(a,role,n):
        observables.append((role,pc,a));return numeric(a,role,pc)
    class V(ListFlags):
        last_load_slot=None
        def address(self,i,o):
            a=resize(self.read(i.reg_name(o.mem.base)),64)+o.mem.disp
            if o.mem.index:
                x=self.read(i.reg_name(o.mem.index))
                if o.ext==ARM64_EXT_SXTW:x=z3.SignExt(32,resize(x,32))
                elif o.ext==ARM64_EXT_SXTX:x=resize(x,64)
                elif o.ext==ARM64_EXT_UXTW:x=z3.ZeroExt(32,resize(x,32))
                else:x=resize(x,64)
                a+=x<<o.shift.value
            return z3.simplify(a)
        def load(self,a,n):
            at=address_value(a,'read_address',n);self.last_load_slot=memory_origins.get(at)if n==8 else None
            if at in FIXUPS and n==8:
                target=FIXUPS[at]['target']
                if isinstance(target,str):target=IMPORTS[target]+binding(at)['total_addend']
                self.last_load_slot=at;fix.add(at);value=z3.BitVecVal(target,64)
            else:
                vals=[]
                for j in range(n):
                    here=at+j
                    if here in ram:value=ram[here]
                    elif lo<=here<hi:
                        if here not in unknown:unknown[here]=z3.BitVec('spill_byte_%x'%here,8)
                        value=unknown[here]
                    elif any(int(o['address'],16)<=here<int(o['address'],16)+o['size_bytes']for o in ctx.get('additional_owners',[])):raise Frontier({'pc':hex(pc),'kind':'before_undefined_arena_read','address':hex(at),'size_bytes':n,'first_missing_byte':hex(here)})
                    elif any(s['start']<=here<s['start']+s['size_bytes']for s in WRITABLE):raise Frontier({'pc':hex(pc),'kind':'before_unmodeled_runtime_read','address':hex(at),'size_bytes':n,'first_missing_byte':hex(here)})
                    else:
                        try:value=z3.BitVecVal(IMAGE.read(here,1)[0],8)
                        except ValueError:raise Frontier({'pc':hex(pc),'kind':'before_unowned_external_read','address':hex(at),'size_bytes':n})
                    vals.append(value)
                value=z3.Concat(*reversed(vals))if n>1 else vals[0]
            effects.append({'pc':hex(pc),'kind':'read','address':hex(at),'size_bytes':n,'expression':value.sexpr()});return value
        def store(self,a,n,value,atpc):
            at=address_value(a,'write_address',n)
            if not(lo<=at<at+n<=hi or any(int(o['address'],16)<=at<at+n<=int(o['address'],16)+o['size_bytes']for o in ctx.get('additional_owners',[]))or any(s['start']<=at<at+n<=s['start']+s['size_bytes']for s in WRITABLE)):raise Frontier({'pc':hex(pc),'kind':'before_unowned_write','address':hex(at),'size_bytes':n})
            value=resize(value,n*8);effects.append({'pc':hex(pc),'kind':'write','address':hex(at),'size_bytes':n,'expression':value.sexpr()});stores.append((pc,at,n,value))
            for j in range(n):ram[at+j]=z3.Extract(8*j+7,8*j,value)
    v=V({'spans':[]});v.seed('sp',int(ctx['SP'],16))
    for name,value in ctx['known_GPRs'].items():v.seed(name,int(value,16))
    boundary=None
    try:
        for _ in range(100000):
            if pc==0x10031f248:raise Frontier({'pc':hex(pc),'kind':'before_allocator_continuation','payload_X23':hex(numeric(v.read('x23'),'result_X23',pc)),'boundary_X0':hex(numeric(v.read('x0'),'result_X0',pc))})
            i=next(CS.disasm(IMAGE.read(pc,4),pc));v.pc=pc;old_origins=origins.copy();first=len(effects)
            if i.mnemonic in ['braa','blraa','braaz','blraaz','ret','retab']:
                ret=i.mnemonic.startswith('ret');name='x30'if ret else i.op_str.split(',')[0].strip();value=v.read(name);observables.append(('branch_target',pc,value));target=numeric(value,'branch_target',pc)
                assert not ret,('unexpected return',hex(pc))
                slot=origins.get(key(name))
                if slot not in FIXUPS:raise Frontier({'pc':hex(pc),'kind':'unresolved_pointer_origin','register':name,'target':hex(target)})
                word=int.from_bytes(IMAGE.read(slot,8),'little');modifier=0 if i.mnemonic.endswith('z')else numeric(v.read(i.op_str.split(',')[1].strip()),'PAC_modifier',pc)
                assert word>>63==1 and(word>>32)&0xffff==modifier and(word>>48)&7==0;fix.add(slot)
                if i.mnemonic.startswith('bl'):
                    bound=binding(slot);assert isinstance(FIXUPS[slot]['target'],str)and target==IMPORTS[FIXUPS[slot]['target']]+bound['total_addend'];raise Frontier({'pc':hex(pc),'kind':'before_import_call','binding':bound,'argument_X0':hex(numeric(v.read('x0'),'import_argument',pc)),'logical_target':hex(target)})
                assert FIXUPS[slot]['target']==target
                edges.append({'pc':hex(pc),'target':hex(target),'slot':hex(slot),'modifier':hex(modifier),'kind':i.mnemonic});steps.append([pc,bytes(i.bytes).hex()]);pc=target;continue
            v.c={'spans':[{'label':'one','start':hex(pc),'bytes_hex':bytes(i.bytes).hex()}]};v.last_load_slot=None;v.run('one')
            rr,ww=i.regs_access()
            new_effects=effects[first:]
            for e in new_effects:
                if e['kind']=='write':
                    at=int(e['address'],16)
                    for oldat in list(memory_origins):
                        if at<oldat+8 and oldat<at+e['size_bytes']:memory_origins.pop(oldat)
            if i.mnemonic in ['str','stur']and i.reg_name(i.operands[0].reg).startswith('x'):
                es=[e for e in new_effects if e['kind']=='write'];o=old_origins.get(key(i.reg_name(i.operands[0].reg)))
                if o is not None and len(es)==1 and es[0]['size_bytes']==8:memory_origins[int(es[0]['address'],16)]=o
            elif i.mnemonic=='stp'and all(i.reg_name(o.reg).startswith('x')for o in i.operands[:2]):
                es=[e for e in new_effects if e['kind']=='write'];assert len(es)==2
                for operand,e in zip(i.operands,es):
                    o=old_origins.get(key(i.reg_name(operand.reg)))
                    if o is not None:memory_origins[int(e['address'],16)]=o
            for reg in ww:origins.pop(key(i.reg_name(reg)),None)
            if i.mnemonic in['ldr','ldur']and i.reg_name(i.operands[0].reg).startswith('x')and v.last_load_slot is not None:origins[key(i.reg_name(i.operands[0].reg))]=v.last_load_slot
            elif i.mnemonic=='mov'and len(i.operands)==2 and i.operands[1].type==ARM64_OP_REG:
                o=old_origins.get(key(i.reg_name(i.operands[1].reg)))
                if o is not None:origins[key(i.reg_name(i.operands[0].reg))]=o
            steps.append([pc,bytes(i.bytes).hex()]);pc+=4
        else:raise Frontier({'pc':hex(pc),'kind':'instruction_limit'})
    except Frontier as e:boundary=e.detail
    assert boundary is not None
    return {'context':ctx,'steps':steps,'effects':effects,'edges':edges,'boundary':boundary,'unknown_bytes':[{'address':hex(a),'variable':b.decl().name()}for a,b in sorted(unknown.items())],'end_GPR_expressions':{n:z3.simplify(x).sexpr()for n,x in v.regs.items()},'original_fixups':verify_used_fixups(fix),'native_target_executed':False,'unknown_bytes_assigned_values':False,'full_goal_complete':False},observables,stores,v

if __name__=='__main__':
    source=json.loads((ROOT/'daemon_arena_list_source.json').read_text());rows=[]
    for case in source['cases']:
        r,obs,stores,v=analyze(case);rows.append({'label':case['label'],'result':r});print(json.dumps({'label':case['label'],'source_steps':len(r['steps']),'boundary':r['boundary']}),flush=True)
    out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['daemon_arena_list_source.json','daemon_record720_spill_symbolic.py','prove_daemon_record720_fingerprint.py']},'cases':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_arena_list_symbolic.json').write_text(json.dumps(out,indent=2)+'\n')
