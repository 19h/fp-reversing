#!/usr/bin/env python3
"""Byte-symbolic source successor; unknown frame bytes stay unconstrained.
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

CS=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);CS.detail=True
class Frontier(Exception):
    def __init__(self,detail):self.detail=detail
def numeric(value,role,pc):
    value=z3.simplify(value)
    if not z3.is_bv_value(value):raise Frontier({'pc':hex(pc),'kind':'symbolic_'+role,'expression':value.sexpr()})
    return value.as_long()

def analyze(source):
    ctx=source['context'];ram={};effects=[];unknown={};steps=[];edges=[];observables=[];origins={};fix=set();stores=[];pc=int(ctx['entry_PC'],16);owner=ctx['frame_owner'];lo=int(owner['address'],16);hi=lo+owner['size_bytes'];WRITABLE=[s for s in sections()if s['segment']=='__DATA']
    for g in ctx['known_byte_groups']:
        for j,b in enumerate(bytes.fromhex(g['bytes_hex'])):ram[int(g['address'],16)+j]=z3.BitVecVal(b,8)
    def address_value(a,role,n):
        observables.append((role,pc,a));return numeric(a,role,pc)
    class V(FingerprintLift):
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
            at=address_value(a,'read_address',n);self.last_load_slot=None
            if at in FIXUPS and n==8:
                target=FIXUPS[at]['target']
                if isinstance(target,str):raise Frontier({'pc':hex(pc),'kind':'imported_pointer','slot':hex(at),'target':target})
                self.last_load_slot=at;fix.add(at);value=z3.BitVecVal(target,64)
            else:
                vals=[]
                for j in range(n):
                    here=at+j
                    if here in ram:value=ram[here]
                    elif lo<=here<hi:
                        if here not in unknown:unknown[here]=z3.BitVec('spill_byte_%x'%here,8)
                        value=unknown[here]
                    elif any(s['start']<=here<s['start']+s['size_bytes']for s in WRITABLE):raise Frontier({'pc':hex(pc),'kind':'before_unmodeled_runtime_read','address':hex(at),'size_bytes':n,'first_missing_byte':hex(here)})
                    else:
                        try:value=z3.BitVecVal(IMAGE.read(here,1)[0],8)
                        except ValueError:raise Frontier({'pc':hex(pc),'kind':'before_unowned_external_read','address':hex(at),'size_bytes':n})
                    vals.append(value)
                value=z3.Concat(*reversed(vals))if n>1 else vals[0]
            effects.append({'pc':hex(pc),'kind':'read','address':hex(at),'size_bytes':n,'expression':value.sexpr()});return value
        def store(self,a,n,value,atpc):
            at=address_value(a,'write_address',n);assert lo<=at<at+n<=hi
            value=resize(value,n*8);effects.append({'pc':hex(pc),'kind':'write','address':hex(at),'size_bytes':n,'expression':value.sexpr()});stores.append((pc,at,n,value))
            for j in range(n):ram[at+j]=z3.Extract(8*j+7,8*j,value)
    v=V({'spans':[]});v.seed('sp',int(ctx['SP'],16))
    for name,value in ctx['known_GPRs'].items():v.seed(name,int(value,16))
    boundary=None
    try:
        for _ in range(1000):
            i=next(CS.disasm(IMAGE.read(pc,4),pc));v.pc=pc;old_origins=origins.copy();first=len(effects)
            if i.mnemonic in ['braa','blraa','braaz','blraaz','ret','retab']:
                ret=i.mnemonic.startswith('ret');name='x30'if ret else i.op_str.split(',')[0].strip();value=v.read(name);observables.append(('branch_target',pc,value));target=numeric(value,'branch_target',pc)
                assert not ret and not i.mnemonic.startswith('bl'),('unexpected call/return',hex(pc))
                slot=origins.get(key(name));assert slot in FIXUPS;word=int.from_bytes(IMAGE.read(slot,8),'little');modifier=0 if i.mnemonic.endswith('z')else numeric(v.read(i.op_str.split(',')[1].strip()),'PAC_modifier',pc)
                assert word>>63==1 and(word>>32)&0xffff==modifier and(word>>48)&7==0 and FIXUPS[slot]['target']==target;fix.add(slot)
                edges.append({'pc':hex(pc),'target':hex(target),'slot':hex(slot),'modifier':hex(modifier),'kind':i.mnemonic});steps.append([pc,bytes(i.bytes).hex()]);pc=target;continue
            v.c={'spans':[{'label':'one','start':hex(pc),'bytes_hex':bytes(i.bytes).hex()}]};v.last_load_slot=None;v.run('one')
            rr,ww=i.regs_access()
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
    s=json.loads((ROOT/'daemon_record720_spill_source.json').read_text());r,obs,stores,v=analyze(s);r.update({'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['daemon_record720_spill_source.json','prove_daemon_record720_fingerprint.py','lskd_values_symbolic.py']}})
    (ROOT/'daemon_record720_spill_symbolic.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'source_steps':len(r['steps']),'effects':len(r['effects']),'logical_edges':len(r['edges']),'unknown_bytes':len(r['unknown_bytes']),'boundary':r['boundary']}))
