#!/usr/bin/env python3
"""Independent MAX-CPU replay of certificate fields, atomics and IA callbacks.
O(source visits+effects) time, O(one private map+known bytes+decoder cache)
space per case. Models malloc/free and logical PAC; no native target execution.
"""
from functools import lru_cache
from collections import Counter
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64_const import ARM64_OP_REG,ARM64_OP_MEM,ARM64_EXT_SXTW,ARM64_EXT_SXTX
import unicorn as uc
from unicorn import arm64_const as ar
from daemon_receive_tools import IMAGE,FIXUPS
from replay_daemon_descriptor_producers import IMPORTS
from daemon_import_bindings import binding
from validate_daemon_object_clock import logical_read
from recover_daemon_object_clock import sections
from capture_daemon_object_clock import memory_width
from daemon_digest_output_access import register_access,key

BASE=0x6800000000;SIZE=0x100000;MASK=(1<<64)-1;WRITABLE=[s for s in sections()if s['segment']=='__DATA'];CS=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);CS.detail=True
@lru_cache(maxsize=None)
def instruction(pc):return next(CS.disasm(IMAGE.read(pc,4),pc))
@lru_cache(maxsize=None)
def page(a):
    try:return logical_read(a,4096)
    except ValueError:
        assert any(s['start']<a+4096 and a<s['start']+s['size_bytes']for s in WRITABLE);return bytes(4096)
def reg(n):
    n={'fp':'x29','lr':'x30','wsp':'sp'}.get(n,n);return getattr(ar,'UC_ARM64_REG_'+n.upper())

def replay(c,cfg,t):
    u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);u.mem_map(BASE,SIZE);u.mem_write(BASE,bytes([cfg['physical_pattern']])*SIZE);pages=set(range(BASE,BASE+SIZE,4096));defined=set();known=set();F=int(c['SP'],16);active={};origins={};spills={};counts=Counter();pos=0;current=0;pending=[];edges=iter(t['edges']);apis=iter(t['API_models']);events=t['events'];owners=[(F-0x4000,0x14000)]+[(int(g['address'],16),len(g['bytes_hex'])//2)for g in c['known_byte_groups']if BASE<=int(g['address'],16)<BASE+SIZE]
    def ensure(a,n):
        for pg in range(a&~4095,(a+n+4095)&~4095,4096):
            if pg in pages:continue
            b=page(pg)if 0x100000000<=pg<0x102000000 else bytes(4096);u.mem_map(pg,4096);u.mem_write(pg,b);pages.add(pg)
    def get(n):return 0 if n in ['xzr','wzr']else u.reg_read(reg(n))
    def put(n,v):u.reg_write(reg(n),v&MASK)
    for g in c['known_byte_groups']:
        a=int(g['address'],16);b=bytes.fromhex(g['bytes_hex']);ensure(a,len(b));u.mem_write(a,b);defined.update(range(a,a+len(b)))
    for n,v in c['entry_defined_GPRs'].items():put(n,int(v,16));known.add(key(n))
    def address(i,o):
        a=get(i.reg_name(o.mem.base))+o.mem.disp
        if o.mem.index:
            v=get(i.reg_name(o.mem.index));bits=32 if o.ext==ARM64_EXT_SXTW else 64 if o.ext==ARM64_EXT_SXTX else None
            if bits:v&=(1<<bits)-1;v=v-(1<<bits)if v>>(bits-1)else v
            a+=v<<o.shift.value
        return a&MASK
    def hook(_,kind,a,n,value,__):
        nonlocal pos
        e=events[pos];pos+=1;assert int(e['pc'],16)==current and int(e['address'],16)==a and e['size_bytes']==n
        if kind==uc.UC_MEM_READ:
            assert e['kind']=='read';actual=bytes(u.mem_read(a,n));assert actual.hex()==e['bytes_hex'];counts['reads_checked']+=1
        else:
            assert e['kind']=='write';defined.update(range(a,a+n));pending.append((a,n,e['after_hex']));counts['writes_checked']+=1
    u.hook_add(uc.UC_HOOK_MEM_READ|uc.UC_HOOK_MEM_WRITE,hook)
    def fetch(_,kind,a,n,value,__):
        assert 0x100000000<=a<a+n<=0x100e2c000,('external instruction fetch',hex(current),hex(a))
        ensure(a,n);return True
    u.hook_add(uc.UC_HOOK_MEM_FETCH_UNMAPPED,fetch)
    snaps=iter(t['ABI_snapshots']);snapshot=next(snaps,None)
    def check_snapshot(item):
        assert get('sp')==int(item['SP'],16)
        for name,value in item['known_GPRs'].items():assert name in known and get(name)==int(value,16),(item['pc'],name)
        counts['ABI_snapshots_checked']+=1
    pc=int(c['entry_PC'],16)
    for expected_pc,raw in t['steps']:
        assert pc==expected_pc
        if snapshot is not None and int(snapshot['pc'],16)==pc:check_snapshot(snapshot);snapshot=next(snaps,None)
        current=pc;i=instruction(pc);assert bytes(i.bytes).hex()==raw;rr,ww=register_access(i)
        assert all(key(i.reg_name(r))in known or i.reg_name(r)in['xzr','wzr']for r in rr),(hex(pc),'undefined register')
        o=next((o for o in i.operands if o.type==ARM64_OP_MEM),None)
        if o is not None:
            a=address(i,o);n=memory_width(i);load=i.mnemonic.startswith(('ldr','ldur','ldp','ldnp','ldar','ldax'))or i.mnemonic=='casal'
            if BASE<=a<a+n<=BASE+SIZE:
                assert any(h<=a<a+n<=h+nb for h,nb in owners)
                if load:assert all(a+j in defined for j in range(n)),(hex(pc),hex(a))
            elif any(s['start']<=a<a+n<=s['start']+s['size_bytes']for s in WRITABLE)or not 0x100000000<=a<a+n<=0x102000000:
                if load:assert all(a+j in defined for j in range(n)),(hex(pc),hex(a))
            ensure(a,n)
        ensure(pc,4);old=origins.copy();first=pos
        if i.mnemonic=='pacibsp':
            e=next(edges);assert e=={'pc':hex(pc),'kind':'logical_pacibsp','target':hex(pc+4)};pc+=4;counts['logical_PAC_heads_checked']+=1;continue
        if i.mnemonic in ['braa','blraa','braaz','blraaz','br','blr','ret','retab','retaa']:
            names=i.op_str.split(', ');ret=i.mnemonic.startswith('ret');target=get('x30')if ret else get(names[0]);mod=0 if i.mnemonic in ['braaz','blraaz']else get(names[1])if len(names)>1 else None;call=i.mnemonic.startswith('bl')
            if not ret:
                slot=origins.get(key(names[0]));assert slot in FIXUPS;word=int.from_bytes(IMAGE.read(slot,8),'little');assert word>>63==1 and (word>>32)&65535==mod and (word>>48)&7==0;assert int.from_bytes(logical_read(slot,8),'little')==target
            if call and target in IMPORTS.values():
                m=next(apis);assert m['pc']==hex(pc);name=m['binding']['symbol']
                if name=='_malloc':
                    assert slot==0x10109ff58 and get('x0')==720;returned=cfg['allocation_return64'];active[returned]=720;owners.append((returned,720));defined.difference_update(range(returned,returned+720));counts['malloc_models_checked']+=1
                else:
                    assert name=='_free' and pc==0x1001c6100 and slot==0x10109ff30;argument=get('x0');nb=active.pop(argument);assert nb==720 and m['arguments1']==[hex(argument)] and m['invalidated_range']=={'address':hex(argument),'size_bytes':nb}
                    defined.difference_update(range(argument,argument+nb));owners[:]=[(h,n)for h,n in owners if not(argument<=h and h+n<=argument+nb)];returned=cfg['void_result64'];counts['free_models_checked']+=1
                assert m['returned_X0']==hex(returned);before={n:get(n)for n in ['sp']+['x'+str(j)for j in range(18,30)]};assert before=={n:int(v)for n,v in m['preserved_GPR_SP'].items()}
                for j in range(18):put('x'+str(j),cfg['clobber_pattern']);origins.pop('x'+str(j),None)
                put('x0',returned);put('x30',pc+4);put('nzcv',cfg['NZCV_after']);known.update(['x'+str(j)for j in range(18)]+['x30','nzcv']);origins.pop('x30',None);pc+=4;continue
            e=next(edges);assert e['pc']==hex(pc)and int(e['target'],16)==target and e['kind']==i.mnemonic
            if not ret:assert e['slot']==hex(slot)and e['modifier']==hex(mod)
            if call:put('x30',pc+4)
            known.update(key(i.reg_name(r))for r in ww);pc=target;counts['logical_edges_checked']+=1;continue
        u.emu_start(pc,0,count=1);pc=get('pc');counts['A64_instructions_checked']+=1
        for a,n,h in pending:assert bytes(u.mem_read(a,n)).hex()==h
        pending.clear();ee=events[first:pos]
        for r in ww:origins.pop(key(i.reg_name(r)),None)
        for e in ee:
            if e['kind']=='write':
                a=int(e['address'],16);n=e['size_bytes']
                for at in list(spills):
                    if a<at+8 and at<a+n:spills.pop(at)
        if i.mnemonic in ['ldr','ldur']and i.reg_name(i.operands[0].reg).startswith('x'):
            er=[e for e in ee if e['kind']=='read'and e['size_bytes']==8]
            if len(er)==1:
                a=int(er[0]['address'],16);origin=a if a in FIXUPS else spills.get(a)
                if origin is not None:origins[key(i.reg_name(i.operands[0].reg))]=origin
        elif i.mnemonic=='mov'and len(i.operands)==2 and i.operands[1].type==ARM64_OP_REG:
            origin=old.get(key(i.reg_name(i.operands[1].reg)))
            if origin is not None:origins[key(i.reg_name(i.operands[0].reg))]=origin
        elif i.mnemonic in ['str','stur']and i.reg_name(i.operands[0].reg).startswith('x'):
            ew=[e for e in ee if e['kind']=='write'and e['size_bytes']==8];origin=old.get(key(i.reg_name(i.operands[0].reg)))
            if len(ew)==1 and origin is not None:spills[int(ew[0]['address'],16)]=origin
        elif i.mnemonic in ['ldp','stp']and all(i.reg_name(o.reg).startswith('x')for o in i.operands[:2]):
            kind='read'if i.mnemonic=='ldp'else'write';er=[e for e in ee if e['kind']==kind];assert sum(e['size_bytes']for e in er)==16;a=int(er[0]['address'],16)
            for j,o in enumerate(i.operands[:2]):
                at=a+8*j;name=key(i.reg_name(o.reg));origin=(at if at in FIXUPS else spills.get(at))if kind=='read'else old.get(name)
                if origin is not None:
                    if kind=='read':origins[name]=origin
                    else:spills[at]=origin
        known.update(key(i.reg_name(r))for r in ww)
    if snapshot is not None and int(snapshot['pc'],16)==pc:check_snapshot(snapshot);snapshot=next(snaps,None)
    assert snapshot is None
    assert pos==len(events)and next(edges,None)is None and next(apis,None)is None and pc==int(t['boundary']['pc'],16)
    assert get('sp')==int(t['boundary']['SP'],16)
    for j,v in enumerate(t['boundary']['registers31']):
        if 'x'+str(j)in known:assert get('x'+str(j))==int(v,16)
    for label,n in [('allocation',720),('record',32)]:
        a=int(t['allocation_owner']if label=='allocation'else t['record_address'],16);mask=t[label+'_defined_mask'+str(n)];b=bytes.fromhex(t[label+'_hex'+str(n)]);assert mask==[a+j in defined for j in range(n)]
        actual=bytes(u.mem_read(a,n));assert all(x==y for x,y,defined_bit in zip(actual,b,mask)if defined_bit)
    counts['fresh_cases_checked']+=1;return dict(counts)
