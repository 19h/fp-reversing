#!/usr/bin/env python3
"""Original installed-cache checked-copy wrapper in private Unicorn memory.

Only strlen/memmove are bounded private models. The original strcpy_chk and
stpcpy wrappers and binding stubs execute privately; PAC is bypassed. Overflow
failure entry is recorded without executing its termination routine. This is
not attestation that the analyzed daemon loaded this library.
"""
import hashlib
import json
from pathlib import Path
import struct
import unicorn as uc
from unicorn import arm64_const as ar
from bootpolicy_cache_reader import Cache,Dylib,CS,ROOT

SOURCE=0x5000100000;DEST=0x5000200000;STACK=0x70000000;HALT=0x6001000000


def run(c,d,length,capacity):
    u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX)
    entry=d.exports['___strcpy_chk']['address'];functions=[d.function(entry),d.function(0x1805b31b4)]
    stubs=[0x18806ce90,0x18806ce70];slots=[0x1e2105240,0x1e2105208]
    pointers=[c.pointer(a) for a in slots];models={int(pointers[0]['target'],16):'strlen',int(pointers[1]['target'],16):'memmove'}
    regions=set()
    for a in [entry,0x1805b31b4,*stubs,*slots,*models,0x1eb074840,0x180620c30]:
        page=a&~4095
        if page not in regions:u.mem_map(page,4096);u.mem_write(page,c.read(page,4096));regions.add(page)
    for p in pointers:u.mem_write(int(p['address'],16),struct.pack('<Q',int(p['target'],16)))
    u.mem_write(0x1eb074840,struct.pack('<I',0))
    for a in [SOURCE,DEST,STACK,HALT]:u.mem_map(a,0x4000)
    payload=bytes([0x43])*length+b'\0';u.mem_write(SOURCE,payload);u.mem_write(DEST,bytes([0xa5])*8192)
    for page in regions:u.mem_protect(page,4096,uc.UC_PROT_READ|uc.UC_PROT_EXEC)
    records=[];visited=set();stop=None
    def reg(n):return u.reg_read(getattr(ar,'UC_ARM64_REG_X'+str(n)))
    def hook(u,pc,size,user):
        nonlocal stop
        if pc==HALT:stop='returned';u.emu_stop();return
        if pc==0x180620c30:stop='original_overflow_failure_entry';records.append({'kind':stop,'pc':hex(pc)});u.emu_stop();return
        if pc in models:
            args=[reg(i) for i in range(4)];name=models[pc];e={'kind':'private_model','name':name,'pc':hex(pc),'return_pc':hex(reg(30)),'args':[hex(v) for v in args]}
            if name=='strlen':
                assert args[0]==SOURCE;result=length
            else:
                assert args[:3]==[DEST,SOURCE,length+1];u.mem_write(DEST,payload);result=DEST
                e['crosses_claimed_destination_extent']=length+1>capacity
            e['result']=hex(result);records.append(e);u.reg_write(ar.UC_ARM64_REG_X0,result);u.reg_write(ar.UC_ARM64_REG_PC,reg(30));return
        allowed=any(int(f['start'],16)<=pc<int(f['end'],16) for f in functions) or any(a<=pc<a+16 for a in stubs)
        assert allowed,hex(pc);visited.add(pc)
        ins=next(CS.disasm(bytes(u.mem_read(pc,4)),pc));m=ins.mnemonic
        if m in ('pacibsp','autibsp'):u.reg_write(ar.UC_ARM64_REG_PC,pc+4)
        elif m=='retab':u.reg_write(ar.UC_ARM64_REG_PC,reg(30))
        elif m=='braa':u.reg_write(ar.UC_ARM64_REG_PC,reg(16))
        elif m in ('svc','hvc','smc'):raise AssertionError('system instruction')
    u.hook_add(uc.UC_HOOK_CODE,hook);u.reg_write(ar.UC_ARM64_REG_SP,STACK+0x3000)
    for n,v in enumerate([DEST,SOURCE,capacity]):u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(n)),v)
    u.reg_write(ar.UC_ARM64_REG_LR,HALT);u.emu_start(entry,0,count=1000)
    assert stop
    for a in visited:assert bytes(u.mem_read(a,4))==c.read(a,4)
    got=bytes(u.mem_read(DEST,8192));assert got[:length+1]==payload and got[length+1:]==bytes([0xa5])*(8191-length)
    assert stop==('returned' if length+1<=capacity else 'original_overflow_failure_entry')
    return {'length_excluding_nul_bytes':length,'claimed_capacity_bytes':capacity,'stop':stop,
        'copied_bytes_before_return_or_failure':length+1,'copied_beyond_claimed_extent_bytes':max(0,length+1-capacity),
        'return_value':hex(reg(0)),'calls':records,'visited_instruction_addresses':[hex(a) for a in sorted(visited)],
        'original_instruction_bytes_verified':len(visited),'destination_logical_boundary_prefix':got[max(0,capacity-8):capacity+16].hex(),
        'source_sha256':hashlib.sha256(payload).hexdigest(),'destination_sha256':hashlib.sha256(got).hexdigest(),
        'monitor_flag_seed':0,'native_target_executed':False,'target_host_operations_executed':False}


def main():
    c=Cache();assert c.uuid=='2bd06591-e751-3e84-963f-b08dab6af23a'
    d=Dylib(c,'/usr/lib/system/libsystem_c.dylib');assert d.uuid=='4bf47ebb-4cd0-3f4a-995a-717b8550cb12'
    ranges=[d.function(a) for a in [0x1805b3148,0x1805b31b4]]
    cases=[run(c,d,n,1024) for n in [0,1,56,1023,1024,1025,4095]]
    (ROOT/'checked_path_copy_profiles.json').write_text(json.dumps({'scope':__doc__,'cache_uuid':c.uuid,'library_path':d.path,'library_uuid':d.uuid,
        'generator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'original_ranges':ranges,
        'original_pointer_chains':[c.pointer(a) for a in [0x1e2105240,0x1e2105208]],
        'stpcpy_exact_symbols':d.symbols_at(0x1805b31b4),'failure_exact_symbols':d.symbols_at(0x180620c30),
        'cases':cases,'runtime_daemon_library_pairing_verified':False},indent=2)+'\n')
    print(json.dumps({'private_cases':len(cases),'copied_then_failure_lengths':[r['length_excluding_nul_bytes'] for r in cases if r['stop']!='returned']}))


if __name__=='__main__':main()
