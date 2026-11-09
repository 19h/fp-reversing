#!/usr/bin/env python3
"""Capture original private-record, cursor-adapter and dispatch contracts.
Input-fragment execution is O(instructions+effects); captures/banks require
O(source bytes+256*bank rules) time/output. Native caller continuity is unknown.
"""
import json,hashlib
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE,UC_MEM_READ
from daemon_receive_tools import ROOT,SOURCE,IMAGE,TABLE,POOL,MASK64,selected,bank,qword
from recover_daemon_descriptor_producers import verify_used_fixups
from capture_daemon_record720 import sha
from recover_daemon_context_lock import ida_output
from validate_daemon_record720 import regid
from daemon_digest_output_access import register_access,key

SPECS=[('input_pack',0x1009d0198,0x1009d0308),('input_fields',0x10095af14,0x10095affc),('caller_record',0x100b0b848,0x100b0b9a4),('cursor_adapter',0x100536e98,0x100537128),('dispatcher',0x100523894,0x100523d6c),('handler_entry',0x10062a624,0x10062a6f0),('status_return',0x10061aa98,0x10061aaf8),('cleanup_record',0x100be0bb0,0x100be0c58),('nonzero_frontier',0x10044dd40,0x10044dd80),('zero_frontier',0x100435b9c,0x100435bdc)]

def source_inputs(F,header):
    """Execute the original 8+4-byte field producers as explicit components."""
    assert len(header)==12;H=0x68000c0000;u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);pages=set();defined=set();known=set();steps=[];events=[];current=[0];cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
    def put(a,b):
        for p in range(a&~4095,(a+len(b)+4095)&~4095,4096):
            if p not in pages:u.mem_map(p,4096);pages.add(p)
        u.mem_write(a,b);defined.update(range(a,a+len(b)))
    def seed(n,v):u.reg_write(regid(n),v&MASK64);known.add(key(n))
    for pg in range(F&~4095,(F+0x10000+4095)&~4095,4096):u.mem_map(pg,4096);pages.add(pg)
    put(H,header);put(F+0x273c,(0x471c).to_bytes(4,'little'))
    for name,a,z in SPECS[:2]:put(a,IMAGE.read(a,z-a))
    for n,v in [('sp',F),('x2',H),('x20',0x45f86ad91b5c5736),('w13',0x98),('x6',0xe3b88695c0d52dbc)]:seed(n,v)
    def hook(_,access,a,n,value,__):
        if access==UC_MEM_READ:
            assert all(a+j in defined for j in range(n));events.append({'pc':hex(current[0]),'kind':'read','address':hex(a),'size_bytes':n,'hex':bytes(u.mem_read(a,n)).hex()})
        else:
            assert F<=a<a+n<=F+0x10000;defined.update(range(a,a+n));events.append({'pc':hex(current[0]),'kind':'write','address':hex(a),'size_bytes':n,'hex':(value&((1<<(8*n))-1)).to_bytes(n,'little').hex()})
    u.hook_add(UC_HOOK_MEM_READ|UC_HOOK_MEM_WRITE,hook)
    for a,z in [(0x1009d0198,0x1009d02ac),(0x1009d02fc,0x1009d0308),(0x10095af18,0x10095af30),(0x10095af50,0x10095afc0)]:
        for pc in range(a,z,4):
            current[0]=pc;i=next(cs.disasm(IMAGE.read(pc,4),pc));rr,ww=register_access(i)
            assert all(key(i.reg_name(r))in known or i.reg_name(r)in ['wzr','xzr']for r in rr),(hex(pc),i.mnemonic,i.op_str)
            u.emu_start(pc,pc+4,count=1);known.update(key(i.reg_name(r))for r in ww);steps.append({'pc':hex(pc),'bytes_hex':bytes(i.bytes).hex()})
    U=int.from_bytes(header[:8],'big')^0x9898989898989898;D=int.from_bytes(header[8:],'big')^0x98989898
    E=int.from_bytes(u.mem_read(F+0x2a70,8),'little');actualU=int.from_bytes(u.mem_read(F+0x2dc0,8),'little');V=int.from_bytes(u.mem_read(F+0x2fec,4),'little')
    assert E==U^0xe3b88695c0d52dbc and actualU==U and V==D^0x8b3dc651
    return {'header12_hex':header.hex(),'U64':hex(U),'D32':hex(D),'E64':hex(E),'V32':hex(V),'source_visits':len(steps),'steps':steps,'events':events,'native_caller_continuity':False}

def capture():
    spans=[{'label':n,'start':hex(a),'end':hex(z),'bytes_hex':IMAGE.read(a,z-a).hex(),'sha256':hashlib.sha256(IMAGE.read(a,z-a)).hexdigest()}for n,a,z in SPECS]
    recipes=[('malloc720',0x100fc4230,0x101031fa0,0xe4,0xcbb0,TABLE,0),('caller_adapter',0x100fc4230,0x101031fa0,0xf3,0xccb0,TABLE,0),('caller_cursor',0x100fc4130,0x101031ea0,0xbb,0x392,POOL,0xffffffffd2331cdd),('adapter_state1',0x100e99700,0x100f4e190,0x81,0x6cd,POOL,0xffffffff87875145),('adapter_state2',0x100e99a00,0x100f4e390,0x54,-0x22,POOL,0xffffffffec9e1772),('adapter_cursor',0x100fc4230,0x101031fa0,0xf3,0x40a,POOL,0xffffffffd2331cdd),('adapter_dispatch_base',0x100e99a00,0x100f4e390,0xd7,0x88e,POOL,0xffffffffd0c4d1ee),('entry_dispatch_base',0x100e99a00,0x100f4e390,0x54,0x864,POOL,0xffffffffd0c4d1ee),('entry_state1',0x101031da0,0x100e99900,0x9a,0xfa4,POOL,0xffffffff9a4528c9),('entry_state2',0x101031da0,0x100e99900,0x9a,-0x51,POOL,0xffffffffec9e1772)]
    rules=[{'label':n,**selected(l,r,k,a,t,b)}for n,l,r,k,a,t,b in recipes]
    extra={'label':'adapter_inner_index','left':'0x101031da0','right':'0x100e99900','key':'0x9a','constant':hex(bank(0x101031da0,0x100e99900,0x9a)),'additive':'0xcb84','index':hex(0xcb84+bank(0x101031da0,0x100e99900,0x9a)),'inputs_checked':256}
    live=[];ida=json.loads((ROOT/'daemon_record720_handoff_ida.json').read_text());assert not ida.get('isError')
    for r in ida_output(ida)['results']:
        a=int(r['address'],16);b=bytes.fromhex(r['bytes']);assert len(b)==r['size_read']==r['size_requested']and IMAGE.read(a,len(b))==b;live.append({'address':hex(a),'size_bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()})
    slots={int(r['slot'],16)for r in rules}|{0x1010a0238,0x1010770c0,0x1010b1e18};roots=json.loads((ROOT/'daemon_object_initialization_context.json').read_text());retained=[r for r in roots['source_frame_fields']if int(r['offset'],16)in[0x2970,0x2978,0x2988,0x29a0]]
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'spans':spans,'exhaustive_bank_rules':rules+[extra],'fixups':verify_used_fixups(slots),'live_IDB_matches':live,'retained_saved_roots':retained,'dependencies':{n:sha(ROOT/n)for n in ['daemon_record720_handoff_ida.json','daemon_object_initialization_context.json','daemon_receive_tools.py','daemon_digest_output_access.py','validate_daemon_record720.py','recover_daemon_descriptor_producers.py']},'native_target_executed':False,'idb_mutated':False,'registry_publication_established':False,'full_goal_complete':False}

def main():
    out=capture();(ROOT/'daemon_record720_handoff_source.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'spans':len(out['spans']),'banks256':len(out['exhaustive_bank_rules']),'IDA_bytes':sum(r['size_bytes']for r in out['live_IDB_matches'])}),flush=True)
if __name__=='__main__':main()
