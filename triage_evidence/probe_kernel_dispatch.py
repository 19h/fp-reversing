#!/usr/bin/env python3
"""Bounded private fixtures of original KC dispatch/Mach2 instructions.

All kernel helpers, PAC, TPIDR_EL1 and global/task/space state are explicit
models. No native kernel, target syscall, IPC, allocation or host callback runs.
Unknown code/data/system operations stop. This is finite local-contract evidence.
"""
import hashlib
import json
from pathlib import Path
import struct
import unicorn as uc
from unicorn import arm64_const as ar
from kernel_native_reader import Kernel
from resolve_kernel_collection_interfaces import chained_rebases
from recover_kernel_dispatch import MACH,BSD,MACH_DISPATCH,BSD_DISPATCH,MACH2,SEND,RECEIVE,RETURN

ROOT=Path(__file__).resolve().parent
STACK=0x6000000000
STATE=0x6100000000
ARGS=0x6200000000
THREAD=0x6300000000
TASK=0x6400000000
SPACE=0x6500000000
RO=0x6600000000
FILTER=0x6700000000
HALT=0x6800000000
CALLBACK=HALT+0x100
PROC=TASK+0x800
VECTOR=ARGS+0x100
MESSAGE=ARGS+0x400
AUX=ARGS+0x800
UTHREAD=THREAD+0x5c0
ALLOC=0xfffffe000bcc24a4
COPYIN=0xfffffe000be76e18


class Probe:
    def __init__(self,k,rebases,label,kind,seed):
        self.k=k;self.rebases=rebases;self.label=label;self.kind=kind;self.seed=seed
        self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);self.steps=0;self.events=[];self.pac=[]
        self.stop_reason=None;self.ranges=[];pages=set()
        for a in (MACH_DISPATCH,BSD_DISPATCH,MACH2,SEND,RETURN,0xfffffe000bf08c94,0xfffffe000c2b5ae8):
            r=k.function(a);b=int(r['end'],16);self.ranges.append((a,b))
            pages.update(range(a&~4095,(b+4095)&~4095,4096))
        h=hashlib.sha256()
        for a in sorted(pages):
            raw=k.read(a,4096);h.update(struct.pack('<Q',a));h.update(raw)
            self.u.mem_map(a,4096,uc.UC_PROT_READ|uc.UC_PROT_EXEC);self.u.mem_write(a,raw)
        self.code_hash=h.hexdigest();self.code_pages=sorted(pages)
        # A branch target must be fetch-mapped before Unicorn calls its code
        # hook. These zero-filled pages contain boundary stubs, not image code;
        # every listed entry is intercepted before any instruction executes.
        stubs={0xfffffe000bd7e9c4,0xfffffe000bd41068,0xfffffe000bd7e084,
               0xfffffe000bd4401c,0xfffffe000c2bd008,0xfffffe000c2ba130,
               0xfffffe000bf8c538,0xfffffe000c5f2534,0xfffffe000c647f10,
               COPYIN,RECEIVE,ALLOC,0xfffffe000c629ba0,0xfffffe000bcef858,
               0xfffffe000bc9d880,0xfffffe000bdc1ec0}
        if seed.get('expected_handler'):stubs.add(seed['expected_handler'])
        self.stub_pages=sorted({a&~4095 for a in stubs}-pages)
        for a in self.stub_pages:self.u.mem_map(a,4096,uc.UC_PROT_READ|uc.UC_PROT_EXEC)
        for a,n in [(STACK,0x10000),(STATE,0x1000),(ARGS,0x1000),(THREAD,0x10000),
                    (TASK,0x1000),(SPACE,0x1000),(RO,0x1000),(FILTER,0x1000),(HALT,0x1000),
                    (MACH&~4095,0x1000),(BSD&~4095,0x4000),
                    (0xfffffe000cb5c000,0x1000),(0xfffffe000cacb000,0x1000),
                    (0xfffffe0007ef8000,0x1000)]:self.u.mem_map(a,n)
        # Only original dispatch tables are copied; pointer fields are decoded
        # using validated original format-8 chain membership. PAC is not executed.
        for a,n in [(MACH,128*24),(BSD,558*24)]:
            raw=bytearray(k.read(a,n))
            seg=next(s for s in k.root['segments'] if s['address']<=a<a+n<=s['address']+s['file_size'])
            off=seg['file_offset']+a-seg['address']
            for x in range(0,n,8):
                if off+x in rebases:struct.pack_into('<Q',raw,x,rebases[off+x])
            self.u.mem_write(a,bytes(raw))
        self.put(TASK+0x318,'Q',SPACE);self.put(SPACE+0x58,'Q',seed.get('space_option_policy',0))
        self.put(TASK+0x6c8,'I',seed.get('task_flags',4))
        self.put(RO+0x18,'Q',PROC);self.put(RO+0x28,'Q',TASK)
        self.put(0xfffffe000cacb000,'Q',0x123456789abcdef0)
        self.put(0xfffffe0007ef8008,'Q',CALLBACK if seed.get('filter_callback') is not None else 0)
        self.u.mem_write(FILTER,bytes(16) if seed.get('filter_deny') else bytes([255])*16)
        self.u.reg_write(ar.UC_ARM64_REG_SP,STACK+0xf000);self.setreg(30,HALT)
        self.put(STATE,'I',seed.get('flavor',21))
        self.put(STATE+0x88,'Q',seed.get('selector',0)&0xffffffffffffffff)
        original_args=seed.get('packet',[0x11110000+i for i in range(8)])
        self.u.mem_write(STATE+8,struct.pack('<8Q',*original_args))
        self.u.mem_write(ARGS,struct.pack('<8Q',*original_args))
        if 'vectors' in seed:
            self.u.mem_write(VECTOR,b''.join(struct.pack('<QQII',*v) for v in seed['vectors']))
        if kind in ('mach_dispatch','bsd_dispatch'):
            self.entry=MACH_DISPATCH if kind=='mach_dispatch' else BSD_DISPATCH
            self.setreg(0,STATE)
            if kind=='bsd_dispatch':self.setreg(1,THREAD);self.setreg(2,PROC)
        elif kind=='mach2':self.entry=MACH2;self.setreg(0,ARGS)
        elif kind=='munmap':
            self.entry=0xfffffe000c2b5ae8;self.setreg(0,PROC);self.setreg(1,ARGS)
            self.u.mem_write(ARGS,struct.pack('<QQ',seed['address'],seed['length']))
            self.put(THREAD+0x428,'Q',SPACE);self.put(SPACE+0x2c,'B',seed.get('page_shift',14))
        elif kind=='bsd_return':
            self.entry=RETURN;self.setreg(0,ARGS+0x700);self.setreg(1,STATE);self.setreg(2,UTHREAD)
            self.setreg(3,seed.get('error',0));self.put(ARGS+0x710,'I',seed['return_type'])
            self.put(UTHREAD+0x40,'Q',seed.get('rval',0x12345678deadbeef))
            self.put(STATE+0x110,'I',seed.get('saved_cpsr',0));self.put(STATE+0x108,'Q',0x77770004)
        else:raise AssertionError(kind)
        self.u.hook_add(uc.UC_HOOK_CODE,self.code)
        self.u.hook_add(uc.UC_HOOK_MEM_READ,self.read)
        self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.write)

    def put(self,a,fmt,v):self.u.mem_write(a,struct.pack('<'+fmt,v))
    def reg(self,n):return self.u.reg_read(getattr(ar,f'UC_ARM64_REG_X{n}'))
    def setreg(self,n,v):self.u.reg_write(getattr(ar,f'UC_ARM64_REG_X{n}'),v&0xffffffffffffffff)
    def getargs(self):return [hex(self.reg(i)) for i in range(8)]
    def stop(self,reason,**kw):self.stop_reason=reason;self.events.append({'kind':reason,**kw});self.u.emu_stop()
    def ret(self,value=0):self.setreg(0,value);self.u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
    def local(self,a,n):return any(x<=a and a+n<=x+s for x,s in [
        (STACK,0x10000),(STATE,0x1000),(ARGS,0x1000),(THREAD,0x10000),(TASK,0x1000),
        (SPACE,0x1000),(RO,0x1000),(FILTER,0x1000)])
    def read(self,u,access,a,n,value,user):
        if self.local(a,n):return
        if MACH<=a and a+n<=MACH+128*24:return
        if BSD<=a and a+n<=BSD+558*24:return
        if (a,n) in [(0xfffffe000cb5c400,1),(0xfffffe000cb5c400,4),
                     (0xfffffe000cb5c6b0,4),(0xfffffe000cacb000,8),(0xfffffe0007ef8008,8)]:return
        self.stop('unknown_data_read',pc=hex(u.reg_read(ar.UC_ARM64_REG_PC)),address=hex(a),size_bytes=n)
    def write(self,u,access,a,n,value,user):
        if not self.local(a,n):self.stop('unknown_data_write',address=hex(a),size_bytes=n)
    def code(self,u,a,n,user):
        self.steps+=1
        if a==HALT:self.stop('returned',x0=hex(self.reg(0)));return
        if a==CALLBACK:
            self.events.append({'kind':'private_filter_callback','args':self.getargs(),
                'result':self.seed['filter_callback']});self.ret(self.seed['filter_callback']);return
        if self.kind=='mach_dispatch' and a==self.seed.get('expected_handler'):
            assert self.local(self.reg(0),64)
            self.events.append({'kind':'selected_mach_handler','address':hex(a),
                'argument_record':bytes(u.mem_read(self.reg(0),64)).hex(),
                'private_result_u32':hex(self.seed.get('handler_result',0)&0xffffffff)})
            self.ret(self.seed.get('handler_result',0));return
        if self.kind=='bsd_dispatch' and a==self.seed.get('expected_handler'):
            self.stop('selected_bsd_handler',address=hex(a),args=self.getargs(),
                argument_record=bytes(u.mem_read(self.reg(1),64)).hex());return
        helpers={0xfffffe000bd7e9c4:TASK,0xfffffe000bd41068:self.seed.get('thread_ro_flags',0),
                 0xfffffe000bd7e084:RO,0xfffffe000bd4401c:FILTER if self.seed.get('filter_deny') else 0,
                 0xfffffe000c2bd008:0,0xfffffe000c2ba130:66,0xfffffe000bf8c538:0,
                 0xfffffe000c5f2534:self.seed.get('bsd_filter_result',0)}
        if a in helpers:
            self.events.append({'kind':'private_helper','address':hex(a),'result':hex(helpers[a])})
            self.ret(helpers[a]);return
        if a==0xfffffe000c647f10:
            assert self.local(self.reg(0),self.reg(2)) and self.local(self.reg(1),self.reg(2))
            raw=bytes(u.mem_read(self.reg(1),self.reg(2)));u.mem_write(self.reg(0),raw)
            self.events.append({'kind':'private_memcpy','size_bytes':len(raw),'bytes':raw.hex()})
            self.ret(self.reg(0));return
        if a==COPYIN:
            self.events.append({'kind':'private_copyin','args':self.getargs(),'result':self.seed.get('copyin_error',0)})
            if not self.seed.get('copyin_error'):
                assert self.local(self.reg(0),self.reg(2)) and self.local(self.reg(1),self.reg(2))
                u.mem_write(self.reg(1),bytes(u.mem_read(self.reg(0),self.reg(2))))
            self.ret(self.seed.get('copyin_error',0));return
        if a==SEND:
            self.events.append({'kind':'send_helper_entry','args':self.getargs(),
                'context_80_bytes':bytes(u.mem_read(self.reg(0),80)).hex(),
                'modeled_status':self.seed.get('send_status')})
            if self.seed.get('send_status') is not None:self.ret(self.seed['send_status']);return
        if a==RECEIVE:
            self.events.append({'kind':'receive_helper_boundary','args':self.getargs(),
                'modeled_status':self.seed.get('receive_status',0)})
            self.ret(self.seed.get('receive_status',0));return
        if a==ALLOC:self.stop('allocation_boundary',args=self.getargs());return
        if a==0xfffffe000bdc1ec0:self.stop('vm_deallocate_boundary',args=self.getargs());return
        if a==0xfffffe000c629ba0:
            self.events.append({'kind':'guard_policy_callback_boundary','args':self.getargs(),
                'private_noop_result':0,'native_effect':'unknown'});self.ret();return
        if a==0xfffffe000bcef858:self.stop('invalid_trap_exception_boundary',args=self.getargs());return
        if a==0xfffffe000bc9d880:self.stop('privileged_restart_boundary',args=self.getargs());return
        if not any(lo<=a<hi for lo,hi in self.ranges):self.stop('unknown_code',pc=hex(a),args=self.getargs());return
        ins=next(self.k.cs.disasm(bytes(u.mem_read(a,4)),a));m=ins.mnemonic
        if m=='mrs':
            if ins.op_str!='x19, tpidr_el1' and ins.op_str not in ('x10, tpidr_el1','x23, tpidr_el1'):
                self.stop('unknown_system_read',pc=hex(a),instruction=ins.op_str);return
            r=int(ins.op_str.split(',')[0][1:]);self.setreg(r,THREAD)
            self.events.append({'kind':'private_tpidr_el1','pc':hex(a),'value':hex(THREAD)})
            u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
        if m in ('pacibsp','autibsp','pacia','autda'):
            self.pac.append({'pc':hex(a),'instruction':m,'operands':ins.op_str});u.reg_write(ar.UC_ARM64_REG_PC,a+4)
        elif m=='retab':
            self.pac.append({'pc':hex(a),'instruction':m});u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
        elif m=='blraa':
            r=int(ins.op_str.split(',')[0][1:]);target=self.reg(r)
            self.pac.append({'pc':hex(a),'instruction':m,'target':hex(target)})
            self.setreg(30,a+4);u.reg_write(ar.UC_ARM64_REG_PC,target)
        elif m.startswith(('aut','pac','xpac')) or m in ('msr','svc','smc','hvc','eret','brk'):
            self.stop('unmodeled_instruction',pc=hex(a),instruction=m+' '+ins.op_str)

    def run(self):
        try:self.u.emu_start(self.entry,0,count=20000)
        except uc.UcError as e:self.stop_reason='engine_error';self.events.append({'kind':'engine_error','error':str(e),'pc':hex(self.u.reg_read(ar.UC_ARM64_REG_PC))})
        if self.stop_reason is None:self.stop_reason='instruction_budget'
        return {'label':self.label,'kind':self.kind,'entry':hex(self.entry),'seed':self.seed,
            'source_code_pages':[hex(a) for a in self.code_pages],'source_code_pages_sha256':self.code_hash,
            'private_boundary_stub_pages':[hex(a) for a in self.stub_pages],
            'stop_reason':self.stop_reason,'steps':self.steps,'events':self.events,'pac_bypasses':self.pac,
            'saved_x0':hex(struct.unpack('<Q',self.u.mem_read(STATE+8,8))[0]),
            'saved_x1':hex(struct.unpack('<Q',self.u.mem_read(STATE+16,8))[0]),
            'saved_cpsr':hex(struct.unpack('<I',self.u.mem_read(STATE+0x110,4))[0]),
            'native_target_executed':False,'target_host_operations_executed':False}


def main():
    k=Kernel();base,r,m=chained_rebases(k.data);rows=[]
    def handler(table,index,offset):
        a=table+index*24+offset;s=next(s for s in k.root['segments'] if s['address']<=a<s['address']+s['file_size'])
        return r[s['file_offset']+a-s['address']]
    def case(label,kind,**seed):
        p=Probe(k,r,label,kind,seed);row=p.run();rows.append(row)
        assert row['stop_reason'] not in ('engine_error','unknown_data_read','unknown_data_write','unknown_code','unknown_system_read','instruction_budget'),row
        print(json.dumps({'label':label,'stop':row['stop_reason'],'x0':row['saved_x0'],
            'last_event':row['events'][-1]}),flush=True)
    for i in (26,28,31,32,47,50,63,100,108):
        case(f'mach_selector_{i}','mach_dispatch',selector=-i,expected_handler=handler(MACH,i,8),handler_result=0x8000000e if i==47 else 0x1234)
    case('mach_selector_low32','mach_dispatch',selector=0x11111111ffffffd1,expected_handler=handler(MACH,47,8))
    for i in (0,127,128,129):case(f'mach_invalid_{i}','mach_dispatch',selector=-i)
    for i in (26,47):
        case(f'mach_filter_deny_{i}','mach_dispatch',selector=-i,filter_deny=True,filter_callback=5,expected_handler=handler(MACH,i,8))
    case('mach_filter_callback_allow','mach_dispatch',selector=-47,filter_deny=True,filter_callback=0,expected_handler=handler(MACH,47,8))
    case('mach_filter_no_callback','mach_dispatch',selector=-47,filter_deny=True,expected_handler=handler(MACH,47,8))
    for i in (5,6,73,197,339,398,399,557,558,65535,0x10005):
        selected=i&0xffff;selected=selected if selected<558 else 63
        case(f'bsd_selector_{i}','bsd_dispatch',selector=i,expected_handler=handler(BSD,selected,0))
    indirect=[197]+[0x22220000+i for i in range(7)]
    case('bsd_indirect_selector','bsd_dispatch',selector=0,packet=indirect,expected_handler=handler(BSD,197,0))
    case('bsd_indirect_compat_munger','bsd_dispatch',selector=0,packet=indirect,task_flags=0,expected_handler=handler(BSD,197,0))
    for rt in (0,1,2,3,4,5,6,7):case(f'bsd_return_type_{rt}','bsd_return',return_type=rt)
    case('bsd_error_carry','bsd_return',return_type=1,error=22)
    case('bsd_justreturn','bsd_return',return_type=1,error=-2,saved_cpsr=0x20000000)
    case('bsd_restart','bsd_return',return_type=1,error=-1)
    for address,length in ((0,0),(0,1),(0x10000,1),(0x10001,1),(0x10000,16384),
                           (0xffffffffffffc000,1),(0x10000,0xffffffffffffffff)):
        case(f'munmap_{address}_{length}','munmap',address=address,length=length)
    # Header pairs deliberately include high-bit port names/IDs and nonzero
    # timeout high bits, to distinguish packing from signed API interpretation.
    def packet(options=0x200000001,size=28,count=0,rcv_size=512):
        return [VECTOR if options&(1<<32) else MESSAGE,options,(size<<32)|0x80001213,0x8000002280000011,
                0x800001f680000033,(0x44<<32)|count,(0x55<<32)|rcv_size,0x11223344aabbccdd]
    for size in (0,23,24,25,27,28,40,50331580,50331584):
        case(f'mach2_scalar_size_{size}','mach2',packet=packet(size=size))
    p=packet();p[2]&=0xffffffff00000000;p[2]|=0x1213;p[5]|=1
    case('mach2_noncomplex_count','mach2',packet=p)
    for size,count in ((28,0),(28,1),(40,1),(40,2),(52,2)):
        case(f'mach2_descriptor_extent_{size}_{count}','mach2',packet=packet(size=size,count=count))
    for cls in (0,2,4,6,8,16):
        case(f'mach2_class_{cls}','mach2',packet=packet(options=(cls<<32)|1),send_status=0)
    case('mach2_user_policy_bits_removed','mach2',
        packet=packet(options=0xffffffe200000441),send_status=0)
    case('mach2_policy_from_task_and_space','mach2',
        packet=packet(options=0x200010441),thread_ro_flags=0x4000,space_option_policy=3,send_status=0)
    for cls in (2,4,8,16):
        p=packet(options=((cls|1)<<32)|1,size=1,rcv_size=0)
        case(f'mach2_vector_class_{cls}','mach2',packet=p,vectors=[(MESSAGE,0,28,512)],send_status=0)
    for count in (0,1,2,3):
        p=packet(options=0x500000001,size=count,rcv_size=0)
        case(f'mach2_vector_count_{count}','mach2',packet=p,vectors=[(MESSAGE,0,28,512),(AUX,0,8,128)],send_status=0)
    for aux in (0,5,7,8,1024,1025):
        p=packet(options=0x500000001,size=2,rcv_size=0)
        case(f'mach2_aux_size_{aux}','mach2',packet=p,vectors=[(MESSAGE,0,28,512),(AUX,0,aux,128)],send_status=0)
    p=packet(options=0x500000003,size=2,rcv_size=2)
    case('mach2_copyin_fault','mach2',packet=p,vectors=[(MESSAGE,0,28,512),(AUX,0,8,128)],copyin_error=14)
    case('mach2_send_fail_skips_receive','mach2',packet=packet(options=0x200000003),send_status=0x10000003)
    case('mach2_send_success_then_receive','mach2',packet=packet(options=0x200004003),send_status=0)
    case('mach2_receive_only','mach2',packet=packet(options=2))
    for aux_rcv,aux_data,aux_alt in ((7,AUX,0),(8,AUX,0),(8,0,0),(8,0,AUX)):
        p=packet(options=0x500000002,size=0,rcv_size=2)
        case(f'mach2_receive_aux_{aux_rcv}_{bool(aux_data)}_{bool(aux_alt)}','mach2',packet=p,
            vectors=[(MESSAGE,MESSAGE+0x100,28,512),(aux_data,aux_alt,8,aux_rcv)])
    p=packet(options=0x500000003,size=1,rcv_size=2)
    case('mach2_send_then_invalid_receive_aux','mach2',packet=p,send_status=0,
        vectors=[(MESSAGE,0,28,512),(AUX,0,8,7)])
    out={'scope':__doc__,'unicorn_version':uc.__version__,'source_sha256':k.sha256,
        'generator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'reader_sha256':hashlib.sha256((ROOT/'kernel_native_reader.py').read_bytes()).hexdigest(),
        'fixture_storage':'explicit private zero-filled memory, original decoded table pointers; no actual port objects',
        'instruction_limit_per_profile':20000,'profiles':rows}
    (ROOT/'kernel_dispatch_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'profiles':len(rows),'source_sha256':k.sha256}))


if __name__=='__main__':main()
