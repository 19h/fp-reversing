#!/usr/bin/env python3
"""Private original-cache wrapper fixtures; every SVC is intercepted, never run.

Selected cache code pages are read-only/executable in Unicorn. Runtime globals,
TLS, callbacks, syscall/trap returns and message contents are explicit seeds.
Unknown data/code/callbacks stop. PAC is bypassed only for the listed wrapper
instructions. No host loader, Mach/BSD syscall, target logging or IPC runs.
"""
import bisect
import hashlib
import json
import struct
from pathlib import Path
import unicorn as uc
from unicorn import arm64_const as ar
from bootpolicy_cache_reader import Cache,Dylib,CS,ROOT

STACK=0x6000000000
BUFFER=0x6100000000
TLS=0x6200000000
VOUCHER=0x6300000000
HALT=0x6400000000
CALLBACK=HALT+0x100
LOGGER=HALT+0x200
ERRNO=TLS+0x100
ENTRY_NAMES=['_mmap','_munmap','_open','_close','_fstat','_mach_msg','_mach_msg_overwrite',
             '_mach_msg2_internal','_mach_msg2_trap','_mach_msg_trap','_mach_msg_overwrite_trap']
EXTRA_FUNCTIONS=[0x180548a08,0x18054b724,0x180548678,0x1805485e0,0x1805495cc]


class Probe:
    def __init__(self,cache,library,entry,args,trap_results=None,bsd_results=None,
                 voucher_version=0,callback_result=None,mode_stack=0,logger=False):
        self.cache=cache;self.lib=library;self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM)
        self.entry=library.exports[entry]['address'];self.args=args
        self.entry_symbol=entry
        self.input_seeds={'trap_results':trap_results,'bsd_results':bsd_results,
            'voucher_version':voucher_version,'callback_result':callback_result,'mode_stack':mode_stack,
            'syscall_logger_nonnull':logger,'stack_initialization':'explicit private zero-filled storage'}
        self.trap_results=None if trap_results is None else list(trap_results)
        self.bsd_results=None if bsd_results is None else list(bsd_results)
        self.callback_result=callback_result;self.events=[];self.steps=0;self.stop_reason=None;self.pac=[]
        self.allowed=[];pages=set()
        starts={library.exports[n]['address'] for n in ENTRY_NAMES}|set(EXTRA_FUNCTIONS)
        for a in starts:
            ix=bisect.bisect_right(library.functions,a)-1
            start,end=library.functions[ix:ix+2]
            assert start==a
            self.allowed.append((start,end))
            pages.update(range(start&~4095,(end+4095)&~4095,4096))
        self.code_pages=sorted(pages);code_hash=hashlib.sha256()
        for a in self.code_pages:
            raw=cache.read(a,4096);code_hash.update(struct.pack('<Q',a));code_hash.update(raw)
            self.u.mem_map(a,4096,uc.UC_PROT_READ|uc.UC_PROT_EXEC)
            self.u.mem_write(a,raw)
        self.code_pages_hash=code_hash.hexdigest()
        for a,n in [(STACK,0x10000),(BUFFER,0x1000),(TLS,0x1000),(VOUCHER,0x1000),(HALT,0x1000),
                    (0x1ed83e000,0x1000),(0x1eb065000,0x1000)]:self.u.mem_map(a,n)
        self.u.mem_write(VOUCHER,struct.pack('<Q',voucher_version)+bytes(32)+struct.pack('<Q',CALLBACK if callback_result is not None else 0))
        self.u.mem_write(0x1ed83e8d8,struct.pack('<Q',VOUCHER))
        self.u.mem_write(0x1eb065e48,struct.pack('<Q',LOGGER if logger else 0))
        self.u.mem_write(TLS+8,struct.pack('<Q',ERRNO))
        self.u.reg_write(ar.UC_ARM64_REG_TPIDRRO_EL0,TLS)
        self.seeded_data=[(0x1ed83e8d8,8),(0x1ed83e960,4),(0x1eb065e48,8),(0x1eb065e58,8),
                          (VOUCHER,48),(TLS,0x1000)]
        self.u.reg_write(ar.UC_ARM64_REG_SP,STACK+0xf000)
        self.u.mem_write(STACK+0xf000,struct.pack('<I',mode_stack))
        for i,value in enumerate(args):self.setreg(i,value)
        self.setreg(30,HALT)
        self.u.hook_add(uc.UC_HOOK_CODE,self.code)
        self.u.hook_add(uc.UC_HOOK_MEM_READ,self.read)
        self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.write)

    def reg(self,n):return self.u.reg_read(getattr(ar,f'UC_ARM64_REG_X{n}'))
    def setreg(self,n,value):self.u.reg_write(getattr(ar,f'UC_ARM64_REG_X{n}'),value&0xffffffffffffffff)
    def stop(self,reason,**data):
        self.stop_reason=reason;self.events.append({'kind':'stop','reason':reason,**data});self.u.emu_stop()
    def code(self,u,address,size,user):
        self.steps+=1
        if address==HALT:self.stop('returned',x0=hex(self.reg(0)),x1=hex(self.reg(1)));return
        if address==CALLBACK:
            self.events.append({'kind':'private_voucher_callback','return_pc':hex(self.reg(30)),
                'args':[hex(self.reg(i)) for i in range(8)],'result':self.callback_result,
                'writes_synthesized':False,'host_callback_executed':False})
            self.setreg(0,self.callback_result);u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30));return
        if not any(a<=address<end for a,end in self.allowed):
            self.stop('unmodeled_code',pc=hex(address));return
        ins=next(CS.disasm(bytes(u.mem_read(address,4)),address));m=ins.mnemonic
        if m=='svc':
            selector=self.reg(16);signed=selector if selector<1<<63 else selector-(1<<64)
            event={'kind':'intercepted_svc','pc':hex(address),'x16_bits':hex(selector),'x16_signed':signed,
                   'args':[hex(self.reg(i)) for i in range(8)],'host_svc_executed':False}
            if signed==-47 and self.reg(1)&(1<<32):
                assert STACK<=self.reg(0)<STACK+0x10000-48
                event['private_vector_bytes_hex']=bytes(u.mem_read(self.reg(0),48)).hex()
            self.events.append(event)
            results=self.trap_results if signed<0 else self.bsd_results
            if results is None:self.stop('svc_boundary');return
            if not results:self.stop('unmodeled_next_svc_result');return
            value=results.pop(0)
            if signed<0:self.setreg(0,value);event['private_result_u32']=hex(value&0xffffffff)
            else:
                result,carry=value;self.setreg(0,result)
                u.reg_write(ar.UC_ARM64_REG_NZCV,(1<<29) if carry else 0)
                event['private_result']={'x0':hex(result&0xffffffffffffffff),'carry':carry}
            u.reg_write(ar.UC_ARM64_REG_PC,address+4);return
        if m in ['pacibsp','autibsp','paciasp','autiasp']:
            self.pac.append({'pc':hex(address),'instruction':m});u.reg_write(ar.UC_ARM64_REG_PC,address+4)
        elif m in ['retab','retaa']:
            self.pac.append({'pc':hex(address),'instruction':m});u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
        elif m in ['blraaz','blraa']:
            target_reg=int(ins.op_str.split(',')[0].strip()[1:]);target=self.reg(target_reg)
            self.pac.append({'pc':hex(address),'instruction':m,'target':hex(target)})
            if target!=CALLBACK:
                self.stop('unmodeled_authenticated_callback',pc=hex(address),target=hex(target),
                          args=[hex(self.reg(i)) for i in range(8)]);return
            self.setreg(30,address+4);u.reg_write(ar.UC_ARM64_REG_PC,target)
        elif m.startswith(('pac','aut','xpac')):self.stop('unmodeled_pac',pc=hex(address),instruction=m)
        elif m in ['hvc','smc']:self.stop('unmodeled_system_instruction',pc=hex(address),instruction=m)
    def read(self,u,access,address,size,value,user):
        if 0x1ed83e000<=address<0x1ed83f000 or 0x1eb065000<=address<0x1eb066000:
            if not any(a<=address and address+size<=a+n for a,n in self.seeded_data):
                self.stop('unknown_runtime_data',pc=hex(u.reg_read(ar.UC_ARM64_REG_PC)),address=hex(address),size_bytes=size)
    def write(self,u,access,address,size,value,user):
        if address in [0x1ed83efa8,ERRNO]:
            self.events.append({'kind':'errno_write','pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),
                'address':hex(address),'size_bytes':size,'value':hex(value&((1<<(size*8))-1))})
    def run(self,header=None):
        if header is not None:self.u.mem_write(BUFFER,header)
        try:self.u.emu_start(self.entry,0,count=20000)
        except uc.UcError as e:self.stop_reason='unicorn_error';self.events.append({'kind':'engine_error','message':str(e),'pc':hex(self.u.reg_read(ar.UC_ARM64_REG_PC))})
        if self.stop_reason is None:self.stop_reason='instruction_budget'
        return {'scope':__doc__,'entry':hex(self.entry),'entry_symbol':self.entry_symbol,
                'initial_args':[hex(x) for x in self.args],'input_seeds':self.input_seeds,
                'header_seed_hex':None if header is None else header.hex(),
                'source_code_pages':[hex(a) for a in self.code_pages],
                'source_code_pages_sha256':self.code_pages_hash,
                'steps':self.steps,'stop_reason':self.stop_reason,'events':self.events,'pac_bypasses':self.pac,
                'global_errno_bits':hex(struct.unpack('<I',self.u.mem_read(0x1ed83efa8,4))[0]),
                'tls_errno_bits':hex(struct.unpack('<I',self.u.mem_read(ERRNO,4))[0]),
                'native_target_executed':False,'target_host_operations_executed':False}


def main():
    cache=Cache();assert cache.uuid=='2bd06591-e751-3e84-963f-b08dab6af23a'
    lib=Dylib(cache,'/usr/lib/system/libsystem_kernel.dylib')
    rows=[]
    def case(label,entry,args,**kwargs):
        header=kwargs.pop('header',None);p=Probe(cache,lib,entry,args,**kwargs);r=p.run(header)
        r['label']=label;rows.append(r)
        print(json.dumps({'label':label,'stop':r['stop_reason'],'svc':sum(e['kind']=='intercepted_svc' for e in r['events']),
                          'last_event':r['events'][-1]}),flush=True)
    for length in [0,1,64,0xffffffffffffffff]:case(f'mmap_{length}','_mmap',[0,length,1,2,7,0])
    case('mmap_no_map_kind','_mmap',[0,64,1,0,7,0])
    case('mmap_success_return','_mmap',[0,64,1,2,7,0],bsd_results=[(0x6500000000,False)])
    case('mmap_error_return','_mmap',[0,64,1,2,7,0],bsd_results=[(12,True)])
    case('mmap_logger_boundary','_mmap',[0,64,1,2,7,0],bsd_results=[(0x6500000000,False)],logger=True)
    case('munmap_boundary','_munmap',[0x6500000000,64])
    case('munmap_logger_boundary','_munmap',[0x6500000000,64],logger=True)
    case('fstat_boundary','_fstat',[7,BUFFER])
    case('fstat_error_return','_fstat',[7,BUFFER],bsd_results=[(9,True)])
    case('close_boundary','_close',[7])
    case('close_error_runtime_unknown','_close',[7],bsd_results=[(9,True)])
    case('open_readonly','_open',[BUFFER,0,0xdeadbeef])
    case('open_create_mode_stack','_open',[BUFFER,0x200,0xdeadbeef],mode_stack=0x123481a4)
    for bits,option,label in [(18,0x11,'reply_simple_once'),(17,1,'reply_simple_send'),(0x80000012,0x11,'reply_complex_once')]:
        header=struct.pack('<6I',bits,80,0x123,0x456,0x789,602)+struct.pack('<I',3)+bytes(52)
        case(label,'_mach_msg',[BUFFER,option,80,0,0,0,0],header=header,trap_results=[0])
    header=struct.pack('<6I',18,80,0x123,0x456,0x789,602)+bytes(56)
    case('reply_voucher_v3_null','_mach_msg',[BUFFER,0x11,80,0,0,0,0],header=header,voucher_version=3,trap_results=[0])
    case('reply_voucher_callback_zero','_mach_msg',[BUFFER,0x11,80,0,0,0,0],header=header,voucher_version=3,callback_result=0,trap_results=[0])
    case('reply_voucher_callback_nonzero','_mach_msg',[BUFFER,0x11,80,0,0,0,0],header=header,voucher_version=3,callback_result=5,trap_results=[0])
    complex_header=struct.pack('<6I',0x80000012,80,0x123,0x456,0x789,602)+struct.pack('<I',3)+bytes(52)
    case('reply_complex_voucher_nonzero','_mach_msg',[BUFFER,0x11,80,0,0,0,0],header=complex_header,voucher_version=3,callback_result=5,trap_results=[0])
    case('send_receive_packed','_mach_msg',[BUFFER,3,80,256,0xabc,19,0xdef],header=complex_header,trap_results=[0])
    case('receive_only_packed','_mach_msg',[BUFFER,2,80,256,0xabc,19,0xdef],header=complex_header,trap_results=[0])
    packed=[BUFFER,0x800000003,0x5000000012,0x45600000123,0x25a00000789,0xabc00000003,0xdef00000100,19]
    for label,options,statuses in [('send_retry',0x800000001,[0x10000007,0]),
        ('send_interrupt',0x800000041,[0x10000007]),('receive_retry',0x800000003,[0x10004005,0]),
        ('receive_interrupt',0x800000403,[0x10004005]),('both_retries',0x800000003,[0x10000007,0x10004005,0]),
        ('receive_sync_wait_both',0x800004003,[0x10004005,0]),
        ('receive_sync_wait_only',0x800004002,[0x10004005,0])]:
        args=list(packed);args[1]=options;case(label,'_mach_msg2_internal',args,trap_results=statuses)
    out={'scope':__doc__,'cache_uuid':cache.uuid,'library_uuid':lib.uuid,
         'generator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
         'cache_reader_sha256':hashlib.sha256((ROOT/'bootpolicy_cache_reader.py').read_bytes()).hexdigest(),
         'engine':'unicorn '+uc.__version__,'profiles':rows}
    (ROOT/'user_trap_profiles.json').write_text(json.dumps(out,indent=2)+'\n')


if __name__=='__main__':main()
