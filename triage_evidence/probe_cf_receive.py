#!/usr/bin/env python3
"""Private original-cache CF receive/callback/registration fixtures.

Mach receive, vouchers, locks, CF runtime objects, allocators and callbacks are
explicit models. No native target or host IPC/loader/callback executes. PAC is
bypassed, original code pages are RX, and unknown code/data/system accesses stop.
"""
import hashlib
import json
from pathlib import Path
import struct
import unicorn as uc
from unicorn import arm64_const as ar
from bootpolicy_cache_reader import Cache,Dylib,CS,ROOT
from recover_cf_receive import CF_PATH,CF_UUID,SERVICE,DO_SOURCE,SOURCE_CALL,PERFORM,CREATE_SOURCE,WITH_PORT,REALLOC,RUN

STACK=0x6000000000;BUFFER=0x6100000000;VARS=0x6200000000;PORT=0x6300000000
RLSOURCE=0x6400000000;BOOST=0x6500000000;INFO=0x6600000000;HALT=0x6700000000
CONTEXT=0x6800000000;EXISTING=0x6900000000;HEAP=0x7000000000
CALLBACK=0x100425f78;STACK_PROBE=HALT+0x100;RETAIN_INFO=HALT+0x200;RELEASE_INFO=HALT+0x300
OTHER_CALLBACK=HALT+0x400
CF_RETAIN=0x1846db030;CF_RELEASE=0x1846e1278;CF_VALID=0x18472cff0


class Probe:
    def __init__(self,c,lib,label,kind,seed):
        self.c=c;self.lib=lib;self.label=label;self.kind=kind;self.seed=seed;self.steps=0
        self.reason=None;self.events=[];self.pac=[];self.traps=list(seed.get('receive_results',[]))
        self.realloc_count=0;self.boost_refs=1 if seed.get('new_boost') else 0;self.phase=0
        self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);self.u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX)
        starts=[SERVICE,DO_SOURCE,SOURCE_CALL,PERFORM,CREATE_SOURCE,WITH_PORT,0x18472cfe8,RUN]
        self.allowed=[];pages=set()
        for a in starts:
            r=lib.function(a);end=int(r['end'],16);self.allowed.append((a,end))
            pages.update(range(a&~4095,(end+4095)&~4095,4096))
        h=hashlib.sha256()
        for a in sorted(pages):
            raw=c.read(a,4096);h.update(struct.pack('<Q',a));h.update(raw)
            self.u.mem_map(a,4096,uc.UC_PROT_READ|uc.UC_PROT_EXEC);self.u.mem_write(a,raw)
        self.code_hash=h.hexdigest();self.code_pages=sorted(pages)
        stubs={0x188076b60,0x188081380,0x188081360,0x188078e40,0x18806ead0,
            REALLOC,0x18806c3d0,0x1848d4550,0x1847078bc,0x184833e50,
            0x18806ebf0,0x18806c600,0x1847841ec,CF_RETAIN,CF_RELEASE,
            0x1846ddde4,0x1880773e0,0x1880773c0,0x188076ab0,0x184832a70,
            0x184833380,0x184833694,CF_VALID,0x1847791b4,0x18472d31c,
            0x188076bc0,0x18476f510,0x1880770a0,0x1846f5978,0x1846f7424,
            0x1846da4dc,0x1846f3b4c,0x1846f5c74,0x184751868,0x188076640}
        self.stub_pages=sorted(({a&~4095 for a in stubs}|{CALLBACK&~4095})-pages)
        for a in self.stub_pages:self.u.mem_map(a,4096,uc.UC_PROT_READ|uc.UC_PROT_EXEC)
        self.local_ranges=[(STACK,0x20000),(BUFFER,0x10000),(VARS,0x4000),(PORT,4096),
            (RLSOURCE,4096),(BOOST,4096),(INFO,4096),(HALT,4096),(CONTEXT,4096),
            (EXISTING,4096),(HEAP,0x80000)]
        for a,n in self.local_ranges:self.u.mem_map(a,n)
        self.globals=[(0x1ed891742,1),(0x1e01c88a8,8),(0x1e0261ea0,8),
            (0x1e21210e0,8),(0x1e01c8b30,8),(0x1ed890e90,8),
            (0x1ed890e08,8),(0x1ed890e10,8),(0x1e01c8738,8)]
        for a in {a&~4095 for a,n in self.globals}:self.u.mem_map(a,4096)
        self.put(0x1ed891742,'B',2);self.put(0x1e01c88a8,'Q',VARS+0x3000)
        self.put(VARS+0x3000,'Q',0x123456789abcdef0);self.put(0x1e0261ea0,'Q',VARS+0x3800)
        self.put(0x1e21210e0,'Q',STACK_PROBE);self.put(0x1e01c8b30,'Q',VARS+0x3900)
        self.put(VARS+0x3900,'I',0x103);self.put(0x1ed890e90,'Q',VARS+0x3a00)
        self.put(0x1ed890e08,'Q',0xffffffffffffffff)
        self.put(0x1ed890e10,'Q',VARS+0x3b00);self.put(0x1e01c8738,'Q',VARS+0x3c00)
        self.put(VARS,'Q',BUFFER);self.put(VARS+16,'Q',0xffffffffffffffff)
        self.put(RLSOURCE+8,'Q',0 if seed.get('invalid_source') else 8)
        self.put(RLSOURCE+0x70,'Q',PORT);self.put(RLSOURCE+0xa8,'Q',0 if seed.get('null_perform') else PERFORM)
        for obj in (PORT,EXISTING):
            self.put(obj+0x14,'I',0x32f);self.put(obj+0x30,'Q',CALLBACK if obj==PORT else OTHER_CALLBACK)
            self.put(obj+0x40,'Q',INFO if obj==EXISTING or seed.get('context_info') else 0)
        self.put(PORT+0x10,'I',1 if seed.get('invalid_port') else 0)
        self.put(PORT+0x60,'Q',BOOST+0x100 if seed.get('old_boost') else 0)
        self.put(PORT+0x70,'Q',RETAIN_INFO if seed.get('context_retain') else 0)
        self.put(PORT+0x78,'Q',RELEASE_INFO if seed.get('context_release') else 0)
        self.put(CONTEXT+8,'Q',INFO if seed.get('context_info') else 0)
        self.put(CONTEXT+16,'Q',RETAIN_INFO if seed.get('context_retain') else 0)
        self.put(CONTEXT+24,'Q',RELEASE_INFO if seed.get('context_release') else 0)
        self.put(CONTEXT+0x100,'B',0xaa)
        self.message(BUFFER,seed.get('message_size',80),0,0x32f)
        self.put(PORT+0x28,'Q',RLSOURCE if seed.get('existing_source') else 0)
        self.u.reg_write(ar.UC_ARM64_REG_SP,STACK+0x1f000);self.setreg(30,HALT)
        if kind in ('service','service_to_source'):self.entry=SERVICE;args=[0x32f,VARS,VARS+8,seed.get('timeout',0xffffffff),VARS+16,0 if seed.get('no_voucher_copy') else VARS+24]
        elif kind=='perform':self.entry=PERFORM;args=[BUFFER,seed.get('message_size',80),VARS+0x3800,PORT]
        elif kind in ('do_source','bridge'):self.entry=DO_SOURCE;args=[VARS+0x1000,VARS+0x2000,RLSOURCE,BUFFER,seed.get('message_size',80),VARS+32]
        elif kind=='create_source':self.entry=CREATE_SOURCE;args=[0,PORT,0]
        elif kind=='with_port':self.entry=0x18472cfe8;args=[0,0x32f,CALLBACK,CONTEXT,CONTEXT+0x100]
        else:raise AssertionError(kind)
        for i,v in enumerate(args):self.setreg(i,v)
        self.u.hook_add(uc.UC_HOOK_CODE,self.code);self.u.hook_add(uc.UC_HOOK_MEM_READ,self.read);self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.write)

    def put(self,a,f,v):self.u.mem_write(a,struct.pack('<'+f,v))
    def get(self,a,f):return struct.unpack('<'+f,self.u.mem_read(a,struct.calcsize('<'+f)))[0]
    def reg(self,n):return self.u.reg_read(getattr(ar,f'UC_ARM64_REG_X{n}'))
    def setreg(self,n,v):self.u.reg_write(getattr(ar,f'UC_ARM64_REG_X{n}'),v&0xffffffffffffffff)
    def args(self):return [hex(self.reg(i)) for i in range(8)]
    def ret(self,v=0):self.setreg(0,v);self.u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
    def stop(self,reason,**kw):self.reason=reason;self.events.append({'kind':reason,**kw});self.u.emu_stop()
    def local(self,a,n):return any(x<=a and a+n<=x+s for x,s in self.local_ranges)
    def read(self,u,access,a,n,v,user):
        if self.local(a,n) or any(x<=a and a+n<=x+s for x,s in self.globals):return
        self.stop('unknown_data_read',pc=hex(u.reg_read(ar.UC_ARM64_REG_PC)),address=hex(a),size_bytes=n)
    def write(self,u,access,a,n,v,user):
        if not self.local(a,n):self.stop('unknown_data_write',address=hex(a),size_bytes=n)
    def message(self,a,size,status,local):
        if status==0:
            assert 24<=size and size+68<=0x10000
            raw=bytearray(size+68);struct.pack_into('<6I',raw,0,0x80000012,size,0x444,local,0,502)
            struct.pack_into('<II',raw,size,0,68);self.u.mem_write(a,bytes(raw))
        elif status==0x10004004:self.put(a+4,'I',size)

    def code(self,u,a,n,user):
        self.steps+=1
        if a==HALT:
            if self.kind=='service_to_source' and self.phase==0:
                self.phase=1;msg=self.get(VARS,'Q');assert msg and self.reg(0)==1
                self.events.append({'kind':'private_next_phase','entry':hex(DO_SOURCE),'message':hex(msg)})
                for i,v in enumerate([VARS+0x1000,VARS+0x2000,RLSOURCE,msg,self.get(msg+4,'I'),VARS+32]):self.setreg(i,v)
                self.setreg(30,HALT);u.reg_write(ar.UC_ARM64_REG_PC,DO_SOURCE);return
            if self.kind=='service_to_source' and self.phase==1:
                self.phase=2;self.events.append({'kind':'private_next_phase','entry':'0x1847577b0'})
                self.put(self.u.reg_read(ar.UC_ARM64_REG_SP)+0x68,'Q',self.get(VARS,'Q'))
                self.setreg(24,BUFFER);u.reg_write(ar.UC_ARM64_REG_PC,0x1847577b0);return
            self.stop('returned',x0=hex(self.reg(0)));return
        if a==0x1847577c8 and self.kind=='service_to_source':self.stop('completed_private_receive_callback_cleanup');return
        if a==STACK_PROBE:self.events.append({'kind':'private_stack_probe','bytes':hex(self.reg(9))});u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30));return
        if a in (CALLBACK,OTHER_CALLBACK):
            self.events.append({'kind':'private_daemon_callback','target':hex(a),'args':self.args(),
                'message_prefix_148':bytes(u.mem_read(self.reg(1),148)).hex(),'native_callback_executed':False})
            self.ret(0xdeadbeef);return
        if a==RETAIN_INFO:self.events.append({'kind':'private_context_retain','args':self.args()});self.ret(INFO+0x100);return
        if a==RELEASE_INFO:self.events.append({'kind':'private_context_release','args':self.args()});self.ret();return
        if a==0x188076b60:
            self.events.append({'kind':'private_mach_msg','args':self.args(),'header_before':bytes(u.mem_read(self.reg(0),24)).hex()})
            if not self.traps:self.stop('unmodeled_next_receive');return
            status,size=self.traps.pop(0);self.message(self.reg(0),size,status,0x32f);self.ret(status);return
        if a==REALLOC:
            self.events.append({'kind':'private_realloc','args':self.args(),'requested_bytes':self.reg(1)})
            if self.reg(1)>0x10000:self.stop('private_allocation_limit',requested_bytes=self.reg(1));return
            self.realloc_count+=1;self.ret(HEAP+(self.realloc_count-1)*0x20000);return
        if a==0x1848d4550:self.stop('receive_error_fail_stop_boundary',status=hex(self.reg(0)));return
        if a==0x1847841ec:
            self.events.append({'kind':'private_boost_create','allocator':hex(self.reg(0))});self.ret(BOOST if self.seed.get('new_boost') else 0);return
        if a in (CF_RETAIN,CF_RELEASE):
            self.events.append({'kind':'private_cf_retain' if a==CF_RETAIN else 'private_cf_release','object':hex(self.reg(0))})
            if self.reg(0)==BOOST:self.boost_refs+=1 if a==CF_RETAIN else -1
            self.ret(self.reg(0) if a==CF_RETAIN else 0);return
        if a==0x18472d31c:
            context=bytes(u.mem_read(self.reg(2),72));self.events.append({'kind':'private_source_create','args':self.args(),'context_72_bytes':context.hex()})
            # Explicit allocator/source-object model; source context values
            # themselves were constructed by original CFMachPort instructions.
            self.put(RLSOURCE+0x70,'Q',self.get(self.reg(2)+8,'Q'));self.put(RLSOURCE+0xa8,'Q',self.get(self.reg(2)+64,'Q'))
            self.ret(RLSOURCE);return
        if a==0x188076bc0:
            self.events.append({'kind':'private_mach_port_type','args':self.args(),'status':self.seed.get('port_type_status',0),'types':hex(self.seed.get('port_types',0x20000))})
            self.put(self.reg(2),'I',self.seed.get('port_types',0x20000));self.ret(self.seed.get('port_type_status',0));return
        if a==0x1846da4dc:
            self.events.append({'kind':'private_runtime_instance','args':self.args()});self.ret(PORT);return
        if a==0x1846f7424:self.events.append({'kind':'private_array_get','args':self.args()});self.ret(EXISTING);return
        if a==0x188081360:
            value=self.seed.get('voucher_state',0xffffffffffffffff)
            self.events.append({'kind':'private_voucher_adopt','args':self.args(),'result':hex(value)});self.ret(value);return
        if a==0x188078e40:
            self.events.append({'kind':'private_voucher_copy','args':self.args(),'result':hex(INFO+0x200)})
            self.ret(INFO+0x200);return
        helpers={0x188081380:0,0x188078e40:0,0x18806ead0:0,0x18806c3d0:0,
            0x1847078bc:0,0x184833e50:0,0x18806ebf0:0,0x18806c600:0,
            0x1846ddde4:0,0x1880773e0:0,0x1880773c0:0,0x188076ab0:0,0x184832a70:0,
            0x184833380:0,0x184833694:0x24,CF_VALID:0 if self.seed.get('invalid_port') else 1,
            0x1847791b4:0 if self.seed.get('invalid_existing_source') else 1,
            0x18476f510:0,0x1880770a0:0,0x1846f5978:1 if self.seed.get('reuse') else 0,
            0x1846f3b4c:VARS+0x3a00,0x1846f5c74:0,0x184751868:0,0x188076640:0}
        if a in helpers:self.events.append({'kind':'private_helper','address':hex(a),'args':self.args(),'result':helpers[a]});self.ret(helpers[a]);return
        if not any(lo<=a<hi for lo,hi in self.allowed):self.stop('unknown_code',pc=hex(a));return
        ins=next(CS.disasm(bytes(u.mem_read(a,4)),a));m=ins.mnemonic
        if m in ('pacibsp','autibsp','paciza','pacia','pacda','autia','xpaci'):
            self.pac.append({'pc':hex(a),'instruction':m,'operands':ins.op_str});u.reg_write(ar.UC_ARM64_REG_PC,a+4)
        elif m=='retab':self.pac.append({'pc':hex(a),'instruction':m});u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
        elif m in ('blraa','blraaz'):
            r=int(ins.op_str.split(',')[0].strip()[1:]);target=self.reg(r)
            self.pac.append({'pc':hex(a),'instruction':m,'target':hex(target)});self.setreg(30,a+4);u.reg_write(ar.UC_ARM64_REG_PC,target)
        elif m in ('svc','hvc','smc','msr','mrs','brk') or m.startswith(('aut','pac','xpac')):self.stop('unmodeled_instruction',pc=hex(a),instruction=m+' '+ins.op_str)

    def run(self):
        try:self.u.emu_start(self.entry,0,count=30000)
        except uc.UcError as e:self.reason='engine_error';self.events.append({'kind':'engine_error','pc':hex(self.u.reg_read(ar.UC_ARM64_REG_PC)),'message':str(e)})
        if self.reason is None:self.reason='instruction_budget'
        return {'label':self.label,'kind':self.kind,'seed':self.seed,'entry':hex(self.entry),'stop_reason':self.reason,
            'events':self.events,'steps':self.steps,'pac_bypasses':self.pac,'source_code_pages':[hex(a) for a in self.code_pages],
            'source_code_pages_sha256':self.code_hash,'private_boundary_stub_pages':[hex(a) for a in self.stub_pages],
            'final':{'buffer_pointer':hex(self.get(VARS,'Q')),'live_port':hex(self.get(VARS+8,'I')),
                'reply_pointer':hex(self.get(VARS+32,'Q')),'boost_pointer':hex(self.get(PORT+0x60,'Q')),
                'voucher_state':hex(self.get(VARS+16,'Q')),'voucher_copy':hex(self.get(VARS+24,'Q')),
                'boost_refs':self.boost_refs,'port_callback':hex(self.get(PORT+0x30,'Q')),
                'existing_callback':hex(self.get(EXISTING+0x30,'Q')),'source_pointer':hex(self.get(PORT+0x28,'Q')),
                'should_free_info':self.get(CONTEXT+0x100,'B')},
            'native_target_executed':False,'target_host_operations_executed':False}


def main():
    c=Cache();lib=Dylib(c,CF_PATH);assert lib.uuid==CF_UUID;rows=[]
    def case(label,kind,**seed):
        r=Probe(c,lib,label,kind,seed).run();rows.append(r)
        assert r['stop_reason'] not in ('engine_error','unknown_data_read','unknown_data_write','unknown_code','unmodeled_instruction','instruction_budget','unmodeled_next_receive'),r
        print(json.dumps({'label':label,'stop':r['stop_reason'],'last':r['events'][-1]}),flush=True)
    for timeout in (0xffffffff,0,5):case(f'service_success_timeout_{timeout}','service',timeout=timeout,receive_results=[(0,80)])
    case('service_large_then_success','service',receive_results=[(0x10004004,4096),(0,4096)])
    case('service_repeated_large','service',receive_results=[(0x10004004,4096),(0x10004004,8192),(0,8192)])
    case('service_timeout_stack','service',receive_results=[(0x10004003,0)])
    case('service_timeout_heap','service',receive_results=[(0x10004004,4096),(0x10004003,0)])
    case('service_unexpected_error','service',receive_results=[(0x10004002,0)])
    case('service_body_error','service',receive_results=[(0x1000440c,0)])
    case('service_growth_u32_wrap','service',receive_results=[(0x10004004,0xfffffffc),(0x10004003,0)])
    case('service_growth_four_gib','service',receive_results=[(0x10004004,0xffffffbb)])
    case('service_without_voucher_copy','service',no_voucher_copy=True,receive_results=[(0,80)])
    case('service_copies_voucher','service',voucher_state=0x12345678,receive_results=[(0,80)])
    case('service_releases_voucher_before_retry','service',voucher_state=0x12345678,receive_results=[(0x10004004,4096),(0,4096)])
    case('service_adopts_without_copy_output','service',voucher_state=0x12345678,no_voucher_copy=True,receive_results=[(0,80)])
    case('receive_callback_stack','service_to_source',receive_results=[(0,80)])
    case('receive_callback_heap','service_to_source',receive_results=[(0x10004004,4096),(0,4096)])
    for old in (False,True):
        for new in (False,True):case(f'perform_boost_{old}_{new}','perform',old_boost=old,new_boost=new)
    case('perform_invalid_port','perform',invalid_port=True,new_boost=True)
    case('perform_context_pair','perform',context_info=True,context_retain=True,context_release=True)
    case('perform_release_without_retain','perform',context_info=True,context_release=True)
    case('source_to_daemon','do_source')
    case('source_invalid','do_source',invalid_source=True)
    case('source_valid_port_invalid','do_source',invalid_port=True)
    case('source_null_perform','do_source',null_perform=True)
    case('create_source_new','create_source')
    case('create_source_existing','create_source',existing_source=True)
    case('create_source_existing_invalid','create_source',existing_source=True,invalid_existing_source=True)
    case('create_source_invalid_port','create_source',invalid_port=True)
    for types in (0,0x10000,0x20000,0x40000,0x80000,0x100000):case(f'with_port_types_{types}','with_port',port_types=types)
    case('with_port_type_query_error','with_port',port_type_status=15)
    case('with_port_reuse','with_port',reuse=True,context_info=True)
    case('with_port_reuse_invalid','with_port',reuse=True,invalid_port=True)
    case('with_port_context_pair','with_port',context_info=True,context_retain=True,context_release=True)
    out={'scope':__doc__,'cache_uuid':c.uuid,'library_uuid':lib.uuid,'unicorn_version':uc.__version__,
        'cpu_model':'UC_CPU_ARM64_MAX; PAC bypassed','generator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'cache_reader_sha256':hashlib.sha256((ROOT/'bootpolicy_cache_reader.py').read_bytes()).hexdigest(),
        'instruction_limit_per_profile':30000,'fixture_memory':'private zero-filled mappings with explicit runtime/helper seeds',
        'profiles':rows}
    (ROOT/'cf_receive_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'profiles':len(rows)}))


if __name__=='__main__':main()
