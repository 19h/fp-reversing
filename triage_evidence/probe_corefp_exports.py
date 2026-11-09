#!/usr/bin/env python3
"""Original CoreFP export execution in private Unicorn pages.

All internal format12 targets are rebased to a private load base. Imports use
private cells/markers. Selected fixtures explicitly model stack probes, once,
sequential atomics, page-size results and anonymous mappings. Unknown APIs,
syscalls and nonprivate writes stop. No native target/loader/IPC executes.
O(C*(B+F+K)) time for cases,image bytes,fixups and bounded instruction count.
"""
import bisect
import hashlib
import json
from pathlib import Path
import struct
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_WRITE
from unicorn import arm64_const as A
from corefp_fixups_reader import Pointers,ROOT,THIN_SHA,sha
from appstore_agent_reader import CS

BASE=0x500000000;STACK=0x7a000000;HEAP=0x7b000000;BIND=0x7c000000;DONE=0x7d000000;MAPPING=0x7e000000


class Probe:
    def __init__(self,s,f):
        self.s=s;self.fixture=f;self.records=[];self.visited=[];self.functions={};self.ins={};self.steps=0;self.reason=None
        self.once_state={};self.once_stack=[]
        self.private_mappings=[]
        self.u=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
        for seg in s.meta['segments']:
            a=BASE+seg['address'];n=(seg['vm_size']+4095)&~4095
            self.u.mem_map(a,n)
            if seg['file_size']:self.u.mem_write(a,s.data[seg['file_offset']:seg['file_offset']+seg['file_size']])
        self.u.mem_map(STACK,0x40000);self.u.mem_map(HEAP,0x10000);self.u.mem_map(BIND,0x2000);self.u.mem_map(DONE,4096)
        self.binds={}
        for at,row in s.decoded.items():
            if row['bind']:
                im=row['import'];target=BIND+im['ordinal']*16+row['pointer_addend'];self.binds[BIND+im['ordinal']*16]=im
                if im['name']=='___stack_chk_guard':self.u.mem_write(BIND+im['ordinal']*16,struct.pack('<Q',0x9012345678abcdef))
            else:target=BASE+int(row['target'],16)
            self.u.mem_write(BASE+at,struct.pack('<Q',target))
        self.sp=STACK+(0x18000 if f['mode']=='version' else 0x38000)+f.get('stack_delta',0);self.u.reg_write(A.UC_ARM64_REG_SP,self.sp);self.u.reg_write(A.UC_ARM64_REG_LR,DONE)
        self.output=HEAP+0x100;self.u.mem_write(self.output,b'\xa5'*16)
        self.state_addresses=[0x1d355c0,0x1d37f68,0x1d358b8]
        for a,v in zip(self.state_addresses,f.get('state64',[0,0,0])):self.u.mem_write(BASE+a,struct.pack('<Q',v))
        self.state_before=[bytes(self.u.mem_read(BASE+a,8)).hex() for a in self.state_addresses]
        self.texts=[x for x in s.meta['sections'] if x['section']=='__text'];self.u.hook_add(UC_HOOK_CODE,self.code);self.u.hook_add(UC_HOOK_MEM_WRITE,self.write)

    def reg(self,n):
        if n in ('xzr','wzr'):return 0
        return self.u.reg_read(getattr(A,'UC_ARM64_REG_'+n.upper()))
    def stop(self,why):self.reason=why;self.u.emu_stop()
    def write(self,u,access,a,n,value,data):
        if STACK<=a and a+n<=STACK+0x40000 or HEAP<=a and a+n<=HEAP+0x10000:return
        if any(start<=a and a+n<=start+size for start,size in self.private_mappings):return
        if any(BASE+x['address']<=a and a+n<=BASE+x['address']+x['vm_size'] for x in self.s.meta['segments'] if x['name']=='__DATA'):
            self.records.append({'kind':'original_private_global_write','pc':hex(self.reg('pc')-BASE),'address':hex(a-BASE),'size_bytes':n,'value':hex(value&((1<<(n*8))-1))});return
        self.stop('nonprivate_write_guard:'+hex(a))
    def code(self,u,pc,n,data):
        self.steps+=1
        if self.steps>30000:return self.stop('instruction_budget_guard')
        if pc==DONE:return self.stop('returned_to_private_fixture')
        if pc==DONE+0x100:
            control,lr=self.once_stack.pop();self.once_state[control]='done';self.u.reg_write(A.UC_ARM64_REG_LR,lr)
            self.records.append({'kind':'modeled_once_initializer_return','control':hex(control-BASE)})
            self.u.reg_write(A.UC_ARM64_REG_X0,0);self.u.reg_write(A.UC_ARM64_REG_PC,lr);return
        if pc in self.binds:
            im=self.binds[pc]
            if im['name']=='___chkstk_darwin' and self.fixture.get('model_stack_check'):
                need=self.reg('x9');self.records.append({'kind':'modeled_stack_probe','import':im,'requested_size_x9':hex(need),
                    'ABI_assumption':'Preserve registers and return normally for bounded private stack; effective native binding unresolved.'})
                if need>self.reg('sp')-STACK-0x1000:return self.stop('private_stack_extent_guard')
                self.u.reg_write(A.UC_ARM64_REG_PC,self.reg('lr'));return
            if im['name']=='_pthread_once' and self.fixture.get('model_once'):
                control=self.reg('x0');callback=self.reg('x1');state=self.once_state.get(control,'unstarted')
                self.records.append({'kind':'modeled_once','control':hex(control-BASE),'callback':hex(callback-BASE),'state':state})
                if state=='done':self.u.reg_write(A.UC_ARM64_REG_X0,0);self.u.reg_write(A.UC_ARM64_REG_PC,self.reg('lr'));return
                if state=='running':return self.stop('private_once_reentry_guard')
                self.once_state[control]='running';self.once_stack.append((control,self.reg('lr')))
                self.u.reg_write(A.UC_ARM64_REG_LR,DONE+0x100);self.u.reg_write(A.UC_ARM64_REG_PC,callback);return
            if im['name']=='_sysconf' and 'page_size_result' in self.fixture:
                assert self.reg('x0')==29
                result=self.fixture['page_size_result'];self.records.append({'kind':'modeled_page_size_query','selector_u32':29,
                    'result_signed64':result,'callsite':hex(self.reg('lr')-4-BASE),'native_query_executed':False})
                self.u.reg_write(A.UC_ARM64_REG_X0,result&((1<<64)-1));self.u.reg_write(A.UC_ARM64_REG_PC,self.reg('lr'));return
            if im['name']=='_mmap' and self.fixture.get('mapping_result'):
                args=[self.reg('x'+str(j)) for j in range(6)]
                assert args[:4]==[0,65536,3,0x1002] and args[4]&0xffffffff==0xffffffff and args[5]==0,args
                success=self.fixture['mapping_result']=='success'
                if success:
                    if self.private_mappings:return self.stop('second_private_mapping_guard')
                    self.u.mem_map(MAPPING,65536);self.private_mappings.append((MAPPING,65536))
                result=MAPPING if success else (1<<64)-1
                self.records.append({'kind':'modeled_anonymous_mapping','callsite':hex(self.reg('lr')-4-BASE),
                    'args_x0_x5':[hex(x) for x in args],'result':hex(result),'zero_initialized':success,'native_mapping_executed':False})
                self.u.reg_write(A.UC_ARM64_REG_X0,result);self.u.reg_write(A.UC_ARM64_REG_PC,self.reg('lr'));return
            self.records.append({'kind':'opaque_import_boundary','import':self.binds[pc],
                'callsite':hex(self.reg('lr')-4-BASE),'live_x0_x7':[hex(self.reg('x'+str(j))) for j in range(8)]});return self.stop('opaque_import_boundary')
        at=pc-BASE
        if not 0<=at<0x2000000:return self.stop('unknown_code_boundary:'+hex(pc))
        if at not in self.ins:
            if not any(x['address']<=at<x['address']+x['size'] for x in self.texts):
                self.records.append({'kind':'original_code_stub_boundary','address':hex(at),'bytes':self.s.read(at,16).hex()});return self.stop('original_code_stub_boundary')
            ix=bisect.bisect_right(self.s.starts,at)-1;entry=self.s.starts[ix];end=self.s.starts[ix+1]
            if entry not in self.functions:
                raw=self.s.read(entry,end-entry)
                row={'start':hex(entry),'end':hex(end),'size_bytes':len(raw),'sha256':sha(raw),'complete_compiler_bounds':True,
                    'complete_body_retained':len(raw)<=0x4000}
                if row['complete_body_retained']:row['bytes']=raw.hex()
                self.functions[entry]=row
            raw=self.s.read(at,4);d=next(CS.disasm(raw,at));self.ins[at]={'ea':hex(at),'bytes':raw.hex(),'mnemonic':d.mnemonic,'operands':d.op_str}
        i=self.ins[at];m=i['mnemonic'];op=i['operands'];self.visited.append(at)
        if m in ('swp','swpa','swpl','swpal'):
            src,dst,mem=op.split(', ');ptr=self.reg(mem.strip('[]'));width=4 if src.startswith('w') else 8
            self.records.append({'kind':'atomic_exchange_boundary','pc':hex(at),'instruction':m,'pointer':hex(ptr),
                'size_bytes':width,'source_value':hex(self.reg(src))})
            event=self.records[-1]
            if not self.fixture.get('model_atomic'):return self.stop('atomic_instruction_boundary')
            before=bytes(self.u.mem_read(ptr,width));new=self.reg(src)&((1<<(8*width))-1)
            self.write(u,0,ptr,width,new,None)
            if self.reason:return
            self.u.mem_write(ptr,new.to_bytes(width,'little'))
            if dst not in ('wzr','xzr'):self.u.reg_write(getattr(A,'UC_ARM64_REG_'+dst.upper()),int.from_bytes(before,'little'))
            event.update({'kind':'modeled_sequential_atomic_exchange','before_bytes':before.hex(),'after_bytes':new.to_bytes(width,'little').hex(),'concurrent_ordering_validated':False})
            self.u.reg_write(A.UC_ARM64_REG_PC,pc+4);return
        if at==0x20f6fc:
            ptr=self.reg('x0');self.records.append({'kind':'original_version_record_entry','record_pointer':hex(ptr),'record16_bytes':bytes(self.u.mem_read(ptr,16)).hex()})
        if at==0x20f790:self.records.append({'kind':'original_version_operation','operation_u32':self.reg('w8'),'output_pointer':hex(self.reg('x9'))})
        if at==0x27afd4:
            ptr=self.reg('x0');self.records.append({'kind':'original_packet_record_entry','record_pointer':hex(ptr),
                'record_written_extent88_bytes':bytes(self.u.mem_read(ptr,88)).hex(),
                'preceding24_bytes':bytes(self.u.mem_read(ptr-24,24)).hex(),
                'extent_is_full_record_size':False})
        if at==0xe410:self.records.append({'kind':'original_packet_status_load','record_status_u32':int.from_bytes(self.u.mem_read(self.reg('sp')+0x30,4),'little')})
        if m in ('svc','hvc','smc','brk'):return self.stop('native_instruction_guard:'+m)
        if m in ('braa','brab','blraa','blrab','braaz','brabz','blraaz','blrabz'):
            regs=op.split(', ');target=self.reg(regs[0]);self.records.append({'kind':'PAC_bypassed_edge','pc':hex(at),'target':hex(target-BASE) if BASE<=target<BASE+0x2000000 else hex(target),
                'modifier':None if len(regs)==1 else hex(self.reg(regs[1])),'link':m.startswith('bl')})
            if m.startswith('bl'):self.u.reg_write(A.UC_ARM64_REG_LR,pc+4)
            self.u.reg_write(A.UC_ARM64_REG_PC,target)
        elif m.startswith(('pac','aut')):self.u.reg_write(A.UC_ARM64_REG_PC,pc+4)
        elif m in ('retab','retaa'):self.u.reg_write(A.UC_ARM64_REG_PC,self.reg('lr'))

    def run(self):
        if self.fixture['mode']=='version':
            entry=0xcd20;args=[0 if self.fixture.get('null') else self.output]
        else:
            entry=0xe160;args=[7,HEAP+0x200,HEAP+0x300,HEAP+0x1000,891,HEAP+0x2000,HEAP+0x400,HEAP+0x500]
            cert=(ROOT/'ams_core_certificate.der').read_bytes();self.u.mem_write(HEAP+0x1000,cert)
            self.u.mem_write(HEAP+0x300,struct.pack('<I',2));self.u.mem_write(HEAP+0x500,struct.pack('<Q',2048))
        for j,x in enumerate(args):self.u.reg_write(A.UC_ARM64_REG_X0+j,x)
        try:self.u.emu_start(BASE+entry,DONE+4,count=30001)
        except Exception as e:
            if self.reason is None:self.reason='private_emulator_exception:'+str(e)
        h=hashlib.sha256()
        for pc in self.visited:h.update(struct.pack('<Q',pc));h.update(self.s.read(pc,4))
        return {'fixture':self.fixture,'entry_sp':hex(self.sp),'stop_reason':self.reason,'steps':self.steps,'result_u32':self.reg('w0'),
            'output16_bytes':bytes(self.u.mem_read(self.output,16)).hex(),'state_before':self.state_before,
            'state_after':[bytes(self.u.mem_read(BASE+a,8)).hex() for a in self.state_addresses],
            'visited_original_instructions':[hex(x) for x in self.visited],'original_instruction_bytes_sha256':h.hexdigest(),
            'visited_instruction_records':list(self.ins.values()),
            'original_functions':list(self.functions.values()),'records':self.records}


def main():
    s=Pointers();fixtures=[]
    for null in (True,False):
        for j,states in enumerate([[0,0,0],[(1<<64)-1,1,0],[0x1122334455667788,0x8877665544332211,0x123456789abcdef0]]):
            fixtures.append({'label':f'version_{"null" if null else "owned"}_{j}','mode':'version','null':null,'state64':states,'stack_delta':j*16})
    fixtures.append({'label':'certificate_packet_first_boundary','mode':'packet','state64':[0,0,0]})
    fixtures.append({'label':'certificate_packet_after_modeled_stack_probe','mode':'packet','state64':[0,0,0],'model_stack_check':True})
    fixtures.append({'label':'certificate_packet_original_once_initializer','mode':'packet','state64':[0,0,0],'model_stack_check':True,'model_once':True})
    fixtures.append({'label':'certificate_packet_private_atomic_initializer','mode':'packet','state64':[0,0,0],'model_stack_check':True,'model_once':True,'model_atomic':True})
    for value in (4096,16384,-1):fixtures.append({'label':f'certificate_packet_page_size_{value}','mode':'packet','state64':[0,0,0],
        'model_stack_check':True,'model_once':True,'model_atomic':True,'page_size_result':value})
    for result in ('success','failed'):fixtures.append({'label':'certificate_packet_mapping_'+result,'mode':'packet','state64':[0,0,0],
        'model_stack_check':True,'model_once':True,'model_atomic':True,'page_size_result':16384,'mapping_result':result})
    profiles=[Probe(s,f).run() for f in fixtures];functions={};instructions={}
    for row in profiles:
        ff=row.pop('original_functions');row['original_function_starts']=[x['start'] for x in ff]
        for f in ff:functions[f['start']]=f
        ii=row.pop('visited_instruction_records')
        for i in ii:instructions[i['ea']]=i
    out={'scope':__doc__,'thin_sha256':THIN_SHA,'load_base':hex(BASE),'generator_sha256':sha(Path(__file__).read_bytes()),
        'pointer_reader_sha256':sha((ROOT/'corefp_fixups_reader.py').read_bytes()),'fixup_inventory_sha256':sha((ROOT/'corefp_fixups_inventory.json').read_bytes()),
        'original_functions':list(functions.values()),'visited_instruction_records':list(instructions.values()),
        'profiles':profiles,'native_target_executed':False,'hardware_PAC_checked':False,'full_goal_complete':False}
    out['atomic_model_reference']={'primary_source':'https://documentation-service.arm.com/static/6245c734b059dc5ff9a8bdab',
        'section':'D3.133 SWP/SWPA/SWPAL/SWPL','scope':'Only sequential register/memory exchange modeled; concurrent acquire/release behavior unvalidated.'}
    (ROOT/'corefp_exports_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
    for row in profiles:print(json.dumps({'label':row['fixture']['label'],'reason':row['stop_reason'],'steps':row['steps'],'result_u32':hex(row['result_u32']),'output':row['output16_bytes'],'last_event':row['records'][-1] if row['records'] else None}))


if __name__=='__main__':main()
