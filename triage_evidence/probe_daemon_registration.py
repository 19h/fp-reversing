#!/usr/bin/env python3
"""Bounded private daemon service-registration fixtures, never host IPC.

Original code/data and normalized original fixups are copied into Unicorn.
PAC is bypassed; bootstrap/CF APIs and runtime data are explicit models.
Unreviewed native continuations, imports, system instructions and bad accesses
stop. Canonical control state is a stated fixture input, not caller reachability.
"""
import hashlib
import json
from pathlib import Path
import struct
import unicorn as uc
from daemon_rpc502_probe import Probe as Base,STACK,STACK_SIZE,HALT,IMPORTS,ar
from daemon_receive_tools import IMAGE,SOURCE,CS,ROOT,TABLE,POOL
from resolve_kernel_collection_interfaces import commands

SERVICES=0x100537b90;CHECKIN=0x10044011c
ARG=STACK+0x1000;SEEDPTR=STACK+0x1100
OBJECTS=0x5000000000
HEADER=0x1010c4cd8
CANONICAL_STATE=0xf44a7867
RANGES=[(SERVICES,0x100538878),(CHECKIN,0x1004403d4),
        (0x1003ad1a8,0x1003ad26c),(0x100001f9c,0x100001fec),
        (0x100e2a8f0,0x100e2a900),(0x1001f531c,0x1001f5340),
        (0x1003172bc,0x100317364),(0x1003151e8,0x10031536c),
        (0x1001ce87c,0x1001ce928),(0x100539234,0x10053948c),
        (0x100083778,0x100083978)]


class RegistrationProbe(Base):
    def __init__(self,label,*,checkin_status=0,fail_service=None,null_cf=False,entry=SERVICES,
                 control_state=CANONICAL_STATE,stack_offset=0,helper=False,null_source=False,
                 seeded_outputs=False):
        super().__init__()
        self.label=label;self.checkin_status=checkin_status;self.fail_service=fail_service
        self.null_cf=null_cf;self.entry=entry;self.control_state=control_state
        self.null_source=null_source;self.seeded_outputs=seeded_outputs
        self.stack_offset=stack_offset;self.helper=helper;self.ordinal=0;self.cf_ordinal=0
        self.visited=set();self.boundaries=[];self.calls=[]
        self.u.mem_map(OBJECTS,0x10000)
        # Preserve original segment protections in the private copy after fixups.
        self.segment_ranges=[]
        for at,cmd,size in commands(IMAGE.data,0):
            if cmd!=0x19:continue
            va,vm,off,n=struct.unpack_from('<4Q',IMAGE.data,at+24)
            prot=struct.unpack_from('<I',IMAGE.data,at+60)[0]
            if va and vm:
                lo=va&~4095;hi=(va+vm+4095)&~4095
                self.u.mem_protect(lo,hi-lo,prot)
                self.segment_ranges.append((va,va+vm,prot))
        self.seed_data('libSystem/_bootstrap_port',0x707)
        # Optional CF mode value is a private opaque CFString token.
        if 'CoreFoundation/_kCFRunLoopCommonModes' in self.import_addresses:
            self.seed_data('CoreFoundation/_kCFRunLoopCommonModes',OBJECTS+0xf000)
        if 'CoreFoundation/_kCFRunLoopDefaultMode' in self.import_addresses:
            self.seed_data('CoreFoundation/_kCFRunLoopDefaultMode',OBJECTS+0xf100)
        if seeded_outputs:
            for i,off in enumerate((0x18,0x20,0x28,0x30,0x40)):
                self.u.mem_write(HEADER+off,struct.pack('<Q',0xbad00000+i))

    def seed_data(self,name,value):
        if name not in self.import_addresses:return
        self.u.mem_write(self.import_addresses[name],struct.pack('<Q',value))
        self.data_import_values.append({'name':name,'value':hex(value),'model':'private runtime cell'})

    def string(self,p):return bytes(self.u.mem_read(p,128)).split(b'\0',1)[0].decode('ascii')

    def hook(self,u,address,size,user):
        if address==HALT:return super().hook(u,address,size,user)
        if self.entry==0x100083778 and address==0x100083974:
            self.stop('completed_private_main_registration_gate',target=hex(self.reg(8)),
                native_branch_site=hex(address));return
        if address==CHECKIN:
            raw=bytes(u.mem_read(self.reg(0),40));dst,name=struct.unpack_from('<QQ',raw)
            state=(struct.unpack_from('<I',raw,32)[0]+0x316f29c1*((self.reg(0)&0xffffffff)^0x987eac8a))&0xffffffff
            self.records.append({'kind':'native_checkin_entry','record_address':hex(self.reg(0)),
                'record_40_bytes':raw.hex(),'destination_cell':hex(dst),'service':self.string(name),'decoded_control_state':hex(state)})
        if address in self.imports:
            self.steps+=1;name=self.imports[address];args=[self.reg(i) for i in range(8)]
            e={'kind':'private_import','name':name,'return_pc':hex(self.reg(30)),
                'args':[hex(x) for x in args]};self.calls.append(e);self.records.append(e)
            if name=='libSystem/_bootstrap_check_in':
                service=self.string(args[1]);e['service']=service;e['ordinal']=self.ordinal
                status=self.checkin_status if self.fail_service is None or self.ordinal==self.fail_service else 0
                value=0xe03+self.ordinal*0x100
                if status==0:self.u.mem_write(args[2],struct.pack('<I',value))
                e.update({'status':status,'modeled_receive_name':hex(value) if status==0 else None})
                self.ordinal+=1;self.return_model(status);return
            if name=='CoreFoundation/_CFMachPortCreateWithPort':
                result=0 if self.null_cf else OBJECTS+(self.ordinal-1)*0x100
                e['context_40_bytes']=bytes(u.mem_read(args[3],40)).hex()
                e['result']=hex(result);self.cf_ordinal+=1;self.return_model(result);return
            if name=='CoreFoundation/_CFMachPortCreateRunLoopSource':
                result=0 if self.null_source else OBJECTS+0x4000+(self.ordinal-1)*0x100
                e['result']=hex(result);self.return_model(result);return
            if name in ('CoreFoundation/_CFRunLoopGetCurrent','CoreFoundation/_CFRunLoopGetMain'):
                e['result']=hex(OBJECTS+0xe000);self.return_model(OBJECTS+0xe000);return
            if name in ('CoreFoundation/_CFRunLoopAddSource','CoreFoundation/_CFRelease',
                        'CoreFoundation/_CFMachPortInvalidate','libSystem/_mach_port_deallocate'):
                self.return_model(0);return
            self.stop('unmodeled_registration_import',name=name,args=e['args']);return
        if not any(lo<=address<hi for lo,hi in RANGES):
            self.stop('unreviewed_native_continuation',pc=hex(address),
                registers={f'x{i}':hex(self.reg(i)) for i in range(29)},sp=hex(u.reg_read(ar.UC_ARM64_REG_SP)))
            return
        self.visited.add(address)
        i=next(CS.disasm(bytes(u.mem_read(address,4)),address))
        if i.mnemonic in ('paciza','pacia','pacda','autia','autiza','xpaci'):
            self.steps+=1;self.pac.append({'site':hex(address),'instruction':i.mnemonic,'authentication':'explicit private bypass'})
            u.reg_write(ar.UC_ARM64_REG_PC,address+4);return
        return super().hook(u,address,size,user)

    def run_registration(self):
        sp=STACK+0x78000+self.stack_offset
        self.u.mem_write(SEEDPTR,struct.pack('<Q',0))
        raw=bytearray(40)
        if not self.helper:
            value=(0x83918153*((ARG&0xffffffff)^0x7cf28be0)+self.control_state)&0xffffffff
            struct.pack_into('<I',raw,4,value)
        else:
            self.u.mem_write(STACK+0x2000,b'com.apple.unfreed\0')
            struct.pack_into('<QQQQI',raw,0,HEADER+0x18,STACK+0x2000,0,0,
                (0x2e4c-0x316f29c1*((ARG&0xffffffff)^0x987eac8a))&0xffffffff)
        self.u.mem_write(ARG,bytes(raw));self.setreg(0,ARG);self.setreg(1,SEEDPTR)
        self.setreg(30,HALT);self.u.reg_write(ar.UC_ARM64_REG_SP,sp)
        actual_arg=ARG
        if self.entry==0x100083778:
            fp=sp-0x10;sp-=0x3e0;actual_arg=fp-0x98
            self.u.reg_write(ar.UC_ARM64_REG_SP,sp);self.setreg(29,fp)
            for reg,value in {13:0x100e99900,14:0x101031da0,19:0x101031ea0,
                20:sp+0x230,23:0x9245,25:POOL,27:0x1010c4670,28:TABLE}.items():self.setreg(reg,value)
            for off,value in [(0x1a0,0x1010b8e50),(0x190,0x100fc4230),
                (0x188,0x101031fa0),(0xe0,0x100fc4130)]:self.u.mem_write(sp+off,struct.pack('<Q',value))
        try:self.u.emu_start(self.entry,0,count=30000)
        except uc.UcError as e:
            self.stop_reason='engine_error';self.records.append({'kind':'engine_error','message':str(e),
                'pc':hex(self.u.reg_read(ar.UC_ARM64_REG_PC))})
        if self.stop_reason is None:self.stop_reason='instruction_budget'
        for a in self.visited:assert bytes(self.u.mem_read(a,4))==IMAGE.read(a,4),hex(a)
        pages=sorted({a&~4095 for a in self.visited});h=hashlib.sha256()
        for a in pages:h.update(struct.pack('<Q',a));h.update(IMAGE.read(a,4096))
        return {'label':self.label,'scope':__doc__,'entry':hex(self.entry),'entry_sp':hex(sp),
            'control_state':hex(self.control_state),'helper_fixture':self.helper,
            'checkin_status':self.checkin_status,'fail_service':self.fail_service,'null_cf':self.null_cf,
            'null_source':self.null_source,'seeded_outputs':self.seeded_outputs,
            'source_sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
            'generator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'base_probe_sha256':hashlib.sha256((ROOT/'daemon_rpc502_probe.py').read_bytes()).hexdigest(),
            'steps':self.steps,'stop_reason':self.stop_reason,'records':self.records,'calls':self.calls,
            'pac_bypasses':self.pac,'image_writes':self.writes,'visited_code_pages':[hex(a) for a in pages],
            'visited_original_code_pages_sha256':h.hexdigest(),'visited_instruction_addresses':[hex(a) for a in sorted(self.visited)],
            'original_instruction_bytes_verified':len(self.visited),
            'actual_argument_address':hex(actual_arg),'final_argument_bytes':bytes(self.u.mem_read(actual_arg,40)).hex(),
            'final_seed':hex(struct.unpack('<Q',self.u.mem_read(SEEDPTR,8))[0]),
            'final_header_72_bytes':bytes(self.u.mem_read(HEADER,72)).hex(),
            'native_target_executed':False,'target_host_operations_executed':False,
            'caller_reachability_established':False,'full_goal_complete':False}


def main():
    profiles=[]
    cases=[('services_success',{}),('services_success_other_stack',{'stack_offset':-0x2000}),
        ('main_continuation_success',{'entry':0x100083778}),
        ('main_continuation_first_checkin_fail',{'entry':0x100083778,'checkin_status':1102,'fail_service':0,'seeded_outputs':True}),
        ('main_continuation_last_checkin_fail',{'entry':0x100083778,'checkin_status':1102,'fail_service':4,'seeded_outputs':True}),
        ('services_all_checkin_fail',{'checkin_status':1102,'seeded_outputs':True}),
        ('services_null_cf',{'null_cf':True,'seeded_outputs':True}),
        ('services_null_source',{'null_source':True,'seeded_outputs':True}),
        ('helper_success',{'entry':CHECKIN,'helper':True})]
    for i in range(5):cases.append((f'services_checkin_fail_{i}',{'checkin_status':1102,'fail_service':i,'seeded_outputs':True}))
    for label,kwargs in cases:
        p=RegistrationProbe(label,**kwargs);r=p.run_registration();profiles.append(r)
        print(json.dumps({'label':label,'steps':r['steps'],'stop':r['stop_reason'],'last':r['records'][-1],
            'checkins':len([e for e in r['calls'] if e['name']=='libSystem/_bootstrap_check_in'])}),flush=True)
    (ROOT/'daemon_registration_profiles.json').write_text(json.dumps({'scope':__doc__,'profiles':profiles},indent=2)+'\n')


if __name__=='__main__':main()
