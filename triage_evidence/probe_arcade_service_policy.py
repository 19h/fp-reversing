#!/usr/bin/env python3
"""Private original-service continuation after peer audit guest lookup.

Explicit Security results and opaque objects only. No native target framework,
signing check, receipt, file, loader or IPC operation runs. Parent PAC/heap/syscall
guards remain active. Time per phase <=2M private steps; memory/source pinning
and finite evidence boundaries are inherited from the frozen service probe.
"""
import hashlib
import json
from pathlib import Path
import struct
import unicorn.arm64_const as ar
from probe_arcade_service import Probe,ROOT,PEER,REPLY,STACK

GUEST=PEER+0x900
REQUIREMENT=PEER+0x920
FILE_MANAGER=PEER+0xa00


class PolicyProbe(Probe):
    def __init__(self,*,guest_status=0,guest_null=False,requirement_status=0,requirement_null=False,validity_status=0,developer_result=None,volatile_seed=None):
        super().__init__(0,True)
        self.guest_status=guest_status;self.guest_null=guest_null
        self.parse_status=requirement_status;self.requirement_null=requirement_null;self.validity_status=validity_status
        self.objc_objects={}
        self.developer_result=developer_result
        self.volatile_seed=volatile_seed;self.active_import=None

    def ret(self,v=None):
        super().ret(v)
        if self.volatile_seed is not None and self.active_import!='libSystem/___chkstk_darwin':
            for j in range(0 if v is None else 1,18):self.setreg(j,(self.volatile_seed+j*0x1000100010001)&((1<<64)-1))
            self.u.reg_write(ar.UC_ARM64_REG_NZCV,0xa0000000)
            self.records.append({'kind':'private_scalar_clobber','api':self.active_import,'seed':hex(self.volatile_seed),
                'registers':'X1-X17; also X0 for void models; X18 preserved; NZCV=0xa0000000',
                'scope':'finite external-API scalar caller-saved perturbation; SIMD not changed'})

    def original_cfstring(self,a):
        sec=next(s for s in self.s.sections if s['section']=='__cfstring')
        assert sec['address']<=a and a+32<=sec['address']+sec['size']
        assert self.s.qword(a)=='CoreFoundation/___CFConstantStringClassReference'
        address=self.s.qword(a+16);n=self.s.qword(a+24);assert n<4096
        text=self.s.read(address,n).decode();assert self.s.read(address+n,1)==b'\0'
        return {'object':hex(a),'flags':hex(self.s.qword(a+8)),'string_address':hex(address),'length_bytes':n,'text':text}

    def describe(self,a):
        if a in self.objc_objects:return self.objc_objects[a]
        if a in self.cf_objects:return self.cf_objects[a]
        if a in self.imports:return {'import':self.imports[a]}
        sec=next(s for s in self.s.sections if s['section']=='__cfstring')
        if sec['address']<=a and a+32<=sec['address']+sec['size']:
            return {'type':'constant_string',**self.original_cfstring(a)}
        return {'unknown_object':hex(a)}

    def defined_string(self,a):
        raw=bytearray()
        for j in range(4096):
            if not self.check_heap(a+j,1):return None
            b=bytes(self.u.mem_read(a+j,1))
            if b==b'\0':return raw.decode()
            raw+=b
        raise ValueError('private C-string budget')

    def code(self,u,a,n,user):
        if a in (0x10000d540,0x10000d568,0x10000d5ec,0x10000d608,0x10000d690,0x10000d6a8):
            sp=u.reg_read(ar.UC_ARM64_REG_SP)
            self.records.append({'kind':'native_policy_checkpoint','pc':hex(a),
                'registers':{f'x{i}':hex(self.reg(i)) for i in (0,21,22,23,24,26)},
                'stack_table':hex(int.from_bytes(u.mem_read(sp+0x208,8),'little')),
                'code_output':hex(int.from_bytes(u.mem_read(sp+0x460,8),'little')),
                'requirement_output':hex(int.from_bytes(u.mem_read(sp+0x3d8,8),'little'))})
        name=self.imports.get(a)
        if name:self.active_import=name
        if name=='libSystem/_strlen':
            self.steps+=1;args=[self.reg(i) for i in range(8)];text=self.defined_string(args[0])
            if text is None:return
            size=len(text.encode());self.records.append({'kind':'private_policy_import','name':name,'return_pc':hex(self.reg(30)),
                'args':[hex(v) for v in args],'length_bytes':size,'model':'bounded defined private C-string length'})
            self.ret(size);return
        if name=='libSystem/___strncat_chk':
            self.steps+=1;args=[self.reg(i) for i in range(8)]
            before=self.defined_string(args[0]);tail=self.defined_string(args[1])
            if before is None or tail is None:return
            result=before.encode()+tail.encode()[:args[2]]
            if len(result)+1>args[3]:self.stop('outside_fitting_private_strncat_model',required_bytes=len(result)+1,capacity_bytes=args[3]);return
            assert STACK<=args[0] and args[0]+args[3]<=STACK+0x80000 and args[3]<=4096
            u.mem_write(args[0],result+b'\0')
            self.records.append({'kind':'private_policy_import','name':name,'return_pc':hex(self.reg(30)),
                'args':[hex(v) for v in args],'before':before,'append':tail,'result_string':result.decode(),
                'model':'bounded fitting checked strncat; no native implementation or host memory effect'})
            self.ret(args[0]);return
        if name=='libSystem/_strncpy':
            self.steps+=1;args=[self.reg(i) for i in range(8)]
            text=self.defined_string(args[1])
            if text is None:return
            raw=text.encode();assert len(raw)<args[2]<=4096 and STACK<=args[0] and args[0]+args[2]<=STACK+0x80000
            u.mem_write(args[0],raw+bytes(args[2]-len(raw)))
            self.records.append({'kind':'private_policy_import','name':name,'return_pc':hex(self.reg(30)),
                'args':[hex(v) for v in args],'string_input':text,'written_bytes':args[2],
                'model':'bounded fitting strncpy including zero padding into private stack'})
            self.ret(args[0]);return
        if name=='libSystem/_xpc_dictionary_set_data':
            self.steps+=1;args=[self.reg(i) for i in range(8)]
            assert args[0]==REPLY and self.private_string(args[1])=='data' and args[3]<=0x40000
            if not self.check_heap(args[2],args[3]):return
            data=bytes(u.mem_read(args[2],args[3]));value={'type':'data','bytes':data.hex(),'size_bytes':args[3]}
            self.reply_fields['data']=value
            self.records.append({'kind':'private_policy_import','name':name,'return_pc':hex(self.reg(30)),
                'args':[hex(v) for v in args],'key':'data','value':value,'model':'explicit private data field; no native XPC operation'})
            self.ret();return
        if name in ('Security/_SecCodeCopyGuestWithAttributes','Security/_SecRequirementCreateWithString',
                    'Security/_SecCodeCheckValidity','CoreFoundation/_CFRelease'):
            self.steps+=1;args=[self.reg(i) for i in range(8)]
            e={'kind':'private_policy_import','name':name,'return_pc':hex(self.reg(30)),
                'args':[hex(v) for v in args]};self.records.append(e)
            if name=='Security/_SecCodeCopyGuestWithAttributes':
                assert args[0]==args[2]==0 and args[3]
                e.update({'attributes':self.cf_objects[args[1]],'output_before':bytes(u.mem_read(args[3],8)).hex(),
                    'status32':self.guest_status,'model':'explicit guest lookup status/output; no native identity lookup'})
                if self.guest_status==0:
                    value=0 if self.guest_null else GUEST
                    u.mem_write(args[3],struct.pack('<Q',value))
                    if value:self.cf_objects[value]={'type':'sec_code','origin':'synthetic peer-audit guest lookup'}
                    e['output_after']=hex(value)
                self.ret(self.guest_status&0xffffffff);return
            if name=='Security/_SecRequirementCreateWithString':
                assert args[1]==0 and args[2]
                string=self.original_cfstring(args[0])
                e.update({'requirement_string':string,'status32':self.parse_status,
                    'output_before':bytes(u.mem_read(args[2],8)).hex(),
                    'model':'explicit requirement parse status/opaque output; no native Security call'})
                if self.parse_status==0:
                    value=0 if self.requirement_null else REQUIREMENT;u.mem_write(args[2],struct.pack('<Q',value))
                    if value:self.cf_objects[value]={'type':'sec_requirement','text':string['text']}
                    e['output_after']=hex(value)
                self.ret(self.parse_status&0xffffffff);return
            if name=='Security/_SecCodeCheckValidity':
                e.update({'code':self.cf_objects.get(args[0]),'requirement':self.cf_objects.get(args[2]),
                    'status32':self.validity_status,'model':'explicit validity status; no native signing/entitlement check'})
                if args[0]==0:self.stop('null_code_validity_boundary');return
                assert args[0]==GUEST and args[1]==0
                assert args[2] in (REQUIREMENT,0)
                self.ret(self.validity_status&0xffffffff);return
            e.update({'opaque_object':self.cf_objects.get(args[0]),'model':'record CF release only; no native reference-count semantics'})
            if args[0] not in self.cf_objects:self.stop('unmodeled_cf_release_object',object=hex(args[0]));return
            self.ret();return
        if name=='libobjc/_objc_msgSend':
            self.steps+=1;args=[self.reg(i) for i in range(8)]
            e={'kind':'private_policy_import','name':name,'return_pc':hex(self.reg(30)),
                'args':[hex(v) for v in args],'receiver':self.imports.get(args[0],hex(args[0])),
                'selector':self.private_string(args[1]),'receiver_object':self.describe(args[0]),
                'argument_objects':[self.describe(v) for v in args[2:4]],'model':'stop before Objective-C method execution'}
            self.records.append(e)
            if e['receiver']=='Foundation/_OBJC_CLASS_$_NSFileManager' and e['selector']=='defaultManager':
                self.objc_objects[FILE_MANAGER]={'type':'file_manager'}
                e.update({'result':hex(FILE_MANAGER),'model':'opaque file-manager object; no file operation'})
                self.ret(FILE_MANAGER);return
            if e['receiver']=='Foundation/_OBJC_CLASS_$_NSString' and e['selector']=='stringWithUTF8String:':
                text=self.defined_string(args[2])
                if text is None:return
                a=self.cf_next;self.cf_next+=0x10;self.objc_objects[a]={'type':'string','text':text}
                e.update({'string_input':text,'result':hex(a),'model':'explicit private NSString value; no native Foundation method'})
                self.ret(a);return
            if args[0]==FILE_MANAGER and e['selector']=='isSignedByDeveloperFileAtPath:basicCheck:' and self.developer_result is not None:
                assert self.objc_objects[args[2]]['type']=='string' and args[3]==1
                e.update({'result_bool':bool(self.developer_result),'model':'explicit developer-signature boolean only; no filesystem/signature check'})
                self.ret(int(bool(self.developer_result)));return
            self.stop('objc_policy_boundary',selector=e['selector']);return
        if name in ('libobjc/_objc_retainAutoreleasedReturnValue','libobjc/_objc_retain','libobjc/_objc_release'):
            self.steps+=1;obj=self.reg(0)
            self.records.append({'kind':'private_policy_import','name':name,'return_pc':hex(self.reg(30)),
                'args':[hex(self.reg(i)) for i in range(8)],'object':self.describe(obj),
                'model':'opaque ARC boundary only; no native reference count'})
            if obj and obj not in self.objc_objects and obj not in self.cf_objects:self.stop('unknown_arc_object',object=hex(obj));return
            self.ret(obj if name!='libobjc/_objc_release' else None);return
        return super().code(u,a,n,user)


def main():
    evidence=ROOT/'arcade_service_peer_profiles.json';profiles=json.loads(evidence.read_text())['profiles']
    original=next(r for r in profiles if r['label']=='event_daemon_packet')
    data=bytes.fromhex(original['synthetic_event']['data_hex']);rows=[]
    for label,kw in [('policy_success',{}),('guest_failure',{'guest_status':-67050}),
            ('requirement_failure',{'requirement_status':-50}),('validity_failure',{'validity_status':-67050}),
            ('guest_null_success',{'guest_null':True}),('requirement_null_success',{'requirement_null':True}),
            ('developer_true',{'developer_result':True}),('developer_false',{'developer_result':False}),
            ('developer_true_volatile',{'developer_result':True,'volatile_seed':0x91a2b3c4d5e6f708}),
            ('developer_false_volatile',{'developer_result':False,'volatile_seed':0x91a2b3c4d5e6f708})]:
        p=PolicyProbe(**kw);entry=p.run(p.s.entry,label=label+'_main')
        assert entry['stop_reason']=='xpc_main_callback_boundary'
        callback=int(entry['records'][-1]['callback'],16);peer=p.run(callback,PEER,label=label+'_peer')
        assert peer['stop_reason']=='returned_to_fixture'
        r=p.event('dictionary',data,label);r.update({'fresh_prefix':[entry,peer],
            'policy_probe_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'synthetic_policy':kw,
            'packet_source_profiles_sha256':hashlib.sha256(evidence.read_bytes()).hexdigest(),
            'policy_scope':__doc__,'full_goal_complete':False})
        rows.append(r)
        print(json.dumps({'label':label,'steps':r['steps'],'stop_reason':r['stop_reason'],'last_records':r['records'][-8:]}),flush=True)
    (ROOT/'arcade_service_policy_profiles.json').write_text(json.dumps({'scope':__doc__,'profiles':rows},indent=2)+'\n')


if __name__=='__main__':main()
