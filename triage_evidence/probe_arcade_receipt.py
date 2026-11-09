#!/usr/bin/env python3
"""Original receipt Objective-C dispatch with explicit private file-data inputs.

Uses original class/method metadata, private zeroed Objective-C instances and
explicit NSObject/Foundation boundaries. No native ObjC runtime, file read,
framework, signing check, loader or target IPC runs. Frozen policy/heap/PAC/syscall
guards remain. Private phases are capped at2M steps by the parent.
"""
import hashlib
import json
from pathlib import Path
import struct
import unicorn.arm64_const as ar
from probe_arcade_service_policy import PolicyProbe,ROOT,PEER
from arcade_objc_metadata import recover as objc_metadata

OBJC_HEAP=0x5400000000
FILE_BYTES=0x5500000000
CMS_CONTEXT=PEER+0xb00
CMS_MESSAGE=PEER+0xb10


class ReceiptProbe(PolicyProbe):
    def __init__(self,*,file_data=None,alloc_null=False,volatile_seed=None,cms_create_status=0,cms_update_status=0,cms_finish_status=0,cms_mode='stop'):
        super().__init__(developer_result=False,volatile_seed=volatile_seed)
        self.file_data=file_data;self.alloc_null=alloc_null
        self.cms_mode=cms_mode;self.cms_create_status=cms_create_status;self.cms_update_status=cms_update_status;self.cms_finish_status=cms_finish_status
        self.cms_contexts={};self.cms_messages={}
        self.receipt_helper_args=None
        self.objc_meta=objc_metadata(self.s);self.class_names={int(r['class_address'],16):r['name'] for r in self.objc_meta['classes']}
        self.method_map={(r['class'],r['kind'],r['selector']):r for r in self.objc_meta['methods']}
        self.objc_instances={};self.u.mem_map(FILE_BYTES,0x10000)
        if file_data is not None:
            assert len(file_data)<=0x10000;self.u.mem_write(FILE_BYTES,file_data)

    def read(self,u,access,a,n,value,user):
        if FILE_BYTES<=a<FILE_BYTES+0x10000 and (self.file_data is None or a+n>FILE_BYTES+len(self.file_data)):
            self.stop('outside_defined_private_receipt_data',address=hex(a),size_bytes=n);return
        for ptr,r in self.objc_instances.items():
            if ptr<=a<ptr+4096 and a+n>ptr+r['size_bytes']:
                self.stop('outside_private_objc_instance_read',address=hex(a),size_bytes=n);return
        return super().read(u,access,a,n,value,user)

    def write(self,u,access,a,n,value,user):
        for ptr,r in self.objc_instances.items():
            if ptr<=a<ptr+4096:
                if a+n>ptr+r['size_bytes']:self.stop('outside_private_objc_instance_write',address=hex(a),size_bytes=n);return
                self.records.append({'kind':'native_receipt_ivar_write','pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),
                    'instance':hex(ptr),'offset_bytes':a-ptr,'size_bytes':n,'value':hex(value&((1<<(8*n))-1))})
        return super().write(u,access,a,n,value,user)

    def event_record(self,name,args,**kw):
        e={'kind':'private_receipt_import','name':name,'return_pc':hex(self.reg(30)),
            'args':[hex(v) for v in args],**kw};self.records.append(e);return e

    def code(self,u,a,n,user):
        if a==0x100000dc8:
            args=[self.reg(i) for i in range(7)];self.receipt_helper_args=args
            self.records.append({'kind':'native_receipt_helper_entry','pc':hex(a),'path':self.defined_string(args[0]),
                'count_u32':args[1]&0xffffffff,'arguments':[hex(v) for v in args],
                'output_initial':{'buffer16':bytes(u.mem_read(args[2],16)).hex(),'word64':bytes(u.mem_read(args[3],8)).hex(),
                    'object64':bytes(u.mem_read(args[4],8)).hex(),'developer_byte':bytes(u.mem_read(args[5],1)).hex(),
                    'kind32':bytes(u.mem_read(args[6],4)).hex()}})
        if a==0x100000f60 and self.receipt_helper_args is not None:
            args=self.receipt_helper_args
            self.records.append({'kind':'native_receipt_helper_exit','pc':hex(a),'status32':hex(self.reg(0)&0xffffffff),
                'output_final':{'buffer16':bytes(u.mem_read(args[2],16)).hex(),'word64':bytes(u.mem_read(args[3],8)).hex(),
                    'object64':bytes(u.mem_read(args[4],8)).hex(),'developer_byte':bytes(u.mem_read(args[5],1)).hex(),
                    'kind32':bytes(u.mem_read(args[6],4)).hex()}})
        name=self.imports.get(a)
        if name:self.active_import=name
        if name and name.startswith('Security/_SecCms') and self.cms_mode!='stop':
            self.steps+=1;args=[self.reg(i) for i in range(8)]
            e=self.event_record(name,args,model='explicit synthetic CMS API status/object/lifetime; no native decoding')
            if name=='Security/_SecCmsDecoderCreate':
                assert args[:7]==[0]*7 and args[7]
                e.update({'output_before':bytes(u.mem_read(args[7],8)).hex(),'status32':self.cms_create_status})
                if self.cms_create_status==0:
                    self.cms_contexts[CMS_CONTEXT]={'alive':True,'decoder_core_alive':True}
                    u.mem_write(args[7],struct.pack('<Q',CMS_CONTEXT));e['output_after']=hex(CMS_CONTEXT)
                else:e['failure_output_written']=False
                self.ret(self.cms_create_status&0xffffffff);return
            if name=='Security/_SecCmsDecoderUpdate':
                assert args[0]==CMS_CONTEXT and self.cms_contexts[args[0]]['alive'] and args[1]==FILE_BYTES and args[2]==len(self.file_data)
                e.update({'status32':self.cms_update_status,'data_hex':self.file_data.hex(),'length_bytes':args[2]})
                if self.cms_update_status:self.cms_contexts[args[0]]['decoder_core_alive']=False
                self.ret(self.cms_update_status&0xffffffff);return
            if name=='Security/_SecCmsDecoderFinish':
                assert args[0]==CMS_CONTEXT and self.cms_contexts[args[0]]['alive'] and args[1]
                self.cms_contexts[args[0]]['alive']=False
                e.update({'status32':self.cms_finish_status,'context_retired':True,
                    'lifetime_model':'installed reference Finish deallocates outer context on both result paths'})
                if self.cms_finish_status==0:
                    self.cms_messages[CMS_MESSAGE]={'alive':True};u.mem_write(args[1],struct.pack('<Q',CMS_MESSAGE));e['output_after']=hex(CMS_MESSAGE)
                self.ret(self.cms_finish_status&0xffffffff);return
            if name=='Security/_SecCmsDecoderDestroy':
                state=self.cms_contexts.get(args[0]);e['context_state']=None if state is None else dict(state)
                if state is None:self.stop('unknown_cms_context_destroy_boundary',context=hex(args[0]));return
                if not state['alive']:self.stop('retired_cms_context_destroy_boundary',context=hex(args[0]));return
                state['alive']=False;e['context_retired']=True;self.ret();return
            if name=='Security/_SecCmsMessageGetContent':
                assert args[0]==CMS_MESSAGE and self.cms_messages[args[0]]['alive']
                e.update({'result':'0x0','model':'explicit absent decoded message content; no valid CMS assertion'})
                self.ret(0);return
            if name=='Security/_SecCmsMessageDestroy':
                assert args[0]==CMS_MESSAGE and self.cms_messages[args[0]]['alive'];self.cms_messages[args[0]]['alive']=False
                e['message_retired']=True;self.ret();return
            self.stop('unmodeled_receipt_cms_import',name=name);return
        if name=='libobjc/_objc_alloc':
            self.steps+=1;args=[self.reg(i) for i in range(8)];cls=args[0];assert cls in self.class_names
            if self.alloc_null:
                self.event_record(name,args,result='0x0',model='explicit Objective-C allocation NULL');self.ret(0);return
            ro=self.s.qword(cls+32)&~7;size=struct.unpack('<I',self.s.read(ro+8,4))[0];assert 8<=size<=4096
            ptr=OBJC_HEAP+len(self.objc_instances)*0x10000;u.mem_map(ptr,4096);u.mem_write(ptr,bytes(size));u.mem_write(ptr,struct.pack('<Q',cls))
            self.objc_instances[ptr]={'class':self.class_names[cls],'class_address':hex(cls),'size_bytes':size}
            self.objc_objects[ptr]={'type':'original_objc_instance',**self.objc_instances[ptr]}
            self.event_record(name,args,result=hex(ptr),size_bytes=size,model='private zeroed instance from original class_ro size; isa is synthetic unauthed class reference')
            self.ret(ptr);return
        if name=='libobjc/_objc_msgSendSuper2':
            self.steps+=1;args=[self.reg(i) for i in range(8)];ptr,cls=struct.unpack('<2Q',u.mem_read(args[0],16));sel=self.private_string(args[1])
            assert ptr in self.objc_instances and cls in self.class_names and sel=='init'
            self.event_record(name,args,objc_super_bytes=bytes(u.mem_read(args[0],16)).hex(),selector=sel,
                result=hex(ptr),model='explicit NSObject init returns private receiver; no superclass method executes')
            self.ret(ptr);return
        if name=='libobjc/_objc_msgSend':
            args=[self.reg(i) for i in range(8)];sel=self.private_string(args[1]);obj=args[0]
            cls=self.class_names.get(obj);kind='class'
            if obj in self.objc_instances:cls=self.objc_instances[obj]['class'];kind='instance'
            method=self.method_map.get((cls,kind,sel))
            if method:
                self.steps+=1;target=int(method['implementation'],16)
                self.event_record(name,args,selector=sel,metadata_entry=method['entry'],class_name=cls,method_kind=kind,
                    implementation=hex(target),model='explicit dispatch to original metadata implementation; runtime replacement not modeled')
                u.reg_write(ar.UC_ARM64_REG_PC,target);return
            if sel=='length' and obj in self.objc_objects:
                self.steps+=1;r=self.objc_objects[obj]
                if r['type']=='string':assert r['text'].isascii();size=len(r['text'])
                else:assert r['type']=='data';size=len(bytes.fromhex(r['bytes']))
                self.event_record(name,args,selector=sel,result_length=size,model='explicit ASCII NSString/NSData length; no Foundation execution')
                self.ret(size);return
            if sel=='dataWithContentsOfFile:' and self.imports.get(obj)=='CoreFoundation/_OBJC_CLASS_$_NSData':
                self.steps+=1;path=self.objc_objects[args[2]];assert path['type']=='string'
                value=0
                if self.file_data is not None:
                    value=self.cf_next;self.cf_next+=0x10;self.objc_objects[value]={'type':'data','bytes':self.file_data.hex(),'buffer':hex(FILE_BYTES)}
                self.event_record(name,args,selector=sel,path=path['text'],result=hex(value),
                    data_hex=None if self.file_data is None else self.file_data.hex(),model='explicit synthetic file data or NULL; no host file read')
                self.ret(value);return
            if sel=='bytes' and obj in self.objc_objects and self.objc_objects[obj]['type']=='data':
                self.steps+=1;ptr=int(self.objc_objects[obj]['buffer'],16)
                self.event_record(name,args,selector=sel,result=hex(ptr),model='pointer to defined private NSData bytes');self.ret(ptr);return
            if obj==0:
                self.steps+=1;self.event_record(name,args,selector=sel,result='0x0',model='explicit nil scalar/pointer message result; no FP/aggregate nil ABI claim')
                self.ret(0);return
        return super().code(u,a,n,user)


def main():
    evidence=ROOT/'arcade_service_peer_profiles.json';source=json.loads(evidence.read_text())['profiles']
    packet=bytes.fromhex(next(r for r in source if r['label']=='event_daemon_packet')['synthetic_event']['data_hex']);rows=[]
    for label,kw in [('receipt_missing',{}),('receipt_empty',{'file_data':b''}),
            ('receipt_short_data',{'file_data':b'\x30\x00'}),('receipt_allocation_null',{'alloc_null':True}),
            ('receipt_missing_volatile',{'volatile_seed':0x8172635445362718}),
            ('cms_create_failure',{'file_data':b'\x30\x00','cms_mode':'explicit','cms_create_status':-26275}),
            ('cms_update_failure',{'file_data':b'\x30\x00','cms_mode':'explicit','cms_update_status':-26275}),
            ('cms_finish_failure',{'file_data':b'\x30\x00','cms_mode':'explicit','cms_finish_status':-26275}),
            ('cms_missing_content',{'file_data':b'\x30\x00','cms_mode':'explicit'})]:
        p=ReceiptProbe(**kw);entry=p.run(p.s.entry,label=label+'_main');callback=int(entry['records'][-1]['callback'],16)
        peer=p.run(callback,PEER,label=label+'_peer');assert peer['stop_reason']=='returned_to_fixture'
        r=p.event('dictionary',packet,label);r.update({'fresh_prefix':[entry,peer],
            'receipt_probe_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'policy_probe_sha256':hashlib.sha256((ROOT/'probe_arcade_service_policy.py').read_bytes()).hexdigest(),
            'metadata_reader_sha256':hashlib.sha256((ROOT/'arcade_objc_metadata.py').read_bytes()).hexdigest(),
            'packet_source_profiles_sha256':hashlib.sha256(evidence.read_bytes()).hexdigest(),
            'synthetic_receipt':{'file_hex':None if kw.get('file_data') is None else kw['file_data'].hex(),
                'alloc_null':kw.get('alloc_null',False),'volatile_seed':kw.get('volatile_seed'),
                'cms_mode':kw.get('cms_mode','stop'),'cms_create_status':kw.get('cms_create_status',0),
                'cms_update_status':kw.get('cms_update_status',0),'cms_finish_status':kw.get('cms_finish_status',0)},
            'objc_instances':{hex(a):r for a,r in p.objc_instances.items()},'native_receipt_operations_executed':False,'full_goal_complete':False})
        rows.append(r);print(json.dumps({'label':label,'steps':r['steps'],'stop_reason':r['stop_reason'],'last_records':r['records'][-6:]}),flush=True)
    (ROOT/'arcade_receipt_profiles.json').write_text(json.dumps({'scope':__doc__,'profiles':rows},indent=2)+'\n')


if __name__=='__main__':main()
