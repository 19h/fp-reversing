#!/usr/bin/env python3
"""Bounded private original-service entry/peer-registration probe.

Only an analyst-side Unicorn CPU runs. External interfaces are explicit opaque
models; unknown imports/data accesses and system instructions stop. PAC is
bypassed, and no native peer, XPC send, signing check or receipt operation runs.
O(N+F+B) bounded time, O(B+N) space; N<=2,000,000 instructions per phase.
"""
import hashlib
import json
from pathlib import Path
import struct
import unicorn as uc
import unicorn.arm64_const as ar
from arcade_service_reader import Service,ROOT,CS,THIN_SHA

STACK=0x70000000
IMPORTS=0x6000000000
HALT=0x6001000000
PEER=0x5000000000
BLOCK=0x5100000000
DATA=0x5300000000
EVENT=PEER+0x100
REPLY=PEER+0x200
AUDIT_KEY=PEER+0x800


class Probe:
    def __init__(self,requirement_status=0,reply_creation_succeeds=True):
        self.s=Service();self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM)
        self.u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX)
        for seg in self.s.meta['segments']:
            if seg['name']=='__PAGEZERO' or not seg['vm_size']:continue
            assert seg['address']%4096==0
            self.u.mem_map(seg['address'],(seg['vm_size']+4095)&~4095,self.s.segment_protections[seg['name']])
            self.u.mem_write(seg['address'],self.s.data[seg['file_offset']:seg['file_offset']+seg['file_size']])
        self.u.mem_map(STACK,0x80000);self.u.mem_map(IMPORTS,0x100000);self.u.mem_map(HALT,4096);self.u.mem_map(PEER,4096)
        self.u.mem_map(BLOCK,4096);self.u.mem_map(DATA,0x10000)
        self.imports={};self.symbols={}
        for a,r in self.s.decoded_fixups.items():
            if r['bind']:
                name=r['target']
                if name not in self.symbols:
                    ptr=IMPORTS+len(self.symbols)*16;self.symbols[name]=ptr;self.imports[ptr]=name
                value=(self.symbols[name]+r['total_addend'])&((1<<64)-1)
            else:value=int(r['target'],16)
            self.u.mem_write(a,struct.pack('<Q',value))
        guard=self.symbols['libSystem/___stack_chk_guard'];self.u.mem_write(guard,struct.pack('<Q',0x67132489a19b55e2))
        allocator=self.symbols['CoreFoundation/_kCFAllocatorDefault'];self.u.mem_write(allocator,bytes(8))
        audit_key=self.symbols['Security/_kSecGuestAttributeAudit'];self.u.mem_write(audit_key,struct.pack('<Q',AUDIT_KEY))
        self.u.hook_add(uc.UC_HOOK_CODE,self.code)
        self.u.hook_add(uc.UC_HOOK_MEM_READ,self.read)
        self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.write)
        self.requirement_status=requirement_status;self.decoded={};self.records=[];self.visited=set();self.steps=0;self.pac=[];self.stopped=None
        self.event_block_bytes=None;self.event_kind='dictionary';self.request_data=None;self.reply_fields={}
        self.allocations=[]
        self.cf_objects={};self.cf_next=PEER+0x300
        self.reply_creation_succeeds=reply_creation_succeeds

    def reg(self,n):return self.u.reg_read(ar.UC_ARM64_REG_X0+n if n<=28 else (ar.UC_ARM64_REG_X29 if n==29 else ar.UC_ARM64_REG_X30))
    def setreg(self,n,v):self.u.reg_write(ar.UC_ARM64_REG_X0+n if n<=28 else (ar.UC_ARM64_REG_X29 if n==29 else ar.UC_ARM64_REG_X30),v)
    def stop(self,reason,**kw):self.stopped=reason;self.records.append({'kind':'stop','reason':reason,**kw});self.u.emu_stop()
    def ret(self,v=None):
        if v is not None:self.setreg(0,v&((1<<64)-1))
        self.u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
    def private_string(self,a):
        out=bytearray()
        for j in range(4096):
            b=bytes(self.u.mem_read(a+j,1))
            if b==b'\0':return out.decode()
            out+=b
        raise ValueError('private string budget')
    def read(self,u,access,a,n,value,user):
        if IMPORTS<=a<IMPORTS+0x100000:
            base=IMPORTS+((a-IMPORTS)//16)*16;name=self.imports.get(base)
            if name not in ('libSystem/___stack_chk_guard','CoreFoundation/_kCFAllocatorDefault','Security/_kSecGuestAttributeAudit'):
                self.stop('unmodeled_imported_data',address=hex(a),size_bytes=n,name=name,pc=hex(u.reg_read(ar.UC_ARM64_REG_PC)))
        if PEER<=a<PEER+4096:self.stop('unmodeled_opaque_peer_read',address=hex(a),size_bytes=n)
        if DATA<=a<DATA+0x10000 and (self.request_data is None or a+n>DATA+len(self.request_data)):
            self.stop('outside_defined_request_data',address=hex(a),size_bytes=n)
        self.check_heap(a,n)

    def check_heap(self,a,n):
        for h in self.allocations:
            if h['address']<=a<h['address']+h['pages']:
                k=a-h['address']
                if h['freed'] or k+n>h['extent'] or not all(h['known'][k:k+n]):
                    self.stop('undefined_private_heap_read',address=hex(a),size_bytes=n,allocation=hex(h['address']),freed=h['freed'])
                    return False
        return True

    def write(self,u,access,a,n,value,user):
        for h in self.allocations:
            if h['address']<=a<h['address']+h['pages']:
                k=a-h['address']
                if h['freed'] or k+n>h['extent']:self.stop('outside_private_heap_write',address=hex(a),size_bytes=n);return
                h['known'][k:k+n]=bytes([1])*n

    def code(self,u,a,n,user):
        self.steps+=1
        if a==HALT:self.stop('returned_to_fixture',result=hex(self.reg(0)));return
        if a in self.imports:
            name=self.imports[a];args=[self.reg(i) for i in range(8)]
            e={'kind':'private_import','name':name,'return_pc':hex(self.reg(30)),'args':[hex(v) for v in args]};self.records.append(e)
            if name=='libSystem/_xpc_main':
                e['callback']=hex(args[0]);self.stop('xpc_main_callback_boundary',callback=hex(args[0]));return
            if name=='libSystem/_xpc_connection_set_peer_code_signing_requirement':
                assert args[0]==PEER;e.update({'requirement':self.private_string(args[1]),'modeled_return_status':self.requirement_status,
                    'model':'record literal requirement; explicit status, no native enforcement'})
                self.ret(self.requirement_status);return
            if name=='libSystem/_xpc_connection_set_event_handler':
                assert args[0]==PEER;b=bytes(u.mem_read(args[1],40));self.event_block_bytes=b
                e.update({'block_bytes_40':b.hex(),'block_invoke':hex(struct.unpack_from('<Q',b,16)[0]),'captured_peer':hex(struct.unpack_from('<Q',b,32)[0]),
                    'model':'record block only; no copy or invocation'})
                self.ret();return
            if name=='libSystem/_xpc_connection_resume':
                assert args[0]==PEER;e['model']='record only; no native activation';self.ret();return
            if name=='libSystem/___chkstk_darwin':e['model']='private stack probing skipped';self.ret();return
            if name=='libSystem/_time':
                assert args[0]==0;e.update({'result_seconds':1700000000,'model':'explicit synthetic time; no host clock query'})
                self.ret(1700000000);return
            if name=='libSystem/_arc4random':
                e.update({'result':'0x12345678','model':'explicit synthetic random word; no host random query'})
                self.ret(0x12345678);return
            if name=='libSystem/_arc4random_uniform':
                assert 0<args[0]<=0xffffffff;value=0x12345678%args[0]
                e.update({'upper_bound':args[0],'result':value,'model':'explicit synthetic admissible uniform result; distribution not modeled'})
                self.ret(value);return
            if name=='libSystem/_malloc':
                size=args[0]
                if not size:e.update({'result':'0x0','model':'explicit permitted malloc(0) result'});self.ret(0);return
                if size>0x40000 or len(self.allocations)>=128:self.stop('private_allocation_budget',size_bytes=size);return
                a=0x5200000000+len(self.allocations)*0x80000;pages=(size+4095)&~4095
                u.mem_map(a,pages);u.mem_write(a,bytes([0xa5])*size)
                self.allocations.append({'address':a,'extent':size,'pages':pages,'freed':False,'known':bytearray(size)})
                e.update({'result':hex(a),'size_bytes':size,'initial_bytes_unknown':True,'model':'private allocation, bounded definedness'})
                self.ret(a);return
            if name=='libSystem/_free':
                if args[0]:
                    h=next(h for h in self.allocations if h['address']==args[0]);assert not h['freed'];h['freed']=True
                e['model']='private lifetime retirement only';self.ret();return
            if name=='CoreFoundation/_CFDataCreate':
                assert args[0]==0 and args[2]==32
                data=bytes(u.mem_read(args[1],args[2]));assert data==struct.pack('<8I',501,501,20,501,20,1234,100,1)
                a=self.cf_next;self.cf_next+=0x10;self.cf_objects[a]={'type':'data','bytes':data.hex()}
                e.update({'size_bytes':args[2],'data_hex':data.hex(),'result':hex(a),'model':'opaque synthetic CFData; no framework execution'})
                self.ret(a);return
            if name=='CoreFoundation/_CFDictionaryCreateMutable':
                assert args[0]==args[1]==0
                assert args[2]==self.symbols['CoreFoundation/_kCFTypeDictionaryKeyCallBacks']
                assert args[3]==self.symbols['CoreFoundation/_kCFTypeDictionaryValueCallBacks']
                a=self.cf_next;self.cf_next+=0x10;self.cf_objects[a]={'type':'dictionary','fields':{}}
                e.update({'result':hex(a),'model':'opaque synthetic CFDictionary; callbacks recorded, not invoked'})
                self.ret(a);return
            if name=='CoreFoundation/_CFDictionarySetValue':
                obj=self.cf_objects[args[0]];assert obj['type']=='dictionary' and args[1]==AUDIT_KEY
                value=self.cf_objects[args[2]];assert value['type']=='data'
                obj['fields']['kSecGuestAttributeAudit']=value;e.update({'key_symbol':'Security/_kSecGuestAttributeAudit',
                    'value':value,'model':'private typed dictionary field only'})
                self.ret();return
            if name=='Security/_SecCodeCopyGuestWithAttributes':
                assert args[0]==args[2]==0 and args[3]
                e.update({'attributes':self.cf_objects[args[1]],'model':'stop before native guest lookup or any modeled result'})
                self.stop('security_guest_lookup_boundary');return
            if name=='libSystem/_xpc_get_type':
                assert args[0]==EVENT
                symbol='libSystem/__xpc_type_'+self.event_kind
                assert symbol in self.symbols,symbol
                e.update({'type_symbol':symbol,'model':'explicit synthetic event type','result':hex(self.symbols[symbol])})
                self.ret(self.symbols[symbol]);return
            if name=='libSystem/_xpc_connection_get_audit_token':
                assert args[0]==PEER and args[1]
                words=[501,501,20,501,20,1234,100,1];token=struct.pack('<8I',*words)
                u.mem_write(args[1],token);e.update({'audit_words':words,'audit_bytes_32':token.hex(),
                    'model':'explicit synthetic audit token; no native peer/process lookup'})
                self.ret();return
            if name=='libSystem/_xpc_dictionary_get_data':
                assert args[0]==EVENT
                key=self.private_string(args[1]);assert key=='data',key;assert args[2]
                e.update({'key':key,'size_bytes':len(self.request_data) if self.request_data is not None else 0,
                    'model':'explicit private request bytes; no native XPC data'})
                u.mem_write(args[2],struct.pack('<Q',len(self.request_data) if self.request_data is not None else 0))
                self.ret(DATA if self.request_data is not None else 0);return
            if name=='libSystem/_xpc_dictionary_create_reply':
                assert args[0]==EVENT;self.reply_fields={};result=REPLY if self.reply_creation_succeeds else 0
                e.update({'result':hex(result),'model':'explicit synthetic reply creation result; native eligibility unknown for error event'})
                self.ret(result);return
            if name=='libSystem/_xpc_dictionary_set_int64':
                if args[0]==0:self.stop('null_reply_field_set_boundary',api=name);return
                assert args[0]==REPLY;key=self.private_string(args[1]);value=args[2]-(1<<64) if args[2]>>63 else args[2]
                self.reply_fields[key]={'type':'int64','value':value};e.update({'key':key,'value':value,'model':'private reply field only'});self.ret();return
            if name=='libSystem/_xpc_connection_send_message':
                assert args[:2]==[PEER,REPLY];e.update({'reply_fields':self.reply_fields,'model':'record only; no native send'})
                self.stop('outgoing_service_reply_boundary');return
            if name=='libSystem/_xpc_release':e['model']='opaque release boundary; no native reference count';self.ret();return
            self.stop('unmodeled_import',name=name);return
        seg=next((s for s in self.s.meta['segments'] if s['address']<=a and a+4<=s['address']+s['file_size'] and self.s.segment_protections[s['name']]&4),None)
        if not seg:self.stop('outside_original_executable',pc=hex(a));return
        raw=bytes(u.mem_read(a,4));assert raw==self.s.read(a,4);self.visited.add(a)
        i=self.decoded.get(a)
        if i is None:i=next(CS.disasm(raw,a));self.decoded[a]=i
        m=i.mnemonic
        if m in ('braa','braaz','brab','brabz','blraa','blraaz','blrab','blrabz'):
            regs=i.op_str.split(',');target=self.reg(int(regs[0].strip()[1:]));mod=self.reg(int(regs[1].strip()[1:])) if len(regs)>1 else 0
            self.pac.append({'site':hex(a),'instruction':m,'target':hex(target),'modifier':hex(mod),'authentication':'explicit private bypass'})
            if m.startswith('blr'):self.setreg(30,a+4)
            u.reg_write(ar.UC_ARM64_REG_PC,target);return
        if m in ('pacibsp','paciasp','autibsp','autiasp','xpaclri','bti','paciza','pacia','pacda','autia','autiza','xpaci'):
            self.pac.append({'site':hex(a),'instruction':m,'authentication':'explicit private bypass'});u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
        if m in ('retab','retaa'):u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30));return
        if m in ('svc','hvc','smc') or m.startswith(('pac','aut','xpac')):self.stop('blocked_instruction',pc=hex(a),instruction=m)

    def run(self,start,arg0=0,label='main',arg1=0):
        for j in range(31):self.setreg(j,0)
        self.setreg(0,arg0);self.setreg(1,arg1);self.setreg(30,HALT);self.u.reg_write(ar.UC_ARM64_REG_SP,STACK+0x7f000)
        self.records=[];self.visited=set();self.steps=0;self.pac=[];self.stopped=None
        try:self.u.emu_start(start,HALT+4,count=2000000)
        except uc.UcError as e:self.stop('private_cpu_error',message=str(e),pc=hex(self.u.reg_read(ar.UC_ARM64_REG_PC)))
        if not self.stopped:self.stop('private_instruction_budget')
        h=hashlib.sha256()
        for a in sorted(self.visited):
            raw=bytes(self.u.mem_read(a,4));assert raw==self.s.read(a,4)
            h.update(struct.pack('<Q',a));h.update(raw)
        return {'label':label,'start':hex(start),'argument0':hex(arg0),'source_sha256':THIN_SHA,'steps':self.steps,'stop_reason':self.stopped,
            'records':self.records,'visited_original_instructions':[hex(a) for a in sorted(self.visited)],'pac_bypass':self.pac,
            'visited_original_instruction_bytes_sha256':h.hexdigest(),
            'native_target_executed':False,'native_peer_authentication_executed':False,
            'generator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'reader_sha256':hashlib.sha256((ROOT/'arcade_service_reader.py').read_bytes()).hexdigest()}

    def event(self,kind,data,label):
        assert self.event_block_bytes is not None
        self.event_kind=kind;self.request_data=data
        self.u.mem_write(BLOCK,self.event_block_bytes)
        if data is not None:self.u.mem_write(DATA,data)
        invoke=struct.unpack_from('<Q',self.event_block_bytes,16)[0]
        r=self.run(invoke,BLOCK,label,arg1=EVENT)
        r['synthetic_event']={'kind':kind,'data_hex':None if data is None else data.hex(),'block_bytes_40':self.event_block_bytes.hex()}
        return r


def main():
    rows=[]
    for status in (0,1):
        p=Probe(status);r=p.run(p.s.entry,label=f'main_requirement_status_{status}');rows.append(r)
        assert r['stop_reason']=='xpc_main_callback_boundary',r['records']
        callback=int(r['records'][-1]['callback'],16)
        rows.append(p.run(callback,PEER,label=f'peer_requirement_status_{status}'))
    dp=json.loads((ROOT/'arcade_reply_profiles.json').read_text())['profiles'][0]
    request=next(e['outgoing_request'] for e in dp['calls'] if e['name']=='libSystem/_xpc_connection_send_message_with_reply_sync')
    packet=bytes.fromhex(request['fields']['data']['value']['bytes'])
    for label,kind,data,create in [('event_error','error',None,True),('event_missing_data','dictionary',None,True),
            ('event_empty_data','dictionary',b'',True),('event_daemon_packet','dictionary',packet,True),
            ('event_error_no_reply','error',None,False),('event_missing_data_no_reply','dictionary',None,False)]:
        p=Probe(0,create);prefix=p.run(p.s.entry,label=label+'_main')
        callback=int(prefix['records'][-1]['callback'],16);registration=p.run(callback,PEER,label=label+'_peer')
        r=p.event(kind,data,label);r['fresh_prefix']=[prefix,registration];rows.append(r)
    (ROOT/'arcade_service_peer_profiles.json').write_text(json.dumps({'scope':__doc__,'profiles':rows,
        'daemon_packet_source_profiles':'arcade_reply_profiles.json',
        'daemon_packet_source_profiles_sha256':hashlib.sha256((ROOT/'arcade_reply_profiles.json').read_bytes()).hexdigest()},indent=2)+'\n')
    for r in rows:print(json.dumps({k:v for k,v in r.items() if k in ('label','steps','stop_reason','records')}))


if __name__=='__main__':main()
