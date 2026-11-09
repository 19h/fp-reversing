#!/usr/bin/env python3
"""Private original MIG61471 stub/application and protected continuation probes.

No target host IPC, files, framework, loader or callback executes. Explicit
API models and PAC bypass are distinct from native behavior. Unknown imports
and system instructions stop. An explicit exploration mode admits additional
original executable bytes for later static review; default uses reviewed spans.
Fixture input is synthetic.
"""
import hashlib
import json
from pathlib import Path
import struct
import re
import unicorn as uc
from daemon_rpc502_probe import Probe as Base,STACK,HALT,ar
from daemon_receive_tools import IMAGE,SOURCE,CS,ROOT
from resolve_kernel_collection_interfaces import commands

REQUEST=STACK+0x1000;REPLY=STACK+0x2000;OBJECTS=0x5000000000;OOL=0x5001000000
RANGES=[(0x1000054d8,0x10000559c),(0x1000057c0,0x100005b54),
    (0x10065ffd8,0x100660254),(0x10061a2d0,0x10061a990),
    (0x1004c244c,0x1004c3638),(0x100610388,0x1006103d8),
    (0x1005283ac,0x1005283f8),(0x100528dd8,0x100528e24)]
RANGES += [(0x100544124,0x10054416c)]
RANGES += [(0x10052566c,0x1005256d4)]
RANGES += [(0x1005aaee8,0x1005aaf80)]
RANGES += [(0x1004d7df4,0x1004d7e30)]
RANGES += [(0x10059848c,0x100598528)]
RANGES += [(0x10051e4e0,0x10051e600)]
RANGES += [(0x10049bbe4,0x10049bc34)]
RANGES += [(0x1006a09d8,0x1006a0a6c)]
RANGES += [(0x1007ccfd4,0x1007cd330)]
RANGES += [(0x100766c18,0x100766cdc)]
RANGES += [(0x100710f38,0x100710f78)]
RANGES += [(0x1006b85c4,0x1006b85f8)]
RANGES += [(0x1006d679c,0x1006d6838)]
RANGES += [(0x100939f64,0x10093a080)]
# Complete compiler-bounded branchless helper:5497 instructions, no calls,
# conditional branches or system instructions; mutable original byte banks.
RANGES += [(0x100444dfc,0x10044a3e0)]


class SubscriptionProbe(Base):
    def __init__(self,label,*,service_name=0x5107,stored_name=0x5107,count=4096,opaque=0x1122334455667788,malloc_null=False,explore_original_code=False,random_word=0x12345678,path_length=None,malloc_fail_at=None,xpc_mode='stop'):
        # Configure CPU before Base maps/writes memory. Restore the shared
        # constructor immediately; the Base source and other probes are unchanged.
        original_constructor=uc.Uc
        def make_private_cpu(*args,**kwargs):
            engine=original_constructor(*args,**kwargs);engine.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);return engine
        uc.Uc=make_private_cpu
        try:super().__init__()
        finally:uc.Uc=original_constructor
        self.label=label;self.service_name=service_name;self.stored_name=stored_name
        self.count=count;self.opaque=opaque;self.visited=set();self.calls=[]
        self.malloc_null=malloc_null;self.allocations=[]
        self.allowed_ranges=list(RANGES);self.initialization_prefix=None
        self.explore_original_code=explore_original_code;self.original_executable_ranges=[]
        self.random_word=random_word;self.random_calls=0;self.initializing=False
        self.rwlocks={}
        self.malloc_fail_at=malloc_fail_at;self.application_malloc_calls=0;self.argument_record_address=None
        self.xpc_mode=xpc_mode;self.xpc_objects={};self.xpc_next=OBJECTS+0x4000
        self.u.mem_map(OBJECTS,0x10000);self.u.mem_map(OOL,0x20000)
        payload=b'/private/synthetic/ArcadeFixture.app/Contents/MacOS/Game\0'
        if path_length is not None:
            assert 0<=path_length<4096;payload=bytes([0x43])*path_length+b'\0'
        self.payload=payload+bytes([0xa5])*(4096-len(payload));self.u.mem_write(OOL,self.payload)
        self.u.mem_write(0x1010c4d10,struct.pack('<Q',OBJECTS))
        for at,cmd,size in commands(IMAGE.data,0):
            if cmd!=0x19:continue
            va,vm,off,n=struct.unpack_from('<4Q',IMAGE.data,at+24);prot=struct.unpack_from('<I',IMAGE.data,at+60)[0]
            if prot&4 and va and n:self.original_executable_ranges.append((va,va+n))
            if va and vm:self.u.mem_protect(va&~4095,((va+vm+4095)&~4095)-(va&~4095),prot)

    def hook(self,u,address,size,user):
        if address==HALT:return super().hook(u,address,size,user)
        if address in self.imports:
            name=self.imports[address]
            if name=='libSystem/___chkstk_darwin':return super().hook(u,address,size,user)
            self.steps+=1;args=[self.reg(i) for i in range(8)]
            e={'kind':'private_import','name':name,'return_pc':hex(self.reg(30)),'args':[hex(a) for a in args]}
            self.records.append(e);self.calls.append(e)
            if name.startswith('libSystem/_xpc_') and self.xpc_mode!='stop':
                method=name.split('/')[-1]
                if method=='_xpc_add_bundle':
                    e.update({'bundle':self.private_string(args[0]),'flags':hex(args[1]),'model':'record only; no host bundle registration'})
                    self.return_model();return
                if method=='_xpc_connection_create':
                    a=0 if self.xpc_mode=='create_null' else self.xpc_next;self.xpc_next+=0x100
                    self.xpc_objects[a]={'type':'connection','name':self.private_string(args[0]),'queue':hex(args[1])}
                    e.update({'connection':self.xpc_objects[a],'result':hex(a),'model':'private opaque connection'})
                    self.return_model(a);return
                if method=='_xpc_dictionary_create':
                    if args[:3]!=[0,0,0]:self.stop('unmodeled_nonempty_xpc_dictionary_create',args=e['args']);return
                    a=self.xpc_next;self.xpc_next+=0x100;self.xpc_objects[a]={'type':'dictionary','fields':{}}
                    e['result']=hex(a);self.return_model(a);return
                if method.startswith('_xpc_dictionary_set_'):
                    obj=self.xpc_objects[args[0]];assert obj['type']=='dictionary';key=self.private_string(args[1]);kind=method.split('_set_',1)[1]
                    if kind=='string':value=self.private_string(args[2])
                    elif kind=='data':value={'bytes':self.private_read(args[2],args[3]).hex(),'size_bytes':args[3]}
                    elif kind in ('int64','uint64','bool'):value=args[2]
                    elif kind=='value':value={'object':hex(args[2]),'value':self.xpc_objects.get(args[2])}
                    else:self.stop('unmodeled_xpc_field_kind',kind=kind);return
                    obj['fields'][key]={'kind':kind,'value':value};e.update({'key':key,'value':value});self.return_model();return
                if method=='_xpc_connection_set_event_handler':
                    raw=self.private_read(args[1],32);e['block_header_32']=raw.hex();e['block_invoke']=hex(struct.unpack_from('<Q',raw,16)[0])
                    e['model']='record block only; no event/copy/invocation';self.return_model();return
                if method in ('_xpc_connection_resume','_xpc_connection_activate','_xpc_connection_set_target_queue','_xpc_release','_xpc_retain'):
                    e['model']='opaque API boundary only; no scheduling or native reference count';self.return_model(args[0] if method=='_xpc_retain' else None);return
                if method.startswith('_xpc_connection_send_message'):
                    e['message']=self.xpc_objects.get(args[1]);self.stop('outgoing_arcade_xpc_message_boundary',method=method,connection=hex(args[0]),message=e['message']);return
            if name=='libSystem/_os_log_type_enabled':e['model']='logging disabled';self.return_model(0);return
            if name=='libSystem/_arc4random':
                self.random_calls+=1;assert self.random_calls<=128
                e.update({'result':hex(self.random_word),'model':'explicit private random word','ordinal':self.random_calls})
                self.return_model(self.random_word);return
            if name=='libSystem/_gettimeofday':
                assert args[0] and args[1]==0
                u.mem_write(args[0],struct.pack('<qi4x',1700000000,123456))
                e.update({'seconds':1700000000,'microseconds':123456,'model':'private timeval fixture'})
                self.return_model(0);return
            if name in ('libSystem/_pthread_rwlock_init','libSystem/_pthread_rwlock_rdlock',
                        'libSystem/_pthread_rwlock_wrlock','libSystem/_pthread_rwlock_unlock'):
                a=args[0];op=name.rsplit('_',1)[1]
                if op=='init':
                    h=next(h for h in self.allocations if h['address']==a)
                    if args[1]!=0 or h['extent']!=200 or a in self.rwlocks:
                        self.stop('unmodeled_rwlock_init_input',address=hex(a),attributes=hex(args[1]),
                            extent_bytes=h['extent'],already_initialized=a in self.rwlocks);return
                    e.update({'initial_known_bytes':sum(h['known']),
                        'known_initial_bytes_all_zero':all(b==0 for b,k in zip(bytes(u.mem_read(a,200)),h['known']) if k)})
                    self.rwlocks[a]={'readers':0,'writer':False};h['known'][:]=bytes(200)
                else:
                    if a not in self.rwlocks:self.stop('unknown_private_rwlock',address=hex(a),operation=op);return
                    state=self.rwlocks[a]
                    if op=='rdlock':
                        assert not state['writer'];state['readers']+=1
                    elif op=='wrlock':
                        assert not state['writer'] and state['readers']==0;state['writer']=True
                    else:
                        if state['writer']:state['writer']=False
                        elif state['readers']:state['readers']-=1
                        else:self.stop('private_rwlock_not_held',address=hex(a));return
                e.update({'model':'single-thread abstract rwlock; opaque bytes unknown after init','state_after':dict(self.rwlocks[a])})
                self.return_model(0);return
            if name=='CoreFoundation/_CFMachPortGetPort':
                assert args[0]==OBJECTS;e['result']=hex(self.stored_name);self.return_model(self.stored_name);return
            if name=='libSystem/___strcpy_chk':
                assert OOL<=args[1]<OOL+len(self.payload)
                raw=bytes(u.mem_read(args[1],OOL+len(self.payload)-args[1]));end=raw.find(b'\0')
                if end<0:self.stop('private_model_uninitialized_input',api=name);return
                if end+1>args[2]:self.stop('outside_fitting_checked_copy_model',source_bytes=end+1,destination_bytes=args[2]);return
                u.mem_write(args[0],raw[:end+1])
                e.update({'input_length':end,'copied_bytes':end+1,'result':hex(args[0]),'model':'bounded private checked strcpy'})
                self.return_model(args[0]);return
            if name=='libSystem/_strnlen':
                assert OOL<=args[0]<OOL+len(self.payload)
                raw=bytes(u.mem_read(args[0],min(args[1],OOL+len(self.payload)-args[0])))
                end=raw.find(b'\0');n=len(raw) if end<0 else end
                e['result']=n;self.return_model(n);return
            if name=='libSystem/_strlen':
                raw=self.private_string(args[0]).encode('utf-8');e['result']=len(raw)
                e['model']='bounded initialized private C string';self.return_model(len(raw));return
            if name=='libSystem/_malloc':
                n=args[0]
                if n==0:
                    e.update({'result':'0x0','model':'explicit permitted malloc(0) result'});self.return_model(0);return
                if n>0x40000 or len(self.allocations)>=128:
                    self.stop('private_allocation_budget',requested_bytes=n,allocations=len(self.allocations));return
                ordinal=self.application_malloc_calls
                if not self.initializing:self.application_malloc_calls+=1
                if not self.initializing and (self.malloc_null or self.malloc_fail_at==ordinal):e['result']='0x0';self.return_model(0);return
                a=0x5200000000+len(self.allocations)*0x80000;pages=(n+4095)&~4095
                u.mem_map(a,pages);u.mem_write(a,bytes([0xa5])*n)
                self.allocations.append({'address':a,'extent':n,'pages':pages,'known':bytearray(n),'freed':False})
                e.update({'result':hex(a),'extent_bytes':n,'initial_bytes_unknown':True});self.return_model(a);return
            if name=='libSystem/_free':
                if args[0]:
                    h=next(h for h in self.allocations if h['address']==args[0]);assert not h['freed']
                    e.update({'extent_bytes':h['extent'],'known_byte_mask':h['known'].hex(),
                        'allocation_bytes_at_free':bytes(u.mem_read(h['address'],h['extent'])).hex()})
                    h['freed']=True
                e['model']='private lifetime retirement only';self.return_model(0);return
            self.stop('unmodeled_subscription_import',name=name,args=e['args']);return
        permitted=any(a<=address<z for a,z in self.allowed_ranges)
        if self.explore_original_code:permitted |= any(a<=address and address+4<=z for a,z in self.original_executable_ranges)
        if not permitted:
            self.stop('unreviewed_subscription_continuation',pc=hex(address),sp=hex(u.reg_read(ar.UC_ARM64_REG_SP)),
                registers={f'x{i}':hex(self.reg(i)) for i in range(29)});return
        if address==0x100005b04:
            self.argument_record_address=int.from_bytes(u.mem_read(self.reg(0)+16,8),'little')
            self.records.append({'kind':'native_subscription_argument_record','pc':hex(address),
                'control_address':hex(self.reg(0)),'control_bytes_32':bytes(u.mem_read(self.reg(0),32)).hex(),
                'argument_address':hex(self.argument_record_address),
                'argument_bytes_40':bytes(u.mem_read(self.argument_record_address,40)).hex()})
        if address==0x100766c18:
            self.records.append({'kind':'native_path_record','pc':hex(address),'address':hex(self.reg(23)),
                'bytes_80':bytes(u.mem_read(self.reg(23),80)).hex()})
        self.visited.add(address)
        i=self.decoded.get(address)
        if i is None:
            i=next(CS.disasm(bytes(u.mem_read(address,4)),address));self.decoded[address]=i
        if i.mnemonic in ('paciza','pacia','pacda','autia','autiza','xpaci'):
            self.steps+=1;self.pac.append({'site':hex(address),'instruction':i.mnemonic,'authentication':'explicit private bypass'})
            u.reg_write(ar.UC_ARM64_REG_PC,address+4);return
        return super().hook(u,address,size,user)

    def read_hook(self,u,access,address,size,value,user):
        if self.argument_record_address is not None and self.argument_record_address<=address and address+size<=self.argument_record_address+40:
            self.records.append({'kind':'native_argument_read','pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),
                'offset_bytes':address-self.argument_record_address,'size_bytes':size})
        for h in self.allocations:
            a=h['address'];n=h['extent']
            if address<a+h['pages'] and address+size>a:
                if address<a or address+size>a+n or h['freed'] or not all(h['known'][address-a:address-a+size]):
                    self.stop('unknown_or_outside_private_heap_read',address=hex(address),size_bytes=size,
                        pc=hex(u.reg_read(ar.UC_ARM64_REG_PC)),allocation=hex(a),extent_bytes=n);return
        return super().read_hook(u,access,address,size,value,user)

    def write_hook(self,u,access,address,size,value,user):
        for h in self.allocations:
            a=h['address'];n=h['extent']
            if address<a+h['pages'] and address+size>a:
                if address<a or address+size>a+n or h['freed']:
                    self.stop('outside_private_heap_write',address=hex(address),size_bytes=size,pc=hex(u.reg_read(ar.UC_ARM64_REG_PC)));return
                h['known'][address-a:address-a+size]=bytes([1])*size
                self.records.append({'kind':'native_heap_write','pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),
                    'allocation':hex(a),'offset_bytes':address-a,'size_bytes':size})
        return super().write_hook(u,access,address,size,value,user)

    def private_read(self,address,size):
        assert size<=0x40000
        for h in self.allocations:
            a=h['address']
            if address<a+h['pages'] and address+size>a:
                assert a<=address and address+size<=a+h['extent'] and not h['freed']
                assert all(h['known'][address-a:address-a+size]),('unknown API input',hex(address),size)
        return bytes(self.u.mem_read(address,size))

    def private_string(self,address):
        raw=bytearray()
        for i in range(4096):
            b=self.private_read(address+i,1)
            if b==b'\0':return raw.decode('utf-8',errors='backslashreplace')
            raw+=b
        raise AssertionError('private string budget')

    def run_initialization_prefix(self,budget=1000000):
        self.initializing=True
        self.allowed_ranges += [(0x10045053c,0x100450788),(0x1003b41fc,0x1003b5724)]
        self.allowed_ranges += [(0x10035df48,0x10035dfa8)]
        self.allowed_ranges += [(0x10032ba0c,0x10032bb8c)]
        self.allowed_ranges += [(0x1003308a0,0x1003308f0)]
        self.allowed_ranges += [(0x1003b5724,0x1003b57d4)]
        self.setreg(30,HALT);self.u.reg_write(ar.UC_ARM64_REG_SP,STACK+0x78000)
        try:self.u.emu_start(0x10045053c,0,count=budget)
        except uc.UcError as e:self.stop('initialization_engine_error',message=str(e),pc=hex(self.u.reg_read(ar.UC_ARM64_REG_PC)))
        if self.stop_reason is None:self.stop('initialization_instruction_budget',pc=hex(self.u.reg_read(ar.UC_ARM64_REG_PC)),budget=budget)
        cells={hex(a):hex(int.from_bytes(self.u.mem_read(a,8),'little')) for a in [0x1010c6808,0x1010c8260]}
        self.initialization_prefix={'stop_reason':self.stop_reason,'steps':self.steps,'last_record':self.records[-1],
            'byte_state_cells':cells,'full_initialization_complete':self.stop_reason=='returned_to_fixture'}
        self.initializing=False
        return self.initialization_prefix

    def run_subscription(self,budget=1000000):
        self.stop_reason=None
        raw=bytearray(64);struct.pack_into('<7I',raw,0,0x80000012,64,0xb03,self.service_name,0,61471,1)
        struct.pack_into('<Q',raw,28,OOL);raw[39]=1;struct.pack_into('<I',raw,40,self.count)
        raw[44:52]=bytes.fromhex('0000000001000000');struct.pack_into('<IQ',raw,52,self.count,self.opaque)
        reply=bytearray(40);struct.pack_into('<6I',reply,0,18,36,0xb03,0,0,61571);struct.pack_into('<I',reply,36,0xdeadbeef)
        self.u.mem_write(REQUEST,bytes(raw));self.u.mem_write(REPLY,bytes(reply))
        self.setreg(0,REQUEST);self.setreg(1,REPLY);self.setreg(30,HALT)
        self.u.reg_write(ar.UC_ARM64_REG_SP,STACK+0x78000)
        try:self.u.emu_start(0x1000054d8,0,count=budget)
        except uc.UcError as e:
            self.stop_reason='engine_error';self.records.append({'kind':'engine_error','message':str(e),'pc':hex(self.u.reg_read(ar.UC_ARM64_REG_PC))})
        if self.stop_reason is None:self.stop_reason='instruction_budget'
        for a in self.visited:assert bytes(self.u.mem_read(a,4))==IMAGE.read(a,4),hex(a)
        h=hashlib.sha256();pages=sorted({a&~4095 for a in self.visited})
        for a in pages:h.update(struct.pack('<Q',a));h.update(IMAGE.read(a,4096))
        return {'scope':__doc__,'label':self.label,'source_sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
            'generator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'base_probe_sha256':hashlib.sha256((ROOT/'daemon_rpc502_probe.py').read_bytes()).hexdigest(),
            'seed':{'service_name':hex(self.service_name),'stored_name':hex(self.stored_name),'count':self.count,'opaque':hex(self.opaque),
                'synthetic_ool_prefix':self.payload[:96].hex(),'initial_output_word':'0xdeadbeef','malloc_fail_at':self.malloc_fail_at},
            'steps':self.steps,'stop_reason':self.stop_reason,'calls':self.calls,'records':self.records,'image_writes':self.writes,
            'initialization_prefix':self.initialization_prefix,
            'exploration_mode':self.explore_original_code,
            'private_cpu_model':'UC_CPU_ARM64_MAX; single private thread; no native concurrency proof',
            'private_allocations':[{'address':hex(a['address']),'extent_bytes':a['extent'],'initialized_bytes':sum(a['known']),'freed':a['freed']} for a in self.allocations],
            'pac_bypasses':self.pac,'visited_instruction_addresses':[hex(a) for a in sorted(self.visited)],
            'original_instruction_bytes_verified':len(self.visited),'visited_original_code_pages':[hex(a) for a in pages],
            'visited_original_code_pages_sha256':h.hexdigest(),'final_reply_40_bytes':bytes(self.u.mem_read(REPLY,40)).hex(),
            'native_target_executed':False,'target_host_operations_executed':False,'full_goal_complete':False}


def main():
    rows=[]
    for label,kw in [('subscription_initial',{}),('subscription_mismatch',{'service_name':0x7107})]:
        r=SubscriptionProbe(label,**kw).run_subscription();rows.append(r)
        print(json.dumps({'label':label,'steps':r['steps'],'stop':r['stop_reason'],'last':r['records'][-1],'calls':r['calls']}),flush=True)
    (ROOT/'arcade_subscription_profiles.json').write_text(json.dumps({'scope':__doc__,'profiles':rows},indent=2)+'\n')


if __name__=='__main__':main()
