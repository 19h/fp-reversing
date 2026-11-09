#!/usr/bin/env python3
"""Private original arcade XPC response handling, never a real service exchange.

Inherits frozen subscription models. Adds explicit reply objects/data only.
No host target IPC, framework, files, loader or block callbacks execute.
Original code is executable only in private mappings; PAC is bypassed.
"""
import hashlib
import json
from pathlib import Path
import pickle
import struct
import zlib
from probe_arcade_subscription import SubscriptionProbe,ROOT,IMAGE,SOURCE,OBJECTS,ar

SNAPSHOT=ROOT/'arcade_reply_initial_state.bin'
SNAPSHOT_META=ROOT/'arcade_reply_initial_state.json'
DATA=0x5300000000


def build_snapshot():
    p=SubscriptionProbe('reply_fresh_initialization',explore_original_code=True)
    r=p.run_initialization_prefix(budget=10000000);assert r['full_initialization_complete'],r
    for a in p.visited:assert bytes(p.u.mem_read(a,4))==IMAGE.read(a,4),hex(a)
    pages=sorted({a&~4095 for a in p.visited});h=hashlib.sha256()
    for a in pages:h.update(struct.pack('<Q',a));h.update(IMAGE.read(a,4096))
    state={k:v for k,v in p.__dict__.items() if k not in ('u','decoded','records','calls','visited','writes','pac')}
    saved={'state':state,'context':p.u.context_save(),
        'memory':[(a,z,pr,bytes(p.u.mem_read(a,z-a+1))) for a,z,pr in p.u.mem_regions()]}
    raw=zlib.compress(pickle.dumps(saved),3);SNAPSHOT.write_bytes(raw)
    meta={'scope':'Fresh private source-pinned initialization; checkpoint contains synthetic memory only.',
        'source_sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        'subscription_probe_sha256':hashlib.sha256((ROOT/'probe_arcade_subscription.py').read_bytes()).hexdigest(),
        'base_probe_sha256':hashlib.sha256((ROOT/'daemon_rpc502_probe.py').read_bytes()).hexdigest(),
        'snapshot_sha256':hashlib.sha256(raw).hexdigest(),'snapshot_bytes':len(raw),'result':r,
        'visited_instruction_addresses':[hex(a) for a in sorted(p.visited)],
        'original_instruction_bytes_verified':len(p.visited),'visited_original_code_pages':[hex(a) for a in pages],
        'visited_original_code_pages_sha256':h.hexdigest(),'api_calls':p.calls,
        'native_target_executed':False,'target_host_operations_executed':False}
    SNAPSHOT_META.write_text(json.dumps(meta,indent=2)+'\n');print(json.dumps({'snapshot_built':True,'steps':p.steps,'bytes':len(raw)}),flush=True)


class ReplyProbe(SubscriptionProbe):
    def __init__(self,label,*,reply_kind='dictionary',reply_data=b'',data_present=True,status_present=True,status_value=0,status_kind='int64'):
        super().__init__(label,explore_original_code=True,xpc_mode='opaque')
        meta=json.loads(SNAPSHOT_META.read_text());raw=SNAPSHOT.read_bytes()
        assert hashlib.sha256(raw).hexdigest()==meta['snapshot_sha256']
        assert meta['source_sha256']==hashlib.sha256(SOURCE.read_bytes()).hexdigest()
        assert meta['subscription_probe_sha256']==hashlib.sha256((ROOT/'probe_arcade_subscription.py').read_bytes()).hexdigest()
        assert meta['base_probe_sha256']==hashlib.sha256((ROOT/'daemon_rpc502_probe.py').read_bytes()).hexdigest()
        saved=pickle.loads(zlib.decompress(raw))
        for a,z,pr in list(self.u.mem_regions()):self.u.mem_unmap(a,z-a+1)
        for a,z,pr,buf in saved['memory']:self.u.mem_map(a,z-a+1,pr);self.u.mem_write(a,buf)
        self.__dict__.update(saved['state']);self.decoded={};self.u.context_restore(saved['context'])
        self.label=label;self.records=[];self.calls=[];self.visited=set();self.writes=[];self.pac=[];self.steps=0
        self.xpc_mode='opaque';self.xpc_objects={};self.xpc_next=OBJECTS+0x4000
        self.application_malloc_calls=0;self.argument_record_address=None;self.malloc_fail_at=None;self.initializing=False
        self.reply_kind=reply_kind;self.reply_data=reply_data;self.data_present=data_present
        self.status_present=status_present;self.status_value=status_value;self.status_object=OBJECTS+0xe100
        self.status_kind=status_kind
        self.reply_object=OBJECTS+0xe000;self.reply_span=max(4096,(len(reply_data)+4095)&~4095)
        self.u.mem_map(DATA,self.reply_span)
        if reply_data:self.u.mem_write(DATA,reply_data)
        self.initialization_prefix={'profile':SNAPSHOT_META.name,'profile_sha256':hashlib.sha256(SNAPSHOT_META.read_bytes()).hexdigest(),
            'full_initialization_complete':True}
        for n in range(29):self.setreg(n,0)

    def hook(self,u,address,size,user):
        if address in (0x100834928,0x10083495c):
            self.records.append({'kind':'native_status_checkpoint','pc':hex(address),
                'registers':{f'x{i}':hex(self.reg(i)) for i in (0,8,9,10,22,26,28)}})
        name=self.imports.get(address)
        if name=='libobjc/_objc_msgSend':
            self.steps+=1;args=[self.reg(i) for i in range(8)];selector=self.private_string(args[1])
            receiver=self.imports.get(args[0],hex(args[0]))
            self.calls.append({'kind':'private_reply_import','name':name,'return_pc':hex(self.reg(30)),
                'args':[hex(v) for v in args],'receiver':receiver,'selector':selector,
                'string_argument':self.private_string(args[2]) if selector=='stringWithUTF8String:' else None,
                'model':'stop before any Objective-C method or native framework effect'})
            self.records.append(self.calls[-1]);self.stop('objc_path_conversion_boundary',receiver=receiver,selector=selector);return
        if name in ('libSystem/_xpc_connection_send_message_with_reply_sync','libSystem/_xpc_get_type','libSystem/_xpc_dictionary_get_data',
                    'libSystem/_xpc_dictionary_get_value','libSystem/_xpc_int64_get_value','libSystem/_xpc_dictionary_get_int64'):
            self.steps+=1;args=[self.reg(i) for i in range(8)]
            e={'kind':'private_reply_import','name':name,'return_pc':hex(self.reg(30)),'args':[hex(v) for v in args]}
            self.records.append(e);self.calls.append(e)
            if name.endswith('_send_message_with_reply_sync'):
                e.update({'outgoing_request':self.xpc_objects[args[1]],'reply_kind':self.reply_kind,
                    'model':'explicit synthetic response; no native XPC send/reply'})
                self.xpc_objects[self.reply_object]={'type':self.reply_kind,'fields':{}}
                self.return_model(0 if self.reply_kind=='null' else self.reply_object);return
            if name.endswith('_xpc_get_type'):
                if args[0] not in (self.reply_object,self.status_object):self.stop('unmodeled_reply_type_object',object=hex(args[0]));return
                symbol='libSystem/__xpc_type_'+(self.status_kind if args[0]==self.status_object else self.reply_kind)
                if symbol not in self.import_addresses:self.stop('unresolved_reply_type_symbol',symbol=symbol);return
                value=self.import_addresses[symbol];e['type_symbol']=symbol;e['result']=hex(value);self.return_model(value);return
            if name.endswith('_xpc_int64_get_value'):
                assert args[0]==self.status_object
                e['result']=self.status_value;self.return_model(self.status_value&((1<<64)-1));return
            assert args[0]==self.reply_object
            key=self.private_string(args[1]);e['key']=key
            if name.endswith('_xpc_dictionary_get_value'):
                assert key=='status',key
                result=self.status_object if self.status_present else 0
                e['result']=hex(result);e['model']='explicit synthetic status object or missing key';self.return_model(result);return
            if name.endswith('_xpc_dictionary_get_int64'):
                assert key=='status',key
                result=self.status_value if self.status_present else 0
                e['result']=result;self.return_model(result&((1<<64)-1));return
            assert key=='data',key
            assert args[2]
            u.mem_write(args[2],struct.pack('<Q',len(self.reply_data) if self.data_present else 0))
            e.update({'size_bytes':len(self.reply_data),'data_present':self.data_present,'result':hex(DATA if self.data_present else 0)})
            self.return_model(DATA if self.data_present else 0);return
        return super().hook(u,address,size,user)

    def read_hook(self,u,access,address,size,value,user):
        if DATA<=address<DATA+self.reply_span:
            self.records.append({'kind':'native_reply_data_read','pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),
                'offset_bytes':address-DATA,'size_bytes':size})
        if DATA<=address<DATA+self.reply_span and address+size>DATA+len(self.reply_data):
            self.stop('synthetic_reply_extent_read',pc=hex(u.reg_read(ar.UC_ARM64_REG_PC)),
                offset_bytes=address-DATA,size_bytes=size,defined_reply_bytes=len(self.reply_data));return
        return super().read_hook(u,access,address,size,value,user)

    def run_reply(self):
        r=self.run_subscription(budget=2000000)
        r.update({'reply_scope':__doc__,'reply_probe_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'synthetic_reply':{'kind':self.reply_kind,'data_present':self.data_present,'data_hex':self.reply_data.hex(),
                'status_present':self.status_present,'status_value':self.status_value,'status_kind':self.status_kind},
            'native_xpc_reply_observed':False})
        return r


def main():
    import argparse
    ap=argparse.ArgumentParser();ap.add_argument('--build-snapshot',action='store_true');args=ap.parse_args()
    if args.build_snapshot:build_snapshot();return
    rows=[]
    for label,kw in [('reply_null',{'reply_kind':'null'}),('reply_error',{'reply_kind':'error'}),
        ('reply_missing_status',{'status_present':False}),('reply_status_zero',{}),
        ('reply_status_one',{'status_value':1}),('reply_status_negative',{'status_value':-1}),
        ('reply_status_high32',{'status_value':1<<32}),('reply_status_negative_high32',{'status_value':-(1<<32)}),
        ('reply_status_high32_low1',{'status_value':(1<<32)+1}),
        ('reply_status_wrong_type',{'status_kind':'dictionary'}),
        ('reply_missing_data',{'data_present':False}),
        ('reply_short_data',{'reply_data':bytes(4)}),
        ('reply_scalar_frame',{'reply_data':struct.pack('>IHI',0,0x9777,4)+struct.pack('>I',0x8b3dc651)}),
        ('reply_service_error_42049',{'status_value':-42049}),
        ('reply_service_error_42052',{'status_value':-42052}),
        ('reply_service_error_42023',{'status_value':-42023})]:
        p=ReplyProbe(label,**kw);r=p.run_reply();rows.append(r)
        print(json.dumps({'label':label,'steps':r['steps'],'stop':r['stop_reason'],'last':r['records'][-1],
            'calls':[{k:v for k,v in e.items() if k!='outgoing_request'} for e in r['calls'][-8:]]}),flush=True)
    (ROOT/'arcade_reply_profiles.json').write_text(json.dumps({'scope':__doc__,'profiles':rows},indent=2)+'\n')


if __name__=='__main__':main()
