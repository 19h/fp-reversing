#!/usr/bin/env python3
"""Unchanged original receipt-failure service replies into daemon Foundation edge.

Adds private NSString values, opaque repair-options/service objects and an
explicit normal return from the intended repair request. No native Foundation,
AppStoreDaemon, file, signing, IPC or callback operation runs. Unknown methods
and opaque-object reads stop. Source/PAC/definedness guards remain active.
"""
import hashlib
import json
from pathlib import Path
from probe_arcade_policy_roundtrip import RoundtripProbe
from probe_arcade_reply import ROOT,OBJECTS


class ReceiptReplyProbe(RoundtripProbe):
    def __init__(self,*a,**kw):
        super().__init__(*a,**kw);self.foundation_values={};self.foundation_next=OBJECTS+0xf000

    def hook(self,u,a,n,user):
        if a==0x100002134:
            self.records.append({'kind':'native_appstore_repair_adapter','pc':hex(a),'path_pointer':hex(self.reg(0)),
                'path':self.private_string(self.reg(0)),'status_argument_u64':hex(self.reg(1))})
        name=self.imports.get(a)
        if name=='libobjc/_objc_alloc':
            self.steps+=1;cls=self.imports.get(self.reg(0));assert cls=='AppStoreDaemon/_OBJC_CLASS_$_ASDRepairOptions',cls
            ptr=self.foundation_next;self.foundation_next+=0x10
            self.foundation_values[ptr]={'type':'repair_options','fields':{}}
            e={'kind':'private_receipt_reply_import','name':name,'return_pc':hex(self.reg(30)),
                'class':cls,'result':hex(ptr),'model':'explicit opaque repair-options allocation; no ObjC runtime'}
            self.records.append(e);self.calls.append(e);self.return_model(ptr);return
        if name=='libobjc/_objc_msgSend':
            self.steps+=1;args=[self.reg(i) for i in range(8)];sel=self.private_string(args[1])
            receiver=self.imports.get(args[0],hex(args[0]));obj=self.foundation_values.get(args[0])
            e={'kind':'private_receipt_reply_import','name':name,'return_pc':hex(self.reg(30)),
                'args':[hex(v) for v in args],'receiver':receiver,'receiver_value':obj,'selector':sel,
                'argument_values':[self.foundation_values.get(v,{'unknown_object':hex(v)}) for v in args[2:4]]}
            self.records.append(e);self.calls.append(e)
            if receiver=='Foundation/_OBJC_CLASS_$_NSString' and sel=='stringWithUTF8String:':
                text=self.private_string(args[2]);ptr=self.foundation_next;self.foundation_next+=0x10
                self.foundation_values[ptr]={'type':'string','text':text}
                e.update({'result':hex(ptr),'string_value':text,'model':'explicit private NSString value; no Foundation method'})
                self.return_model(ptr);return
            if obj and obj['type']=='repair_options' and sel=='initWithBundlePath:':
                path=self.foundation_values[args[2]];assert path['type']=='string'
                obj['fields']['bundlePath']=path['text'];e.update({'model':'opaque private options initializer','result':hex(args[0])})
                self.return_model(args[0]);return
            if obj and obj['type']=='repair_options' and sel in ('setExitReason:','setFairplayStatus:'):
                key={'setExitReason:':'exitReason','setFairplayStatus:':'fairplayStatus'}[sel]
                value=args[2]
                if key=='fairplayStatus':
                    value&=0xffffffff
                    if value&0x80000000:value-=1<<32
                obj['fields'][key]=value;e.update({'field':key,'value_u64':hex(args[2]),'stored_value':value,
                    'model':'private options field; reference setter/property use int32 fairplayStatus, u64 exitReason'})
                self.return_model();return
            if receiver=='AppStoreDaemon/_OBJC_CLASS_$_ASDRepairService' and sel=='defaultService':
                ptr=self.foundation_next;self.foundation_next+=0x10;self.foundation_values[ptr]={'type':'repair_service'}
                e.update({'result':hex(ptr),'model':'opaque default repair service; no framework operation'})
                self.return_model(ptr);return
            if obj and obj['type']=='repair_service' and sel=='repairAppWithOptions:replyHandler:':
                options=self.foundation_values[args[2]];assert options['type']=='repair_options'
                raw=bytes(u.mem_read(args[3],32));invoke=int.from_bytes(raw[16:24],'little');assert invoke==0x1000021bc
                e.update({'options':options,'reply_block':hex(args[3]),'reply_block_header_32':raw.hex(),'reply_block_invoke':hex(invoke),
                    'model':'record intended repair request and explicit normal return; no native framework/IPC or callback'})
                self.return_model(0);return
            e['model']='stop before Foundation/file/bundle method'
            self.stop('receipt_reply_foundation_boundary',receiver=receiver,selector=sel);return
        if name in ('libobjc/_objc_retainAutoreleasedReturnValue','libobjc/_objc_retain','libobjc/_objc_release'):
            self.steps+=1;obj=self.reg(0);assert obj==0 or obj in self.foundation_values
            e={'kind':'private_receipt_reply_import','name':name,'return_pc':hex(self.reg(30)),
                'object':hex(obj),'model':'opaque ARC boundary only; no native reference count'}
            self.records.append(e);self.calls.append(e);self.return_model(obj if name!='libobjc/_objc_release' else None);return
        return super().hook(u,a,n,user)

    def read_hook(self,u,access,a,n,value,user):
        if OBJECTS+0xf000<=a<OBJECTS+0x10000:
            self.stop('opaque_receipt_reply_object_read',address=hex(a),size_bytes=n);return
        return super().read_hook(u,access,a,n,value,user)


def main():
    source=ROOT/'arcade_receipt_profiles.json';rows=json.loads(source.read_text())['profiles'];out=[]
    for service in rows:
        sends=[e for e in service['records'] if e.get('name')=='libSystem/_xpc_connection_send_message' and 'data' in e.get('reply_fields',{})]
        if not sends:continue
        fields=sends[-1]['reply_fields'];data=bytes.fromhex(fields['data']['bytes'])
        p=ReceiptReplyProbe('receipt_reply_'+service['label'],reply_data=data,status_value=fields['status']['value'])
        r=p.run_reply();request=next(e['outgoing_request'] for e in r['calls'] if e.get('name')=='libSystem/_xpc_connection_send_message_with_reply_sync')
        assert request['fields']['data']['value']['bytes']==service['synthetic_event']['data_hex']
        r.update({'receipt_reply_scope':__doc__,'service_case':service['label'],'request_bytes_identical':True,
            'source_receipt_profiles_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
            'receipt_reply_probe_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'roundtrip_probe_sha256':hashlib.sha256((ROOT/'probe_arcade_policy_roundtrip.py').read_bytes()).hexdigest(),
            'native_mig_output_writes':p.mig_writes,'native_receipt_transaction_observed':False})
        out.append(r);print(json.dumps({'label':r['label'],'steps':r['steps'],'stop_reason':r['stop_reason'],
            'last_records':r['records'][-4:]}),flush=True)
    assert out
    (ROOT/'arcade_receipt_reply_profiles.json').write_text(json.dumps({'scope':__doc__,'profiles':out},indent=2)+'\n')


if __name__=='__main__':main()
