#!/usr/bin/env python3
"""Feed source-produced private service replies into original daemon handlers.

No native transaction is executed. Each side uses its explicit private models;
the service policy result is synthetic. Packet bytes cross the two source-pinned
CPU fixtures unchanged. Original PAC and host IPC remain unexecuted.
"""
import hashlib
import json
from pathlib import Path
from probe_arcade_reply import ReplyProbe,ROOT
from probe_arcade_subscription import REPLY,ar


class RoundtripProbe(ReplyProbe):
    def __init__(self,*args,**kw):
        super().__init__(*args,**kw);self.mig_writes=[]

    def write_hook(self,u,access,a,n,value,user):
        sp=u.reg_read(ar.UC_ARM64_REG_SP)
        if a==sp+0xb30:
            self.records.append({'kind':'native_response_low32_slot_write','pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),
                'size_bytes':n,'value':hex(value&((1<<(8*n))-1))})
        if REPLY<=a and a+n<=REPLY+40:
            self.mig_writes.append({'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'offset_bytes':a-REPLY,
                'size_bytes':n,'value':hex(value&((1<<(8*n))-1))})
        return super().write_hook(u,access,a,n,value,user)

    def hook(self,u,a,n,user):
        if a==0x1008b35f0:
            sp=u.reg_read(ar.UC_ARM64_REG_SP)
            self.records.append({'kind':'native_response_low32_compare','pc':hex(a),
                'candidate_u32':int.from_bytes(u.mem_read(sp+0xb30,4),'little'),'expected_u32':1})
        if a==0x100580978:
            sp=u.reg_read(ar.UC_ARM64_REG_SP)
            self.records.append({'kind':'native_response_decision_byte','pc':hex(a),
                'candidate_byte':int.from_bytes(u.mem_read(sp+0xc1a,1),'little'),
                'expected_byte':(self.reg(11)-0x4c)&255,'register_x27':hex(self.reg(27))})
        return super().hook(u,a,n,user)


def main():
    source=ROOT/'arcade_service_policy_profiles.json';rows=json.loads(source.read_text())['profiles'];out=[]
    cases=[]
    for service in rows:
        sends=[e for e in service['records'] if e.get('name')=='libSystem/_xpc_connection_send_message' and 'data' in e.get('reply_fields',{})]
        if not sends:continue
        fields=sends[-1]['reply_fields'];assert fields['status']['type']=='int64'
        data=bytes.fromhex(fields['data']['bytes'])
        cases.append((service,data,None))
        if service['label']=='developer_true':
            marker=bytes.fromhex('1fe19f29848500000008');assert data.count(marker)==1
            at=data.index(marker)+len(marker);assert data[at:at+8]==(1).to_bytes(8,'big')
            for value in (0,2,257,65537,1<<32,(1<<32)+1,1<<63,(1<<63)+1,(1<<64)-1):
                changed=data[:at]+value.to_bytes(8,'big')+data[at+8:]
                cases.append((service,changed,{'kind':'synthetic single response field replacement','offset_bytes':at,
                    'key':'0x1fe19f29','tag':'0x8485','raw_be64':hex(value)}))
    for service,data,mutation in cases:
        send=next(e for e in service['records'] if e.get('name')=='libSystem/_xpc_connection_send_message')
        fields=send['reply_fields'];label='roundtrip_'+service['label']+('' if mutation is None else '_raw_'+mutation['raw_be64'])
        p=RoundtripProbe(label,reply_data=data,status_value=fields['status']['value'])
        r=p.run_reply();request=next(e['outgoing_request'] for e in r['calls'] if e['name']=='libSystem/_xpc_connection_send_message_with_reply_sync')
        assert request['fields']['data']['value']['bytes']==service['synthetic_event']['data_hex']
        r.update({'roundtrip_scope':__doc__,'service_case':service['label'],
            'service_profiles_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
            'roundtrip_probe_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'request_bytes_identical':True,'native_roundtrip_observed':False,'response_mutation':mutation,
            'native_mig_output_writes':p.mig_writes})
        out.append(r);print(json.dumps({'label':r['label'],'steps':r['steps'],'stop_reason':r['stop_reason'],
            'final_reply_40_bytes':r['final_reply_40_bytes'],'last_records':r['records'][-4:]}),flush=True)
    assert out,'no source-produced data replies'
    (ROOT/'arcade_policy_roundtrip_profiles.json').write_text(json.dumps({'scope':__doc__,'profiles':out},indent=2)+'\n')


if __name__=='__main__':main()
