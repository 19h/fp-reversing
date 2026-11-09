#!/usr/bin/env python3
"""Original provider post block under explicit local frame/record inputs.

The retained checkpoint originates in a complete original request prefix.
Entry218fbc and record/register/status fixtures skip unproved predecessors.
No native notification or whole-request success/reachability is established.
O(B+F+C*K) time/space;10000 original-hook cap per fragment.
"""
import json
from pathlib import Path
import struct
from unicorn import arm64_const as A
from adid_reader import Adid,ROOT,THIN_SHA,sha
from probe_adid_startup import Startup,unpack_records
from probe_adid_receiver import HEAP

MASK=(1<<64)-1
ENTRY=0x100218fbc
AFTER=0x1002191a8


class Posts(Startup):
    def __init__(self,s,f,checkpoint):
        super().__init__(s,f,checkpoint);sp=self.reg('sp');holder=HEAP+0x1b000;nested=HEAP+0x1c000
        fields=[(nested+8,struct.pack('<Q',f['DSID_u64']^0xda8ca8cae5dfbd2d),'analyst encoded DSID64 field'),(holder,struct.pack('<Q',(nested+0x6fac17cb61e34e69)&MASK),'analyst encoded nested pointer'),(sp+0x1f28,struct.pack('<Q',(holder-0xd2e521bdf8c1d751)&MASK),'analyst frame encoded holder pointer'),(sp+0x1648,struct.pack('<I',f['encoded_status_u32']),'analyst encoded status')]
        writes=[]
        for a,raw,role in fields:
            before=bytes(self.u.mem_read(a,len(raw)));self.u.mem_write(a,raw);writes.append({'address':hex(a),'before':before.hex(),'after':raw.hex(),'role':role})
        registers={'pc':ENTRY,'x30':int.from_bytes(self.u.mem_read(sp+0x1660,8),'little'),'x23':0x1002c1f90}
        before={r:hex(self.reg(r)) for r in registers}
        for r,value in registers.items():self.u.reg_write(getattr(A,'UC_ARM64_REG_'+r.upper()),value)
        assert self.reg('w21')==0xd5b and self.reg('w6')==0x801ffa49 and self.reg('x27')==0x1002c40c0
        self.records.append({'kind':'analyst_local_notification_fragment_entry','entry':hex(ENTRY),'registers_before':before,'register_overrides':{r:hex(v) for r,v in registers.items()},'frame_and_record_writes':writes,'checkpoint_provenance':checkpoint['source_ordered_instruction_sha256'],'checkpoint_SP_preserved':True,'source_frame_predecessors_after_checkpoint_validated':False,'whole_request_or_native_reachability_established':False})
    def code(self,u,pc,n,data):
        if pc==AFTER:
            self.records.append({'kind':'original_notification_continuation_boundary','pc':hex(pc),'X0_incidental':hex(self.reg('x0'))});return self.stop('notification_after_local_post_or_status_rejection')
        if pc in [0x100218fd0,0x100218fec,0x100219038,0x100219054,0x100219110,0x100219120,0x10021915c,0x100219198]:self.records.append({'kind':'original_provider_notification_selection','pc':hex(pc),'registers':{r:hex(self.reg(r)) for r in ['x0','x8','x9','x10','x11','x12','x15','x16','x17','x19','x21','x23','x27','x30']},'NZCV':hex(u.reg_read(A.UC_ARM64_REG_NZCV))})
        return super().code(u,pc,n,data)
    def api(self,im):
        if im['name']!='_notify_post':return super().api(im)
        p=self.reg('x0');event={'kind':'original_notification_post_boundary','name':im['name'],'callsite':hex(self.reg('lr')-4),'name_pointer':hex(p),'notification_name':self.string(p),'import':im,'native_API_executed':False};self.records.append(event)
        if 'post_result_u32' not in self.fixture:return self.stop('opaque_notify_post_boundary')
        event.update(kind='explicit_notification_post_result',result_u32=self.fixture['post_result_u32']);return self.finish_api(self.fixture['post_result_u32'])


def fixtures():
    out=[]
    for key in [-17,-16,-9,-8,-7,-6,-5,-4,-3,-2,-1,0,1,0x1122334455667788,0x7fffffffffffffff,0x8000000000000000]:out.append({'label':'DSID_'+str(key),'DSID_u64':key&MASK,'encoded_status_u32':0x59248f})
    for status in [0,0x59248e,0x592490,0xffffffff]:out.append({'label':'encoded_status_'+hex(status),'DSID_u64':1,'encoded_status_u32':status})
    for result in [0,1,0xffffffff]:out.append({'label':'post_result_'+hex(result),'DSID_u64':1,'encoded_status_u32':0x59248f,'post_result_u32':result})
    for f in out:f.update(entry=ENTRY,instruction_budget=10000,model_eor3=True,model_atomic=True,local_fragment_and_frame_overrides=True)
    return out


def run_one(s,f,ck):
    q=Posts(s,json.loads(json.dumps(f)),ck);return q,q.run_continuation()


def main():
    s=Adid();checkpoint=json.loads((ROOT/'adid_driver_dispatch_frame.json').read_text());rows=[];functions={};instructions={}
    for f in fixtures():
        q,row=run_one(s,f,checkpoint)
        for v in row.pop('original_functions'):functions[v['start']]=v
        for v in row.pop('instruction_records'):instructions[v['ea']]=v
        rows.append(row);print(json.dumps({'label':f['label'],'stop':row['stop_reason'],'steps':row['steps'],'post_names':[e['notification_name'] for e in unpack_records(row) if e.get('name')=='_notify_post']}),flush=True)
    deps=['adid_reader.py','probe_adid_receiver.py','probe_adid_startup.py','adid_driver_dispatch_frame.json'];out={'scope':__doc__,'thin_sha256':THIN_SHA,'profiles':rows,'original_functions':list(functions.values()),'original_instruction_records':list(instructions.values()),'generator_sha256':sha(Path(__file__).read_bytes()),'dependencies':{n:sha((ROOT/n).read_bytes()) for n in deps},'native_target_executed':False,'full_goal_complete':False};(ROOT/'adid_notification_post_profiles.json').write_text(json.dumps(out,indent=2)+'\n')


if __name__=='__main__':main()
