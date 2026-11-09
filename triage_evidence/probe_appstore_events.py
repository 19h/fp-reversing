#!/usr/bin/env python3
"""Private original event relay/notification reconstruction cases.

Uses frozen agent-probe mapping/register helpers; only five original event
functions can execute. ObjC/XPC/CF/queue/task effects are explicit private models.
No native event, notification, account, network, repair or IPC call is issued.
O(C*K) time for C finite cases and K=4000 instruction budget; O(B) private memory.
"""
import hashlib
import json
from pathlib import Path
import struct
from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_LR,UC_ARM64_REG_PC
from appstore_agent_reader import ROOT,THIN_SHA,sha
from probe_appstore_agent import Probe as Base,HEAP,DONE


class EventsProbe(Base):
    def __init__(self,fixture):
        super().__init__(fixture);self.objects={};self.next=HEAP+0x2000;self.posts=[];self.tasks=[];self.schedules=[];self.calls=[]
        self.allowed={};r=json.loads((ROOT/'appstore_events_contracts.json').read_text())
        self.stubs={int(x['address'],16):x for x in r['stubs']}
        for row in r['ranges']:
            if row['start'] in ('0x100140dfc','0x1001410d4','0x1001415a4','0x100058718','0x1000587c4'):
                self.allowed.update({int(i['ea'],16):(i['mnemonic'],i['operands']) for i in row['instructions']})
        self.writeq(0x1005a9a00,HEAP+0xa000);self.writeq(HEAP+0xa000,HEAP+0xa200)
        self.u.mem_write(HEAP+0xa200,b'XPCEventName\0');self.writeq(0x1005a9a10,HEAP+0xa100)
        self.writeq(0x1005a99b8,HEAP+0xb000);self.writeq(HEAP+0xb000,0x1234abcd)
        self.block=HEAP+0xc000;self.observer=HEAP+0xc100;self.queue=self.obj('queue')
        self.writeq(self.observer+r['queue_ivar_original_u32'],self.queue)
        self.user_info=self.obj('dictionary',values=fixture.get('user_info',{})) if fixture.get('user_info') is not None else 0
        self.notification=self.obj('notification',user_info=self.user_info)
        self.writeq(self.block+32,self.notification)
        self.event=self.obj('event') if not fixture.get('event_null') else 0

    def obj(self,kind,**values):
        p=self.next;self.next+=0x100;assert self.next<HEAP+0x9000
        self.objects[p]={'kind':kind,**values};return p
    def object(self,p):return self.objects.get(p,{'kind':'nil'} if p==0 else {'kind':'unknown'})
    def string(self,p):
        if p in self.objects:return self.objects[p].get('value')
        if p==0:return None
        try:return self.s.cstring(self.s.qword(p+16))
        except Exception:return None
    def cstr(self,p):
        if not p:return None
        out=bytearray()
        for j in range(512):
            b=bytes(self.u.mem_read(p+j,1))
            if b==b'\0':return out.decode()
            out+=b
        raise ValueError('private C-string bound')
    def returned_value(self,p):
        o=self.object(p)
        return o.get('value') if o['kind']=='value' else o

    def hook(self,u,pc,size,data):
        self.steps+=1
        if self.steps>4000:return self.stop('instruction_budget_guard')
        if pc==DONE:return self.stop('returned_to_private_fixture')
        if pc in (0x10007bd88,0x1000d3458):
            if pc==0x10007bd88:
                p=self.obj('task_queue');self.writeq(p+8,self.queue);return self.ret(p)
            options=self.object(self.reg(1));assert options['kind']=='repair_options'
            self.tasks.append({'options':options.copy(),'log_key_argument':hex(self.reg(2)),'callsite':hex(self.u.reg_read(UC_ARM64_REG_LR)-4)})
            return self.ret(self.obj('repair_task'))
        if pc in self.stubs:
            st=self.stubs[pc];symbol=st.get('binding',{}).get('target');sel=st.get('selector');x=[self.reg(i) for i in range(6)]
            site=self.u.reg_read(UC_ARM64_REG_LR)-4;self.calls.append({'pc':hex(pc),'callsite':hex(site),'symbol':symbol,'selector':sel})
            o=self.object(x[0]);result=None
            if symbol in ('libobjc/_objc_retain','libobjc/_objc_claimAutoreleasedReturnValue','libobjc/_objc_retainAutorelease'):result=x[0]
            elif symbol in ('libobjc/_objc_release','CoreFoundation/_CFRelease'):result=0
            elif symbol=='AppStoreDaemon/_ASDLogHandleForCategory':result=self.obj('log')
            elif symbol=='libSystem/_os_log_type_enabled':result=0
            elif symbol=='libSystem/_os_variant_allows_internal_security_policies':result=int(self.fixture.get('internal_policy',False))
            elif symbol=='libSystem/_xpc_get_type':
                is_dict=(x[0]==self.event and not self.fixture.get('event_wrong_type')) or (x[0]==self.user_info and not self.fixture.get('user_info_wrong_type'))
                result=HEAP+0xa100 if x[0] and is_dict else HEAP+0xa300
            elif symbol=='libSystem/_xpc_dictionary_get_string':
                assert self.cstr(x[1])=='XPCEventName';name=self.fixture.get('event_name')
                if name is None:result=0
                else:
                    self.u.mem_write(HEAP+0xa400,name.encode()+b'\0');result=HEAP+0xa400
            elif symbol=='libSystem/_xpc_dictionary_get_dictionary':
                assert self.cstr(x[1])=='UserInfo';result=self.user_info if not self.fixture.get('user_info_wrong_type') else 0
            elif symbol=='CoreFoundation/__CFXPCCreateCFObjectFromXPCObject':result=0 if self.fixture.get('cf_conversion_null') else self.user_info
            elif sel=='defaultCenter':result=HEAP+0xc200
            elif sel=='stringWithUTF8String:':result=self.obj('value',value=self.cstr(x[2]))
            elif sel in ('postNotificationName:object:','postNotificationName:object:userInfo:'):
                self.posts.append({'name':self.string(x[2]),'object':hex(x[3]),'user_info':self.object(x[4]).get('values') if sel.endswith('userInfo:') else None,
                    'callsite':hex(site),'selector':sel});result=0
            elif symbol=='libSystem/_dispatch_async':
                raw=bytes(self.u.mem_read(x[1],40));self.schedules.append({'queue':hex(x[0]),'block_bytes':raw.hex(),
                    'invoke':hex(struct.unpack_from('<Q',raw,16)[0]),'capture':hex(struct.unpack_from('<Q',raw,32)[0])});result=0
            elif symbol=='libobjc/_objc_alloc':
                kind='repair_options' if site==0x1000589a0 else 'allocated'
                result=self.obj(kind,fields={})
            elif sel=='initWithName:':result=x[0]
            elif sel=='userInfo':result=o.get('user_info',0)
            elif sel=='objectForKeyedSubscript:':
                key=self.string(x[2]);values=o.get('values',{});self.records.append({'field_lookup':key})
                result=self.obj('value',value=values[key]) if key in values and values[key] is not None else 0
            elif sel in ('initWithBundlePath:','initWithBundleID:'):
                assert o['kind']=='repair_options';o['fields']['bundlePath' if 'Path' in sel else 'bundleID']=self.string(x[2]);result=x[0]
            elif sel in ('unsignedIntValue','unsignedIntegerValue','boolValue','length'):
                v=o.get('value')
                if v is None:result=0
                elif sel=='length':assert isinstance(v,str);result=len(v)
                else:
                    assert isinstance(v,(int,bool)),(sel,v)
                    result=int(bool(v)) if sel=='boolValue' else (int(v)&(0xffffffff if sel=='unsignedIntValue' else (1<<64)-1))
            elif sel in ('setFairplayStatus:','setExitReason:','setForceUpsell:','setForceRevoke:'):
                assert o['kind']=='repair_options'
                key={'setFairplayStatus:':'fairplayStatus','setExitReason:':'exitReason','setForceUpsell:':'forceUpsell','setForceRevoke:':'forceRevoke'}[sel]
                value=x[2]
                if key=='fairplayStatus':value&=0xffffffff;value=value-(1<<32) if value&(1<<31) else value
                elif key.startswith('force'):value=bool(value)
                o['fields'][key]=value;result=0
            elif sel=='arrayWithObjects:count:':
                assert x[3]==1;result=self.obj('array',members=[hex(struct.unpack('<Q',bytes(self.u.mem_read(x[2],8)))[0])])
            elif sel=='addOperations:waitUntilFinished:':
                self.schedules.append({'selector':sel,'wait_u64':x[3],'operations':self.object(x[2]),'callsite':hex(site)});result=0
            if result is None:return self.stop('unmodeled_API_guard:'+str((hex(pc),symbol,sel)))
            return self.ret(result)
        if pc not in self.allowed:return self.stop('unapproved_original_function_guard:'+hex(pc))
        self.visited.append(pc);m,op=self.allowed[pc]
        if m.startswith(('pac','aut')):self.u.reg_write(UC_ARM64_REG_PC,pc+4)
        elif m in ('retab','retaa'):self.u.reg_write(UC_ARM64_REG_PC,self.u.reg_read(UC_ARM64_REG_LR))

    def run(self):
        mode=self.fixture['mode']
        if mode=='relay':entry=0x100140dfc;args=[self.block,self.event]
        elif mode=='notifyd':entry=0x1001415a4;args=[self.block,self.event]
        elif mode=='observer':entry=0x100058718;args=[self.observer,0,self.notification]
        else:entry=0x1000587c4;args=[self.block]
        for j,v in enumerate(args):self.u.reg_write(UC_ARM64_REG_X0+j,v)
        try:self.u.emu_start(entry,DONE+4,count=4001)
        except Exception as e:self.reason='private_emulator_exception:'+str(e)
        h=hashlib.sha256()
        for pc in self.visited:h.update(struct.pack('<Q',pc));h.update(self.s.read(pc,4))
        return {'fixture':self.fixture,'stop_reason':self.reason,'steps':self.steps,'posts':self.posts,'tasks':self.tasks,
            'schedules':self.schedules,'field_lookups':[x['field_lookup'] for x in self.records if 'field_lookup' in x],
            'calls':self.calls,'visited_original_instructions':[hex(x) for x in self.visited],
            'original_instruction_bytes_sha256':h.hexdigest()}


def main():
    name='com.apple.appstored.ASDRepairBundleID';info={'bundlePath':'/private/synthetic/ArcadeFixture.app','status':-42352,'exitReason':16}
    fixtures=[{'label':'relay_null','mode':'relay','event_null':True},
        {'label':'relay_wrong_type','mode':'relay','event_wrong_type':True},
        {'label':'relay_name_absent','mode':'relay','user_info':info},
        {'label':'relay_userinfo_absent','mode':'relay','event_name':name},
        {'label':'relay_userinfo_wrong_type','mode':'relay','event_name':name,'user_info':info,'user_info_wrong_type':True},
        {'label':'relay_full_repair','mode':'relay','event_name':name,'user_info':info},
        {'label':'relay_cf_conversion_null','mode':'relay','event_name':name,'user_info':info,'cf_conversion_null':True},
        {'label':'notifyd_resync_name','mode':'notifyd','event_name':'com.apple.fairplayd.resync-fpkeybag'},
        {'label':'observer_queues_notification','mode':'observer','user_info':info}]
    cases=[('consumer_path',info,False),('consumer_both_path_wins',dict(info,bundleID='fixture.bundle'),False),
        ('consumer_identifier',{'bundleID':'fixture.bundle','status':-42352,'exitReason':16},False),
        ('consumer_missing_fields',{},False),('consumer_zero_status',dict(info,status=0),False),
        ('consumer_u32_wrap',dict(info,status=(1<<32)+0xffff5a90,exitReason=(1<<64)-1),False),
        ('consumer_external_ignored_fields',dict(info,isBackground=True,forceUpsell=True,forceRevoke=True,accountDSID=123,relaunchOptions=7),False),
        ('consumer_internal_force_fields',dict(info,bundleID='fixture.bundle',forceUpsell=True,forceRevoke=True),True)]
    fixtures.extend({'label':n,'mode':'consumer','user_info':v,'internal_policy':internal} for n,v,internal in cases)
    rows=[EventsProbe(f).run() for f in fixtures]
    out={'scope':__doc__,'source_sha256':THIN_SHA,'generator_sha256':sha(Path(__file__).read_bytes()),
        'parent_probe_sha256':sha((ROOT/'probe_appstore_agent.py').read_bytes()),
        'source_contracts_sha256':sha((ROOT/'appstore_events_contracts.json').read_bytes()),'profiles':rows,
        'native_target_executed':False,'hardware_PAC_checked':False,'full_goal_complete':False}
    (ROOT/'appstore_events_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
    assert all(x['stop_reason']=='returned_to_private_fixture' for x in rows),[(x['fixture']['label'],x['stop_reason']) for x in rows]
    print(json.dumps({'cases':len(rows),'all_returned':True,'native_target_executed':False}))


if __name__=='__main__':main()
