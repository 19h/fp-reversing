#!/usr/bin/env python3
"""Continue original ADID requests from the retained listener/peer state.

No native target/API/IPC/file/environment operation runs. Original pages and
explicit fixtures extend the frozen startup engine. Unknown file/API shapes
stop. O(C*(B+F+K)) private time, O(B+F+C*K) evidence space; finite hook caps.
"""
import base64
import json
from pathlib import Path
import struct
import zlib
from adid_reader import Adid,ROOT,sha,THIN_SHA
from probe_adid_startup import Startup,unpack_records,HEAP


class Request(Startup):
    def __init__(self,s,f,checkpoint):
        super().__init__(s,f,checkpoint)
        self.umask_value=f.get('initial_umask',0x12)
        self.u.mem_write(HEAP+0x1f000,struct.pack('<I',f.get('initial_errno',2)))
        self.lock_models={}
        self.lockf_calls=0
        for path,meta in f.get('extra_filesystem',{}).items():self.fs[path]=json.loads(json.dumps(meta))
    def api(self,im):
        if im['name']=='___error' and im['name'] in self.fixture.get('model_APIs',[]):
            self.records.append({'kind':'request_modeled_API','name':'___error','callsite':hex(self.reg('lr')-4),'errno_u32':struct.unpack('<I',self.u.mem_read(HEAP+0x1f000,4))[0],'result':hex(HEAP+0x1f000),'native_API_executed':False})
            return self.finish_api(HEAP+0x1f000)
        if im['name']=='_lockf' and im['name'] in self.fixture.get('model_APIs',[]):
            fd=struct.unpack('<i',struct.pack('<I',self.reg('x0')&0xffffffff))[0];cmd=self.reg('w1');extent=self.reg('x2');path=self.fds.get(fd)
            e={'kind':'request_modeled_API','name':'_lockf','callsite':hex(self.reg('lr')-4),'fd_signed32':fd,'path':path,'command_u32':cmd,'extent_u64':extent,'native_API_executed':False,'concurrency_validated':False};self.records.append(e)
            if path not in self.fs or cmd not in (0,1) or extent!=0:return self.stop('request_lockf_shape_guard')
            sequence=self.fixture.get('lockf_result_sequence',[]);result=sequence[min(self.lockf_calls,len(sequence)-1)] if sequence else self.fixture.get('lockf_result',0);self.lockf_calls+=1
            if result==0:self.lock_models[fd]={'path':path,'locked':cmd==1,'offset':self.fd_offsets[fd],'extent':extent}
            else:self.u.mem_write(HEAP+0x1f000,struct.pack('<I',self.fixture.get('lockf_errno',13)))
            e['result']=hex(result);return self.finish_api(result)
        if im['name']=='_statfs' and im['name'] in self.fixture.get('model_APIs',[]):
            path=self.string(self.reg('x0'));raw=bytearray(2168);kind=self.fixture.get('filesystem_type','apfs').encode();result=self.fixture.get('statfs_result',0)
            e={'kind':'request_modeled_API','name':'_statfs','callsite':hex(self.reg('lr')-4),'path':path,'filesystem_type':kind.decode(),'result':hex(result),'native_API_executed':False};self.records.append(e)
            if path not in self.fs or len(kind)>15:return self.stop('request_statfs_shape_guard')
            struct.pack_into('<Ii',raw,0,4096,4096);struct.pack_into('<I',raw,64,self.fixture.get('mount_flags',0x1000));raw[72:72+len(kind)]=kind
            if result==0:self.u.mem_write(self.reg('x1'),bytes(raw));e['statfs2168_bytes']=raw.hex()
            else:self.u.mem_write(HEAP+0x1f000,struct.pack('<I',self.fixture.get('statfs_errno',5)))
            return self.finish_api(result)
        if im['name'] in ('_fchmod','_umask','_fcntl') and im['name'] in self.fixture.get('model_APIs',[]):
            args=[self.reg('x'+str(i)) for i in range(8)];e={'kind':'request_modeled_API','name':im['name'],'callsite':hex(self.reg('lr')-4),'args_x0_x7':[hex(v) for v in args],'native_API_executed':False};self.records.append(e)
            if im['name']=='_umask':
                result=self.umask_value;self.umask_value=args[0]&0o777;e['mask_u32']=args[0]&0xffffffff
            else:
                fd=struct.unpack('<i',struct.pack('<I',args[0]&0xffffffff))[0];path=self.fds.get(fd);e.update({'fd_signed32':fd,'path':path,'mode_u32':args[1]&0xffffffff})
                if path not in self.fs:return self.stop('request_fchmod_ownership_guard')
                if im['name']=='_fchmod':
                    result=self.fixture.get('fchmod_result',0)
                    if result==0:self.fs[path]['mode']=(self.fs[path]['mode']&0xf000)|(args[1]&0o7777)
                    else:self.u.mem_write(HEAP+0x1f000,struct.pack('<I',self.fixture.get('fchmod_errno',1)))
                else:
                    e.pop('mode_u32');e['command_u32']=args[1]&0xffffffff
                    if e['command_u32']!=50:return self.stop('request_fcntl_command_guard')
                    dest=struct.unpack('<Q',self.u.mem_read(self.reg('sp'),8))[0];raw=self.fixture.get('fcntl_path',path).encode()+b'\0'
                    e['variadic_stack_pointer']=hex(dest);e['returned_path_bytes']=raw.hex();result=self.fixture.get('fcntl_result',0)
                    if len(raw)>1024:return self.stop('request_fcntl_path_extent_guard')
                    if result==0:self.u.mem_write(dest,raw)
                    else:self.u.mem_write(HEAP+0x1f000,struct.pack('<I',self.fixture.get('fcntl_errno',9)))
            e['result']=hex(result);return self.finish_api(result)
        if im['name']=='_lstat':
            path=self.string(self.reg('x0'))
            if path in self.fixture.get('stat_path_status',{}):
                missing='lstat_result' not in self.fixture;old=self.fixture.get('lstat_result');self.fixture['lstat_result']=self.fixture['stat_path_status'][path]
                try:
                    result=super().api(im)
                    if self.fixture['lstat_result']!=0:self.u.mem_write(HEAP+0x1f000,struct.pack('<I',self.fixture.get('stat_path_errno',{}).get(path,2)))
                    return result
                finally:
                    if missing:self.fixture.pop('lstat_result')
                    else:self.fixture['lstat_result']=old
        if im['name'] in ('_IOServiceMatching','_IOServiceGetMatchingServices','_IOServiceOpen','_IOConnectCallStructMethod','_notify_post'):
            args=[self.reg('x'+str(i)) for i in range(8)];e={'kind':'original_deeper_interface_boundary','name':im['name'],'callsite':hex(self.reg('lr')-4),'args_x0_x7':[hex(v) for v in args],'native_API_executed':False}
            if im['name'] in ('_IOServiceMatching','_notify_post'):e['name_string']=self.string(args[0])
            self.records.append(e)
        close_fd=struct.unpack('<i',struct.pack('<I',self.reg('x0')&0xffffffff))[0] if im['name']=='_close' else None
        result=super().api(im)
        if im['name']=='_open' and self.fixture.get('open_result',0)<0:self.u.mem_write(HEAP+0x1f000,struct.pack('<I',self.fixture.get('open_errno',13)))
        if im['name']=='_close' and self.reason is None:
            self.lock_models.pop(close_fd,None)
        return result
    def code(self,u,pc,n,data):
        if pc==0x10010d250:
            address=self.reg('x17');self.records.append({'kind':'original_filesystem_reference','pc':hex(pc),'reference_address':hex(address),'index_u64':self.reg('x8'),'source_bytes':self.s.read(address,16).hex()})
        if pc in (0x100110484,0x100110518,0x10010cdbc,0x10010d264,0x10010d2f8):
            self.records.append({'kind':'original_persistence_predicate','pc':hex(pc),'registers':{r:hex(self.reg(r)) for r in ('w0','w2','w3','w8','w9','w11','w20','w22','w23','w24','w25','w27','x8','x9','x21','x22','x23','x30')}})
        return super().code(u,pc,n,data)


def main():
    s=Adid();checkpoint=json.loads((ROOT/'adid_peer_checkpoint.json').read_text());old=json.loads((ROOT/'adid_receiver_profiles.json').read_text());startup=json.loads((ROOT/'adid_startup_profiles.json').read_text())
    admitted=next(r['fixture'] for r in old['profiles'] if r['fixture']['label']=='initialized_root_osinstall_None')
    main_apis=next(r['fixture']['model_APIs'] for r in startup['profiles'] if r['fixture']['label']=='listener_setup')
    common={**admitted,'seed_from':'linked_peer_setup','restore_models':True,'new_entry':0x100029fc8,'new_args':[HEAP+0x300,HEAP+0xd100],'model_eor3':True,
        'instruction_budget':300000,'model_APIs':sorted(set(admitted['model_APIs']+main_apis))}
    fixtures=[]
    for selector in (-8,-6,-5,-4,-3,-2):
        for value in (0,265,0x7b000100):
            fixtures.append({**common,'label':f'selector_{selector}_argument_{value:016x}','selector_signed64':selector,'argument_u64':value,
                'payload_hex':struct.pack('>IIIqQ',1,0x632b8d6e,1,selector,value).hex()})
    for selector in (-9,-7,-1,0,1,0xfffffff8):
        fixtures.append({**common,'label':f'counterfactual_selector_{selector}','selector_signed64':selector,'argument_u64':0,
            'payload_hex':struct.pack('>IIIqQ',1,0x632b8d6e,1,selector,0).hex()})
    bag_path='/var/db/fpsd/adi/adi-gb'
    for kind,mode in [('directory',0o40700),('regular',0o100600),('absent',0o40700)]:
        extra={bag_path:{'mode':mode,'uid':265,'gid':265,'size':0,'excluded':False}}
        f={**common,'label':'adi_gb_type_'+kind,'selector_signed64':-8,'argument_u64':0,'extra_filesystem':extra,
            'payload_hex':struct.pack('>IIIqQ',1,0x632b8d6e,1,-8,0).hex()}
        if kind=='absent':f['stat_path_status']={bag_path:-1};f['model_APIs']=[a for a in f['model_APIs'] if a!='_mkdir']
        fixtures.append(f)
    for selector in (-8,-6,-5,-4,-3,-2):
        fixtures.append({**common,'label':'directory_selector_'+str(selector),'selector_signed64':selector,'argument_u64':0,
            'extra_filesystem':{bag_path:{'mode':0o40700,'uid':265,'gid':265,'size':0,'excluded':False}},
            'payload_hex':struct.pack('>IIIqQ',1,0x632b8d6e,1,selector,0).hex()})
    for selector in (-8,-6,-5,-4,-3,-2):
        fixtures.append({**common,'label':'lock_selector_'+str(selector),'selector_signed64':selector,'argument_u64':0,
            'extra_filesystem':{bag_path:{'mode':0o100600,'uid':265,'gid':265,'size':0,'excluded':False},
                bag_path+'.lck':{'mode':0o100600,'uid':265,'gid':265,'size':0,'excluded':False}},
            'payload_hex':struct.pack('>IIIqQ',1,0x632b8d6e,1,selector,0).hex()})
    for selector in (-8,-6,-5,-4,-3,-2):
        f=next(json.loads(json.dumps(v)) for v in fixtures if v['label']=='lock_selector_'+str(selector))
        f['label']='fchmod_selector_'+str(selector);f['model_APIs']=f['model_APIs']+['_fchmod'];fixtures.append(f)
    for selector in (-8,-6,-5,-4,-3,-2):
        f=next(json.loads(json.dumps(v)) for v in fixtures if v['label']=='fchmod_selector_'+str(selector))
        f['label']='getpath_selector_'+str(selector);f['model_APIs']=f['model_APIs']+['_fcntl'];fixtures.append(f)
    for selector in (-8,-6,-5,-4,-3,-2):
        f=next(json.loads(json.dumps(v)) for v in fixtures if v['label']=='getpath_selector_'+str(selector))
        f['label']='statfs_selector_'+str(selector);f['model_APIs']=f['model_APIs']+['_statfs'];fixtures.append(f)
    for kind in ('nfs','hfs','smbfs'):
        f=next(json.loads(json.dumps(v)) for v in fixtures if v['label']=='statfs_selector_-8')
        f['label']='statfs_type_'+kind;f['filesystem_type']=kind;fixtures.append(f)
    for selector in (-8,-6,-5,-4,-3,-2):
        f=next(json.loads(json.dumps(v)) for v in fixtures if v['label']=='statfs_selector_'+str(selector))
        f['label']='locked_selector_'+str(selector);f['model_APIs']=f['model_APIs']+['_lockf'];fixtures.append(f)
    locked=next(v for v in fixtures if v['label']=='locked_selector_-8')
    for value in (265,0xffffffff,0x100000000,0x7b000100):
        f=json.loads(json.dumps(locked));f.update({'label':'locked_argument_'+hex(value),'argument_u64':value,'payload_hex':struct.pack('>IIIqQ',1,0x632b8d6e,1,-8,value).hex()});fixtures.append(f)
    for label,updates in [('initial_errno_zero',{'initial_errno':0}),('initial_errno_EACCES',{'initial_errno':13}),
        ('lock_open_fd_zero',{'open_result':0}),('lock_open_failure',{'open_result':-1}),('fchmod_failure',{'fchmod_result':-1}),
        ('getpath_failure',{'fcntl_result':-1}),('statfs_failure',{'statfs_result':-1}),('lockf_EACCES',{'lockf_result':-1,'lockf_errno':13}),
        ('lockf_EINTR_then_success',{'lockf_result_sequence':[-1,0],'lockf_errno':4})]:
        f=json.loads(json.dumps(locked));f.update(updates);f['label']=label;fixtures.append(f)
    for mode in (0o100666,0o100777,0o100640):
        f=json.loads(json.dumps(locked));f['extra_filesystem'][bag_path+'.lck']['mode']=mode;f['label']='lock_mode_'+oct(mode);fixtures.append(f)
    for selector in (-8,-6,-5,-4,-3,-2):
        f=next(json.loads(json.dumps(v)) for v in fixtures if v['label']=='locked_selector_'+str(selector));f['label']='record_selector_'+str(selector)
        f['extra_filesystem']['/Users/Shared/adi/adi-00000000.pb']={'mode':0o100666,'uid':265,'gid':265,'size':0,'contents_hex':'','excluded':False};fixtures.append(f)
    for selector in (-8,-6,-5,-4,-3,-2):
        for status in (0,-1):
            f=next(json.loads(json.dumps(v)) for v in fixtures if v['label']=='record_selector_'+str(selector));f['label']=f'setup_selector_{selector}_status_{status}'
            f['extra_filesystem']['/var/db/.AppleSetupUser']={'mode':0o100600,'uid':0,'gid':0,'size':0,'excluded':False};f['stat_path_status']={'/var/db/.AppleSetupUser':status};fixtures.append(f)
    for label,updates in [('setup_initial_errno_zero',{'initial_errno':0}),('setup_nonroot_501',{'audit_euid_result':501}),('setup_nonroot_265',{'audit_euid_result':265}),
        ('setup_argument_265',{'argument_u64':265,'payload_hex':struct.pack('>IIIqQ',1,0x632b8d6e,1,-8,265).hex()})]:
        f=next(json.loads(json.dumps(v)) for v in fixtures if v['label']=='setup_selector_-8_status_-1');f.update(updates);f['label']=label;fixtures.append(f)
    for kind,mode in [('directory',0o40700),('symlink',0o120777)]:
        f=json.loads(json.dumps(locked));f['initial_errno']=0;f['extra_filesystem'][bag_path]['mode']=mode;f['label']='gb_errno_zero_'+kind;fixtures.append(f)
    for selector in (-8,-6,-5,-4,-3,-2):
        for status in (0,-1):
            f=next(json.loads(json.dumps(v)) for v in fixtures if v['label']==f'setup_selector_{selector}_status_-1');f['label']=f'setup_fallback_selector_{selector}_status_{status}'
            f['extra_filesystem']['/var/setup/.AppleSetupUser']={'mode':0o100600,'uid':0,'gid':0,'size':0,'excluded':False};f['stat_path_status']['/var/setup/.AppleSetupUser']=status;fixtures.append(f)
    for selector in (-8,-6,-5,-4,-3,-2):
        f=next(json.loads(json.dumps(v)) for v in fixtures if v['label']==f'setup_fallback_selector_{selector}_status_-1');f['initial_errno']=0;f['label']='setup_no_markers_errno_zero_'+str(selector);fixtures.append(f)
    rows=[];functions={};instructions={}
    for f in fixtures:
        probe=Request(s,f,checkpoint);r=probe.run_continuation();r['lock_model_final']=probe.lock_models;r['umask_model_final']=probe.umask_value
        for v in r.pop('original_functions'):functions[v['start']]=v
        for v in r.pop('instruction_records'):instructions[v['ea']]=v
        rows.append(r)
        e=unpack_records(r);print(json.dumps({'label':r['fixture']['label'],'stop':r['stop_reason'],'steps':r['steps'],'last':e[-1] if e else None}),flush=True)
    out={'scope':__doc__,'thin_sha256':THIN_SHA,'profiles':rows,'original_functions':list(functions.values()),'original_instruction_records':list(instructions.values()),
        'generator_sha256':sha(Path(__file__).read_bytes()),'dependencies':{n:sha((ROOT/n).read_bytes()) for n in ['adid_reader.py','probe_adid_receiver.py','probe_adid_startup.py',
            'adid_peer_checkpoint.json','adid_startup_profiles.json','adid_receiver_profiles.json']},'native_target_executed':False,'full_goal_complete':False}
    (ROOT/'adid_request_profiles.json').write_text(json.dumps(out,indent=2)+'\n')


if __name__=='__main__':main()
