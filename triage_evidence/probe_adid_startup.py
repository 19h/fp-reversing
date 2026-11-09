#!/usr/bin/env python3
"""Continue original adid startup from a source-produced private checkpoint.

The frozen receiver engine supplies original pages and PAC/atomic/vector models.
Only declared fixture APIs continue; no target, loader, host API/IPC/file or
environment operation executes. Checkpoints preserve every mutable guest page
and GPR/SIMD state. O(B+F+K0+C*K) time, O(B+F+K0+C*K) evidence space.
"""
import base64
import hashlib
import json
from pathlib import Path
import struct
import zlib
from unicorn import arm64_const as A
from adid_reader import Adid,ROOT,sha,THIN_SHA
from probe_adid_receiver import Probe,STACK,HEAP,BIND,DONE,MASK


def unpack_records(row):return row['records'] if 'records' in row else json.loads(zlib.decompress(base64.b64decode(row['records_zlib_base64'])))


class Startup(Probe):
    def __init__(self,s,f,checkpoint=None):
        super().__init__(s,f);self.boundaries=[];self.cf_objects={};self.cf_cursor=HEAP+0x14000;self.fds={};self.fd_offsets={}
        self.fs={'/Users/Shared/adi':{'mode':f.get('stat_mode',0o40755),'uid':f.get('stat_uid',265),'gid':f.get('stat_gid',265),'excluded':False}}
        if f.get('include_shared_record'):self.fs['/Users/Shared/adi/adi.pb']={'mode':f.get('record_mode',0o100666),'uid':265,'gid':265,'size':f.get('record_size',0),'excluded':False}
        if f.get('include_private_context'):
            self.fs['/var/db/fpsd/adi']={'mode':0o40700,'uid':265,'gid':265,'excluded':False}
            self.fs['/var/db/fpsd/adi/adi.pb']={'mode':0o100600,'uid':265,'gid':265,'size':0,'excluded':False}
        if checkpoint:
            for region in checkpoint['regions']:
                a=int(region['address'],16);raw=zlib.decompress(base64.b64decode(region['bytes_zlib_base64']))
                if region['mapping']:self.u.mem_map(a,len(raw));self.mappings.append((a,len(raw)))
                self.u.mem_write(a,raw)
            for name,value in checkpoint['registers'].items():self.u.reg_write(getattr(A,'UC_ARM64_REG_'+name),int(value,16))
            if f.get('restore_models'):
                self.fs=json.loads(json.dumps(checkpoint['filesystem_model_state']));self.cf_objects={int(k):json.loads(json.dumps(v)) for k,v in checkpoint['CF_object_models'].items()};self.cf_cursor=checkpoint['CF_cursor']
                self.fds={int(k):v for k,v in checkpoint['descriptor_models'].items()};self.fd_offsets={int(k):v for k,v in checkpoint['descriptor_offsets'].items()}
        if f.get('new_entry'):
            self.u.reg_write(A.UC_ARM64_REG_SP,self.sp);self.u.reg_write(A.UC_ARM64_REG_LR,DONE);self.u.reg_write(A.UC_ARM64_REG_PC,f['new_entry'])
            for j in range(8):self.u.reg_write(getattr(A,'UC_ARM64_REG_X'+str(j)),f.get('new_args',[])[j] if j<len(f.get('new_args',[])) else 0)
    def checkpoint(self,row):
        regions=[]
        extents=[(seg['address'],seg['vm_size'],False) for seg in self.s.meta['segments'] if seg['name']=='__DATA']
        extents += [(STACK,0x40000,False),(HEAP,0x20000,False),(BIND,0x10000,False)]+[(a,n,True) for a,n in self.mappings]
        for a,n,mapping in extents:
            raw=bytes(self.u.mem_read(a,n));regions.append({'address':hex(a),'size_bytes':n,'mapping':mapping,'sha256':sha(raw),'bytes_zlib_base64':base64.b64encode(zlib.compress(raw)).decode()})
        names=[f'X{j}' for j in range(31)]+[f'Q{j}' for j in range(32)]+['SP','PC','NZCV','FPCR','FPSR','CPACR_EL1']
        registers={name:hex(self.u.reg_read(getattr(A,'UC_ARM64_REG_'+name))) for name in names}
        return {'source_profile':row['fixture']['label'],'source_stop_reason':row['stop_reason'],'source_ordered_instruction_sha256':row['ordered_original_instruction_sha256'],
            'source_thin_sha256':THIN_SHA,'regions':regions,'registers':registers,'native_state':False,
            'filesystem_model_state':self.fs,'CF_object_models':self.cf_objects,'CF_cursor':self.cf_cursor,'descriptor_models':self.fds,'descriptor_offsets':self.fd_offsets}
    def api(self,im):
        name=im['name'];new={'_getuid','_sysctlbyname','_getpid','_gethostuuid','_notify_post','_umask','_signal','_xpc_connection_create_mach_service','_CFRunLoopGetMain','_CFRunLoopGetCurrent','_lstat','_chmod','_mkdir','___error',
            '_CFURLCreateFromFileSystemRepresentation','_CFURLCopyResourcePropertyForKey','_CFURLSetResourcePropertyForKey','_CFFileSecuritySetMode','_CSBackupIsItemExcluded','_CSBackupSetItemExcluded','_open','_fstat','_close','_read','_ftruncate','_write','_unlink','_pthread_rwlock_destroy','_os_release','_kqueue','_kevent',
            '_CFFileDescriptorCreate','_CFFileDescriptorCreateRunLoopSource','_CFFileDescriptorEnableCallBacks','_CFRunLoopAddSource','_CFFileDescriptorGetNativeDescriptor','_CFFileDescriptorInvalidate','_CFRunLoopStop','_CFRunLoopRun','_munmap'}
        if name not in new:return super().api(im)
        args=[self.reg('x'+str(j)) for j in range(8)];site=self.reg('lr')-4
        if not self.s.base<=site<self.s.base+len(self.s.data):site=int(self.last_edge['pc'],16)
        e={'kind':'startup_opaque_API_boundary','name':name,'callsite':hex(site),'args_x0_x7':[hex(v) for v in args],'native_API_executed':False};self.records.append(e)
        if name in ('_sysctlbyname','_notify_post','_xpc_connection_create_mach_service'):e['name_string']=self.string(args[0])
        if name=='_sysctlbyname':e['old_size_u64']=struct.unpack('<Q',self.u.mem_read(args[2],8))[0]
        if name in ('_lstat','_chmod','_mkdir','_open','_unlink'):e['path']=self.string(args[0])
        if name=='_open':e['flags_u32']=args[1]&0xffffffff;e['first_variadic_stack_u64']=hex(struct.unpack('<Q',self.u.mem_read(self.reg('sp'),8))[0])
        if name in ('_fstat','_close','_read','_ftruncate','_write'):e['fd_signed32']=struct.unpack('<i',struct.pack('<I',args[0]&0xffffffff))[0];e['path']=self.fds.get(e['fd_signed32'])
        if name=='_CFURLCreateFromFileSystemRepresentation':
            if args[2]>4096:return self.stop('startup_URL_extent_guard')
            e.update({'path_bytes':bytes(self.u.mem_read(args[1],args[2])).hex(),'is_directory':args[3]&0xff})
        if name in ('_CFURLCopyResourcePropertyForKey','_CFURLSetResourcePropertyForKey'):
            keys=[n for n,at in self.symbols.items() if n.startswith('_kCFURL') and args[1] in (at,struct.unpack('<Q',self.u.mem_read(at,8))[0])];e['key_symbols']=keys
        if name=='_kevent':
            if args[2]>16 or args[4]>16:return self.stop('startup_kevent_extent_guard')
            e['changes_bytes']=bytes(self.u.mem_read(args[1],32*args[2])).hex() if args[2] else '';e['change_count']=args[2];e['event_capacity']=args[4]
        if name=='_CFFileDescriptorCreate':e['context40_bytes']=bytes(self.u.mem_read(args[4],40)).hex() if args[4] else None;e['callback']=hex(args[3]);e['close_on_invalidate_boolean']=args[2]&0xff
        if name not in self.fixture.get('model_APIs',[]):return self.stop('startup_opaque_API_boundary:'+name)
        e['kind']='startup_modeled_API';result=0
        if name=='_getuid':result=self.fixture.get('provider_uid',265)
        elif name=='_getpid':result=2117
        elif name=='_sysctlbyname':
            if e['name_string']!='kern.hv_vmm_present' or e['old_size_u64']!=4 or args[3:5]!=[0,0]:return self.stop('startup_sysctl_shape_guard')
            result=self.fixture.get('VMM_status',0)
            if result==0:self.u.mem_write(args[1],struct.pack('<I',self.fixture.get('VMM_value',0)));self.u.mem_write(args[2],struct.pack('<Q',4))
            e['modeled_value_u32']=self.fixture.get('VMM_value',0)
        elif name=='_gethostuuid':
            raw=bytes.fromhex(self.fixture.get('host_uuid_hex','00112233445566778899aabbccddeeff'));self.u.mem_write(args[0],raw);e['uuid_bytes']=raw.hex()
        elif name=='_umask':e['mask_u32']=args[0]&0xffffffff;result=0x12
        elif name=='_signal':e['signal_u32']=args[0]&0xffffffff;e['handler']=hex(args[1]);result=0
        elif name=='_xpc_connection_create_mach_service':result=0 if self.fixture.get('listener_result')=='NULL' else HEAP+0xe500
        elif name in ('_CFRunLoopGetMain','_CFRunLoopGetCurrent'):result=HEAP+0xe600
        elif name in ('_lstat','_fstat'):
            if e['path'] not in self.fs:return self.stop('startup_unknown_stat_path_guard')
            meta=self.fs[e['path']];raw=bytearray(144);struct.pack_into('<H',raw,4,meta['mode']);struct.pack_into('<I',raw,16,meta['uid']);struct.pack_into('<I',raw,20,meta['gid']);struct.pack_into('<q',raw,96,meta.get('size',0));result=self.fixture.get('fstat_result' if name=='_fstat' else 'lstat_result',0)
            if name=='_lstat' and meta.get('path_unlinked'):result=-1
            if result==0:self.u.mem_write(args[1],bytes(raw));e['stat144_bytes']=raw.hex()
        elif name in ('_chmod','_mkdir'):
            e['mode_u32']=args[1]&0xffffffff;result=self.fixture.get('chmod_result' if name=='_chmod' else 'mkdir_result',0)
            if result==0:
                if e['path'] not in self.fs:return self.stop('startup_unknown_mode_path_guard')
                self.fs[e['path']]['mode']=(self.fs[e['path']]['mode']&0xf000 if name=='_chmod' else 0o40000)|(args[1]&0xfff)
        elif name=='___error':result=HEAP+0x1f000;self.u.mem_write(result,struct.pack('<I',self.fixture.get('errno_value',2)));e['errno_u32']=self.fixture.get('errno_value',2)
        elif name=='_CFURLCreateFromFileSystemRepresentation':
            result=0 if self.fixture.get('URL_result')=='NULL' else self.cf_cursor
            if result:self.cf_cursor+=64;self.cf_objects[result]={'kind':'URL','path_bytes':e['path_bytes']}
        elif name=='_CFURLCopyResourcePropertyForKey':
            if e['key_symbols']==['_kCFURLFileSecurityKey']:
                ptr=self.cf_cursor;self.cf_cursor+=64;self.cf_objects[ptr]={'kind':'file_security','mode':0}
            elif e['key_symbols']==['_kCFURLIsDirectoryKey']:
                path=bytes.fromhex(self.cf_objects[args[0]]['path_bytes']).decode();isdir=(self.fs[path]['mode']&0xf000)==0o40000
                symbol='_kCFBooleanTrue' if self.fixture.get('URL_is_directory',isdir) else '_kCFBooleanFalse';ptr=struct.unpack('<Q',self.u.mem_read(self.symbols[symbol],8))[0]
            else:return self.stop('startup_CF_property_key_guard')
            self.u.mem_write(args[2],struct.pack('<Q',ptr))
            if args[3]:self.u.mem_write(args[3],struct.pack('<Q',0))
            e['property_value']=hex(ptr);result=1
        elif name=='_CFFileSecuritySetMode':e['mode_u32']=args[1]&0xffffffff;self.cf_objects[args[0]]['mode']=args[1]&0xfff;result=1
        elif name=='_CFURLSetResourcePropertyForKey':
            e['property_value']=hex(args[2]);result=1
            if e['key_symbols']==['_kCFURLFileSecurityKey']:
                path=bytes.fromhex(self.cf_objects[args[0]]['path_bytes']).decode();self.fs[path]['mode']=(self.fs[path]['mode']&0xf000)|self.cf_objects[args[2]]['mode']
            if args[3]:self.u.mem_write(args[3],struct.pack('<Q',0))
        elif name=='_CSBackupIsItemExcluded':
            if args[1]:self.u.mem_write(args[1],b'\0')
            path=bytes.fromhex(self.cf_objects[args[0]]['path_bytes']).decode();result=int(self.fs[path]['excluded'])
        elif name=='_CSBackupSetItemExcluded':
            e['exclude_boolean']=args[1]&0xff;e['exclude_by_path_boolean']=args[2]&0xff;result=0
            path=bytes.fromhex(self.cf_objects[args[0]]['path_bytes']).decode();self.fs[path]['excluded']=bool(args[1]&0xff)
        elif name=='_open':
            result=self.fixture.get('open_result',73+len(self.fds))
            if result>=0:
                if result in self.fds:return self.stop('startup_descriptor_collision_guard')
                if self.fs.get(e['path'],{}).get('path_unlinked'):
                    if args[1]&0x200:self.fs[e['path']]['path_unlinked']=False
                    else:return self.stop('startup_open_unlinked_path_guard')
                self.fds[result]=e['path'];self.fd_offsets[result]=0
        elif name=='_close':
            if e['fd_signed32'] not in self.fds:return self.stop('startup_unowned_close_guard')
            self.fds.pop(e['fd_signed32']);self.fd_offsets.pop(e['fd_signed32']);result=0
        elif name=='_read':
            if e['fd_signed32'] not in self.fds or args[2]>65536:return self.stop('startup_read_extent_or_ownership_guard')
            result=self.fixture.get('read_result',0);e['requested_bytes']=args[2]
            if self.fixture.get('record_bytes_hex'):
                raw=bytes.fromhex(self.fixture['record_bytes_hex'] if e['path']=='/Users/Shared/adi/adi.pb' else self.fs[e['path']].get('contents_hex',''));result=min(args[2],len(raw)-self.fd_offsets[e['fd_signed32']]);raw=raw[self.fd_offsets[e['fd_signed32']]:]
            else:raw=bytes.fromhex(self.fixture.get('record_bytes_hex',''))
            if result>0:
                if result>args[2]:return self.stop('startup_read_result_guard')
                assert len(raw)>=result;self.u.mem_write(args[1],raw[:result]);e['bytes']=raw[:result].hex();self.fd_offsets[e['fd_signed32']]+=result
        elif name=='_ftruncate':
            if e['path'] not in self.fs:return self.stop('startup_unowned_truncate_guard')
            e['size_u64']=args[1];result=self.fixture.get('truncate_result',0)
            if result==0:self.fs[e['path']]['size']=args[1]
        elif name=='_write':
            if e['path'] not in self.fs or args[2]>65536:return self.stop('startup_unowned_or_large_write_guard')
            e['bytes']=bytes(self.u.mem_read(args[1],args[2])).hex();e['size_bytes']=args[2];result=self.fixture.get('write_result',args[2])
            if result>args[2]:return self.stop('startup_write_result_guard')
            if result>=0:self.fs[e['path']]['size']=result;self.fs[e['path']]['contents_hex']=e['bytes'][:result*2];self.fd_offsets[e['fd_signed32']]+=result
        elif name=='_unlink':
            if e['path'] not in self.fs:return self.stop('startup_unknown_unlink_path_guard')
            e['modeled_only']=True;result=self.fixture.get('unlink_result',0)
            if result==0:self.fs[e['path']]['path_unlinked']=True
        elif name=='_pthread_rwlock_destroy':e['lock_pointer']=hex(args[0]);result=0
        elif name=='_os_release':e['object_pointer']=hex(args[0]);result=0
        elif name=='_kqueue':result=self.fixture.get('kqueue_result',91)
        elif name=='_kevent':
            result=self.fixture.get('kevent_result',0)
            if result>0:
                if result!=1 or args[4]<1:return self.stop('startup_kevent_output_guard')
                raw=struct.pack('<QhHIqQ',self.fixture.get('event_ident',15),self.fixture.get('event_filter',-6),0,0,1,0);self.u.mem_write(args[3],raw);e['returned_event_bytes']=raw.hex()
        elif name=='_CFFileDescriptorCreate':result=0 if self.fixture.get('fd_wrapper_result')=='NULL' else HEAP+0xe800
        elif name=='_CFFileDescriptorCreateRunLoopSource':result=0 if self.fixture.get('runloop_source_result')=='NULL' else HEAP+0xe900
        elif name in ('_CFFileDescriptorEnableCallBacks','_CFRunLoopAddSource'):result=0
        elif name=='_CFFileDescriptorGetNativeDescriptor':result=91
        elif name in ('_CFFileDescriptorInvalidate','_CFRunLoopStop','_CFRunLoopRun'):result=0
        elif name=='_munmap':
            if (args[0],args[1]) not in self.mappings:return self.stop('startup_unowned_unmap_guard')
            self.u.mem_unmap(args[0],args[1]);self.mappings.remove((args[0],args[1]));e['private_only']=True;result=0
        e['result']=hex(result);self.finish_api(result)
    def code(self,u,pc,n,data):
        if pc in (0x10001e65c,0x10001e6a4,0x10001e8a0,0x10001e900):
            self.records.append({'kind':'original_startup_stat_predicate','pc':hex(pc),'w8':hex(self.reg('w8')),'w9':hex(self.reg('w9')),'w21':hex(self.reg('w21')),'w24':hex(self.reg('w24'))})
        if pc==0x100014e14:self.records.append({'kind':'original_open_predicate','pc':hex(pc),'result_u32':self.reg('w0'),'threshold_u32':self.reg('w8')})
        if pc==0x100016d8c:self.records.append({'kind':'original_write_count_predicate','pc':hex(pc),'result_u64':self.reg('x0'),'expected_u64':self.reg('x25'),
            'w26':self.reg('w26'),'w24':self.reg('w24'),'table':hex(self.reg('x12'))})
        if pc==0x10002bdac:self.records.append({'kind':'original_VMM_result_byte','pc':hex(pc),'destination':hex(self.reg('x19')+4),'value_u8':self.reg('w8')&255})
        return super().code(u,pc,n,data)
    def run_continuation(self):
        entry=self.reg('pc');entry_sp=self.reg('sp')
        try:self.u.emu_start(entry,DONE+4,count=self.fixture.get('instruction_budget',100000)+1)
        except Exception as e:
            if self.reason is None:self.reason='private_guest_exception:'+str(e)
        h=hashlib.sha256()
        for pc in self.visited:h.update(struct.pack('<Q',pc));h.update(self.s.read(pc,4))
        row={'fixture':self.fixture,'resume_pc':hex(entry),'entry_sp':hex(entry_sp),'stop_reason':self.reason,'steps':self.steps,'result_u32':self.reg('w0'),
            'ordered_original_instruction_sha256':h.hexdigest(),'records':self.records,'original_functions':list(self.functions.values()),'instruction_records':list(self.instructions.values()),
            'visited_original_instruction_count':len(self.visited),'visited_original_instructions_zlib_base64':base64.b64encode(zlib.compress(b''.join(struct.pack('<Q',pc) for pc in self.visited))).decode(),
            'filesystem_model_final':self.fs,'open_descriptors_final':self.fds,'private_mappings_final':[(hex(a),n) for a,n in self.mappings]}
        if len(row['records'])>256:
            raw=json.dumps(row.pop('records'),separators=(',',':')).encode();row['records_zlib_base64']=base64.b64encode(zlib.compress(raw)).decode()
        return row


def main():
    s=Adid();prior=json.loads((ROOT/'adid_receiver_profiles.json').read_text());baseline=next(r['fixture'] for r in prior['profiles'] if r['fixture']['label']=='startup_vector')
    base=Startup(s,{**baseline,'label':'original_main_prefix_to_getuid'});first=base.run();ck=base.checkpoint(first)
    assert first['stop_reason']=='startup_opaque_API_boundary:_getuid'
    (ROOT/'adid_startup_checkpoint.json').write_text(json.dumps(ck,indent=2)+'\n')
    fixtures=[]
    for uid in (0,265,501):fixtures.append({**baseline,'label':'provider_uid_'+str(uid),'provider_uid':uid,'seed_from':'original_main_prefix_to_getuid','model_APIs':baseline['model_APIs']+['_getuid']})
    for value in (0,1):fixtures.append({**baseline,'label':'VMM_'+str(value),'VMM_value':value,'seed_from':'original_main_prefix_to_getuid','model_APIs':baseline['model_APIs']+['_getuid','_sysctlbyname']})
    for result in (0,-1):fixtures.append({**baseline,'label':'directory_lstat_'+str(result),'seed_from':'original_main_prefix_to_getuid','lstat_result':result,
        'model_APIs':baseline['model_APIs']+['_getuid','_lstat']})
    for label,extra,apis in [('directory_umask',{},['_umask']),('directory_metadata',{},['_umask','_chmod','_mkdir']),
        ('directory_missing',{'lstat_result':-1,'errno_value':2},['___error']),('directory_denied',{'lstat_result':-1,'errno_value':13},['___error']),
        ('directory_regular_file',{'stat_mode':0o100644},['_umask','_chmod','_mkdir'])]:
        fixtures.append({**baseline,'label':label,'seed_from':'original_main_prefix_to_getuid',**extra,'model_APIs':baseline['model_APIs']+['_getuid','_lstat']+apis})
    filesystem=['_getuid','_lstat','_umask','_chmod','_mkdir','___error','_CFURLCreateFromFileSystemRepresentation','_CFURLCopyResourcePropertyForKey','_CFFileSecuritySetMode',
        '_CFURLSetResourcePropertyForKey','_CSBackupIsItemExcluded','_CSBackupSetItemExcluded','_CFRelease']
    fixtures.append({**baseline,'label':'directory_CF_metadata','seed_from':'original_main_prefix_to_getuid','model_APIs':baseline['model_APIs']+filesystem})
    for size in (0,4096):fixtures.append({**baseline,'label':'record_metadata_'+str(size),'seed_from':'original_main_prefix_to_getuid','include_shared_record':True,'record_size':size,
        'model_APIs':baseline['model_APIs']+filesystem})
    for fd in (0,73,-1):fixtures.append({**baseline,'label':'record_open_'+str(fd),'seed_from':'original_main_prefix_to_getuid','include_shared_record':True,'open_result':fd,
        'model_APIs':baseline['model_APIs']+filesystem+['_open']})
    fixtures.append({**baseline,'label':'record_fstat','seed_from':'original_main_prefix_to_getuid','include_shared_record':True,
        'model_APIs':baseline['model_APIs']+filesystem+['_open','_fstat','_close']})
    for result in (0,-1):fixtures.append({**baseline,'label':'record_read_'+str(result),'seed_from':'original_main_prefix_to_getuid','include_shared_record':True,'read_result':result,
        'model_APIs':baseline['model_APIs']+filesystem+['_open','_fstat','_close','_read','_os_log_type_enabled']})
    fixtures.append({**baseline,'label':'two_contexts','seed_from':'original_main_prefix_to_getuid','include_shared_record':True,'include_private_context':True,
        'model_APIs':baseline['model_APIs']+filesystem+['_open','_fstat','_close','_read','_os_log_type_enabled']})
    fixtures.append({**baseline,'label':'two_contexts_write','seed_from':'original_main_prefix_to_getuid','include_shared_record':True,'include_private_context':True,
        'model_APIs':baseline['model_APIs']+filesystem+['_open','_fstat','_close','_read','_os_log_type_enabled','_ftruncate','_write']})
    for size in (0,16,31,257):
        raw=bytes((i*37+11)&255 for i in range(size));fixtures.append({**baseline,'label':'migrate_record_'+str(size),'seed_from':'original_main_prefix_to_getuid','include_shared_record':True,'include_private_context':True,
            'record_size':size,'record_bytes_hex':raw.hex(),'model_APIs':baseline['model_APIs']+filesystem+['_open','_fstat','_close','_read','_os_log_type_enabled','_ftruncate','_write','_unlink']})
    continuation=baseline['model_APIs']+filesystem+['_open','_fstat','_close','_read','_os_log_type_enabled','_ftruncate','_write','_unlink','_pthread_rwlock_destroy','_os_release']
    for label,extra in [('migration_cleanup',{}),('migration_short_write',{'write_result':15}),('migration_write_error',{'write_result':-1}),
        ('migration_truncate_error',{'truncate_result':-1}),('migration_unlink_error',{'unlink_result':-1})]:
        fixtures.append({**baseline,'label':label,'seed_from':'original_main_prefix_to_getuid','include_shared_record':True,'include_private_context':True,
            'record_size':31,'record_bytes_hex':bytes((i*37+11)&255 for i in range(31)).hex(),**extra,'model_APIs':continuation})
    for label,value,status in [('postinit_VMM_0',0,0),('postinit_VMM_1',1,0),('postinit_VMM_2',2,0),('postinit_VMM_error',0,5)]:
        fixtures.append({**baseline,'label':label,'seed_from':'original_main_prefix_to_getuid','include_shared_record':True,'include_private_context':True,
            'record_size':31,'record_bytes_hex':bytes((i*37+11)&255 for i in range(31)).hex(),'VMM_value':value,'VMM_status':status,'model_APIs':continuation+['_sysctlbyname']})
    fixtures.append({**baseline,'label':'event_queue_setup','seed_from':'original_main_prefix_to_getuid','include_shared_record':True,'include_private_context':True,
        'record_size':31,'record_bytes_hex':bytes((i*37+11)&255 for i in range(31)).hex(),'model_APIs':continuation+['_sysctlbyname','_kqueue','_kevent']})
    event_apis=continuation+['_sysctlbyname','_kqueue','_kevent','_signal','_CFRunLoopGetMain','_CFRunLoopGetCurrent','_CFFileDescriptorCreate',
        '_CFFileDescriptorCreateRunLoopSource','_CFFileDescriptorEnableCallBacks','_CFRunLoopAddSource','_xpc_connection_create_mach_service',
        '_xpc_connection_set_event_handler','_xpc_connection_activate','_xpc_connection_resume','_xpc_connection_set_target_queue']
    fixtures.append({**baseline,'label':'listener_setup','seed_from':'original_main_prefix_to_getuid','include_shared_record':True,'include_private_context':True,
        'record_size':31,'record_bytes_hex':bytes((i*37+11)&255 for i in range(31)).hex(),'model_APIs':event_apis})
    fixtures.insert(len(fixtures)-1,{**baseline,'label':'listener_after_short_write','seed_from':'original_main_prefix_to_getuid','include_shared_record':True,'include_private_context':True,
        'record_size':31,'record_bytes_hex':bytes((i*37+11)&255 for i in range(31)).hex(),'write_result':15,'model_APIs':event_apis})
    rows=[first];loop_checkpoint=None
    for f in fixtures:
        probe=Startup(s,f,ck);row=probe.run_continuation();rows.append(row)
        if f['label']=='listener_setup':
            loop_checkpoint=probe.checkpoint(row);(ROOT/'adid_listener_checkpoint.json').write_text(json.dumps(loop_checkpoint,indent=2)+'\n')
    assert loop_checkpoint is not None
    extra=[]
    callback_apis=['_CFFileDescriptorGetNativeDescriptor','_kevent','_CFRunLoopGetCurrent','_CFRunLoopGetMain','_CFRunLoopStop','_CFFileDescriptorInvalidate','_CFFileDescriptorEnableCallBacks','_os_log_type_enabled']
    for label,value,ident in [('signal_no_events',0,15),('signal_SIGTERM',1,15),('signal_other_ident',1,2),('signal_kevent_error',-1,15)]:
        extra.append({**baseline,'label':label,'seed_from':'listener_setup','restore_models':True,'new_entry':0x100045bdc,'new_args':[HEAP+0xe800,1,0],
            'kevent_result':value,'event_ident':ident,'model_APIs':baseline['model_APIs']+callback_apis})
    for vmm in (0,1):
        extra.append({**baseline,'label':'signal_SIGTERM_VMM_'+str(vmm),'seed_from':'listener_setup','restore_models':True,'new_entry':0x100045bdc,'new_args':[HEAP+0xe800,1,0],
            'kevent_result':1,'event_ident':15,'VMM_value':vmm,'model_APIs':baseline['model_APIs']+callback_apis+['_sysctlbyname']})
    extra.append({**fixtures[-1],'label':'loop_return_cleanup','seed_from':'listener_setup','restore_models':True,'model_APIs':event_apis+['_CFRunLoopRun','_CFFileDescriptorInvalidate']})
    extra.append({**fixtures[-1],'label':'loop_return_unmap','seed_from':'listener_setup','restore_models':True,'model_APIs':event_apis+['_CFRunLoopRun','_CFFileDescriptorInvalidate','_munmap']})
    f=next(r['fixture'] for r in prior['profiles'] if r['fixture']['label']=='initialized_root_osinstall_None')
    extra.append({**f,'label':'receiver_after_listener_setup','seed_from':'listener_setup','restore_models':True,'model_eor3':True,'new_entry':0x100029fc8,'new_args':[HEAP+0x100,HEAP+0x400]})
    for f in extra:rows.append(Startup(s,f,loop_checkpoint).run_continuation())
    before={**f,'label':'receiver_before_getuid_same_models','seed_from':'original_main_prefix_to_getuid','restore_models':True}
    rows.append(Startup(s,before,ck).run_continuation())
    setup_row=next(r for r in rows if r['fixture']['label']=='listener_setup')
    listener_handler=next(e for e in unpack_records(setup_row) if e.get('name')=='_xpc_connection_set_event_handler')
    peer_fixture={**baseline,'label':'linked_peer_setup','seed_from':'listener_setup','restore_models':True,'new_entry':0x1000009f8,
        'new_args':[int(listener_handler['args_x0_x7'][1],16),HEAP+0xd000],'model_APIs':['_xpc_connection_set_target_queue','_xpc_connection_set_event_handler','_xpc_connection_resume']}
    peer=Startup(s,peer_fixture,loop_checkpoint);peer_row=peer.run_continuation();rows.append(peer_row)
    handler=next(e for e in unpack_records(peer_row) if e.get('name')=='_xpc_connection_set_event_handler');block=bytes.fromhex(handler['block48_bytes']);size=s.qword(struct.unpack_from('<Q',block,24)[0]+8);assert size==40
    peer.u.mem_write(HEAP+0x300,block[:size]);peer_row.setdefault('fixture_events',[]).append({'kind':'explicit_private_block_copy','source':handler['args_x0_x7'][1],'destination':hex(HEAP+0x300),'size_bytes':size,'native_block_lifetime_inferred':False})
    peer_checkpoint=peer.checkpoint(peer_row);(ROOT/'adid_peer_checkpoint.json').write_text(json.dumps(peer_checkpoint,indent=2)+'\n')
    request=next(r['fixture'] for r in prior['profiles'] if r['fixture']['label']=='denied_selector_-8')
    linked={**request,'label':'linked_peer_request','seed_from':'linked_peer_setup','restore_models':True,'model_eor3':True,'new_entry':0x100029fc8,'new_args':[HEAP+0x300,HEAP+0xd100]}
    rows.append(Startup(s,linked,peer_checkpoint).run_continuation())
    functions={};instructions={}
    for r in rows:
        for v in r.pop('original_functions'):functions[v['start']]=v
        for v in r.pop('instruction_records',r.pop('visited_instruction_records',[])):instructions[v['ea']]=v
    out={'scope':__doc__,'thin_sha256':THIN_SHA,'profiles':rows,'original_functions':list(functions.values()),'original_instruction_records':list(instructions.values()),
        'checkpoint_sha256':sha((ROOT/'adid_startup_checkpoint.json').read_bytes()),'checkpoint_sha256s':{n:sha((ROOT/n).read_bytes()) for n in ['adid_startup_checkpoint.json','adid_listener_checkpoint.json','adid_peer_checkpoint.json']},'generator_sha256':sha(Path(__file__).read_bytes()),
        'dependencies':{n:sha((ROOT/n).read_bytes()) for n in ['adid_reader.py','probe_adid_receiver.py','adid_receiver_profiles.json']},'native_target_executed':False,'full_goal_complete':False}
    (ROOT/'adid_startup_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
    for r in rows:
        rr=unpack_records(r);print(json.dumps({'label':r['fixture']['label'],'stop':r['stop_reason'],'steps':r['steps'],'last':rr[-1] if rr else None}))


if __name__=='__main__':main()
