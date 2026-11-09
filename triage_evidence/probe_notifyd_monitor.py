#!/usr/bin/env python3
"""Original notifyd deferred monitor/VFS callbacks in a bounded private guest.

Original config parsing creates names/token vectors;explicit Block copy,
scheduling,dispatch,FD,stat and realpath fixtures drive original callbacks.
No native file/credential/watch/dispatch/IPC operation executes.
O(B+P+V+W+A) bounded time/space;unknown interfaces stop.
"""
import copy,json,struct,hashlib,re
from pathlib import Path
from unicorn import arm64_const as A
from probe_notifyd_policy import Policy
from probe_notifyd_admission import HEAP,STACK,DONE
from notifyd_ipc_reader import Notifyd,ROOT,sha
from bootpolicy_cache_reader import Dylib


class Monitor(Policy):
    def __init__(self,d,f):
        super().__init__(d,f);self.blocks=[];self.next_block=HEAP+0xa000;self.pending_once=[];self.fds={};self.next_fd=100;self.fs=copy.deepcopy(f.get('fs',{'/':{'mode':0o040755},'/model':{'mode':0o040755},'/model/file':{'mode':0o100644}}));self.event_data={};self.history=[];self.reference_bindings=[];self.source_records={}
        for path,symbol in [('/usr/lib/system/libsystem_sandbox.dylib','_SANDBOX_CHECK_NO_REPORT'),('/usr/lib/system/libsystem_info.dylib','_gL1CacheEnabled')]:
            lib=Dylib(self.cache.cache,path);address=lib.exports[symbol]['address'];raw=self.cache.read(address,4);value=f.get('initial_L1_u32',int.from_bytes(raw,'little')) if symbol=='_gL1CacheEnabled' else int.from_bytes(raw,'little');self.u.mem_write(self.symbols[symbol],struct.pack('<I',value));self.reference_bindings.append({'symbol':symbol,'library':path,'uuid':lib.uuid,'original_cache_address':hex(address),'original_bytes':raw.hex(),'declared_guest_initial_u32':value,'guest_bound_address':hex(self.symbols[symbol]),'runtime_native_value_established':False})
    def copy_block(self,p,e,kind):
        raw=bytes(self.u.mem_read(p,32));descriptor=int.from_bytes(raw[24:32],'little');size=int.from_bytes(self.u.mem_read(descriptor+8,8),'little');assert 32<=size<=128;dest=self.next_block;self.next_block+=0x100;assert self.next_block<=HEAP+0x18000;raw=bytes(self.u.mem_read(p,size));self.api_write(dest,raw,e);record={'kind':kind,'source_pointer':hex(p),'copy_pointer':hex(dest),'size_bytes':size,'bytes':raw.hex(),'invoke_pointer':hex(int.from_bytes(raw[16:24],'little')),'descriptor_pointer':hex(descriptor),'native_Block_copy_or_scheduling_validated':False};self.blocks.append(record);e['explicit_Block_copy']=record;return record
    def stat_bytes(self,path):
        item=self.fs.get(path)
        if item is None or item.get('missing'):return None
        raw=bytearray(144);struct.pack_into('<IHHQII',raw,0,1,item.get('mode',0o100644),1,item.get('inode',int.from_bytes(hashlib.sha256(path.encode()).digest()[:8],'little')),item.get('uid',0),item.get('gid',20));struct.pack_into('<4q',raw,48,item.get('mtime_seconds',10),item.get('mtime_nanoseconds',0),item.get('ctime_seconds',20),item.get('ctime_nanoseconds',0));struct.pack_into('<q',raw,96,item.get('size_bytes',1));return bytes(raw)
    def api(self,im):
        name=im['name'];x=[self.reg('x'+str(j)) for j in range(8)];f=self.fixture
        special=['_dispatch_async','_dispatch_after','_dispatch_once','_dispatch_source_set_event_handler','_dispatch_source_set_cancel_handler','_dispatch_source_create','_dispatch_source_merge_data','_dispatch_source_get_data','_dispatch_source_testcancel','_dispatch_suspend','_dispatch_resume','_dispatch_activate','_dispatch_source_cancel','_dispatch_release','_strchr','_strncpy','_strlcat','___strlcat_chk','___memset_chk','_realpath$DARWIN_EXTSN','_lstat','_fstat','_open','_open$NOCANCEL','_close','_close$NOCANCEL','___close_nocancel','_stat','_getgroups','_getpwuid','_initgroups','_pthread_setugid_np','_syscall','___error','_sandbox_check_by_audit_token','_strncasecmp','_strtol']
        if name not in special:return super().api(im)
        e={'kind':'explicit_monitor_API_model','name':name,'callsite':hex(getattr(self,'last_source_branch',self.reg('lr')-4)),'args_x0_x7':[hex(v) for v in x],'native_API_executed':False};self.records.append(e)
        if name=='_strtol':
            assert x[1:3]==[0,0];text=self.string(x[0]);m=re.match(r'^[\t\n\v\f\r ]*([+-]?)(0[xX][0-9a-fA-F]+|0[0-7]*|[1-9][0-9]*)',text);value=0
            if m:
                digits=m[2];base=16 if digits.lower().startswith('0x') else 8 if digits.startswith('0') else 10;value=int(digits,base)*(-1 if m[1]=='-' else 1)
            assert -(1<<63)<=value<(1<<63);e.update(input=text,declared_base=0,modeled_result_signed64=value);return self.finish_api(value)
        if name=='_strncasecmp':
            a=self.string(x[0]).encode()[:x[2]].lower();b=self.string(x[1]).encode()[:x[2]].lower();e.update(left_hex=a.hex(),right_hex=b.hex(),bound_bytes=x[2]);return self.finish_api((a>b)-(a<b))
        if name=='_sandbox_check_by_audit_token':
            arg=int.from_bytes(self.u.mem_read(self.reg('sp'),8),'little');e.update(audit_token32_hex=bytes(self.u.mem_read(x[0],32)).hex(),operation=self.string(x[1]),filter_u32=x[2],variadic_path=self.string(arg),declared_result_signed32=f.get('sandbox_monitor_result',0));return self.finish_api(f.get('sandbox_monitor_result',0))
        if name=='_getgroups':
            groups=f.get('group_list',[20,80]);e.update(requested_count=x[0],declared_group_list=groups)
            if f.get('getgroups_failure'):e['result_signed32']=-1;return self.finish_api(-1)
            assert len(groups)<=x[0]<=16;self.api_write(x[1],struct.pack('<'+'I'*len(groups),*groups),e);return self.finish_api(len(groups))
        if name=='_getpwuid':
            e['requested_uid_u32']=x[0]&0xffffffff
            if f.get('passwd_missing'):return self.finish_api(0)
            raw=bytearray(80);struct.pack_into('<Q',raw,0,HEAP+0x1b00);struct.pack_into('<II',raw,16,x[0]&0xffffffff,f.get('credential_gid',20));self.api_write(HEAP+0x1a00,bytes(raw),e);self.api_write(HEAP+0x1b00,b'fixture-user\0',e);return self.finish_api(HEAP+0x1a00)
        if name=='_initgroups':e.update(username=self.string(x[0]),gid_u32=x[1]&0xffffffff,modeled_effect='no native supplementary groups change');return self.finish_api(f.get('initgroups_result',0))
        if name=='_pthread_setugid_np':e.update(uid_u32=x[0]&0xffffffff,gid_u32=x[1]&0xffffffff,modeled_effect='no native thread credential change');return self.finish_api(0)
        if name=='_syscall':
            assert x[0]==243;count,pointer,uid=struct.unpack('<QQQ',self.u.mem_read(self.reg('sp'),24));assert count<=16;e.update(syscall_number=243,variadic_count=count,variadic_groups_u32=list(struct.unpack('<'+'I'*count,self.u.mem_read(pointer,4*count))),variadic_uid_u64=uid,modeled_effect='no native syscall/groups change');return self.finish_api(f.get('restore_groups_result',0))
        if name=='___error':e.update(result=hex(HEAP+0x1900));return self.finish_api(HEAP+0x1900)
        if name=='_stat':
            path=self.string(x[0])
            if path=='/etc/notify.conf':return super().api(im)
            raw=self.stat_bytes(path);denied=path in f.get('user_stat_denied_paths',[]);e.update(path=path,declared_result_signed32=-1 if raw is None or denied else 0)
            if denied:self.api_write(HEAP+0x1900,struct.pack('<I',13),e)
            elif raw is not None:self.api_write(x[1],raw,e)
            else:self.api_write(HEAP+0x1900,struct.pack('<I',2),e)
            return self.finish_api(-1 if raw is None or denied else 0)
        if name=='_dispatch_once':
            old=int.from_bytes(self.u.mem_read(x[0],8),'little');e['old_token_u64']=hex(old)
            if old==(1<<64)-1:return self.finish_api(0)
            assert old==0;callback=int.from_bytes(self.u.mem_read(x[1]+16,8),'little');marker=DONE+0x100+len(self.pending_once)*16;self.pending_once.append({'marker':marker,'token':x[0],'return':self.reg('lr')});e['original_callback']=hex(callback);self.u.reg_write(A.UC_ARM64_REG_X0,x[1]);self.u.reg_write(A.UC_ARM64_REG_LR,marker);self.u.reg_write(A.UC_ARM64_REG_PC,callback);return
        if name in ['_dispatch_async','_dispatch_after']:
            p=x[2] if name=='_dispatch_after' else x[1];record=self.copy_block(p,e,'after' if name.endswith('after') else 'async');record['queue_or_time_args']=[hex(v) for v in x[:2]];return self.finish_api(0)
        if name in ['_dispatch_source_set_event_handler','_dispatch_source_set_cancel_handler']:
            if x[0]==0:return self.stop('explicit_NULL_dispatch_source_boundary')
            record=self.copy_block(x[1],e,'cancel' if 'cancel' in name else 'event');obj=self.objects[x[0]];obj['cancel_block' if 'cancel' in name else 'event_block']=record['copy_pointer'];return self.finish_api(0)
        if name=='_dispatch_source_create':
            source_type=next((k for k,v in self.symbols.items() if v==x[0]),'unknown bound source type')
            if f.get('source_create_NULL_type')==source_type:e.update(type_symbol=source_type,result='NULL fixture');return self.finish_api(0)
            # Frozen API model provides the owned opaque object;retain exact declaration.
            result=super().api(im);ptr=self.reg('x0');obj=self.objects[ptr];obj.update(type_symbol=next((k for k,v in self.symbols.items() if v==x[0]),'unknown bound source type'),handle_u64=x[1],mask_u64=x[2],queue_pointer=hex(x[3]),merge_requests=[],pending_data_u64=0,cancel_requested=False);return result
        if name=='_dispatch_source_merge_data':
            obj=self.objects[x[0]];obj['merge_requests'].append(x[1]);obj['pending_data_u64']|=x[1];e['modeled_pending_data_u64']=obj['pending_data_u64'];return self.finish_api(0)
        if name=='_dispatch_source_get_data':
            value=self.event_data.get(x[0],self.objects[x[0]].get('pending_data_u64',0));e['declared_event_data_u64']=value;return self.finish_api(value)
        if name=='_dispatch_source_testcancel':value=int(self.objects[x[0]].get('cancel_requested',False));e['declared_cancel_bool']=bool(value);return self.finish_api(value)
        if name in ['_dispatch_suspend','_dispatch_resume','_dispatch_activate','_dispatch_source_cancel','_dispatch_release']:
            obj=self.objects.get(x[0]);e['modeled_effect']='request recorded;native scheduling/refcounts unknown'
            if obj is not None:
                obj.setdefault('requests',[]).append(name)
                if name=='_dispatch_source_cancel':obj['cancel_requested']=True
            return self.finish_api(0)
        if name=='_strchr':
            raw=self.string(x[0]).encode()+b'\0';at=raw.find(bytes([x[1]&255]));e.update(source_bytes=raw.hex(),result=hex(0 if at<0 else x[0]+at));return self.finish_api(0 if at<0 else x[0]+at)
        if name=='_strncpy':
            raw=self.string(x[1]).encode();assert x[2]<=4096;raw=raw[:x[2]]+bytes(max(0,x[2]-len(raw)));self.api_write(x[0],raw,e);return self.finish_api(x[0])
        if name in ['_strlcat','___strlcat_chk']:
            left=self.string(x[0]).encode();right=self.string(x[1]).encode();assert 0<x[2]<=4096
            if name.startswith('___'):assert x[2]<=x[3]
            if len(left)<x[2]:self.api_write(x[0],(left+right)[:x[2]-1]+b'\0',e)
            value=min(len(left),x[2])+len(right);e.update(left_hex=left.hex(),right_hex=right.hex(),result_length_bytes=value);return self.finish_api(value)
        if name=='___memset_chk':
            assert x[2]<=x[3]<=4096;self.api_write(x[0],bytes([x[1]&255])*x[2],e);return self.finish_api(x[0])
        if name=='_realpath$DARWIN_EXTSN':
            path=self.string(x[0]);result=f.get('realpaths',{}).get(path,path);e.update(path=path,declared_result=result)
            if result is None:self.api_write(HEAP+0x1900,struct.pack('<I',2),e);return self.finish_api(0)
            self.api_write(x[1],result.encode()+b'\0',e);return self.finish_api(x[1])
        if name in ['_lstat','_fstat']:
            path=self.fds[x[0]]['path'] if name=='_fstat' else self.string(x[0]);raw=self.stat_bytes(path);e.update(path=path,declared_result_signed32=0 if raw is not None else -1)
            if raw is not None:self.api_write(x[1],raw,e)
            else:self.api_write(HEAP+0x1900,struct.pack('<I',2),e)
            return self.finish_api(0 if raw is not None else -1)
        if name in ['_open','_open$NOCANCEL']:
            path=self.string(x[0]);e.update(path=path,flags_u32=x[1]&0xffffffff,variadic_mode_u64=hex(int.from_bytes(self.u.mem_read(self.reg('sp'),8),'little')))
            if self.stat_bytes(path) is None or path in f.get('open_fail_paths',[]):e['result_fd_signed32']=-1;self.api_write(HEAP+0x1900,struct.pack('<I',2),e);return self.finish_api(-1)
            fd=self.next_fd;self.next_fd+=1;self.fds[fd]={'path':path,'closed':False};e['result_fd_signed32']=fd;return self.finish_api(fd)
        if name in ['_close','_close$NOCANCEL','___close_nocancel']:
            if x[0]==72:return super().api(im)
            assert x[0] in self.fds and not self.fds[x[0]]['closed'];self.fds[x[0]]['closed']=True;return self.finish_api(0)
    def write(self,u,access,a,n,value,data):
        if hasattr(self,'symbols') and self.symbols.get('_gL1CacheEnabled',-1)<=a and a+n<=self.symbols.get('_gL1CacheEnabled',-1)+4:
            e={'kind':'original_bound_global_write','symbol':'_gL1CacheEnabled','pc':hex(self.reg('pc')),'address':hex(a),'size_bytes':n,'value_hex':(value&((1<<(8*n))-1)).to_bytes(n,'little').hex()};self.records.append(e);self.pending_writes.append(e);return
        return super().write(u,access,a,n,value,data)
    def code(self,u,pc,n,data):
        if self.pending_once and pc==self.pending_once[-1]['marker']:
            pending=self.pending_once.pop();e={'kind':'explicit_original_once_callback_return','token':hex(pending['token']),'native_once_or_concurrency_validated':False};self.records.append(e);self.api_write(pending['token'],struct.pack('<Q',(1<<64)-1),e);self.u.reg_write(A.UC_ARM64_REG_LR,pending['return']);return self.finish_api(0)
        return super().code(u,pc,n,data)
    def invoke(self,label,entry,args):
        r=super().invoke(label,entry,args)
        for e in r['records']:
            if e.get('name')=='_malloc_type_calloc' and e.get('callsite') in ['0x100007430','0x10000828c']:
                self.source_records[int(e['result'],16)]='monitor' if e['callsite']=='0x100007430' else 'watcher'
        snapshots=[]
        for p,kind in self.source_records.items():
            owner=self.allocations[p];raw=bytes(self.u.mem_read(p,owner['size_bytes']));item={'pointer':hex(p),'kind':kind,**owner,'bytes':raw.hex()}
            if not owner['freed']:
                item['path']=self.string(int.from_bytes(raw[:8],'little'))
                if kind=='monitor':item.update(status_u32=int.from_bytes(raw[64:68],'little'),flags_u32=int.from_bytes(raw[68:72],'little'),source_pointer=hex(int.from_bytes(raw[72:80],'little')),refcount_u32=int.from_bytes(raw[104:108],'little'),client_key_u64=int.from_bytes(raw[96:104],'little'))
                else:
                    count=int.from_bytes(raw[56:60],'little');ptr=int.from_bytes(raw[64:72],'little');assert count<=64;item.update(fd_signed32=int.from_bytes(raw[12:16],'little',signed=True),follow_u32=int.from_bytes(raw[8:12],'little'),monitor_count_u32=count,monitor_pointers=[hex(int.from_bytes(self.u.mem_read(ptr+8*j,8),'little')) for j in range(count)])
            snapshots.append(item)
        r.update(source_owned_record_snapshots=snapshots,explicit_copied_blocks_after=copy.deepcopy(self.blocks),declared_FD_state_after=copy.deepcopy(self.fds),declared_fs_after=copy.deepcopy(self.fs),reference_data_bindings=copy.deepcopy(self.reference_bindings),bound_L1_u32_after=int.from_bytes(self.u.mem_read(self.symbols['_gL1CacheEnabled'],4),'little'),provider_invocation_index=len(self.history));self.history.append(r);return r


def main():
    q=Monitor(Notifyd(),{'model_port_constructor':True,'model_port_request_notification':True,'config_hex':b'monitor fixture.path /model/file\n'.hex()});startup=q.invoke('startup',q.provider.entry,[q.argc,HEAP+0x1800]);block=next(b for b in q.blocks if b['invoke_pointer']=='0x10000712c');r=q.invoke('deferred_monitor',0x10000712c,[int(block['copy_pointer'],16)]);Path('/tmp/notifyd-monitor-first.json').write_text(json.dumps({'startup':startup,'callback':r}));print(json.dumps({'stop':r['stop_reason'],'steps':r['steps'],'last':r['records'][-1],'objects':q.objects}),flush=True)

if __name__=='__main__':main()
