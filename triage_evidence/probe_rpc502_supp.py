#!/usr/bin/env python3
"""Original RPC502 supplemental-file continuation with separate private owners.

Frozen sinf prefix builds the record and next filename. A second declared
open/stat/mapping/copy epoch has distinct FD/mapping/allocation identities.
No parser PC/frame/gate override and no native target/API execution. Original
guest code bytes are checked at every source visit. O(B+V+E+S) bounded space
and event construction time;native scheduling/transport/IO remain unknown.
"""
import copy,json,struct
from pathlib import Path
from probe_rpc502_parser import Parser,ROOT,SOURCE,IMAGE,ar,uc,STACK
from probe_rpc502_sidecar_metadata import MetadataProbe

SUPP_POINTS={0x1008b5170,0x1008b5200,0x100895d78,0x10095e7f0,0x100a43b8c,0x1008776f4,0x10049bc34,0x10049bd24,0x100500ad4,0x10099ace0,0x100a4fd14,0x1009519e4,0x100315ae8}
MAP2=0x5300000000
ERRNO2=0x5500000000

class Supplemental(Parser):
    def __init__(self,second_raw=b'',fixture=None,first_raw=None):
        self.second_raw=second_raw;self.supp_fixture=fixture or {};self.supp_phase=False;self.supp_read_events=[];self.supp_copy=None;self.maps={};self.FDs={};self.roles={};self.supp_api_boundaries=[];self.supp_call_frames=[];self.errno_mapped=False;self.core_calls=[];self.active_core=[];self.core_reads=[];self.core_writes=[];self.supp_points=[]
        if first_raw is None:first_raw=struct.pack('>6I',1,0,1,0,0,0)+bytes(40)
        super().__init__(first_raw,self.supp_fixture)
    def model(self,name,**kw):
        e=super().model(name,**kw)
        if self.supp_phase:e.update(kind='explicit_supp_API_model',file_epoch=2)
        return e
    def second_size(self):return self.supp_fixture.get('second_size_u64',len(self.second_raw))
    def allocate_supp(self,n,site):
        assert 0<=n<=65536 and len(self.heap_allocations)<16
        size=max(1,n);mapped=(size+4095)&~4095;ptr=self.heap_next;self.heap_next+=mapped+4096;self.u.mem_map(ptr,mapped);self.u.mem_write(ptr,b'\xa5'*size);self.heap_allocations.append({'address':ptr,'size':n,'mapped':mapped,'initialized':bytearray(size),'allocation_pc':site});return ptr
    def hook(self,u,a,n,d):
        self.flush();name=self.imports.get(a)
        if 0x100000000<=a<0x102000000:assert bytes(u.mem_read(a,4))==IMAGE.read(a,4),('guest opcode differs',hex(a))
        if self.active_core and a==int(self.core_calls[self.active_core[-1]]['return_pc'],16):self.core_calls[self.active_core.pop()]['returned_at_step']=self.steps
        if a==0x10099ab1c:
            ptr=self.reg(0);call={'entry':hex(a),'pointer':hex(ptr),'return_pc':hex(self.reg(30)),'entry_step':self.steps,'file_epoch':2 if self.supp_phase else 1,'prefix128_hex':bytes(u.mem_read(ptr,128)).hex(),'registers_x0_x28':[hex(self.reg(j))for j in range(29)],'predecessor_source_stores':[copy.deepcopy(e)for e in self.stack_stores if int(e['address'],16)<ptr+44 and int(e['address'],16)+e['size_bytes']>ptr]};self.active_core.append(len(self.core_calls));self.core_calls.append(call)
        if self.supp_phase and a in SUPP_POINTS:
            sp=u.reg_read(ar.UC_ARM64_REG_SP);point={'pc':hex(a),'sp':hex(sp),'step':self.steps,'registers_x0_x30':[hex(self.reg(j))for j in range(29)]+[hex(u.reg_read(ar.UC_ARM64_REG_X29)),hex(self.reg(30))]}
            if a==0x10049bc34:point['frame_ad80_hex']=bytes(u.mem_read(sp+0xad80,4)).hex();point['frame_ad6c_hex']=bytes(u.mem_read(sp+0xad6c,4)).hex()
            if a==0x1008b5170:point['mapping_record_hex']=bytes(u.mem_read(self.reg(21),32)).hex()
            self.supp_points.append(point)
        if self.supp_phase and a in [0x10041a5e0,0x10099ab1c,0x1005b94fc,0x1005b9544,0x100118ec8,0x100081090,0x10010e334]:
            ptr=self.reg(0);prefix=None
            try:prefix=bytes(u.mem_read(ptr,128)).hex()
            except uc.UcError:pass
            self.supp_call_frames.append({'pc':hex(a),'sp':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'registers_x0_x28':[hex(self.reg(j))for j in range(29)],'x0_prefix128_hex':prefix,'prefix_definedness_not_established':True})
        if name=='libSystem/_open'and self.open_count>=1:
            self.supp_phase=True;self.open_count+=1;self.steps+=1;raw=bytes(u.mem_read(self.reg(0),256)).split(b'\0')[0];obs={'kind':'source_open_arguments_observation','site':hex(self.reg(30)-4),'path_pointer':hex(self.reg(0)),'path_hex':raw.hex(),'flags_u32':self.reg(1)&0xffffffff,'observed_at_step':self.steps,'file_epoch':self.open_count,'native_API_executed':False};self.open_observations.append(obs);self.records.append(obs)
            if self.open_count>2:self.model(name,result='further file epoch boundary',path_hex=raw.hex());return self.stop('further_file_open_epoch')
            result=self.supp_fixture.get('second_open_result',8);self.model(name,result_signed32=result,path_hex=raw.hex())
            if result>=0:self.FDs[result]={'epoch':2,'path_hex':raw.hex(),'close_requests':[],'declared_closed':False}
            return self.return_model(result)
        if self.supp_phase and name=='libSystem/_fstat':
            self.steps+=1;fd=self.reg(0);assert fd in self.FDs and self.FDs[fd]['epoch']==2;self.stat_buffer=self.reg(1);self.stat_known=bytearray(144);status=self.supp_fixture.get('second_fstat_result',0);self.stat_status=status;self.model(name,result_signed32=status,stat_buffer=hex(self.stat_buffer),metadata_extent_bytes=144)
            if status==0 or self.supp_fixture.get('seed_size_on_stat_error'):
                size=self.second_size();u.mem_write(self.stat_buffer+96,struct.pack('<Q',size));self.stat_known[96:104]=bytes([1])*8;self.records.append({'kind':'explicit_supp_stat_size_seed','file_epoch':2,'address':hex(self.stat_buffer+96),'bytes_hex':struct.pack('<Q',size).hex(),'other_metadata_bytes_unknown':True,'seed_on_failure':status!=0})
            return self.return_model(status)
        if self.supp_phase and name=='libSystem/___error':
            self.steps+=1
            if not self.errno_mapped:u.mem_map(ERRNO2,4096);self.errno_mapped=True
            value=self.supp_fixture.get('second_errno_u32',2);u.mem_write(ERRNO2,struct.pack('<I',value));self.model(name,result=hex(ERRNO2),declared_errno_u32=value,explicit_output_effect={'address':hex(ERRNO2),'bytes_hex':struct.pack('<I',value).hex()});return self.return_model(ERRNO2)
        if self.supp_phase and name=='libSystem/_mmap':
            self.steps+=1;args=[self.reg(j)for j in range(6)];size=self.second_size();assert args==[0,size,1,2,self.supp_fixture.get('second_open_result',8),0],args
            if self.supp_fixture.get('second_mmap_failed'):self.model(name,result='0xffffffffffffffff',logical_extent_bytes=size);return self.return_model((1<<64)-1)
            if size>0x40000:self.model(name,result='analysis mapping budget',logical_extent_bytes=size);return self.stop('supp_mapping_budget')
            if MAP2 in self.maps:self.model(name,result='repeated mapping boundary',logical_extent_bytes=size);return self.stop('repeated_supp_mapping')
            pages=(max(1,size)+4095)&~4095;u.mem_map(MAP2,pages,uc.UC_PROT_READ);assert len(self.second_raw)<=size;u.mem_write(MAP2,self.second_raw);self.maps[MAP2]={'epoch':2,'size_bytes':size,'mapped_bytes':pages,'known_prefix_bytes':len(self.second_raw),'declared_bytes_hex':self.second_raw.hex(),'retired':False,'unmap_requests':[]};self.model(name,result=hex(MAP2),logical_extent_bytes=size,known_prefix_bytes=len(self.second_raw),declared_bytes_hex=self.second_raw.hex());return self.return_model(MAP2)
        if self.supp_phase and name=='libSystem/_malloc'and self.reg(30)==0x10095b5cc:
            self.steps+=1;size=self.reg(0);assert size==self.second_size()
            if self.supp_fixture.get('second_copy_malloc_NULL'):self.model(name,result='0x0',requested_size_bytes=size,owner_role='supp_copy');return self.return_model(0)
            if size>65536 or len(self.heap_allocations)>=16:self.model(name,result='analysis allocation budget',requested_size_bytes=size);return self.stop('supp_copy_allocation_budget')
            ptr=self.allocate_supp(size,self.reg(30)-4);self.supp_copy=ptr;self.roles[ptr]='supp_copy';self.model(name,result=hex(ptr),requested_size_bytes=size,owner_role='supp_copy',initial_bytes='a5 poison;unwritten reads blocked');return self.return_model(ptr)
        if self.supp_phase and name=='libSystem/_munmap':
            self.steps+=1;ptr,size=self.reg(0),self.reg(1);assert ptr in self.maps and self.maps[ptr]['size_bytes']==size;status=self.supp_fixture.get('second_unmap_result'if self.maps[ptr]['epoch']==2 else'first_unmap_result',0);self.maps[ptr]['unmap_requests'].append(status)
            if status==0:self.maps[ptr]['retired']=True;self.retired.add(ptr)
            self.model(name,result_signed32=status,mapping=hex(ptr),length_bytes=size);return self.return_model(status)
        if self.supp_phase and name=='libSystem/_close':
            self.steps+=1;fd=self.reg(0);assert fd in self.FDs,fd;status=self.supp_fixture.get('second_close_result'if self.FDs[fd]['epoch']==2 else'first_close_result',0);self.FDs[fd]['close_requests'].append(status)
            if status==0:self.FDs[fd]['declared_closed']=True
            self.model(name,result_signed32=status,declared_FD=fd);return self.return_model(status)
        answer=super().hook(u,a,n,d)
        if self.supp_phase and a==0x100cc0870:
            event=next(e for e in reversed(self.records)if e['kind']=='file_size_encoding_checkpoint');event.update(size_bits=hex(self.second_size()),file_epoch=2,observer_note='second-epoch label replaces inherited single-file size label')
        if name=='libSystem/_open'and self.open_count==1:self.FDs[7]={'epoch':1,'path_hex':self.open_observations[-1]['path_hex'],'close_requests':[],'declared_closed':False}
        if name=='libSystem/_mmap'and self.mapping is not None and self.mapping not in self.maps:self.maps[self.mapping]={'epoch':1,'size_bytes':self.mapping_length,'mapped_bytes':self.mapping_pages,'known_prefix_bytes':len(self.pattern),'declared_bytes_hex':self.pattern.hex(),'retired':False,'unmap_requests':[]}
        return answer
    def read_hook(self,u,access,a,n,value,d):
        if self.active_core:
            idx=self.active_core[-1];p=int(self.core_calls[idx]['pointer'],16)
            if a<p+44 and a+n>p:self.core_reads.append({'call_index':idx,'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'address':hex(a),'offset_bytes':a-p,'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex(),'registers_x0_x28':[hex(self.reg(j))for j in range(29)]})
        for p,m in self.maps.items():
            if m['epoch']!=2 or not(a<p+m['mapped_bytes']and a+n>p):continue
            if m['retired']:return self.stop('supp_retired_mapping_read',pc=hex(u.reg_read(ar.UC_ARM64_REG_PC)),address=hex(a),size_bytes=n)
            if a<p or a+n>p+m['size_bytes']:return self.stop('supp_mapping_extent_read',pc=hex(u.reg_read(ar.UC_ARM64_REG_PC)),address=hex(a),size_bytes=n,logical_extent_bytes=m['size_bytes'])
            if a+n>p+m['known_prefix_bytes']:return self.stop('supp_mapping_unknown_read',pc=hex(u.reg_read(ar.UC_ARM64_REG_PC)),address=hex(a),size_bytes=n,offset_bytes=a-p)
            self.supp_read_events.append({'kind':'supp_mapping','pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'offset_bytes':a-p,'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()})
        if self.supp_copy is not None:
            owner=next(v for v in self.heap_allocations if v['address']==self.supp_copy);p=self.supp_copy
            if a<p+owner['mapped']and a+n>p:
                if a<p or a+n>p+owner['size']:return self.stop('supp_copy_extent_read',pc=hex(u.reg_read(ar.UC_ARM64_REG_PC)),address=hex(a),size_bytes=n,logical_extent_bytes=owner['size'])
                if p in self.retired:return self.stop('supp_retired_copy_read',pc=hex(u.reg_read(ar.UC_ARM64_REG_PC)),address=hex(a),size_bytes=n)
                if all(owner['initialized'][a-p:a-p+n]):self.supp_read_events.append({'kind':'supp_copy','pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'offset_bytes':a-p,'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()})
        return super().read_hook(u,access,a,n,value,d)
    def write_hook(self,u,access,a,n,value,d):
        if self.active_core:
            idx=self.active_core[-1];p=int(self.core_calls[idx]['pointer'],16)
            if a<p+44 and a+n>p:
                e={'call_index':idx,'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'address':hex(a),'offset_bytes':a-p,'size_bytes':n};self.core_writes.append(e);self.pending_owner_stores.append(e);self.records.append({'kind':'source_core_argument_write','store':e})
        return super().write_hook(u,access,a,n,value,d)
    def run(self):
        r=super().run();r.update(scope=__doc__,supp_fixture=self.supp_fixture,declared_second_file_bytes_hex=self.second_raw.hex(),supplemental_points=self.supp_points,supplemental_reads=self.supp_read_events,supplemental_call_frames=self.supp_call_frames,core_argument_calls=self.core_calls,core_argument_reads=self.core_reads,core_argument_writes=self.core_writes,declared_mapping_owners={hex(k):copy.deepcopy(v)for k,v in self.maps.items()},declared_FD_owners={str(k):copy.deepcopy(v)for k,v in self.FDs.items()},supp_copy_pointer=hex(self.supp_copy)if self.supp_copy is not None else None,owner_roles={hex(k):v for k,v in self.roles.items()},guest_source_opcodes_checked_each_visit=True,full_goal_complete=False);return r

if __name__=='__main__':
    q=Supplemental(bytes(64));r=q.run();Path('/tmp/rpc502-supp-first.json').write_text(json.dumps(r));print(r['steps'],r['stop_reason'],r['records'][-1],flush=True)
