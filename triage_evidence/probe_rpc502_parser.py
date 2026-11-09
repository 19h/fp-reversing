#!/usr/bin/env python3
"""Original RPC502 sidecar parser with explicit bytes and guarded private owners.

Extends frozen mapping/copy engines. No PC/frame/gate override; execution starts
at the original RPC502 public worker fixture. Explicit file bytes, additional
malloc/free/munmap/close results are models; unknown interfaces stop. No native
target,filesystem,credential,loader,Mach or synchronization API executes.
Time/space O(B+V+E+S) for bounded source bytes,visits,events and snapshots.
"""
import base64,hashlib,json,struct,zlib
from pathlib import Path
from probe_rpc502_sidecar_contents import ContentsProbe
from daemon_rpc502_context_probe import ContextProbe,ROOT
from daemon_rpc502_probe import ar,uc,STACK
from daemon_receive_tools import IMAGE,SOURCE,CS,FIXUPS

POINTS=[0x1009b7728,0x1009b6eac,0x1009b6f64,0x100a49ca0,0x100a50508,0x100a50580,0x100a505ac,0x100930174,0x1009301c8,0x100a386cc,0x100a65db0,0x100a65888,0x100891120,0x100a6876c,0x1009a002c,0x100972888,0x100913528,0x100913594,0x1009d8804,0x1009bb5c4,0x1009bb8dc,0x100926bc0]

class Parser(ContentsProbe):
    def __init__(self,raw,fixture=None):
        self.fixture=fixture or {};self.visit_pcs=[];self.instruction_bank={};self.source_hash=hashlib.sha256();self.parser_started=False;self.edges=[];self.points=[];self.fixup_reads={};self.owner_stores=[];self.stack_stores=[];self.pending_owner_stores=[];self.models=[];self.retired=set();self.extra_malloc_count=0;self.open_count=0;self.open_observations=[]
        assert 1<=len(raw)<=0x40000
        super().__init__(len(raw));self.pattern=raw
    def flush(self):
        for e in self.pending_owner_stores:e['actual_after_hex']=bytes(self.u.mem_read(int(e['address'],16),e['size_bytes'])).hex()
        self.pending_owner_stores=[]
    def owner(self,a,n=1):
        if self.copy_allocation is not None and a<self.copy_allocation+self.copy_pages and a+n>self.copy_allocation:return self.copy_allocation,self.copy_extent,'copy'
        for r in self.heap_allocations:
            if a<r['address']+r['mapped']and a+n>r['address']:return r['address'],r['size'],'heap'
        return None
    def model(self,name,**kw):
        e={'kind':'explicit_parser_API_model','name':name,'site':hex(self.reg(30)-4),'return_pc':hex(self.reg(30)),'args_x0_x7':[hex(self.reg(j))for j in range(8)],'native_API_executed':False,**kw};self.models.append(e);self.records.append(e);return e
    def hook(self,u,a,n,d):
        self.flush()
        if 0x100000000<=a<0x102000000:
            raw=IMAGE.read(a,4)
            if a not in self.instruction_bank:
                ins=next(CS.disasm(raw,a));self.instruction_bank[a]={'ea':hex(a),'bytes':raw.hex(),'mnemonic':ins.mnemonic,'operands':ins.op_str}
            self.visit_pcs.append(a);self.source_hash.update(struct.pack('<Q',a));self.source_hash.update(raw)
        if a in [0x1009b7728,0x1009b6eac]:self.parser_started=True
        if self.parser_started and a in self.instruction_bank:
            ins=self.instruction_bank[a]
            if ins['mnemonic']in ['braa','blraa','br','blr']:
                reg=int(ins['operands'].split(',')[0][1:]);self.edges.append({'pc':hex(a),'mnemonic':ins['mnemonic'],'operands':ins['operands'],'target':hex(self.reg(reg)),'registers_x0_x28':[hex(self.reg(j))for j in range(29)],'sp':hex(u.reg_read(ar.UC_ARM64_REG_SP))})
            if a in POINTS:
                sp=u.reg_read(ar.UC_ARM64_REG_SP);self.points.append({'pc':hex(a),'registers_x0_x28':[hex(self.reg(j))for j in range(29)],'sp':hex(sp),'frame_0x900_hex':bytes(u.mem_read(sp,0x900)).hex()})
        name=self.imports.get(a)
        if name=='libSystem/_open':
            self.open_count+=1
            raw=bytes(u.mem_read(self.reg(0),256)).split(b'\0')[0];obs={'kind':'source_open_arguments_observation','site':hex(self.reg(30)-4),'path_pointer':hex(self.reg(0)),'path_hex':raw.hex(),'flags_u32':self.reg(1)&0xffffffff,'observed_at_step':self.steps,'native_API_executed':False};self.open_observations.append(obs);self.records.append(obs)
            if self.open_count>1:
                self.steps+=1;self.model(name,result='new file epoch boundary',path_hex=bytes(u.mem_read(self.reg(0),256)).split(b'\0')[0].hex());return self.stop('next_file_open_epoch')
        if name=='libSystem/_malloc'and self.reg(30)!=0x10095b5cc:
            size=self.reg(0);self.steps+=1;self.extra_malloc_count+=1
            if self.fixture.get('extra_malloc_stop'):self.model(name,requested_size_bytes=size,result='boundary');return self.stop('new_malloc_boundary')
            if size>65536 or len(self.heap_allocations)>=16:self.model(name,requested_size_bytes=size,result='analysis budget');return self.stop('new_malloc_budget')
            if self.fixture.get('extra_malloc_NULL'):self.model(name,requested_size_bytes=size,result='0x0');return self.return_model(0)
            n=max(1,size);mapped=(n+4095)&~4095;ptr=self.heap_next;self.heap_next+=mapped+4096;u.mem_map(ptr,mapped);u.mem_write(ptr,b'\xa5'*n);self.heap_allocations.append({'address':ptr,'size':size,'mapped':mapped,'initialized':bytearray(n),'allocation_pc':self.reg(30)-4});self.model(name,requested_size_bytes=size,result=hex(ptr),initial_bytes='poison a5;unwritten reads blocked');return self.return_model(ptr)
        if name=='libSystem/_free':
            ptr=self.reg(0);self.steps+=1
            if ptr:
                owned=self.owner(ptr);assert owned and owned[0]==ptr and ptr not in self.retired,(hex(ptr),'free owner');self.retired.add(ptr)
            snapshot=bytes(u.mem_read(ptr,owned[1])).hex()if ptr else'';self.model(name,result=0,retired_pointer=hex(ptr),retired_bytes_hex=snapshot);return self.return_model(0)
        if name=='libSystem/_munmap':
            self.steps+=1;assert self.reg(0)==self.mapping and self.reg(1)==self.mapping_length;status=self.fixture.get('unmap_result',0);self.model(name,result_signed32=status,logical_mapping_retired=status==0)
            if status==0:self.retired.add(self.mapping)
            return self.return_model(status)
        if name=='libSystem/_close':
            self.steps+=1;assert self.reg(0)==7;status=self.fixture.get('close_result',0);self.model(name,result_signed32=status,declared_FD=7);return self.return_model(status)
        return super().hook(u,a,n,d)
    def read_hook(self,u,access,a,n,value,d):
        if self.mapping is not None and self.mapping in self.retired and a<self.mapping+self.mapping_pages and a+n>self.mapping:return self.stop('retired_mapping_read',pc=hex(u.reg_read(ar.UC_ARM64_REG_PC)),address=hex(a),size_bytes=n)
        owner=self.owner(a,n)
        if owner and owner[0]in self.retired:return self.stop('retired_owner_read',pc=hex(u.reg_read(ar.UC_ARM64_REG_PC)),address=hex(a),size_bytes=n)
        if a in FIXUPS:
            key=(u.reg_read(ar.UC_ARM64_REG_PC),a,n);self.fixup_reads[key]={'pc':hex(key[0]),'address':hex(a),'size_bytes':n,'original_word_hex':IMAGE.read(a,8).hex(),'original_fixup':FIXUPS[a]}
        return super().read_hook(u,access,a,n,value,d)
    def write_hook(self,u,access,a,n,value,d):
        if STACK<=a and a+n<=STACK+0x80000:
            e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'address':hex(a),'size_bytes':n,'step_index':self.steps};self.stack_stores.append(e);self.pending_owner_stores.append(e)
        owner=self.owner(a,n)
        if owner:
            base,extent,kind=owner
            if base in self.retired:return self.stop('retired_owner_write',pc=hex(u.reg_read(ar.UC_ARM64_REG_PC)),address=hex(a),size_bytes=n)
            if base<=a and a+n<=base+extent:
                e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'address':hex(a),'owner':hex(base),'offset_bytes':a-base,'size_bytes':n,'kind':kind};self.owner_stores.append(e);self.pending_owner_stores.append(e);self.records.append({'kind':'source_owner_store','store':e})
        return super().write_hook(u,access,a,n,value,d)
    def run(self):
        r=super().run();self.flush();snapshots=[]
        if self.copy_allocation is not None:snapshots.append({'address':hex(self.copy_allocation),'size_bytes':self.copy_extent,'kind':'copy','retired':self.copy_allocation in self.retired,'initialized_mask_hex':bytes(self.copy_known).hex(),'bytes_hex':bytes(self.u.mem_read(self.copy_allocation,self.copy_extent)).hex()})
        for v in self.heap_allocations:snapshots.append({'address':hex(v['address']),'size_bytes':v['size'],'kind':'heap','retired':v['address']in self.retired,'allocation_pc':hex(v['allocation_pc']),'initialized_mask_hex':bytes(v['initialized']).hex(),'bytes_hex':bytes(self.u.mem_read(v['address'],v['size'])).hex()})
        sp=int(self.points[0]['sp'],16)if self.points else 0;watched=[sp+v for v in [0x1d0,0x1d8,0x1e0,0x4f8]];stores=[e for e in self.stack_stores if any(int(e['address'],16)<a+8 and int(e['address'],16)+e['size_bytes']>a for a in watched)]
        path_stores=[e for e in self.stack_stores if any(int(e['address'],16)<int(o['path_pointer'],16)+len(bytes.fromhex(o['path_hex']))+1 and int(e['address'],16)+e['size_bytes']>int(o['path_pointer'],16)for o in self.open_observations)]
        r.update(scope=__doc__,fixture=self.fixture,declared_file_bytes_hex=self.pattern.hex(),original_visit_count=len(self.visit_pcs),original_ordered_bytes_sha256=self.source_hash.hexdigest(),original_visits_zlib_base64=base64.b64encode(zlib.compress(struct.pack('<'+'Q'*len(self.visit_pcs),*self.visit_pcs))).decode(),parser_points=self.points,parser_edges=self.edges,original_fixup_reads=list(self.fixup_reads.values()),owner_stores=self.owner_stores,source_frame_field_stores=stores,source_path_stores=path_stores,source_open_observations=self.open_observations,explicit_parser_models=self.models,owner_snapshots=snapshots,file_read_events=self.file_read_events,extra_malloc_calls=self.extra_malloc_count,post_stat_pcs=[hex(x)for x in self.post_stat_pcs],full_goal_complete=False);return r

if __name__=='__main__':
    p=Parser(struct.pack('>I',1)+bytes(60));r=p.run();Path('/tmp/rpc502-parser-new.json').write_text(json.dumps(r));print(r['steps'],r['stop_reason'],r['records'][-1],flush=True)
