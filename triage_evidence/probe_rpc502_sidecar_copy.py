#!/usr/bin/env python3
"""Private malloc-result continuation after read-only sidecar mapping.

Only a bounded private allocation or NULL result is modeled. New allocation
bytes and file bytes remain unknown; native writes initialize only the actual
allocation extent. No memcpy/read/file/loader/IPC API is executed on the host.
"""
import hashlib
import json
from pathlib import Path
from probe_rpc502_sidecar_mapping import MappingProbe
from daemon_rpc502_context_probe import ROOT
from daemon_rpc502_probe import ar,uc

ALLOCATION=0x5200000000
PROFILES=[('copy64_unknown',64,True),('copy1_unknown',1,True),('malloc64_null',64,False)]


class CopyProbe(MappingProbe):
    def __init__(self,size_bits,success):
        self.malloc_success=success;self.copy_allocation=None;self.copy_extent=0;self.copy_pages=0
        self.copy_known=bytearray();self.ordinary_malloc_calls=0
        super().__init__(size_bits,True)
    def hook(self,u,address,size,user):
        if self.imports.get(address)=='libSystem/_malloc':
            assert self.reg(30)==0x10095b5cc and self.reg(0)==self.size_bits
            self.steps+=1;self.ordinary_malloc_calls+=1
            if self.ordinary_malloc_calls>1:
                self.stop('private_copy_allocation_budget');return
            if self.malloc_success:
                assert 0<self.size_bits<=0x40000
                self.copy_allocation=ALLOCATION;self.copy_extent=self.size_bits
                self.copy_pages=(self.size_bits+4095)&~4095
                self.copy_known=bytearray(self.size_bits)
                u.mem_map(ALLOCATION,self.copy_pages,uc.UC_PROT_READ|uc.UC_PROT_WRITE)
                result=ALLOCATION
            else:result=0
            self.records.append({'kind':'private_malloc_result_model','return_pc':hex(self.reg(30)),
                'requested_extent_bytes':self.size_bits,'return_bits':hex(result),
                'allocation_bytes_unknown':True,'host_malloc_for_target_executed':False})
            self.return_model(result)
            return
        return super().hook(u,address,size,user)
    def read_hook(self,u,access,address,size,value,user):
        a=self.copy_allocation
        if a is not None and address<a+self.copy_pages and address+size>a:
            left=max(a,address)-a;right=min(a+self.copy_extent,address+size)-a
            if address<a or address+size>a+self.copy_extent:
                self.stop('private_copy_allocation_extent_read',pc=hex(u.reg_read(ar.UC_ARM64_REG_PC)),
                    address=hex(address),size_bytes=size,extent_bytes=self.copy_extent);return
            if not all(self.copy_known[left:right]):
                self.stop('unknown_copy_allocation_read',pc=hex(u.reg_read(ar.UC_ARM64_REG_PC)),
                    address=hex(address),size_bytes=size,offset_bytes=address-a);return
        return super().read_hook(u,access,address,size,value,user)
    def write_hook(self,u,access,address,size,value,user):
        a=self.copy_allocation
        if a is not None and address<a+self.copy_pages and address+size>a:
            if address<a or address+size>a+self.copy_extent:
                self.stop('private_copy_allocation_extent_write',pc=hex(u.reg_read(ar.UC_ARM64_REG_PC)),
                    address=hex(address),size_bytes=size,extent_bytes=self.copy_extent);return
            self.copy_known[address-a:address-a+size]=bytes([1])*size
            self.records.append({'kind':'native_copy_allocation_write',
                'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'offset_bytes':address-a,'size_bytes':size})
        return super().write_hook(u,access,address,size,value,user)


def main():
    rows=[]
    for label,size_bits,success in PROFILES:
        p=CopyProbe(size_bits,success);r=p.run();r['scope']=__doc__
        r['copy_generator_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        r['inherited_copy_generators']={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest()
            for name in ['probe_rpc502_sidecar_mapping.py','probe_rpc502_sidecar_data.py',
                         'probe_rpc502_sidecar_metadata.py','probe_rpc502_sidecar_io.py']}
        r['private_size_bits']=hex(size_bits);r['private_malloc_success']=success
        r['post_stat_instruction_pcs']=[hex(x) for x in p.post_stat_pcs]
        name=f'rpc502_sidecar_copy_{label}.json'
        (ROOT/name).write_text(json.dumps(r,indent=2)+'\n')
        row={'profile':label,'path':name,'size_bits':hex(size_bits),'malloc_success':success,
             'steps':r['steps'],'stop_reason':r['stop_reason'],'last_record':r['records'][-1]}
        rows.append(row);print(json.dumps(row),flush=True)
    (ROOT/'rpc502_sidecar_copy_index.json').write_text(json.dumps({'scope':__doc__,'profiles':rows},indent=2)+'\n')


if __name__=='__main__':main()
