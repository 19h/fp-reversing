#!/usr/bin/env python3
"""Private mmap-result continuations with unknown file bytes and guarded extent.

No host mapping/file API is called. A success result is a fresh read-only
Unicorn allocation; logical file bytes are all unknown and reads stop before
their use. Page padding is not assumed to contain file data. A failure result
is MAP_FAILED only; errno and all subsequent API behavior remain unmodeled.
"""
import hashlib
import json
from pathlib import Path
from probe_rpc502_sidecar_data import DataProbe
from daemon_rpc502_context_probe import ROOT
from daemon_rpc502_probe import ar,uc

MAPPING=0x5100000000
PROFILES=[('map64_unknown',64,True),('map1_unknown',1,True),('map64_failed',64,False)]


class MappingProbe(DataProbe):
    def __init__(self,size_bits,success):
        self.mapping=None;self.mapping_length=0;self.mapping_pages=0;self.map_success=success
        super().__init__(size_bits,0)
    def hook(self,u,address,size,user):
        if self.imports.get(address)=='libSystem/_mmap':
            assert self.reg(30)==0x100c85e44
            args=[self.reg(i) for i in range(6)]
            assert args==[0,self.size_bits,1,2,7,0]
            self.steps+=1
            if self.map_success:
                assert 0<self.size_bits<=0x40000
                self.mapping=MAPPING;self.mapping_length=self.size_bits
                self.mapping_pages=(self.size_bits+4095)&~4095
                u.mem_map(MAPPING,self.mapping_pages,uc.UC_PROT_READ)
                result=MAPPING
            else:result=0xffffffffffffffff
            self.records.append({'kind':'private_mmap_result_model','return_pc':hex(self.reg(30)),
                'args':[hex(x) for x in args],'return_bits':hex(result),'logical_file_extent_bytes':self.size_bits,
                'metadata_and_contents_native':False,'file_contents_unknown':True,'host_mmap_executed':False})
            self.return_model(result)
            return
        return super().hook(u,address,size,user)
    def read_hook(self,u,access,address,size,value,user):
        if self.mapping is not None and address<self.mapping+self.mapping_pages and address+size>self.mapping:
            reason='unknown_mapped_file_read'
            if address<self.mapping or address+size>self.mapping+self.mapping_length:
                reason='private_mapping_file_extent_read'
            self.stop(reason,pc=hex(u.reg_read(ar.UC_ARM64_REG_PC)),address=hex(address),
                size_bytes=size,logical_file_extent_bytes=self.mapping_length,
                mapping=hex(self.mapping),offset_bytes=address-self.mapping,
                file_contents_synthesized=False)
            return
        return super().read_hook(u,access,address,size,value,user)


def main():
    rows=[]
    for label,size_bits,success in PROFILES:
        p=MappingProbe(size_bits,success);r=p.run();r['scope']=__doc__
        r['mapping_generator_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        r['inherited_mapping_generators']={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest()
            for name in ['probe_rpc502_sidecar_data.py','probe_rpc502_sidecar_metadata.py','probe_rpc502_sidecar_io.py']}
        r['private_size_bits']=hex(size_bits);r['private_mapping_success']=success
        r['post_stat_instruction_pcs']=[hex(x) for x in p.post_stat_pcs]
        name=f'rpc502_sidecar_mapping_{label}.json'
        (ROOT/name).write_text(json.dumps(r,indent=2)+'\n')
        row={'profile':label,'path':name,'size_bits':hex(size_bits),'mapping_success':success,
             'steps':r['steps'],'stop_reason':r['stop_reason'],'last_record':r['records'][-1]}
        rows.append(row);print(json.dumps(row),flush=True)
    (ROOT/'rpc502_sidecar_mapping_index.json').write_text(json.dumps({'scope':__doc__,'profiles':rows},indent=2)+'\n')


if __name__=='__main__':main()
