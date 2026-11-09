#!/usr/bin/env python3
"""Known synthetic sidecar bytes for exact native-copy provenance.

Explicit pattern bytes are the only file contents supplied. Private mmap and
malloc models remain bounded; every other API/output retains its inherited
unknown boundary. These byte strings are not asserted to be valid sidecars.
"""
import hashlib
import json
from pathlib import Path
from probe_rpc502_sidecar_copy import CopyProbe
from probe_rpc502_sidecar_metadata import MetadataProbe
from daemon_rpc502_context_probe import ROOT
from daemon_rpc502_probe import ar

PROFILES=[('pattern1',1),('pattern7',7),('pattern8',8),('pattern9',9),
          ('pattern64',64),('pattern256',256)]


class ContentsProbe(CopyProbe):
    def __init__(self,size_bits):
        self.pattern=bytes(((i*73)^0xa5)&255 for i in range(size_bits))
        self.file_read_events=[];self.header_checkpoints=[]
        super().__init__(size_bits,True)
    def hook(self,u,address,size,user):
        if address in [0x1009b6eac,0x1009b6f64]:
            self.header_checkpoints.append({'pc':hex(address),
                'registers':{f'x{i}':hex(self.reg(i)) for i in range(29)}})
        is_map=self.imports.get(address)=='libSystem/_mmap'
        answer=super().hook(u,address,size,user)
        if is_map:
            assert self.mapping is not None
            u.mem_write(self.mapping,self.pattern)
            self.records.append({'kind':'private_file_contents_seed','logical_extent_bytes':len(self.pattern),
                'sha256':hashlib.sha256(self.pattern).hexdigest(),'bytes_hex':self.pattern.hex(),
                'valid_sidecar_assumed':False,'native_file_contents':False})
        return answer
    def read_hook(self,u,access,address,size,value,user):
        for label,a,n in [('mapping',self.mapping,self.mapping_length),
                          ('allocation',self.copy_allocation,self.copy_extent)]:
            if a is not None and a<=address and address+size<=a+n:
                self.file_read_events.append({'kind':label,'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),
                    'offset_bytes':address-a,'size_bytes':size,
                    'bytes_hex':bytes(u.mem_read(address,size)).hex()})
        if self.mapping is not None and self.mapping<=address and address+size<=self.mapping+self.mapping_length:
            return MetadataProbe.read_hook(self,u,access,address,size,value,user)
        return super().read_hook(u,access,address,size,value,user)


def main():
    rows=[]
    for label,size_bits in PROFILES:
        p=ContentsProbe(size_bits);r=p.run();r['scope']=__doc__
        r['contents_generator_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        r['inherited_contents_generators']={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest()
            for name in ['probe_rpc502_sidecar_copy.py','probe_rpc502_sidecar_mapping.py',
              'probe_rpc502_sidecar_data.py','probe_rpc502_sidecar_metadata.py','probe_rpc502_sidecar_io.py']}
        r['private_size_bits']=hex(size_bits);r['source_pattern_hex']=p.pattern.hex()
        r['copied_allocation_hex']=bytes(p.u.mem_read(p.copy_allocation,size_bits)).hex()
        r['copy_initialized_bytes']=sum(p.copy_known)
        r['file_read_events']=p.file_read_events;r['header_checkpoints']=p.header_checkpoints
        r['post_stat_instruction_pcs']=[hex(x) for x in p.post_stat_pcs]
        assert r['copied_allocation_hex']==p.pattern.hex() and all(p.copy_known)
        name=f'rpc502_sidecar_contents_{label}.json'
        (ROOT/name).write_text(json.dumps(r,indent=2)+'\n')
        row={'profile':label,'path':name,'size_bytes':size_bits,'copy_exact':True,
             'steps':r['steps'],'stop_reason':r['stop_reason'],'last_record':r['records'][-1]}
        rows.append(row);print(json.dumps(row),flush=True)
    (ROOT/'rpc502_sidecar_contents_index.json').write_text(json.dumps({'scope':__doc__,'profiles':rows},indent=2)+'\n')


if __name__=='__main__':main()
