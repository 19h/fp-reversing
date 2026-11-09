#!/usr/bin/env python3
"""Finite private sidecar-size continuations with one explicit metadata field.

Only stat-buffer bytes96..103 are seeded; every other output byte remains
unknown under MetadataProbe. No file contents, read result, errno or target
host resource is modeled. Existing bounded import/heap/once/lock models apply.
Negative and extreme size bit patterns are stress inputs, not native files.
"""
import hashlib
import json
import struct
from pathlib import Path
from probe_rpc502_sidecar_metadata import MetadataProbe
from daemon_rpc502_context_probe import ROOT
from daemon_rpc502_probe import ar

PROFILES=[('size0',0,0),('size1',1,0),('size8',8,0),('size64',64,0),
          ('size4096',4096,0),('size1m',1<<20,0),('size_u32max',0xffffffff,0),
          ('size_i64max',0x7fffffffffffffff,0),('size_i64min',0x8000000000000000,0),
          ('size_u64max',0xffffffffffffffff,0),('stat_error_size64',64,-1)]


class DataProbe(MetadataProbe):
    def __init__(self,size_bits,status):
        self.size_bits=size_bits;self.post_stat_pcs=[]
        super().__init__(status)
    def hook(self,u,address,size,user):
        if self.stat_buffer is not None and address not in self.imports:self.post_stat_pcs.append(address)
        if address==0x100cc0870:
            self.records.append({'kind':'file_size_encoding_checkpoint','pc':hex(address),
                'size_bits':hex(self.size_bits),'encoded_x23':hex(self.reg(23)),
                'status_w28':hex(self.reg(28)&0xffffffff)})
        if self.imports.get(address)=='libSystem/_fstat':
            super().hook(u,address,size,user)
            u.mem_write(self.stat_buffer+96,struct.pack('<Q',self.size_bits))
            self.stat_known[96:104]=bytes([1])*8
            self.records.append({'kind':'private_metadata_field_seed','field':'SDK struct stat.st_size',
                'buffer':hex(self.stat_buffer),'offset_bytes':96,'size_bytes':8,
                'value_bits':hex(self.size_bits),'status':self.stat_status,
                'other_output_bytes_unknown':True})
            return
        return super().hook(u,address,size,user)


def main():
    rows=[]
    for label,size_bits,status in PROFILES:
        p=DataProbe(size_bits,status);r=p.run();r['scope']=__doc__
        r['data_generator_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        r['inherited_generator_sha256']={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest()
            for name in ['probe_rpc502_sidecar_metadata.py','probe_rpc502_sidecar_io.py']}
        r['private_size_bits']=hex(size_bits);r['private_fstat_result']=status
        r['post_stat_instruction_pcs']=[hex(x) for x in p.post_stat_pcs]
        name=f'rpc502_sidecar_data_{label}.json'
        (ROOT/name).write_text(json.dumps(r,indent=2)+'\n')
        row={'profile':label,'path':name,'size_bits':hex(size_bits),'fstat_status':status,
             'steps':r['steps'],'stop_reason':r['stop_reason'],'last_record':r['records'][-1],
             'encoding':[x for x in r['records'] if x['kind']=='file_size_encoding_checkpoint']}
        rows.append(row);print(json.dumps(row),flush=True)
    (ROOT/'rpc502_sidecar_data_index.json').write_text(json.dumps({'scope':__doc__,'profiles':rows},indent=2)+'\n')


if __name__=='__main__':main()
