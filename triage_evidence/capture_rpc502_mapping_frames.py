#!/usr/bin/env python3
"""Private selected-frame, record-write and cleanup provenance; no target host IO.

Records are observed from original target instructions in explicit fixtures.
One continuation models successful private munmap for the malloc-NULL route;
this does not attest native resource cleanup or descriptor ownership.
"""
import hashlib
import json
import struct
from pathlib import Path
from probe_rpc502_sidecar_data import DataProbe
from probe_rpc502_sidecar_mapping import MappingProbe
from probe_rpc502_sidecar_copy import CopyProbe
from probe_rpc502_sidecar_contents import ContentsProbe
from daemon_rpc502_context_probe import ROOT
from daemon_rpc502_probe import ar,uc

POINTS=[0x100d943d0,0x100ca39f8,0x100ca3a38,0x100c85da8,0x100c85e20,
        0x100c85e44,0x100c85e58,0x10095b558,0x10095b5bc,0x10095b5cc,
        0x10095b5e4,0x1003aae88,0x1003aaee8,0x1008ec6a0,0x1008ec708,
        0x100dcf770,0x1005eeb20,0x1005eeb74,0x1005eeb88,0x100dacb54,0x1001f1988,0x1001f19bc,
        0x1005ffa78,0x1005ffabc]
OFFSETS=[0x5d0,0x5d8,0x960,0x968,0x9a8,0x9b0,0x9c0,0x9c8,0x9d8,0xab0,0xcec]


class UnmapCleanupProbe(CopyProbe):
    def __init__(self,unmap_status=0,close_status=None):
        self.unmap_status=unmap_status;self.close_status=close_status
        super().__init__(64,False)
    def hook(self,u,address,size,user):
        if self.imports.get(address)=='libSystem/_munmap':
            assert self.reg(30)==0x1003aaef8
            assert self.reg(0)==self.mapping and self.reg(1)==self.mapping_length==64
            self.steps+=1
            self.records.append({'kind':'private_munmap_status_model','return_pc':hex(self.reg(30)),
                'address':hex(self.mapping),'length_bytes':self.mapping_length,
                'return_status':self.unmap_status,'host_munmap_executed':False})
            if self.unmap_status==0:
                u.mem_unmap(self.mapping,self.mapping_pages);self.mapping=None
            self.return_model(self.unmap_status);return
        if self.close_status is not None and self.imports.get(address)=='libSystem/_close':
            assert self.reg(30)==0x1001f19c8 and self.reg(0)==7
            self.steps+=1
            self.records.append({'kind':'private_close_status_model','return_pc':hex(self.reg(30)),
                'descriptor':7,'return_status':self.close_status,'host_close_executed':False})
            self.return_model(self.close_status);return
        return super().hook(u,address,size,user)


def run(label,p):
    frames=[];writes=[];record=None;descriptor=None
    def code(u,a,size,user):
        nonlocal record,descriptor
        if a in POINTS:
            sp=u.reg_read(ar.UC_ARM64_REG_SP)
            row={'pc':hex(a),'sp':hex(sp),'registers':{f'x{i}':hex(p.reg(i)) for i in range(29)},
                 'stack_qwords':{hex(o):hex(struct.unpack('<Q',u.mem_read(sp+o,8))[0]) for o in OFFSETS}}
            if a==0x1005ffa78:
                row['qos_change_flag_byte']=u.mem_read(sp+0x344f,1)[0]
            if a==0x100d943d0:
                record=p.reg(24);descriptor=struct.unpack('<Q',u.mem_read(record+0x20,8))[0]
                row.update({'file_helper_record':hex(record),'record_initial_hex':bytes(u.mem_read(record,48)).hex(),
                            'descriptor_output_pointer':hex(descriptor),
                            'mapping_result_initial_hex':bytes(u.mem_read(descriptor,32)).hex()})
            frames.append(row)
    def write(u,access,a,size,value,user):
        if (record is not None and a<record+48 and a+size>record) or (
              descriptor is not None and a<descriptor+32 and a+size>descriptor):
            writes.append({'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'address':hex(a),'size_bytes':size,
                           'value_hex':(value&((1<<(size*8))-1)).to_bytes(size,'little').hex()})
    p.u.hook_add(uc.UC_HOOK_CODE,code);p.u.hook_add(uc.UC_HOOK_MEM_WRITE,write)
    r=p.run()
    return {'label':label,'steps':r['steps'],'stop_reason':r['stop_reason'],'last_record':r['records'][-1],
        'frames':frames,'record_and_descriptor_writes':writes,'file_helper_record':hex(record),
        'record_final_hex':bytes(p.u.mem_read(record,48)).hex(),'descriptor_pointer':hex(descriptor),
        'descriptor_final_hex':bytes(p.u.mem_read(descriptor,4)).hex(),
        'mapping_result_final_hex':bytes(p.u.mem_read(descriptor,32)).hex(),
        'imports':[x for x in r['records'] if x['kind']=='import'],
        'private_api_models':[x for x in r['records'] if x['kind'].startswith('private_')],
        'bound_import_reads':r['bound_import_reads'],'source_sha256':r['source_sha256'],
        'model_generator_sha256':r['generator_sha256'],'base_generator_sha256':r['base_generator_sha256'],
        'qos_query_model_result':r['qos_query_model_result'],'qos_set_model_result':r['qos_set_model_result'],
        'post_stat_pcs':[hex(x) for x in p.post_stat_pcs]}


def main():
    rows=[]
    query_failed=DataProbe(64,-1);query_failed.qos_query=5
    set_failed=DataProbe(64,-1);set_failed.qos_set=5
    for label,p in [('fstat_error',DataProbe(64,-1)),('mmap_failed',MappingProbe(64,False)),
                    ('malloc_null',CopyProbe(64,False)),('pattern64',ContentsProbe(64)),
                    ('malloc_null_unmap_success',UnmapCleanupProbe()),
                    ('malloc_null_cleanup_success',UnmapCleanupProbe(0,0)),
                    ('malloc_null_cleanup_unmap_failed',UnmapCleanupProbe(-1,0)),
                    ('malloc_null_cleanup_close_failed',UnmapCleanupProbe(0,-1)),
                    ('fstat_error_qos_query_failed',query_failed),('fstat_error_qos_set_failed',set_failed)]:
        r=run(label,p);rows.append(r)
        print(json.dumps({'label':label,'steps':r['steps'],'stop_reason':r['stop_reason'],
            'descriptor_final_hex':r['descriptor_final_hex'],'record_writes':len(r['record_and_descriptor_writes']),
            'last_record':r['last_record']}),flush=True)
    out={'scope':__doc__,'generator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
         'inherited_generators':{name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in [
            'probe_rpc502_sidecar_contents.py','probe_rpc502_sidecar_copy.py','probe_rpc502_sidecar_mapping.py',
            'probe_rpc502_sidecar_data.py','probe_rpc502_sidecar_metadata.py','probe_rpc502_sidecar_io.py']},
         'native_target_executed':False,'target_host_operations_executed':False,'profiles':rows}
    (ROOT/'rpc502_mapping_frames.json').write_text(json.dumps(out,indent=2)+'\n')


if __name__=='__main__':main()
