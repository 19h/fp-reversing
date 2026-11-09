#!/usr/bin/env python3
"""Private fstat-result continuation, stopping before unknown metadata use.

Open returns a private descriptor7. Fstat returns the selected status but writes
no metadata. All 144 SDK-sized output bytes are marked unknown. A target read
of any still-unknown byte stops before subsequent target control/dataflow is
interpreted; native writes initialize only their actual byte range. No host
filesystem, descriptor, errno value or metadata is obtained or synthesized.
"""
import hashlib
import json
from probe_rpc502_sidecar_io import IOProbe
from daemon_rpc502_context_probe import ROOT
from daemon_rpc502_probe import ar


class MetadataProbe(IOProbe):
    def __init__(self,status):
        self.stat_status=status;self.stat_buffer=None;self.stat_known=bytearray(144)
        super().__init__(7)
    def hook(self,u,address,size,user):
        if self.imports.get(address)=='libSystem/_fstat':
            assert self.reg(30)==0x100aaf958 and self.reg(0)==7
            self.steps+=1;self.stat_buffer=self.reg(1)
            self.records.append({'kind':'private_fstat_status_model','return_pc':hex(self.reg(30)),
                'descriptor':self.reg(0),'buffer':hex(self.stat_buffer),'signed_32_result':self.stat_status,
                'output_extent_bytes':144,'metadata_written':False,'host_fstat_executed':False})
            self.return_model(self.stat_status)
            return
        return super().hook(u,address,size,user)
    def read_hook(self,u,access,address,size,value,user):
        a=self.stat_buffer
        if a is not None and address<a+144 and address+size>a:
            left=max(address,a)-a;right=min(address+size,a+144)-a
            if not all(self.stat_known[left:right]):
                self.stop('unknown_fstat_output_read',pc=hex(u.reg_read(ar.UC_ARM64_REG_PC)),
                    address=hex(address),size_bytes=size,buffer=hex(a),offset_bytes=address-a,
                    stat_status=self.stat_status,metadata_synthesized=False)
                return
        return super().read_hook(u,access,address,size,value,user)
    def write_hook(self,u,access,address,size,value,user):
        a=self.stat_buffer
        if a is not None and address<a+144 and address+size>a:
            left=max(address,a)-a;right=min(address+size,a+144)-a
            self.stat_known[left:right]=bytes([1])*(right-left)
            self.records.append({'kind':'native_metadata_buffer_write',
                'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'offset_bytes':address-a,'size_bytes':size})
        return super().write_hook(u,access,address,size,value,user)


def main():
    rows=[]
    for status in [0,-1]:
        p=MetadataProbe(status);r=p.run();r['scope']=__doc__
        r['metadata_generator_sha256']=hashlib.sha256(open(__file__,'rb').read()).hexdigest()
        r['io_generator_sha256']=hashlib.sha256((ROOT/'probe_rpc502_sidecar_io.py').read_bytes()).hexdigest()
        r['private_fstat_result']=status
        name=f'rpc502_sidecar_metadata_{"minus1" if status<0 else status}.json'
        (ROOT/name).write_text(json.dumps(r,indent=2)+'\n')
        row={'path':name,'status':status,'steps':r['steps'],
             'stop_reason':r['stop_reason'],'last_record':r['records'][-1]}
        rows.append(row);print(json.dumps(row),flush=True)
    (ROOT/'rpc502_sidecar_metadata_index.json').write_text(json.dumps({'scope':__doc__,'profiles':rows},indent=2)+'\n')


if __name__=='__main__':main()
