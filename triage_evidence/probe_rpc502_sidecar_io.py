#!/usr/bin/env python3
"""Private open-result continuation only; no target host file exists/is opened.

Each run injects a synthetic signed-32-bit open result at the established call
site, and stops at the next unmodeled import or original probe boundary. No
stat bytes, file contents, errno or later imported behavior are synthesized.
"""
import hashlib
import json
from daemon_rpc502_context_probe import ContextProbe,ROOT
from daemon_rpc502_probe import ar


class IOProbe(ContextProbe):
    def __init__(self,status):
        super().__init__(mode=1,model_once=True,model_heap=True,model_locks=True,sysctl_vmm=1)
        self.model_loader=True;self.open_status=status
    def hook(self,u,address,size,user):
        if address in [0x100d9449c,0x100d944d0,0x100aaf8d8,0x100aaf93c,0x100c2119c,0x100c211d0]:
            self.records.append({'kind':'sidecar_io_checkpoint','pc':hex(address),
                'sp':hex(u.reg_read(ar.UC_ARM64_REG_SP)),
                'registers':{f'x{i}':hex(self.reg(i)) for i in range(29)}})
        if self.imports.get(address)=='libSystem/_open':
            assert self.reg(30)==0x100d94498 and self.reg(1)==0
            self.steps+=1
            raw=bytes(u.mem_read(self.reg(0),256)).split(b'\0')[0]
            self.records.append({'kind':'private_open_result_model','return_pc':hex(self.reg(30)),
                'path_hex':raw.hex(),'flags':self.reg(1),'signed_32_result':self.open_status,
                'host_file_opened':False,'errno_synthesized':False})
            self.return_model(self.open_status)
            return
        return super().hook(u,address,size,user)


def main():
    rows=[]
    for status in [-1,0,7]:
        p=IOProbe(status);r=p.run()
        r['scope']=__doc__;r['private_open_result']=status
        r['sidecar_io_generator_sha256']=hashlib.sha256(open(__file__,'rb').read()).hexdigest()
        name=f'rpc502_sidecar_io_{"minus1" if status<0 else status}.json'
        (ROOT/name).write_text(json.dumps(r,indent=2)+'\n')
        row={'path':name,'status':status,'steps':r['steps'],
             'stop_reason':r['stop_reason'],'last_record':r['records'][-1]}
        rows.append(row);print(json.dumps(row),flush=True)
    (ROOT/'rpc502_sidecar_io_index.json').write_text(json.dumps({'scope':__doc__,'profiles':rows},indent=2)+'\n')


if __name__=='__main__':main()
