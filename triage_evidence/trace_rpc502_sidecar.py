#!/usr/bin/env python3
"""Finite native-instruction provenance for the existing private sidecar fixture.

Target filesystem/IPC/CoreKE are never executed. Existing model assumptions
remain intact. This traces bytes; it does not certify a valid native filename.
"""
import collections
import json
from daemon_rpc502_context_probe import ContextProbe,ROOT
from daemon_rpc502_probe import uc,ar,STACK


def main():
    p=ContextProbe(model_once=True,model_heap=True,model_locks=True,sysctl_vmm=1)
    p.model_loader=True
    dest=0x700734c0
    writes=[];reads=collections.deque(maxlen=12);recent=collections.deque(maxlen=12)
    first_sites={}
    source_reads=[]
    def code(u,address,size,user):recent.append(hex(address))
    def read(u,access,address,size,value,user):
        pc=u.reg_read(ar.UC_ARM64_REG_PC)
        if STACK<=address<STACK+0x80000:
            reads.append({'pc':hex(pc),'address':hex(address),'size':size,
                          'bytes_before_read':bytes(u.mem_read(address,size)).hex()})
        if STACK+0x1000<=address<STACK+0x1100:
            source_reads.append({'pc':hex(pc),'address':hex(address),'size':size})
    def write(u,access,address,size,value,user):
        if address<dest+256 and address+size>dest:
            pc=u.reg_read(ar.UC_ARM64_REG_PC)
            writes.append({'pc':hex(pc),'address':hex(address),'size':size,
                'value_hex':(value&((1<<(size*8))-1)).to_bytes(size,'little').hex(),
                'recent_pcs':list(recent),'recent_stack_reads':list(reads)})
            if pc not in first_sites:
                first_sites[pc]={'pc':hex(pc),'sp':hex(u.reg_read(ar.UC_ARM64_REG_SP)),
                    'registers':{f'x{i}':hex(p.reg(i)) for i in range(29)}}
    p.u.hook_add(uc.UC_HOOK_CODE,code)
    p.u.hook_add(uc.UC_HOOK_MEM_READ,read)
    p.u.hook_add(uc.UC_HOOK_MEM_WRITE,write)
    result=p.run()
    out={'scope':__doc__,'source_sha256':result['source_sha256'],
        'generator_sha256':result['generator_sha256'],
        'watched_output_address':hex(dest),'writes':writes,'first_write_sites':list(first_sites.values()),
        'original_filename_after_hex':bytes(p.u.mem_read(STACK+0x1000,64)).hex(),
        'source_filename_reads':source_reads,
        'path_after_hex':bytes(p.u.mem_read(dest,128)).split(b'\0')[0].hex(),
        'stop_reason':result['stop_reason'],'last_record':result['records'][-1],
        'native_target_executed':False,'target_host_file_opened':False,
        'coreke_code_executed':False,'steps':result['steps']}
    (ROOT/'rpc502_sidecar_byte_trace.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'steps':result['steps'],'output_writes':len(writes),
                     'write_sites':len(first_sites),'path_hex':out['path_after_hex'],
                     'stop_reason':result['stop_reason']}))


if __name__=='__main__':main()
