#!/usr/bin/env python3
"""Bounded private instruction fixtures for sidecar provenance.

No target host IPC/files/loader/sysctl/CoreKE execution. The existing explicit
PAC, BootPolicy, CSR, serial-once/rwlock and private-heap models apply. Entry
seeds and memory perturbations below are synthetic, not observed native state.
O(C*(T+W)) time and O(T+W) peak storage for C cases, bounded T instructions and
W watched events; original-image setup/hashing is additional streamed work.
"""
import hashlib
import json
import struct
from daemon_rpc502_context_probe import ContextProbe, ROOT
from daemon_rpc502_probe import uc, ar, STACK

GLOBAL=0x1010b9630
INITIAL=0x1cea168a
ENTRY=0x100422d48
PREFIX=0x700730c0
OUTPUT=0x700734c0
POINTS={0x1005bbb20:'policy_update',0x1005d136c:'scan_start',
        0x100787f48:'shift_first',0x100787f4c:'shift_second',
        0x1004f59a0:'encoded_terminator',0x1007f0d94:'scan_bound',
        0x10074cbdc:'encoder_shift',0x10078e168:'prefix_decoder'}
PROFILES=[
 {'label':'mode0','mode':0}, {'label':'mode1','mode':1},
 {'label':'mode2','mode':2}, {'label':'mode3','mode':3},
 {'label':'csr1','mode':1,'csr':1}, {'label':'csr10','mode':1,'csr':16},
 {'label':'csr_error','mode':1,'csr_status':5},
 {'label':'bootpolicy_error','mode':1,'bootpolicy_status':5},
 {'label':'app_o0','mode':1,'origin':0,'filename':'/Applications/Test.app/Contents/MacOS/Test'},
 {'label':'app_o1','mode':1,'origin':1,'filename':'/Applications/Test.app/Contents/MacOS/Test'},
 {'label':'app_o2','mode':1,'origin':2,'filename':'/Applications/Test.app/Contents/MacOS/Test'},
 {'label':'short','mode':1,'filename':'/tmp/app'},
 {'label':'cpu_sentinel','mode':1,'cpu':0xabcd,'filename':'/Applications/Test.app/Contents/MacOS/Test'},
 {'label':'perturbed_state_plus6','mode':1,'global_seed':INITIAL+6},
 {'label':'perturbed_prefix_a5','mode':0,'prefix_seed':0xa5},
]


def run(config):
    p=ContextProbe(mode=config['mode'],csr=config.get('csr',0),
        csr_status=config.get('csr_status',0),bootpolicy_status=config.get('bootpolicy_status',0),
        model_once=True,model_heap=True,model_locks=True,sysctl_vmm=1)
    p.model_loader=True;p.cpu=config.get('cpu',0x100000c)
    filename=config.get('filename','/synthetic/fixture.bin').encode('ascii')+b'\0'
    origin=config.get('origin',1)
    snapshots={};writes=[];prefix_writes=[];output_writes=[]
    def code(u,address,size,user):
        if address==ENTRY:
            u.mem_write(p.reg(1),filename);p.setreg(2,len(filename));p.setreg(5,origin)
            if 'global_seed' in config:u.mem_write(GLOBAL,struct.pack('<I',config['global_seed']))
            if 'prefix_seed' in config:u.mem_write(PREFIX,bytes([config['prefix_seed']])*0x400)
        if address in POINTS and POINTS[address] not in snapshots:
            snapshots[POINTS[address]]={'pc':hex(address),'sp':hex(u.reg_read(ar.UC_ARM64_REG_SP)),
                'registers':{f'x{i}':hex(p.reg(i)) for i in range(29)}}
    def write(u,access,address,size,value,user):
        pc=u.reg_read(ar.UC_ARM64_REG_PC)
        row={'pc':hex(pc),'address':hex(address),'size_bytes':size,
             'value_hex':(value&((1<<(8*size))-1)).to_bytes(size,'little').hex()}
        if address<GLOBAL+4 and address+size>GLOBAL:writes.append(row)
        if address<PREFIX+0x400 and address+size>PREFIX:prefix_writes.append(row)
        if address<OUTPUT+0x400 and address+size>OUTPUT:output_writes.append(row)
    p.u.hook_add(uc.UC_HOOK_CODE,code)
    p.u.hook_add(uc.UC_HOOK_MEM_WRITE,write)
    r=p.run()
    out={'label':config['label'],'explicit_seeds':config,'filename_hex':filename.hex(),
         'declared_count_bytes':len(filename),'cpu':hex(p.cpu),'origin':origin,
         'snapshots':snapshots,'global_writes':writes,'prefix_writes':prefix_writes,
         'output_writes':output_writes,'global_final':hex(struct.unpack('<I',p.u.mem_read(GLOBAL,4))[0]),
         'open_boundaries':[v for v in r['records'] if v['kind']=='unmodeled_open_boundary'],
         'stop_reason':r['stop_reason'],'last_record':r['records'][-1],
         'steps':r['steps'],'end_registers':r['end_registers'],
         'prefix_final_hex':bytes(p.u.mem_read(PREFIX,80)).hex(),
         'target_input_filename_after_hex':bytes(p.u.mem_read(STACK+0x1000,len(filename))).hex(),
         'model_source_sha256':r['generator_sha256'],
         'base_model_source_sha256':r['base_generator_sha256']}
    assert out['target_input_filename_after_hex']==filename.hex()
    return out


def main():
    rows=[]
    for c in PROFILES:
        r=run(c);rows.append(r)
        print(json.dumps({'label':r['label'],'steps':r['steps'],'global_final':r['global_final'],
            'scan_start':r['snapshots'].get('scan_start',{}).get('registers',{}).get('x8'),
            'open':r['open_boundaries'],'stop_reason':r['stop_reason']}),flush=True)
    result={'scope':__doc__,'source_sha256':'4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e',
            'generator_sha256':hashlib.sha256(__file__ and open(__file__,'rb').read()).hexdigest(),
            'native_target_executed':False,'target_host_operations_executed':False,
            'coreke_code_executed':False,'idb_mutated':False,'profiles':rows}
    (ROOT/'rpc502_sidecar_profiles.json').write_text(json.dumps(result,indent=2)+'\n')


if __name__=='__main__':main()
