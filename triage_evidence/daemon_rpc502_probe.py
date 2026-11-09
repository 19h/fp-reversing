#!/usr/bin/env python3
"""Isolated, finite synthetic RPC502 probe; no host IPC/files/system calls.

Original image bytes are mapped privately and chained pointers normalized.
PAC instructions/branches are explicitly bypassed. Only the listed imports
are modeled. The probe stops before every other import and every SVC.
This is model evidence, never native reachability or authentication proof.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import unicorn as uc
from unicorn import arm64_const as ar
from daemon_receive_tools import IMAGE, SOURCE, FIXUPS, CS, ROOT
from resolve_kernel_collection_interfaces import commands

STACK=0x70000000
STACK_SIZE=0x80000
IMPORTS=0x6000000000
HALT=0x6001000000


class Probe:
    def __init__(self, pid=0, cpu=0x100000c, qos_query=0, qos_set=0,
                 csr_config=None, csr_result=0):
        self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM)
        segs=[]
        for at,cmd,size in commands(IMAGE.data,0):
            if cmd==0x19:
                va,vm,off,n=struct.unpack_from('<4Q',IMAGE.data,at+24)
                if va and vm:segs.append((va,vm,off,n))
        lo=min(s[0] for s in segs)&~4095
        hi=max(s[0]+s[1] for s in segs)+4095&~4095
        assert hi-lo<0x4000000
        self.u.mem_map(lo,hi-lo)
        for va,vm,off,n in segs:
            if n:self.u.mem_write(va,IMAGE.data[off:off+n])
        self.u.mem_map(STACK,STACK_SIZE)
        self.u.mem_map(IMPORTS,0x100000)
        self.u.mem_map(HALT,4096)
        self.imports={}
        self.import_addresses={}
        self.nonzero_binding_addends=[]
        fixcmd=next(at for at,cmd,size in commands(IMAGE.data,0) if cmd==0x80000034)
        fixoff,fixsize=struct.unpack_from('<II',IMAGE.data,fixcmd+8)
        ver,starts,imports,symbols,count,fmt,symfmt=struct.unpack_from('<7I',IMAGE.data,fixoff)
        assert (ver,fmt,symfmt)==(0,2,0)
        for a,fix in FIXUPS.items():
            value=fix['target']
            if isinstance(value,str):
                if value not in self.import_addresses:
                    address=IMPORTS+16*len(self.import_addresses)
                    self.import_addresses[value]=address
                    self.imports[address]=value
                symbol_address=self.import_addresses[value]
                word=struct.unpack('<Q',IMAGE.read(a,8))[0]
                ordinal=word&0xffffff
                assert ordinal<count
                iw,import_addend=struct.unpack_from('<Ii',IMAGE.data,fixoff+imports+8*ordinal)
                auth=word>>63
                pointer_addend=0 if auth else ((word>>32)&0x7ffff)
                if pointer_addend&(1<<18):pointer_addend-=1<<19
                addend=import_addend+pointer_addend
                if addend:self.nonzero_binding_addends.append({'slot':hex(a),'symbol':value,
                    'word':hex(word),'import_addend':import_addend,'pointer_addend':pointer_addend,
                    'total_addend':addend})
                value=(symbol_address+addend)&((1<<64)-1)
            self.u.mem_write(a,struct.pack('<Q',value))
        # Bind stack guard and NDR *data*, not executable imports.
        data_imports={'libSystem/___stack_chk_guard':0x6a39c82e1d4075b0}
        self.data_import_values=[]
        for name,value in data_imports.items():
            if name in self.import_addresses:
                a=self.import_addresses[name]
                self.u.mem_write(a,struct.pack('<Q',value))
                self.data_import_values.append({'name':name,'value':hex(value)})
        ndr='libSystem/_NDR_record'
        if ndr in self.import_addresses:
            self.u.mem_write(self.import_addresses[ndr],bytes.fromhex('0000000001000000'))
        self.pid=pid
        self.cpu=cpu
        self.qos_query=qos_query
        self.qos_set=qos_set
        self.csr_config=csr_config
        self.csr_result=csr_result
        self.records=[]
        self.pac=[]
        self.decoded={}
        self.steps=0
        self.stop_reason=None
        self.writes=[]
        self.qos_calls=[]
        self.u.hook_add(uc.UC_HOOK_CODE,self.hook)
        self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.write_hook)
        self.u.hook_add(uc.UC_HOOK_MEM_READ,self.read_hook)

    def reg(self,n):
        return self.u.reg_read(getattr(ar,'UC_ARM64_REG_X'+str(n)))

    def setreg(self,n,value):
        self.u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(n)),value&((1<<64)-1))

    def return_model(self,value=None):
        if value is not None:self.setreg(0,value)
        self.u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))

    def stop(self,reason,**fields):
        self.stop_reason=reason
        self.records.append({'kind':'stop','reason':reason,**fields})
        self.u.emu_stop()

    def hook(self,u,address,size,user):
        self.steps+=1
        if address in (0x1005be85c,0x100616000,0x100607ec4,0x10041a5e0,
                       0x1004ac1c4,0x1004f8bd4,0x1004cfcec):
            sp=u.reg_read(ar.UC_ARM64_REG_SP)
            self.records.append({'kind':'checkpoint','pc':hex(address),'sp':hex(sp),
                'registers':{f'x{i}':hex(self.reg(i)) for i in range(29)},
                'boost_flag':bytes(u.mem_read(sp+0x344f,1)).hex(),
                'csr_output_word':struct.unpack('<I',u.mem_read(sp+0x4134,4))[0]})
        if address==HALT:
            self.stop('returned_to_fixture',result=hex(self.reg(0)))
            return
        if address in self.imports:
            name=self.imports[address]
            record={'kind':'import','name':name,'return_pc':hex(self.reg(30)),
                    'args':[hex(self.reg(i)) for i in range(8)]}
            self.records.append(record)
            if name=='libSystem/___chkstk_darwin':
                record['model']='skip stack probing; preserve all registers'
                self.return_model()
            elif name=='libbsm/_audit_token_to_au32':
                assert self.reg(6)
                token=bytes(u.mem_read(self.reg(0),32))
                out_pid=struct.unpack_from('<I',token,20)[0]
                u.mem_write(self.reg(6),struct.pack('<I',out_pid))
                record.update({'model':'write token word5 to X6 output only','pid':out_pid})
                self.return_model()
            elif name=='libSystem/_pthread_self':
                record['model']='synthetic pthread token'
                self.return_model(0x51515151)
            elif name=='libSystem/_pthread_get_qos_class_np':
                if self.qos_query==0:
                    u.mem_write(self.reg(1),struct.pack('<I',0x15))
                    u.mem_write(self.reg(2),struct.pack('<i',-2))
                record.update({'model':'seed query result and optional output values',
                               'return_value':self.qos_query})
                self.qos_calls.append(record)
                self.return_model(self.qos_query)
            elif name=='libSystem/_pthread_set_qos_class_self_np':
                record.update({'model':'record request; seed return status only',
                               'return_value':self.qos_set})
                self.qos_calls.append(record)
                self.return_model(self.qos_set)
            elif name=='libSystem/_csr_get_active_config' and self.csr_config is not None:
                if self.csr_result==0:
                    u.mem_write(self.reg(0),struct.pack('<I',self.csr_config&0xffffffff))
                record.update({'model':'seed CSR status and optional config output; no host query',
                               'return_value':self.csr_result,'config_seed':hex(self.csr_config)})
                self.return_model(self.csr_result)
            else:
                self.stop('unmodeled_import',name=name,return_pc=hex(self.reg(30)),
                          args=[hex(self.reg(i)) for i in range(8)])
            return
        if address not in self.decoded:
            raw=bytes(u.mem_read(address,4))
            self.decoded[address]=next(CS.disasm(raw,address))
        i=self.decoded[address]
        m=i.mnemonic
        if m in ('braa','braaz','brab','brabz','blraa','blraaz','blrab','blrabz'):
            regs=i.op_str.split(',')
            n=int(regs[0].strip()[1:])
            target=self.reg(n)
            modifier=self.reg(int(regs[1].strip()[1:])) if len(regs)>1 else 0
            self.pac.append({'site':hex(address),'instruction':m,'target':hex(target),
                             'modifier':hex(modifier),'authentication':'bypassed in private synthetic model'})
            if m.startswith('blr'):self.setreg(30,address+4)
            u.reg_write(ar.UC_ARM64_REG_PC,target)
        elif m in ('pacibsp','paciasp','autibsp','autiasp','xpaclri','bti'):
            self.pac.append({'site':hex(address),'instruction':m,'authentication':'skipped'})
            u.reg_write(ar.UC_ARM64_REG_PC,address+4)
        elif m in ('retab','retaa'):
            self.pac.append({'site':hex(address),'instruction':m,'authentication':'bypassed'})
            u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
        elif m.startswith(('pac','aut','xpac')):
            self.stop('unmodeled_pointer_auth_instruction',site=hex(address),instruction=m)
        elif m in ('svc','hvc','smc'):
            self.stop('blocked_system_instruction',site=hex(address),instruction=m)

    def write_hook(self,u,access,address,size,value,user):
        if 0x100000000<=address<0x102000000:
            self.writes.append({'pc':hex(self.u.reg_read(ar.UC_ARM64_REG_PC)),
                                'address':hex(address),'size':size,'value':hex(value&((1<<(8*size))-1))})

    def read_hook(self,u,access,address,size,value,user):
        if IMPORTS<=address<IMPORTS+0x100000:
            base=IMPORTS+((address-IMPORTS)//16)*16
            name=self.imports.get(base)
            allowed={x['name'] for x in self.data_import_values}|{'libSystem/_NDR_record'}
            if name and name not in allowed:
                self.stop('unmodeled_imported_data',name=name,address=hex(address),
                          site=hex(u.reg_read(ar.UC_ARM64_REG_PC)),read_bytes=size)

    def run(self):
        sp=STACK+0x78000
        name=STACK+0x1000
        audit=STACK+0x2000
        fixed0=STACK+0x3000
        fixed1=STACK+0x4000
        out=STACK+0x5000
        name_bytes=b'/synthetic/fixture.bin\0'
        self.u.mem_write(name,name_bytes)
        self.u.mem_write(audit,struct.pack('<8I',0,0,0,0,0,self.pid&0xffffffff,0,0))
        self.u.mem_write(sp,struct.pack('<5Q',fixed1,out,out+8,out+16,out+24))
        for n,v in enumerate([0x107,name,len(name_bytes),self.cpu,0,1,audit,fixed0]):self.setreg(n,v)
        self.setreg(30,HALT)
        self.u.reg_write(ar.UC_ARM64_REG_SP,sp)
        try:
            self.u.emu_start(0x100422d48,0,count=200000)
        except uc.UcError as e:
            self.stop_reason='unicorn_error'
            self.records.append({'kind':'engine_error','message':str(e),
                                 'pc':hex(self.u.reg_read(ar.UC_ARM64_REG_PC))})
        if self.stop_reason is None:self.stop_reason='instruction_budget'
        return {'scope':__doc__,'source_sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
          'engine':'unicorn '+uc.__version__,'pid_seed':self.pid,'cpu_seed':hex(self.cpu),
          'qos_query_model_result':self.qos_query,'qos_set_model_result':self.qos_set,
          'csr_config_model_seed':None if self.csr_config is None else hex(self.csr_config),
          'csr_model_status':self.csr_result,'stack_initialization':'synthetic zero-filled; not error-output validity proof',
          'stack_base':hex(STACK),'entry_sp':hex(sp),'steps':self.steps,
          'stop_reason':self.stop_reason,'records':self.records,'pac_bypasses':self.pac,
          'image_writes':self.writes,'data_import_models':self.data_import_values,
          'nonzero_binding_addends':self.nonzero_binding_addends,
          'guarded_global':{'address':'0x1010b5f70','bytes':bytes(self.u.mem_read(0x1010b5f70,32)).hex()},
          'end_registers':{f'x{i}':hex(self.reg(i)) for i in range(8)},
          'native_target_executed':False,'synthetic_target_instructions_executed':True,
          'target_host_ipc_files_or_system_calls_executed':False,'idb_mutated':False}


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--pid',type=int,default=0)
    parser.add_argument('--cpu',type=lambda s:int(s,0),default=0x100000c)
    parser.add_argument('--qos-query',type=int,default=0)
    parser.add_argument('--qos-set',type=int,default=0)
    parser.add_argument('--csr-config',type=lambda s:int(s,0))
    parser.add_argument('--csr-result',type=int,default=0)
    parser.add_argument('--output',required=True)
    args=parser.parse_args()
    result=Probe(args.pid,args.cpu,args.qos_query,args.qos_set,args.csr_config,args.csr_result).run()
    (ROOT/args.output).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'steps':result['steps'],'stop_reason':result['stop_reason'],
      'last_record':result['records'][-1] if result['records'] else None,
      'guard_bytes_hex':result['guarded_global']['bytes']}))
