#!/usr/bin/env python3
"""Finite private RPC502 continuation fixture with an explicit BootPolicy model.

The real BootPolicy library, filesystem/registry/IOKit/SEP path is NOT executed.
PAC is bypassed as in the base fixture; native reachability is not established.
Stops before every unmodeled import/data read/system instruction.
"""
import argparse
import hashlib
import json
import struct
from daemon_rpc502_probe import Probe,ROOT,STACK,HALT,ar
from daemon_receive_tools import FIXUPS,IMAGE

ONCE_PAIRS={0x1010c5350:0x100ddb5d4,0x1010c5340:0x100de3608}
ONCE_SIGNINGS={0x100de5364:0x100ddb5d4,0x100ddffe8:0x100de3608,0x100de00ec:0x100de3608}
COREKE_EXPORTS={'IWvA5fm4IwMS88oQXDANCS':HALT+0x200,'JY0DfiUyFiVcNw89R4t':HALT+0x204}


class ContextProbe(Probe):
    def __init__(self,mode=0,bootpolicy_status=0,csr=0,csr_status=0,model_once=False,model_heap=False,
                 model_locks=False,lock_init_result=0,sysctl_vmm=None,sysctl_status=0):
        super().__init__(csr_config=csr,csr_result=csr_status)
        self.mode=mode;self.bootpolicy_status=bootpolicy_status
        self.after_bootpolicy=False;self.context_pcs=[]
        self.model_once=model_once;self.once_active=[];self.once_done=set()
        self.model_heap=model_heap;self.heap_next=0x5000000000;self.heap_allocations=[]
        self.model_locks=model_locks;self.lock_init_result=lock_init_result;self.rwlocks={}
        self.sysctl_vmm=sysctl_vmm;self.sysctl_status=sysctl_status
        self.model_loader=False;self.loader_handle=0x6002000000
        self.import_reads={}
        self.policy_path=STACK+0x6000;self.volume_uuid=STACK+0x6100
        self.u.mem_write(self.policy_path,b'/System/Volumes/iSCPreboot\0')
        self.u.mem_write(self.volume_uuid,bytes(16))
        for name,value in [
          ('libbootpolicy/_bootpolicy_default_policy_volume_path_value',self.policy_path),
          ('libbootpolicy/_bootpolicy_root_volume_uuid_value',self.volume_uuid)]:
            a=self.import_addresses[name]
            self.u.mem_write(a,struct.pack('<Q',value))
            self.data_import_values.append({'name':name,'value':hex(value),
                'model':'private imported cell; runtime library value not observed'})

    def hook(self,u,address,size,user):
        if address in COREKE_EXPORTS.values():
            name=next(n for n,a in COREKE_EXPORTS.items() if a==address)
            args=[self.reg(i) for i in range(8)]
            self.stop('unmodeled_coreke_export',name=name,return_pc=hex(self.reg(30)),
                      args=[hex(a) for a in args],coreke_code_executed=False,
                      third_argument_prefix_hex=bytes(u.mem_read(args[2],128)).hex()
                        if name=='IWvA5fm4IwMS88oQXDANCS' else None)
            return
        if address==HALT+0x100 and self.once_active:
            row=self.once_active.pop();self.once_done.add(row['control'])
            self.records.append({'kind':'once_initializer_return','control':hex(row['control']),
                                 'return_pc':hex(row['return_pc'])})
            self.setreg(30,row['return_pc']);self.return_model(0)
            return
        name=self.imports.get(address)
        if self.model_loader and name in ['libSystem/_dlopen','libSystem/_dlsym','libSystem/_puts']:
            self.steps+=1
            ptr=self.reg(1) if name.endswith('_dlsym') else self.reg(0)
            label=bytes(u.mem_read(ptr,256)).split(b'\0')[0].decode('ascii')
            row={'kind':'import','name':name,'return_pc':hex(self.reg(30)),
                 'args':[hex(self.reg(i)) for i in range(8)],'string_argument':label,
                 'model':'private opaque loader handle/export trampolines or discarded output; no host loader/output'}
            self.records.append(row)
            if name.endswith('_dlopen'):
                assert label=='/System/Library/PrivateFrameworks/CoreKE.framework/CoreKE' and self.reg(1)==5
                self.return_model(self.loader_handle)
            elif name.endswith('_dlsym'):
                assert self.reg(0)==self.loader_handle and label in COREKE_EXPORTS
                self.return_model(COREKE_EXPORTS[label])
            else:self.return_model(0)
            return
        if name=='libbootpolicy/_bootpolicy_get_security_mode':
            self.steps+=1
            assert self.reg(0)==self.policy_path and self.reg(1)==self.volume_uuid
            if self.bootpolicy_status==0:
                u.mem_write(self.reg(2),struct.pack('<I',self.mode&0xffffffff))
            self.records.append({'kind':'import','name':name,'return_pc':hex(self.reg(30)),
                'args':[hex(self.reg(i)) for i in range(8)],
                'model':'seed BootPolicy status; write mode only on status zero; real library not executed',
                'return_value':self.bootpolicy_status,'mode_seed':hex(self.mode&0xffffffff)})
            self.after_bootpolicy=True
            self.return_model(self.bootpolicy_status)
            return
        if self.model_once and address in ONCE_SIGNINGS:
            assert self.reg(16)==ONCE_SIGNINGS[address]
            self.pac.append({'site':hex(address),'instruction':'paciza',
                'pointer':hex(self.reg(16)),
                'authentication':'initializer literal left unsigned in explicit private model'})
            self.u.reg_write(ar.UC_ARM64_REG_PC,address+4)
            self.steps+=1
            return
        if self.model_once and name=='libSystem/_pthread_once':
            self.steps+=1;control,initializer=self.reg(0),self.reg(1)
            if ONCE_PAIRS.get(control)!=initializer:
                self.stop('unmodeled_once_pair',control=hex(control),initializer=hex(initializer))
                return
            current=bytes(u.mem_read(control,16))
            if control not in self.once_done:
                assert current==bytes.fromhex('babcb130000000000000000000000000')
            self.records.append({'kind':'import','name':name,'return_pc':hex(self.reg(30)),
                'args':[hex(self.reg(i)) for i in range(8)],
                'model':'serial first-use initializer invocation only; opaque control state not synthesized',
                'control_bytes':current.hex(),'already_initialized_in_model':control in self.once_done})
            if control in self.once_done:self.return_model(0)
            else:
                if self.once_active:
                    self.stop('unmodeled_recursive_once',control=hex(control));return
                self.once_active.append({'control':control,'return_pc':self.reg(30)})
                self.setreg(30,HALT+0x100)
                u.reg_write(ar.UC_ARM64_REG_PC,initializer)
            return
        if self.model_heap and name=='libSystem/_malloc_type_malloc':
            self.steps+=1;size=self.reg(0)
            if size>0x40000 or len(self.heap_allocations)>=16:
                self.stop('private_heap_budget',requested_bytes=size)
                return
            n=max(size,1);mapped=(n+4095)&~4095;a=self.heap_next
            self.heap_next+=mapped+4096
            self.u.mem_map(a,mapped);self.u.mem_write(a,bytes([0xa5])*n)
            self.heap_allocations.append({'address':a,'size':size,'mapped':mapped,
                'initialized':bytearray(n),'allocation_pc':self.reg(30)-4})
            self.records.append({'kind':'import','name':name,'return_pc':hex(self.reg(30)),
                'args':[hex(self.reg(i)) for i in range(8)],
                'model':'fresh private allocation; unknown bytes tracked and reads blocked until written',
                'private_address':hex(a),'size_bytes':size})
            self.return_model(a)
            return
        sync_names={'libSystem/_pthread_rwlock_init','libSystem/_pthread_rwlock_wrlock',
                    'libSystem/_pthread_rwlock_rdlock','libSystem/_pthread_rwlock_unlock'}
        if self.model_locks and name in sync_names:
            self.steps+=1;a=self.reg(0);operation=name.rsplit('_',1)[1]
            if operation=='init':
                assert self.reg(1)==0
                allocation=next(r for r in self.heap_allocations if r['address']==a)
                assert allocation['size']==200 and all(allocation['initialized'])
                assert bytes(u.mem_read(a,200))==bytes(200)
                self.rwlocks[a]={'initialized':self.lock_init_result==0,'readers':0,'writer':False}
                status=self.lock_init_result
            else:
                state=self.rwlocks.get(a)
                if not state or not state['initialized']:
                    self.stop('unmodeled_rwlock_object',operation=operation,address=hex(a));return
                if operation=='wrlock':
                    if state['writer'] or state['readers']:
                        self.stop('unmodeled_rwlock_contention',operation=operation,address=hex(a));return
                    state['writer']=True
                elif operation=='rdlock':
                    if state['writer']:
                        self.stop('unmodeled_rwlock_contention',operation=operation,address=hex(a));return
                    state['readers']+=1
                elif operation=='unlock':
                    if state['writer']:state['writer']=False
                    elif state['readers']:state['readers']-=1
                    else:
                        self.stop('unmodeled_rwlock_unheld_unlock',address=hex(a));return
                status=0
            self.records.append({'kind':'import','name':name,'return_pc':hex(self.reg(30)),
                'args':[hex(self.reg(i)) for i in range(8)],'return_value':status,
                'model':'serial abstract rwlock state only; opaque native representation not synthesized',
                'state_after':dict(self.rwlocks[a]),
                'initial_200_bytes_zero':True if operation=='init' else None})
            self.return_model(status)
            return
        if name=='libSystem/_sysctlbyname':
            raw=bytes(u.mem_read(self.reg(0),128));label=raw.split(b'\0')[0]
            capacity=struct.unpack('<Q',u.mem_read(self.reg(2),8))[0]
            self.records.append({'kind':'sysctl_call_boundary','return_pc':hex(self.reg(30)),
                'name_hex':label.hex(),'name_ascii':label.decode('ascii',errors='backslashreplace'),
                'old_capacity_bytes':capacity,'old_buffer_initial_hex':bytes(u.mem_read(self.reg(1),min(capacity,128))).hex(),
                'new_pointer':hex(self.reg(3)),'new_size':self.reg(4),
                'host_sysctl_executed':False})
            if self.sysctl_vmm is not None and label==b'kern.hv_vmm_present':
                assert capacity==4 and self.reg(3)==0 and self.reg(4)==0
                self.steps+=1
                if self.sysctl_status==0:
                    u.mem_write(self.reg(1),struct.pack('<I',self.sysctl_vmm&0xffffffff))
                    u.mem_write(self.reg(2),struct.pack('<Q',4))
                self.records.append({'kind':'import','name':name,'return_pc':hex(self.reg(30)),
                    'args':[hex(self.reg(i)) for i in range(8)],'return_value':self.sysctl_status,
                    'model':'seed VMM inquiry status and output on zero; errno and host query unmodeled',
                    'value_seed':hex(self.sysctl_vmm&0xffffffff)})
                self.return_model(self.sysctl_status)
                return
        if name=='libSystem/_open':
            raw=bytes(u.mem_read(self.reg(0),256)).split(b'\0')[0]
            self.records.append({'kind':'unmodeled_open_boundary','return_pc':hex(self.reg(30)),
                'path_hex':raw.hex(),'path_ascii':raw.decode('ascii',errors='backslashreplace'),
                'flags':hex(self.reg(1)&0xffffffff),'host_file_opened':False,
                'third_register_not_assumed_meaningful':True})
        if self.after_bootpolicy and address not in self.imports:
            self.context_pcs.append(address)
        if address==0x100ddc63c and self.reg(30) in [0x100de18a0,0x100de1a30]:
            self.records.append({'kind':'encoded_comparison_frame','callee':hex(address),
                'return_pc':hex(self.reg(30)),'frame_address':hex(self.reg(0)),
                'frame_bytes':bytes(u.mem_read(self.reg(0),56)).hex()})
        if address in [0x100de6930,0x100de6990,0x100de15ec,0x100de1794,0x100de1b58,0x100de9c6c]:
            row={'kind':'runtime_checkpoint','pc':hex(address),
                 'registers':{f'x{i}':hex(self.reg(i)) for i in range(29)},
                 'sp':hex(u.reg_read(ar.UC_ARM64_REG_SP))}
            if address==0x100de15ec:
                row['name_encoded_source_address']=hex(self.reg(13))
                row['name_encoded_source_hex']=bytes(u.mem_read(self.reg(13),20)).hex()
            self.records.append(row)
        if address in [0x1005bbb20,0x10051e790,0x1004d4b18]:
            sp=u.reg_read(ar.UC_ARM64_REG_SP)
            self.records.append({'kind':'context_checkpoint','pc':hex(address),'sp':hex(sp),
                'registers':{f'x{i}':hex(self.reg(i)) for i in range(29)},
                'csr_indicator_saved':struct.unpack('<I',u.mem_read(sp+0xad14,4))[0],
                'mode_marker_saved':struct.unpack('<I',u.mem_read(sp+0x9b90,4))[0]})
        return super().hook(u,address,size,user)

    def read_hook(self,u,access,address,size,value,user):
        if getattr(self,'after_bootpolicy',False) and address in FIXUPS and FIXUPS[address]['kind'].endswith('bind'):
            site=u.reg_read(ar.UC_ARM64_REG_PC);key=(site,address)
            if key not in self.import_reads:
                self.import_reads[key]={'pc':hex(site),'slot':hex(address),'read_bytes':size,
                    'original_word_hex':IMAGE.read(address,8).hex(),
                    'target':FIXUPS[address]['target'],'visits':0}
            self.import_reads[key]['visits']+=1
        for a in getattr(self,'once_done',[]):
            if address<a+16 and address+size>a+8:
                self.stop('unmodeled_opaque_once_state_read',address=hex(address),read_bytes=size,
                          site=hex(u.reg_read(ar.UC_ARM64_REG_PC)))
                return
        for a in getattr(self,'rwlocks',{}):
            if address<a+200 and address+size>a:
                self.stop('unmodeled_opaque_rwlock_state_read',address=hex(address),read_bytes=size,
                          site=hex(u.reg_read(ar.UC_ARM64_REG_PC)))
                return
        for r in getattr(self,'heap_allocations',[]):
            if r['address']<=address<r['address']+r['mapped']:
                offset=address-r['address']
                if offset+size>r['size']:
                    self.stop('private_heap_out_of_extent_read',address=hex(address),read_bytes=size,
                              site=hex(u.reg_read(ar.UC_ARM64_REG_PC)))
                    return
                if not all(r['initialized'][offset:offset+size]):
                    self.stop('unmodeled_uninitialized_heap_read',address=hex(address),read_bytes=size,
                              site=hex(u.reg_read(ar.UC_ARM64_REG_PC)))
                    return
        return super().read_hook(u,access,address,size,value,user)

    def write_hook(self,u,access,address,size,value,user):
        for r in getattr(self,'heap_allocations',[]):
            if r['address']<=address<r['address']+r['mapped']:
                offset=address-r['address']
                if offset+size>r['size']:
                    self.stop('private_heap_out_of_extent_write',address=hex(address),write_bytes=size,
                              site=hex(u.reg_read(ar.UC_ARM64_REG_PC)))
                    return
                r['initialized'][offset:offset+size]=bytes([1])*size
        return super().write_hook(u,access,address,size,value,user)

    def run(self):
        out=super().run()
        out.update({'scope':__doc__,'bootpolicy_mode_model_seed':hex(self.mode&0xffffffff),
            'bootpolicy_status_model_seed':self.bootpolicy_status,
            'bootpolicy_library_executed':False,'context_pcs':[hex(p) for p in self.context_pcs],
            'context_instruction_visits':len(self.context_pcs),
            'serial_once_model_enabled':self.model_once,
            'serial_once_completed_controls':[hex(a) for a in sorted(self.once_done)],
            'private_heap_model_enabled':self.model_heap,
            'serial_lock_model_enabled':self.model_locks,
            'lock_init_model_result':self.lock_init_result,
            'serial_lock_states':{hex(a):r for a,r in self.rwlocks.items()},
            'sysctl_vmm_model_seed':self.sysctl_vmm,'sysctl_model_status':self.sysctl_status,
            'private_loader_model_enabled':self.model_loader,'coreke_code_executed':False,
            'bound_import_reads':list(self.import_reads.values()),
            'generator_sha256':hashlib.sha256((ROOT/'daemon_rpc502_context_probe.py').read_bytes()).hexdigest(),
            'base_generator_sha256':hashlib.sha256((ROOT/'daemon_rpc502_probe.py').read_bytes()).hexdigest(),
            'private_heap_allocations':[{'address':hex(r['address']),'size_bytes':r['size'],
                 'initialized_bytes':sum(r['initialized']),'allocation_pc':hex(r['allocation_pc']),
                 'unknown_unwritten_bytes':'reads blocked; not treated as zero'} for r in self.heap_allocations],
            'stop_registers':{f'x{i}':hex(self.reg(i)) for i in range(29)},
            'stop_sp':hex(self.u.reg_read(ar.UC_ARM64_REG_SP)),
            'once_control_candidates':[
                {'address':hex(a),'bytes':bytes(self.u.mem_read(a,16)).hex()}
                for a in sorted(ONCE_PAIRS)],
            'imported_default_model_note':'private opaque values; does not execute actual default-volume resolution'})
        return out


if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--mode',type=lambda x:int(x,0),default=0)
    p.add_argument('--bootpolicy-status',type=int,default=0)
    p.add_argument('--csr',type=lambda x:int(x,0),default=0)
    p.add_argument('--csr-status',type=int,default=0)
    p.add_argument('--model-once',action='store_true')
    p.add_argument('--model-heap',action='store_true')
    p.add_argument('--model-locks',action='store_true')
    p.add_argument('--lock-init-result',type=int,default=0)
    p.add_argument('--sysctl-vmm',type=lambda x:int(x,0))
    p.add_argument('--sysctl-status',type=int,default=0)
    p.add_argument('--model-loader',action='store_true')
    p.add_argument('--output',required=True)
    a=p.parse_args();probe=ContextProbe(a.mode,a.bootpolicy_status,a.csr,a.csr_status,a.model_once,a.model_heap,
                                  a.model_locks,a.lock_init_result,a.sysctl_vmm,a.sysctl_status)
    probe.model_loader=a.model_loader;r=probe.run()
    (ROOT/a.output).write_text(json.dumps(r,indent=2)+'\n')
    print(json.dumps({'steps':r['steps'],'context_visits':r['context_instruction_visits'],
        'stop_reason':r['stop_reason'],'last_record':r['records'][-1]}))
