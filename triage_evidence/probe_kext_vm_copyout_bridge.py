#!/usr/bin/env python3
"""Original kext caller <-> kernel copyout/discard frame and memory transfers.
Declared internal reply and primitive effects; no native transport/VM/rights.
O(visits+RAM+effects), O(image+RAM+journals). Kext producer imports only enumerated
VM regions; later call/return components transfer complete RAM/register/SIMD state.
"""
import json,struct,copy
from unicorn import arm64_const as ar
from probe_rpc502_vm_handoff import Probe as VMParent,compressed,decode,P,SIZE,SP,HALT,MAP,KMAP,THREAD,COPIES,ZONE,AUX
from probe_kext_constructor_reply_state import Probe as KextParent
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
PREFIX='kext_vm_copyout_bridge';BACK=P+0x78000;MAPPED=P+0xa8000;META=P+0x9c000;REQCOPY=P+0xb8000
def globals_of(obj):
 addresses=list(dict.fromkeys((int(e['address'],16),len(e['bytes_hex'])//2)for e in obj.image_initial));return[{'address':hex(a),'bytes_hex':bytes(obj.u.mem_read(a,n)).hex()}for a,n in addresses]
def simd(u):return[hex(u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))))for j in range(32)]
class VMProbe(VMParent):
 def __init__(self,im,c,src,seed,producer=None,index=None):
  super().__init__(im,c,src,seed,producer,index);self.bridge_entry_Q=None;self.bridge_return=None;self.adapter_edges=[];self.adapter=None
  if producer is None:
   meta=META-((COPIES[0]>>10)&0xffffffff0)
   for a,tag in[(COPIES[0],0x13),(COPIES[1],0x13),(MAP,0x10),(KMAP,0x10)]:self.fixture(meta+((a>>10)&0xffffffff0),struct.pack('<H',tag))
   self.image_fixture(0xfffffe0007e66f00,struct.pack('<Q',meta),'Declared metadata relocation disjoint from kext filename')
  else:
   b=producer['boundary'];self.entry=int(b['pc'],16);self.bridge_return=int(b['registers31'][30],16);self.adapter=next(e for e in src['kext_VM_adapters']if e['adapter']==hex(self.entry));self.allowed.extend([(self.entry,self.entry+8),(int(self.adapter['stub_start'],16),int(self.adapter['stub_start'],16)+16)])
   for j,x in enumerate(b['registers31']):self.set(j,int(x,16))
   self.u.reg_write(ar.UC_ARM64_REG_SP,int(b['SP'],16));self.u.reg_write(ar.UC_ARM64_REG_NZCV,int(b['NZCV'],16))
   for j,x in enumerate(producer['final_Q_registers32']):self.u.reg_write(getattr(ar,'UC_ARM64_REG_Q'+str(j)),int(x,16))
   self.bridge_entry_Q=producer['final_Q_registers32']
  self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV));self.bridge_entry_SP=hex(self.u.reg_read(ar.UC_ARM64_REG_SP));self.bridge_output=None if producer is None or c['stage']=='discard'else self.reg(1)
 def code(self,u,a,n,d):
  self.flush()
  if self.bridge_return is not None and a==self.bridge_return:return self.stop('returned')
  if self.adapter is not None and a==int(self.adapter['stub_start'],16)+12:
   raw=bytes(u.mem_read(a,4));ins=next(self.image.k.cs.disasm(raw,a));assert ins.mnemonic=='braa'and ins.op_str=='x16, x17'and raw==self.image.k.read(a,4)and self.reg(16)==int(self.adapter['pointer']['target'],16)and self.reg(17)==int(self.adapter['pointer']['slot'],16);self.adapter_edges.append({'pc':hex(a),'source_visit_index':len(self.visits),'target':hex(self.reg(16)),'modifier':hex(self.reg(17))});self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});u.reg_write(ar.UC_ARM64_REG_PC,self.reg(16));return
  if a==0xfffffe000bcfe5b8 and self.stage=='copyin':assert self.active==0;return self.effect(a,'backing_allocate_model',BACK)
  if a==0xfffffe000bdc76b4:
   error=self.c.get('allocation_result',0);self.effect(a,'bridge_VM_allocate_model',error,[]if error else[(self.reg(1),struct.pack('<Q',MAPPED),'declared destination VA')]);self.effects[-1]['stack_prefix12_hex']=bytes(u.mem_read(u.reg_read(ar.UC_ARM64_REG_SP),12)).hex();return
  if a==0xfffffe000be7798c:return self.effect(a,'bridge_copyout_bytes_model',0,[(self.reg(1),bytes(u.mem_read(self.reg(0),self.reg(2))),'exact produced backing bytes transferred')])
  return super().code(u,a,n,d)
 def run(self):
  row=super().run();row.update(bridge_phase=self.c['stage'],entry_SP=self.bridge_entry_SP,entry_Q_registers32=self.bridge_entry_Q,final_Q_registers32=simd(self.u),logical_adapter_edges=self.adapter_edges,bridge_return_PC=None if self.bridge_return is None else hex(self.bridge_return),bridge_output_address=None if self.bridge_output is None else hex(self.bridge_output),bridge_output_u64=None if self.bridge_output is None else int.from_bytes(bytes(self.u.mem_read(self.bridge_output,8)),'little'),bridge_backing4096_hex=bytes(self.u.mem_read(BACK,4096)).hex(),bridge_mapped4096_hex=bytes(self.u.mem_read(MAPPED,4096)).hex(),final_image_globals=globals_of(self));return row
class KextProbe(KextParent):
 def __init__(self,im,c,producer,index,resume=False):
  super().__init__(im,{'warm':1,'mode':1,'wire_return':0,'page_shift':14,'length':28,'cpu_type':0x100000c,'cpu_subtype':0,'origin':1});self.c.update(c);self.bridge_transfer=None;self.bridge_regions=[];self.bridge_entry_Q=None;self.bridge_frames=[]
  self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,THREAD)
  if not resume:
   ram=decode(producer['final_private_RAM']);regions=[(MAP,256),(THREAD,0x600),(KMAP,256),(COPIES[0],48),(BACK,4096),(ZONE,64),(AUX,16),(META-0x200,0x400)]
   for a,n in regions:
    b=ram[a-P:a-P+n];self.fixture(a,b);self.bridge_regions.append({'address':hex(a),'size_bytes':n,'bytes_hex':b.hex(),'producer_case':index})
   for e in producer['final_image_globals']:
    a=int(e['address'],16);b=bytes.fromhex(e['bytes_hex']);self.ensure(a,len(b));self.u.mem_write(a,b);self.image_initial.append({**e,'provenance':'Exact source VM producer final-global import'})
  else:
   self.u.mem_write(P,decode(producer['final_private_RAM']));self.initial=[];self.bridge_transfer={'producer_case':index,**producer['final_private_RAM']};self.image_initial=[]
   for e in producer['final_image_globals']:
    a=int(e['address'],16);b=bytes.fromhex(e['bytes_hex']);self.ensure(a,len(b));self.u.mem_write(a,b);self.image_initial.append({**e,'provenance':'Exact kernel return-global transfer'})
   b=producer['boundary'];self.entry=int(b['pc'],16)
   for j,x in enumerate(b['registers31']):self.set(j,int(x,16))
   self.u.reg_write(ar.UC_ARM64_REG_SP,int(b['SP'],16));self.u.reg_write(ar.UC_ARM64_REG_NZCV,int(b['NZCV'],16))
   for j,x in enumerate(producer['final_Q_registers32']):self.u.reg_write(getattr(ar,'UC_ARM64_REG_Q'+str(j)),int(x,16))
   self.bridge_entry_Q=producer['final_Q_registers32'];self.staging_extent=16384
  self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV));self.bridge_entry_SP=hex(self.u.reg_read(ar.UC_ARM64_REG_SP))
 def effect(self,a,b,reason):
  if reason.startswith('Opaque vm_map_copy_t result'):b=struct.pack('<Q',REQCOPY);reason='Declared request-copy identity disjoint from reply-zone metadata'
  return super().effect(a,b,reason)
 def code(self,u,a,n,d):
  self.flush()
  if a in[0xfffffe000a508e34,0xfffffe000a508e24,0xfffffe000a508e0c,0xfffffe000bcd0448]:
   self.bridge_frames.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments':[hex(self.reg(j))for j in range(5)]});return self.stop('bridge_boundary')
  if a==0xfffffe000a508e4c:return self.modeled(a,'request_staging_free_model',0)
  if a==0xfffffe000bcf5e28:
   self.transport_request=bytes(u.mem_read(self.reg(0),88)).hex();msg=self.reg(0);b=bytearray(392);struct.pack_into('<IIQQII',b,0,0x80000000,392,0,0,0,602);struct.pack_into('<I',b,32,2);struct.pack_into('<QII',b,36,COPIES[0],0x01000101,4096);struct.pack_into('<QII',b,52,0,0x01000101,0);b[68:76]=bytes.fromhex('0000000001000000');struct.pack_into('<I',b,76,0xbeefed02);struct.pack_into('<II',b,384,4096,0);self.declared_reply=bytes(b).hex();self.effect(msg,bytes(b),'Declared internal reply carrying source-produced copy object; no native IPC');return self.modeled(a,'transport_reply_model',0)
  return super().code(u,a,n,d)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=100000);self.flush();assert self.reason in['bridge_boundary','before_external_code'],self.boundary
  addresses=list(dict.fromkeys((int(e['address'],16),len(e['bytes_hex'])//2)for e in self.image_initial));return{'bridge_phase':'kext_resume'if self.bridge_transfer else'kext_prefix','configuration':self.c,'entry_PC':hex(self.entry),'entry_SP':self.bridge_entry_SP,'entry_registers31':self.entry_regs,'entry_NZCV':self.entry_NZCV,'entry_Q_registers32':self.bridge_entry_Q,'final_Q_registers32':simd(self.u),'private_RAM':{'address':hex(P),'size_bytes':SIZE,'initial_byte':0},'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,'private_system_register_fixtures':[{'register':'TPIDR_EL1','value':hex(THREAD)}],'initial_private_RAM_transfer':self.bridge_transfer,'VM_region_imports':self.bridge_regions,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'logical_edges':self.edges,'calls':self.calls,'snapshots':self.snapshots,'state_snapshots':self.state_snapshots,'allocations':self.allocs,'boundary':self.boundary,'bridge_frames':self.bridge_frames,'staging_extent_bytes':getattr(self,'staging_extent',0),'staging_final_hex':bytes(self.u.mem_read(P+0x70000,16385)).hex(),'name_final_hex':bytes(self.u.mem_read(P+0x90000,29)).hex(),'output_handle_final_hex':bytes(self.u.mem_read(P+0x81000,8)).hex(),'message88_hex':None,'transport_request88_hex':self.transport_request,'declared_reply392_hex':self.declared_reply,'final_scratch160_hex':bytes(self.u.mem_read(P+0x20000,160)).hex(),'final_child152_hex':bytes(self.u.mem_read(P+0x22000,152)).hex(),'final_private_RAM':compressed(bytes(self.u.mem_read(P,SIZE))),'final_image_globals':[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()}for a,n in addresses],'native_target_executed':False,'native_VM_effects_executed':False,'native_IPC_executed':False,'native_retirement_executed':False,'native_namespace_conversion_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'complete_FairPlay_round_trip_established':False,'full_goal_complete':False}
def main():
 im=Image();src=json.loads((ROOT/(PREFIX+'_source.json')).read_text());seed=copy.deepcopy(json.loads((ROOT/'rpc502_reply_copyin_profiles.json').read_text())['cases'][18]);seed['configuration']['lengths']=[4096,0];h=int(seed['message_header_address'],16);f=next(f for f in seed['initial_private_fixtures']if int(f['address'],16)==h);b=bytearray.fromhex(f['bytes_hex']);struct.pack_into('<I',b,64,0);struct.pack_into('<I',b,388,0);f['bytes_hex']=b.hex();rows=[]
 def add(r):rows.append(r);print(json.dumps({'case':len(rows)-1,'phase':r['bridge_phase'],'visits':len(r['source_visits']),'boundary':r['boundary']}),flush=True)
 add(VMProbe(im,{'stage':'copyin'},src,seed).run());add(KextProbe(im,{},rows[0],0).run());add(VMProbe(im,{'stage':'copyout','descriptor_index':0},src,seed,rows[1],1).run());add(KextProbe(im,{},rows[2],2,True).run());add(VMProbe(im,{'stage':'copyout','descriptor_index':0,'allocation_result':6},src,seed,rows[1],1).run());add(KextProbe(im,{},rows[4],4,True).run());add(VMProbe(im,{'stage':'discard','descriptor_index':0},src,seed,rows[5],5).run());add(KextProbe(im,{},rows[6],6,True).run())
 deps=[PREFIX+'_source.json','rpc502_reply_copyin_profiles.json','probe_rpc502_vm_handoff.py','probe_rpc502_reply_copyin.py','probe_kext_constructor_reply_state.py','probe_kext_constructor_request.py','probe_kernel_vm_mig.py','kernel_vm_mig_tools.py'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'cases':rows,'native_target_executed':False,'native_VM_effects_executed':False,'native_IPC_executed':False,'native_retirement_executed':False,'native_namespace_conversion_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'complete_FairPlay_round_trip_established':False,'full_goal_complete':False};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
