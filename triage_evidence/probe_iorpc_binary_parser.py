#!/usr/bin/env python3
"""Original parser/collection reconstruction from exact previously emitted bytes.
Nominal class allocations, typed buffer allocation, symbol intern, refs and VM
remain declared models. O(visits+effects), O(journals+private RAM).
"""
import json,struct
from unicorn import arm64_const as ar
from probe_iorpc_ool_serialization import Probe as Parent,P,MAPOBJ,MAPPED,COPY,PACKET,VMCOUNT,CTX,HANDLER,DEV
from probe_aes_command_gate import Probe as SourceCPU
from probe_kernel_vm_mig import HALT
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
PREFIX='iorpc_binary_parser';PARSER=0xfffffe000c489b18;D=P+0x90000;V=P+0x90100;K=P+0x90200;KB=P+0x90300;PAIRS=P+0x91000;BYTES=P+0x92000;TABLE=P+0x93000;NEST=P+0x94000;COOKIE=P+0x95000;ERROR=P+0x95080;FILTER=P+0xe4200
class Probe(Parent):
 def __init__(self,im,c,src,origin,old,packets,reconstructed=None):
  super().__init__(im,{**c,'stage':'inverse'},src,origin,old,packets);self.c={**c,'stage':'adapter'if reconstructed else'inverse'};self.handler_contents=[];self.filter_frames=[];self.parser_returns=[];self.parser_calls=[];self.parser_allocs=[];self.symbols=[];self.parser_refs=[];self.all_objects +=[(D,64),(V,64),(K,64),(KB,64),(PAIRS,256),(BYTES,256),(TABLE,512),(NEST,512),(COOKIE,16),(ERROR,8)];self.parser_targets={(s['class'],s['offset']):int(s['pointer']['target'],16)for s in src['binary_parser_slots']};md=int(src['binary_parser_definitions']['__ZTVN12OSDictionary9MetaClassE'][0]['address'],16)+16;self.image_fixture(self.meta['12OSDictionary'],struct.pack('<Q',md),'Declared dictionary metaclass vptr for original parser construction');self.data_meta_alloc=self.targets[('__ZTVN6OSData9MetaClassE',0xa8)];self.dict_meta_alloc=self.parser_targets[('__ZTVN12OSDictionary9MetaClassE',0xa8)]
  if reconstructed:
   for e in reconstructed['final_objects']:self.fixture(int(e['address'],16),bytes.fromhex(e['bytes_hex']))
   for key in ['final_source_globals','final_environment_globals','final_registry_globals','final_serialization_globals']:
    for e in reconstructed[key]:self.image_fixture(int(e['address'],16),bytes.fromhex(e['bytes_hex']),'Exact original-parser component final-global transfer')
   self.entry=0xfffffe000c4a3290;self.stage='invoke'
   for j,v in enumerate([CTX,DEV,HANDLER]):self.set(j,v)
   self.set(30,HALT);self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))
  if c.get('parser_component'):
   self.c['stage']='parser_component';self.stage='parser_component';self.entry=0xfffffe000c488964;self.fixture(MAPPED,self.incoming_bytes);self.fixture(ERROR,b'\xa5'*8)
   for j,v in enumerate([MAPPED,len(self.incoming_bytes),FILTER,COOKIE,c['options'],ERROR]):self.set(j,v)
   self.set(30,HALT);self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))
 def return_extent(self,a,name,pointer,extent):
  self.modeled(a,name,pointer);self.set(1,extent);self.models[-1]['after_registers31'][1]=hex(extent);self.models[-1]['return_register_X1']=hex(extent)
 def code(self,u,a,n,d):
  self.flush()
  if a==0xfffffe000c596bf4 or(a==HALT and self.c.get('parser_component')):self.parser_returns.append(self.frame(a,1))
  if a==FILTER:
   e=self.frame(a,4);e['payload_hex']=bytes(u.mem_read(BYTES,int.from_bytes(bytes(u.mem_read(V+0xc,4)),'little'))).hex();self.filter_frames.append(e);return self.modeled(a,'declared_parser_filter_passthrough',self.reg(3))
  if a==HANDLER:
   e=self.frame(a,2);e['dictionary64_hex']=bytes(u.mem_read(self.reg(1),64)).hex();e['pair16_hex']=bytes(u.mem_read(PAIRS,16)).hex();e['data64_hex']=bytes(u.mem_read(V,64)).hex();e['payload_hex']=bytes(u.mem_read(BYTES,int.from_bytes(bytes(u.mem_read(V+0xc,4)),'little'))).hex();self.handler_contents.append(e)
  if a==PARSER:
   e=self.frame(a,6);e['bytes_hex']=bytes(u.mem_read(self.reg(0),self.reg(1))).hex();self.parser_frames.append(e);self.parser_calls.append(e);return SourceCPU.code(self,u,a,n,d)
  if a in [0xfffffe000c44d70c,0xfffffe000c44cd64,0xfffffe000c44cd70,0xfffffe000c44ab74,0xfffffe000c44ac2c]:self.parser_calls.append(self.frame(a,3 if a in [0xfffffe000c44cd64,0xfffffe000c44ab74]else 4 if a==0xfffffe000c44cd70 else 2))
  if a in [self.dict_meta_alloc,self.data_meta_alloc]:
   dest,vptr=(D,self.v['12OSDictionary'])if a==self.dict_meta_alloc else(V,self.v['6OSData']);self.parser_allocs.append(self.frame(a,1));self.effect(dest,struct.pack('<QI',vptr,1)+bytes(52),'Declared nominal parser object allocation; original field initialization follows');return self.modeled(a,'declared_parser_dictionary_allocation'if dest==D else'declared_parser_data_allocation',dest)
  if a==0xfffffe000bcfe5b8 and self.reg(30)in [0xfffffe000c44d754,0xfffffe000c44ac78]:
   self.parser_allocs.append(self.frame(a,4));dest=PAIRS if self.reg(30)==0xfffffe000c44d754 else BYTES;extent=max(self.reg(1),16);assert extent<=256;self.effect(dest,bytes(extent),'Declared private typed allocation extent; native rounding unknown');return self.return_extent(a,'declared_parser_typed_buffer_allocation',dest,extent)
  if a==0xfffffe000bcff0b8:
   self.parser_allocs.append(self.frame(a,6));dest=TABLE if self.reg(30)==0xfffffe000c48a14c else NEST;assert self.reg(1)==0 and self.reg(2)==0 and self.reg(3)==512 and self.reg(4)==0x41244;self.effect(dest,bytes(512),'Declared private 512-byte parser bookkeeping allocation');return self.return_extent(a,'declared_parser_bookkeeping_allocation',dest,512)
  if a==0xfffffe000bcfec48:
   self.parser_allocs.append(self.frame(a,3));assert self.reg(1)in[TABLE,NEST]and self.reg(2)==512;return self.modeled(a,'declared_parser_bookkeeping_free',0)
  if a==0xfffffe000c484334:
   e=self.frame(a,1);text=self.bytestring(self.reg(0));e['string_hex']=text.hex();self.symbols.append(e);assert text==b'key';self.effect(K,struct.pack('<QI',self.v['8OSSymbol'],1)+bytes(52),'Declared symbol-intern result identity');self.effect(K+0xc,struct.pack('<I',(len(text)+1)<<14),'Declared packed interned-symbol length');self.effect(K+0x10,struct.pack('<Q',KB),'Declared interned-symbol CString');self.effect(KB,text+b'\0','Declared retained symbol bytes');return self.modeled(a,'declared_parser_symbol_intern',K)
  refs=[0xfffffe000c445200,0xfffffe000c4451d0,0xfffffe000c444fa8,self.targets[('__ZTV8OSSymbol',0x48)],self.targets[('__ZTV8OSSymbol',0x50)]]
  if a in refs and self.reg(0)in[D,V,K]:
   self.parser_refs.append(self.frame(a,2 if a in refs[2:]else 1));return self.modeled(a,'declared_parser_object_reference',0)
  if a==0xfffffe000c647f10 and self.reg(2)==0:return self.modeled(a,'declared_parser_zero_byte_copy',self.reg(0))
  return super().code(u,a,n,d)
 def run(self):
  row=super().run();row.update(binary_parser_return_frames=self.parser_returns,binary_parser_filter_frames=self.filter_frames,binary_parser_handler_frames=self.handler_contents,binary_parser_frames=self.parser_calls,binary_parser_allocation_frames=self.parser_allocs,binary_parser_symbol_frames=self.symbols,binary_parser_reference_frames=self.parser_refs,native_binary_parser_executed=False,exact_packet_producer={'path':'iorpc_ool_serialization_profiles.json','case':self.c['packet_case']});return row

def main():
 im=Image();src=json.loads((ROOT/(PREFIX+'_source.json')).read_text());origin=json.loads((ROOT/'iorpc_object_conversion_profiles.json').read_text())['cases'][0];old=json.loads((ROOT/'platform_iorpc_profiles.json').read_text())['cases'];packets=json.loads((ROOT/'iorpc_ool_serialization_profiles.json').read_text())['cases'];rows=[]
 for case in [2,4,5,6,7,8,9,16,17]:
  row=Probe(im,{'packet_case':case},src,origin,old,packets).run();rows.append(row);print(json.dumps({'case':len(rows)-1,'packet_case':case,'boundary':row['boundary']['kind'],'raw_X0':row['boundary']['registers31'][0],'visits':len(row['source_visits'])}),flush=True)
 for producer in [5,8]:
  row=Probe(im,{'packet_case':rows[producer]['configuration']['packet_case'],'parser_producer_case':producer},src,origin,old,packets,rows[producer]).run();rows.append(row);print(json.dumps({'case':len(rows)-1,'producer':producer,'boundary':row['boundary']['kind'],'visits':len(row['source_visits'])}),flush=True)
 for options in range(8):
  row=Probe(im,{'packet_case':8,'parser_component':True,'options':options},src,origin,old,packets).run();rows.append(row);print(json.dumps({'case':len(rows)-1,'options':options,'filters':len(row['binary_parser_filter_frames']),'visits':len(row['source_visits'])}),flush=True)
 flags=['native_target_executed','native_IPC_executed','native_registry_or_platform_effects_executed','native_remote_transport_executed','native_port_objects_observed','native_object_port_registry_effects_executed','native_serialized_VM_or_parser_effects_executed','native_binary_parser_executed','runtime_device_or_controller_identity_established','runtime_metaclass_hierarchy_established','hardware_PAC_executed','idb_mutated','full_goal_complete'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in [PREFIX+'_source.json','iorpc_ool_serialization_profiles.json','iorpc_object_conversion_profiles.json','platform_iorpc_profiles.json','probe_iorpc_ool_serialization.py','probe_iorpc_object_conversion.py','probe_iorpc_remote.py','probe_platform_iorpc.py','probe_aes_platform_gate.py','probe_aes_hardware_job.py','probe_aes_provider_queue.py','probe_aes_command_pool.py','probe_workloop_gate_attachment.py','probe_aes_command_gate.py','probe_kernel_vm_mig.py','kernel_vm_mig_tools.py']},'cases':rows,**{k:False for k in flags}};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
