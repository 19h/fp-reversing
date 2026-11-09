#!/usr/bin/env python3
"""Original kext constructor -> actual VM-copy adapter/factory -> RPC queue.
O(image+visits+RAM+effects), O(image+RAM+journals). Map/typed allocation epochs,
raw backing/header allocations, lower map byte copy and inherited primitives/PAC
are declared; no native mapping, VM, allocator, IPC or authentication executes.
"""
import json,struct
from unicorn import arm64_const as ar
from probe_kernel_rpc_request import Request as Parent,qregs,THREAD,P,SIZE,KS,RS,D0,D1,REPLY,TS,KMSG
from probe_rpc502_vm_handoff import compressed,decode
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
PREFIX='kernel_request_copyin';HEADER=P+0x88010;BACK=P+0x8c000;KMAP=P+0x84000;IMAP=P+0x85000;STAGING=P+0x70000;ZSTATS=P+0x50000
class Probe(Parent):
 def __init__(self,im,src,c,parent,origin):
  super().__init__(im,src,c,parent,origin);self.vm_frames=[];self.vm_handoffs=[];self.vm_raw=[];self.vm_copies=[];self.vm_return=None;self.vm_out=None;self.setup_start=len(self.overlays);meta=int.from_bytes(bytes(self.u.mem_read(0xfffffe0007e66f00,8)),'little')
  for m in[KMAP,IMAP]:
   b=bytearray(1024);struct.pack_into('<QQ',b,0x10,P,P+SIZE);struct.pack_into('<I',b,0x2c,14);struct.pack_into('<I',b,0x88,3);self.overlay(m,bytes(b),'Declared disjoint VM-map observation record, bounds/page shift/reference epoch; native allocation unknown')
  for a,b in[(HEADER,bytes(48)),(HEADER+48,b'\xa5'),(BACK,b'\xa5'*(c['length']+1)),(BACK+c['length']+1,b'\xa5'),(THREAD+0x428,struct.pack('<Q',KMAP)),(meta+((IMAP>>10)&0xffffffff0),struct.pack('<H',16)),(meta+((HEADER>>10)&0xffffffff0),struct.pack('<H',19))]:self.overlay(a,b,'Declared disjoint raw copy storage, current map and type-cell epoch')
  self.global_fixture(0xfffffe000caec2c0,struct.pack('<QQ',0xfffffe000caec2c0,ZSTATS),'Declared class19 allocation view identity/statistics pair; creation writer unknown');self.policy_initial=bytes(self.u.mem_read(0xfffffe0007e6a01c,4)).hex()if 0xfffffe0007e6a000 in self.pages else None;self.ensure(0xfffffe0007e6a01c,4);self.policy_initial=bytes(self.u.mem_read(0xfffffe0007e6a01c,4)).hex();assert self.policy_initial=='02000000'
 def vm_frame(self,a):
  self.vm_frames.append({'pc':hex(a),'source_visit_index':len(self.visits),'arguments8':[hex(self.reg(j))for j in range(8)],'SP':hex(self.u.reg_read(ar.UC_ARM64_REG_SP)),'copy48_hex':bytes(self.u.mem_read(HEADER,48)).hex(),'backing_hex':bytes(self.u.mem_read(BACK,self.c['length']+1)).hex(),'staging_hex':bytes(self.u.mem_read(STAGING,self.c['length']+1)).hex(),'published_pointer_hex':bytes(self.u.mem_read(self.vm_out,8)).hex()if self.vm_out else None})
 def code(self,u,a,n,d):
  self.flush()
  if a in[0xfffffe000a508e2c,0xfffffe000bdd1594,0xfffffe000bdd15a4,0xfffffe000bdd183c,0xfffffe000bdd1e94,0xfffffe000bdd1eb4,0xfffffe000bdd1ef8,0xfffffe000bdd1f38]or a==self.vm_return:self.vm_frame(a)
  if a in[0xfffffe000a508e2c,0xfffffe000bdd1f38,0xfffffe000bcf5e28]or a==self.vm_return:self.vm_handoffs.append({'pc':hex(a),'source_visit_index':len(self.visits),'registers31':[hex(self.reg(j))for j in range(31)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'NZCV':hex(u.reg_read(ar.UC_ARM64_REG_NZCV)),'Q_registers32':qregs(u),'private_RAM':compressed(bytes(u.mem_read(P,SIZE)))})
  if a==0xfffffe000bcfe5b8:
   self.vm_raw.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments4':[hex(self.reg(j))for j in range(4)],'returned_pointer':hex(BACK),'object_before_hex':bytes(u.mem_read(BACK,self.c['length']+1)).hex()});return self.model(a,'declared_raw_copy_backing_storage',BACK)
  if a==0xfffffe000bd75c64 and self.reg(0)==0xfffffe000caec2c0:
   self.vm_raw.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments4':[hex(self.reg(j))for j in range(4)],'returned_pointer':hex(HEADER),'object_before_hex':bytes(u.mem_read(HEADER,48)).hex()});return self.model(a,'declared_raw_copy_header_storage',HEADER)
  if a==0xfffffe000bdc2fc0:
   src,dst,count=self.reg(1),self.reg(2),self.reg(3);b=bytes(u.mem_read(src,count));self.vm_copies.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments5':[hex(self.reg(j))for j in range(5)],'source_hex':b.hex(),'destination_before_hex':bytes(u.mem_read(dst,count)).hex()});self.effect(dst,b,'Explicit lower map byte-copy primitive; no native map switch/protection/VM effect');return self.modeled(a,'declared_copyin_map_byte_effect',0)
  if a==0xfffffe000be318e8:return self.stop('before_original_request_entry_copy_lookup')
  if any(lo<=a<hi for lo,hi in self.kext_ranges):
   raw=bytes(u.mem_read(a,4));i=next(self.image.k.cs.disasm(raw,a))
   if i.mnemonic=='blraa'and self.reg(int(i.op_str.split(',')[0][1:]))==0xfffffe000a508e2c:
    rr=[int(v.strip()[1:])for v in i.op_str.split(',')];self.vm_return=a+4;self.vm_out=self.reg(4);self.edges.append({'pc':hex(a),'visit':len(self.visits),'kind':'blraa','target':'0xfffffe000a508e2c','modifier':hex(self.reg(rr[1]))});self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});self.calls.append({'pc':hex(a),'target':'0xfffffe000a508e2c','args8':[hex(self.reg(j))for j in range(8)]});self.set(30,a+4);u.reg_write(ar.UC_ARM64_REG_PC,0xfffffe000a508e2c);return
  return super().code(u,a,n,d)
 def run(self):
  r=super().run();r.update(kind='constructor_VM_copyin_RPC_request',VM_environment_overlay_start=self.setup_start,VM_copyin_frames=self.vm_frames,VM_full_CPU_RAM_handoffs=self.vm_handoffs,VM_raw_storage_contracts=self.vm_raw,VM_lower_copy_contracts=self.vm_copies,VM_actual_caller_return_PC=hex(self.vm_return)if self.vm_return else None,VM_copy_output_address=hex(self.vm_out)if self.vm_out else None,VM_final_copy48_hex=bytes(self.u.mem_read(HEADER,48)).hex(),VM_final_backing_hex=bytes(self.u.mem_read(BACK,self.c['length']+1)).hex(),VM_copy_guard_hex=bytes(self.u.mem_read(HEADER+48,1)).hex(),VM_backing_guard_hex=bytes(self.u.mem_read(BACK+self.c['length']+1,1)).hex(),VM_policy_initial_u32_bytes=self.policy_initial);return r

def main():
 im=Image();src=json.loads((ROOT/(PREFIX+'_source.json')).read_text());prior=json.loads((ROOT/'kernel_rpc_request_profiles.json').read_text());rows=[]
 for family,index in enumerate([4,10,15,21]):
  env=prior['environment'][index];assert env['family']==family;c=dict(prior['requests'][family]['configuration']);parent={'ram':decode(env['final_private_RAM']),'globals':env['final_image_globals']};r=Probe(im,src,c,parent,{'path':'kernel_rpc_request_profiles.json','environment':index}).run();r['family']=family;rows.append(r);print(json.dumps({'case':family,'visits':len(r['source_visits']),'boundary':r['boundary']['pc'],'copy48':r['VM_final_copy48_hex'],'VM_return':r['VM_actual_caller_return_PC']}),flush=True)
 deps=[PREFIX+'_source.json','kernel_rpc_request_profiles.json','probe_kernel_rpc_request.py','probe_kext_constructor_request.py','probe_kernel_vm_mig.py','probe_rpc502_vm_handoff.py','kernel_vm_mig_tools.py'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'cases':rows,**{k:False for k in FLAGS}};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
