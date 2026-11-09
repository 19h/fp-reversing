#!/usr/bin/env python3
"""Original special-space bootstrap -> bound kernel reply port -> linkage/copyout.
O(image+visits+RAM+effects), O(image+RAM+journals). Raw storage/results, separate
startup/call/CPU epochs, packet representation and logical PAC remain declared.
No native namespace, bootstrap, IPC, VM, scheduling or allocator retirement.
"""
import json,struct
from unicorn import arm64_const as ar
from probe_kernel_reply_namespace import Probe as Parent,RECV,PORT,SPACE,TABLE,REPLY,TASK,OWNER,KMSG,MAP,OUT,PSP
from probe_kernel_zone_startup import Probe as ZoneParent,ARRAY
from probe_kernel_vm_mig import P,SIZE,HALT
from probe_rpc502_vm_handoff import compressed,decode
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
PREFIX='kernel_special_reply';KTHREAD=P+0x2c000;KSPACE=P+0x54000;RSPACE=P+0x54100;SNDTS=P+0xa8040;CLIENT_TASK=P+0x987c0;RECEIVER_OWNER=P+0x70000;TASK_RECORD=P+0x5c000;BOOT=0xfffffe000c629780;CREATE=0xfffffe000bcf8e14;LINK=0xfffffe000bccef30;PREPARE=0xfffffe000bcced98;COMPLETE=0xfffffe000bcceadc;ADJUST=0xfffffe000bcce5b8;UNBIND=0xfffffe000bcf837c;DESTROY=0xfffffe000bccdbb4
CONFIGS=[{'case':'unlinked','constructor_case':1},{'case':'first_link','constructor_case':1},{'case':'shared_link','constructor_case':1},{'case':'bootstrap_link_reset','constructor_case':17},{'case':'unbind','constructor_case':1},{'case':'replace','constructor_case':1}]
class Zone(ZoneParent):
 def __init__(self,im,c,src,entry):
  self.selected_stats=c['storage_base'];self.selected_cache=c['storage_base']+0x1000;self.selected_magazines=c['storage_base']+0x2000;super().__init__(im,c,src,entry)
  if entry['identifier_u16']==0xffff:self.image_fixture(0xfffffe0007e5c470,bytes(8),'Declared unpublished ipc-space zone epoch; original callback writes publication')
 def image_fixture(self,a,b,why):
  if self.ident==0xffff and a==self.zone:self.ident=40;self.zone=ARRAY+192*40;a=self.zone
  return super().image_fixture(a,b,why)
 def write(self,u,t,a,n,v,d):
  if a==0xfffffe0007e5c470 and n==8:
   e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e);return
  return super().write(u,t,a,n,v,d)
 def code(self,u,a,n,d):
  self.flush()
  if a==0xfffffe000bd71a20:
   assert self.reg(0)==0xfffffe000caeb600 and(self.reg(1),self.reg(2))in[(32,7),(64,0x3f)];return self.model(a,'declared_raw_percpu_statistics_storage'if self.reg(1)==32 else'declared_raw_percpu_cache_storage',self.selected_stats if self.reg(1)==32 else self.selected_cache)
  if a==0xfffffe000bd75c64:
   index=len(self.magazines);ptr=self.selected_magazines+index*0x100;assert self.reg(0)==P+0x8a000 and self.reg(1)==P+0x8b000 and self.reg(2)==0x8004;self.magazines.append({'index':index,'pointer':hex(ptr)});return self.model(a,'declared_raw_magazine_storage',ptr)
  return super().code(u,a,n,d)
 def run(self):
  r=super().run();r['requested_identifier_u16']=self.catalog_entry['identifier_u16'];r['final_statistics32_hex']=bytes(self.u.mem_read(self.selected_stats,32)).hex();r['final_cache_instances64_hex']=[bytes(self.u.mem_read(self.selected_cache,64)).hex()];r['selected_statistics_address']=hex(self.selected_stats);r['selected_cache_address']=hex(self.selected_cache);regions=[(self.selected_stats,32,'original statistics record')]+([(self.selected_cache,64,'original cache record')]if int.from_bytes(bytes.fromhex(r['final_zone192_hex'])[0x40:0x48],'little')else[])+[(int(e['pointer'],16),144,'declared 144-byte magazine observation extent; native allocator extent unknown')for e in self.magazines];r['source_private_regions']=[{'address':hex(a),'size_bytes':n,'bytes_hex':bytes(self.u.mem_read(a,n)).hex(),'role':role}for a,n,role in regions]
  r['published_space_zone_pointer']=hex(int.from_bytes(bytes(self.u.mem_read(0xfffffe0007e5c470,8)),'little'))if self.catalog_entry['identifier_u16']==0xffff else None;return r
WATCH=[0xfffffe000c2ba130,BOOT,0xfffffe000c62982c,CREATE,0xfffffe000bcf8ea8,0xfffffe000bcf8ef4,PREPARE,LINK,0xfffffe000bccf01c,ADJUST,0xfffffe000bcce9c8,COMPLETE,0xfffffe000bcceb64,0xfffffe000bd68428,0xfffffe000bd68450,0xfffffe000bd7deec,UNBIND,DESTROY]
class Probe(Parent):
 def __init__(self,im,src,c,kind,parent,origin,packet,raw,zones):
  nc={'index':2,'old_bits':0,'constructor_case':c['constructor_case']};super().__init__(im,src,nc,'header'if kind=='header'else'reply_unlock',parent,origin,packet,raw);self.kind=kind;self.c={**nc,**c};self.current=RECV if kind=='header'else KTHREAD;self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,self.current);self.special_frames=[];self.allocations=[];self.retirements=[];self.regional_imports=[];self.zone_imports=[];self.model_allocations=0
  if kind=='space_bootstrap':
   meta=int.from_bytes(bytes(self.u.mem_read(0xfffffe0007e66f00,8)),'little')
   for a,b in[(KSPACE,bytes(128)),(RSPACE,bytes(128)),(SNDTS,bytes(96)),(SNDTS+96,b'\xa5'),(meta+((SNDTS>>10)&0xffffffff0),struct.pack('<H',28)),(CLIENT_TASK-0x7c0,bytes(0xe90)),(RECEIVER_OWNER+0x28,struct.pack('<Q',CLIENT_TASK)),(SPACE+0x50,struct.pack('<Q',CLIENT_TASK)),(CLIENT_TASK+0x318,struct.pack('<Q',SPACE)),(meta+(((CLIENT_TASK-0x7c0)>>10)&0xffffffff0),struct.pack('<H',26)),(meta+((KSPACE>>10)&0xffffffff0),struct.pack('<H',40)),(meta+((SPACE>>10)&0xffffffff0),struct.pack('<H',40)),(CLIENT_TASK-0x7c0+0x60,struct.pack('<I',4242)),(TASK_RECORD,bytes(32)),(TASK_RECORD+0x18,struct.pack('<I',77)),(CLIENT_TASK+0x320,struct.pack('<Q',TASK_RECORD)),(CLIENT_TASK+0x6c8,struct.pack('<I',int(c['case']!='shared_link')))]:self.overlay(a,b,'Declared raw special-space/turnstile storage and typed NULL-BSD-task epoch')
   for j,z in enumerate(zones):
    for e in z['source_private_regions']:
     a=int(e['address'],16);b=bytes.fromhex(e['bytes_hex']);self.overlay(a,b,'Exact original zone-producer private record import');self.regional_imports.append({'producer':j,**e})
    a=int(z['zone_address'],16);b=bytes.fromhex(z['final_zone192_hex']);self.global_overlay(a,b,'Exact original complete 192-byte zone-record import; allocator lifetime not joined');self.zone_imports.append({'producer':j,'address':hex(a),'bytes192_hex':b.hex()})
   self.global_overlay(0xfffffe0007e5c470,bytes.fromhex(zones[2]['published_space_zone_pointer'][2:].zfill(16))[::-1],'Exact original dynamic zone callback publication')
   self.global_overlay(0xfffffe0007e63348,im.k.read(0xfffffe0007e63348,8),'Original file-zero reply-space publication epoch')
  for j in range(31):self.set(j,0)
  self.set(30,HALT)
  if kind=='space_bootstrap':self.entry=BOOT;args=[]
  elif kind in ['create','replace']:self.entry=CREATE;args=[]
  elif kind=='make_send_once':self.entry=0xfffffe000bcd0694;args=[REPLY]
  elif kind=='prepare_outer_hold':self.entry=PREPARE;args=[PORT]
  elif kind=='link':self.entry=LINK;args=[REPLY,PORT,int(c['case']=='bootstrap_link_reset')]
  elif kind=='header':self.entry=0xfffffe000bcc4e98;args=[KMSG,SPACE,MAP,0x07000002]
  elif kind in ['drop_outer_hold']:self.entry=COMPLETE;args=[PORT]
  elif kind=='reply_lock':self.entry=0xfffffe000bccc128;args=[REPLY]
  elif kind=='allow_linkage':self.entry=ADJUST;args=[REPLY,0,1,0]
  elif kind=='unbind':self.entry=UNBIND;args=[KTHREAD]
  else:raise AssertionError(kind)
  for j,v in enumerate(args):self.set(j,v)
  self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV));self.entryQ=[hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))))for j in range(32)]
 def global_overlay(self,a,b,why):
  super().global_overlay(a,b,why)
  for e in self.image_initial:
   at=int(e['address'],16);size=len(e['bytes_hex'])//2
   if max(a,at)<min(a+len(b),at+size):e['bytes_hex']=bytes(self.u.mem_read(at,size)).hex()
 def write(self,u,t,a,n,v,d):
  if a in[0xfffffe0007e62b68,0xfffffe0007e63348]and n==8:
   e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e);return
  return super().write(u,t,a,n,v,d)
 def code(self,u,a,n,d):
  self.flush()
  if a in WATCH:self.special_frames.append({'pc':hex(a),'source_visit_index':len(self.visits),'arguments8':[hex(self.reg(j))for j in range(8)],'port144_hex':bytes(u.mem_read(PORT,144)).hex(),'reply144_hex':bytes(u.mem_read(REPLY,144)).hex(),'send_turnstile96_hex':bytes(u.mem_read(SNDTS,96)).hex(),'kernel_thread1536_hex':bytes(u.mem_read(KTHREAD,1536)).hex(),'receiver1536_hex':bytes(u.mem_read(RECV,1536)).hex(),'kernel_space128_hex':bytes(u.mem_read(KSPACE,128)).hex(),'reply_space128_hex':bytes(u.mem_read(RSPACE,128)).hex()})
  if a==0xfffffe000c62982c and self.kind=='space_bootstrap':return self.stop('before_unrelated_bootstrap_kernel_object')
  if a==DESTROY:return self.stop('before_original_bound_port_destruction')
  if a==0xfffffe000bd75c64:
   if self.kind=='space_bootstrap':ret=[KSPACE,RSPACE][self.model_allocations];self.model_allocations+=1;symbol='declared_zeroed_raw_special_space_storage'
   elif self.kind=='create':ret=REPLY;symbol='declared_zeroed_raw_kernel_reply_port_storage'
   else:ret=SNDTS;symbol='declared_zeroed_raw_send_turnstile_storage'
   self.allocations.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments4':[hex(self.reg(j))for j in range(4)],'returned_pointer':hex(ret),'object_before_hex':bytes(u.mem_read(ret,128 if self.kind=='space_bootstrap'else 144 if self.kind=='create'else 96)).hex()});return self.model(a,symbol,ret)
  if a==0xfffffe000bd74fcc:self.retirements.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments4':[hex(self.reg(j))for j in range(4)],'turnstile96_hex':bytes(u.mem_read(SNDTS,96)).hex(),'guard_byte_hex':bytes(u.mem_read(SNDTS+96,1)).hex()});return self.model(a,'declared_raw_send_turnstile_retirement',0)
  return super().code(u,a,n,d)
 def run(self):
  try:r=super().run()
  except Exception:
   print({'failed_kind':self.kind,'pc':hex(self.u.reg_read(ar.UC_ARM64_REG_PC)),'boundary':self.boundary,'arguments8':[hex(self.reg(j))for j in range(8)]},flush=True);raise
  r.update(current_thread=hex(self.current),special_reply_frames=self.special_frames,raw_storage_contracts=self.allocations,raw_retirement_contracts=self.retirements,zone_record_imports=self.zone_imports,zone_private_record_imports=self.regional_imports,final_kernel_thread1536_hex=bytes(self.u.mem_read(KTHREAD,1536)).hex(),final_receiver1536_hex=bytes(self.u.mem_read(RECV,1536)).hex(),final_send_turnstile96_hex=bytes(self.u.mem_read(SNDTS,96)).hex(),final_send_turnstile_guard_hex=bytes(self.u.mem_read(SNDTS+96,1)).hex(),final_kernel_space128_hex=bytes(self.u.mem_read(KSPACE,128)).hex(),final_reply_space128_hex=bytes(self.u.mem_read(RSPACE,128)).hex(),final_current_nesting=int.from_bytes(bytes(self.u.mem_read(self.current+0x1c8,4)),'little'));return r
def main():
 im=Image();src=json.loads((ROOT/(PREFIX+'_source.json')).read_text());zs=json.loads((ROOT/'kernel_zone_startup_source.json').read_text());zones=[]
 for name,base in [('ipc ports',P+0x40000),('turnstiles',P+0x44000),('ipc spaces',P+0x48000)]:
  e=next(e for e in src['special_zone_entries']if e['name']==name);c={'identifier':e['identifier_u16'],'storage_base':base};z=Zone(im,c,zs,e).run();assert z['boundary']['kind']=='startup_callback_returned',z['boundary'];zones.append(z);print(json.dumps({'zone':name,'actual_identifier':z['identifier'],'visits':len(z['source_visits']),'boundary':z['boundary']['kind']}),flush=True)
 prior=json.loads((ROOT/'kernel_reply_namespace_profiles.json').read_text());cp=json.loads((ROOT/'kernel_receive_copyout_profiles.json').read_text());ctors=json.loads((ROOT/'kext_constructor_request_profiles.json').read_text());raw=decode(cp['consumers'][0]['final_private_RAM'])[0xd0000:0xd0100];rows=[]
 for family,c in enumerate(CONFIGS):
  parent={'ram':decode(prior['cases'][1]['final_private_RAM']),'globals':prior['cases'][1]['final_image_globals']};origin={'path':'kernel_reply_namespace_profiles.json','case':1};packet=bytes.fromhex(ctors['cases'][c['constructor_case']]['message88_hex']);kinds=['space_bootstrap','create','make_send_once']
  if c['case']=='shared_link':kinds.append('prepare_outer_hold')
  if c['case']!='unlinked':kinds.append('link')
  kinds.append('header')
  if c['case']=='shared_link':kinds.append('drop_outer_hold')
  if c['case']=='bootstrap_link_reset':kinds+=['reply_lock','allow_linkage']
  if c['case']in ['unbind','replace']:kinds.append(c['case'])
  for kind in kinds:
   r=Probe(im,src,c,kind,parent,origin,packet,raw,zones).run();r['family']=family;rows.append(r);parent={'ram':decode(r['final_private_RAM']),'globals':r['final_image_globals']};origin={'path':PREFIX+'_profiles.json','case':len(rows)-1};print(json.dumps({'case':len(rows)-1,'family':family,'kind':kind,'visits':len(r['source_visits']),'boundary':r['boundary']['kind'],'pc':r['boundary']['pc']}),flush=True)
   assert r['boundary']['kind']in ['before_unrelated_bootstrap_kernel_object','original_component_returned','before_original_descriptor_copyout','before_original_bound_port_destruction'],r['boundary']
 deps=[PREFIX+'_source.json','kernel_reply_namespace_profiles.json','kernel_zone_startup_source.json','kernel_receive_copyout_profiles.json','kext_constructor_request_profiles.json','probe_kernel_reply_namespace.py','probe_kernel_zone_startup.py','probe_kernel_vm_mig.py','probe_rpc502_vm_handoff.py','kernel_vm_mig_tools.py'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'zone_producers':zones,'cases':rows,**{k:False for k in FLAGS}};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
