#!/usr/bin/env python3
"""Original cursor initialization, encoded candidate lookup and type2 range walk.
Private map/packed-store geometry, position resolver and lower VM/locks are
premises. O(visits+RAM+effects), O(RAM+journals). No native mappings or rights.
"""
import json,struct
from unicorn import arm64_const as ar
from probe_rpc502_vm_handoff import Probe as Parent,P,SIZE,SP,HALT,MAP,THREAD
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
PREFIX='kernel_vm_range_cursor';CUR=P+0xa0000;LOOKOUT=P+0xa1000;SENTINEL=P+0xa2000;START=P+0x50000;END=P+0x5c000;KBASE=0xfffffe0000000000;ENTRY=KBASE+0x1000000;PAGE=KBASE+0x2000000;HANDLE=0x20000;EID=0x40000;MARKER=0xfffffe000cb0bf18;VMOBJ=P+0xa4000;CBGLOBAL=0xfffffe000cae4e58;CALLBACK=0xfffffe000bdd2750;AUX_REGIONS=[(ENTRY,4096),(PAGE,4096)]
class Probe(Parent):
 def __init__(self,im,c,src,seed):
  self.aux_regions=AUX_REGIONS;super().__init__(im,{'stage':'copyin'},src,seed);self.c.update(c);self.stage=c['stage'];self.cursor_frames=[];self.position_frames=[];self.lock_frames=[];self.callback_frames=[];self.cursor_returns=[];self.edges=[];self.callback_binding=src['range_callback']['pointer'];self.current_cursor=CUR
  self.fixture(THREAD+0x238,struct.pack('<Q',SENTINEL));self.fixture(CUR,b'\xa5'*128);self.fixture(LOOKOUT,b'\xa5'*8);self.fixture(MAP+0x58,struct.pack('<Q',{'null':0,'marker':MARKER,'other':P+0xa3000}[c.get('associated','null')]));self.fixture(MAP+0x2c,bytes([c.get('page_shift',14)]))
  if self.stage in['lookup','type2','callback']:
   b=bytearray(64);struct.pack_into('<I',b,0,0x10000);struct.pack_into('<QQ',b,0x10,START,END);struct.pack_into('<I',b,0x38,0x100);self.fixture(ENTRY,bytes(b));self.fixture(PAGE,struct.pack('<HI',1,0)+bytes(4090));self.fixture(PAGE+0xa8,struct.pack('<I',0 if c.get('empty_store')else EID))
  if self.stage=='init':self.entry=0xfffffe000be31808;args=[CUR,MAP,c['start'],c['end'],c['flags']]
  elif self.stage=='callback':
   self.fixture(VMOBJ,bytes(128));self.fixture(VMOBJ+0x68,struct.pack('<I',c['object_class']));self.fixture(ENTRY+0x28,struct.pack('<Q',0 if c.get('null_object')else VMOBJ));self.fixture(ENTRY+0x38,struct.pack('<I',8 if c['entry_bit3']else 0));self.fixture(CUR+0x10,struct.pack('<Q',0 if c['map_kind']=='null'else MAP));self.fixture(MAP+0x2c,bytes([12 if c['map_kind']=='page12'else 14]));self.image_fixture(CBGLOBAL,struct.pack('<I',c['global_flag']),'Declared callback global epoch; native value unknown');self.entry=CALLBACK;args=[0xfffffe0007e6a140,CUR,ENTRY]
  elif self.stage=='lookup':self.entry=0xfffffe000bdc7274;args=[MAP,c['address'],LOOKOUT]
  else:assert self.stage=='type2';args=None
  if args is not None:
   for j in range(31):self.set(j,0)
   for j,x in enumerate(args):self.set(j,x)
   self.set(30,HALT);self.u.reg_write(ar.UC_ARM64_REG_SP,SP)
  self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))
 def ensure(self,a,n=1):
  for pg in range(a&~4095,((a+n-1)&~4095)+4096,4096):
   if any(lo<=pg<lo+size for lo,size in self.aux_regions):
    if pg not in self.pages:self.u.mem_map(pg,4096);self.u.mem_write(pg,bytes(4096));self.pages.add(pg)
   else:super().ensure(pg,1)
 def fixture(self,a,b):self.ensure(a,max(1,len(b)));return super().fixture(a,b)
 def write(self,u,t,a,n,v,d):
  if any(lo<=a<a+n<=lo+size for lo,size in self.aux_regions):
   e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e);return
  return super().write(u,t,a,n,v,d)
 def code(self,u,a,n,d):
  self.flush()
  if a==CALLBACK:self.callback_frames.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments':[hex(self.reg(j))for j in range(3)]})
  if a in[0xfffffe000bdd17a4,0xfffffe000bdd17b8]:self.cursor_returns.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments':[hex(self.reg(0))],'cursor128_hex':bytes(u.mem_read(self.current_cursor,128)).hex(),'thread_active_cursor':hex(int.from_bytes(bytes(u.mem_read(THREAD+0x238,8)),'little'))})
  if a in[0xfffffe000be31808,0xfffffe000be318e8,0xfffffe000be3218c,0xfffffe000be33a44,0xfffffe000bdd20d8,0xfffffe000bdd21fc]:
   count=5 if a in[0xfffffe000be31808,0xfffffe000be318e8,0xfffffe000be3218c]else 2 if a==0xfffffe000be33a44 else 4;self.cursor_frames.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments':[hex(self.reg(j))for j in range(count)],'cursor128_hex':bytes(u.mem_read(self.reg(0),128)).hex()});self.current_cursor=self.reg(0)
   if a==0xfffffe000bdd21fc:return self.stop('before_entry_clone_body')
  if a==0xfffffe000bd0944c:self.lock_frames.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments':[hex(self.reg(0))]});return self.model(a,'declared_range_read_unlock_no_effect',0)
  if a==0xfffffe000bddd5dc:self.position_frames.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments':[hex(self.reg(j))for j in range(2)]});return self.model(a,'declared_packed_store_position_model',HANDLE)
  if a==0xfffffe000be318e8:return self.source_instruction(a)
  if any(lo<=a<hi for lo,hi in self.allowed):
   ins=next(self.image.k.cs.disasm(bytes(u.mem_read(a,4)),a))
   if ins.mnemonic=='blraa':
    x,y=[int(v.strip()[1:])for v in ins.op_str.split(',')];target,modifier=self.reg(x),self.reg(y)
    if target==int(self.callback_binding['target'],16)and modifier==int(self.callback_binding['slot'],16):
     self.edges.append({'pc':hex(a),'source_visit_index':len(self.visits),'target':hex(target),'modifier':hex(modifier)});self.visits.append({'pc':hex(a),'bytes_hex':bytes(u.mem_read(a,4)).hex()});self.set(30,a+4);u.reg_write(ar.UC_ARM64_REG_PC,target);return
   if ins.mnemonic in['brk','blraa']:return self.stop('before_original_assertion'if ins.mnemonic=='brk'else'before_indirect_call',{'mnemonic':ins.mnemonic,'operands':ins.op_str,'registers18':[hex(self.reg(j))for j in range(18)]})
  return super().code(u,a,n,d)
 def source_instruction(self,a):
  raw=bytes(self.u.mem_read(a,4));assert raw==self.image.k.read(a,4)and next(self.image.k.cs.disasm(raw,a)).mnemonic=='pacibsp';self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});self.u.reg_write(ar.UC_ARM64_REG_PC,a+4)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=60000);self.flush();assert self.reason in['returned','before_entry_clone_body','before_original_assertion','before_indirect_call'],self.boundary;return self.collect()
 def collect(self):
  from probe_rpc502_vm_handoff import compressed
  addresses=list(dict.fromkeys((int(e['address'],16),len(e['bytes_hex'])//2)for e in self.image_initial))
  return {'configuration':self.c,'kind':'body','entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_registers31':self.entry_regs,'entry_NZCV':self.entry_NZCV,'private_RAM':{'address':hex(P),'size_bytes':SIZE,'initial_byte':0},'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,'initial_private_RAM_transfer':None,'private_auxiliary_regions':[{'address':hex(a),'size_bytes':n,'initial_byte':0}for a,n in self.aux_regions],'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'declared_effects':self.effects,'logical_data_authentication':self.auth,'logical_data_signing':self.sign,'VM_copyin_entries':self.cuts,'private_system_register_fixtures':self.sysregs,'VM_handoff_frames':self.frames,'map_context_frames':self.contexts,'cursor_frames':self.cursor_frames,'position_frames':self.position_frames,'range_lock_frames':self.lock_frames,'callback_frames':self.callback_frames,'cursor_return_frames':self.cursor_returns,'logical_indirect_edges':self.edges,'final_private_RAM':compressed(bytes(self.u.mem_read(P,SIZE))),'final_auxiliary_regions':[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()}for a,n in self.aux_regions if a in self.pages],'final_image_globals':[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()}for a,n in addresses],'cursor_address':hex(self.current_cursor),'cursor128_hex':bytes(self.u.mem_read(self.current_cursor,128)).hex(),'thread_active_cursor':hex(int.from_bytes(bytes(self.u.mem_read(THREAD+0x238,8)),'little')),'thread_entry_nesting':int.from_bytes(bytes(self.u.mem_read(THREAD+0x22c,4)),'little'),'entry_lock_word':None if ENTRY not in self.pages else int.from_bytes(bytes(self.u.mem_read(ENTRY,4)),'little'),'lookup_output':hex(int.from_bytes(bytes(self.u.mem_read(LOOKOUT,8)),'little')),'boundary':self.boundary,'raw_return_u32':self.reg(0)&0xffffffff,'native_target_executed':False,'native_VM_effects_executed':False,'native_IPC_executed':False,'native_retirement_executed':False,'native_namespace_conversion_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'complete_FairPlay_round_trip_established':False,'full_goal_complete':False}

def main():
 im=Image();src=json.loads((ROOT/(PREFIX+'_source.json')).read_text());seed=json.loads((ROOT/'rpc502_reply_copyin_profiles.json').read_text())['cases'][42];rows=[];pairs=[(START,END),(P,P+SIZE),(START,START),(END,START),(P-4,START),(START,P+SIZE+4)];configs=[{'stage':'init','start':a,'end':b,'flags':f}for f in[0x40019,0x42015]for a,b in pairs]+[{'stage':'init','start':START,'end':END,'flags':0x40019,'associated':v}for v in['null','marker','other']]+[{'stage':'init','start':0,'end':0,'flags':0x1000,'page_shift':p}for p in[12,14]]+[{'stage':'lookup','address':a}for a in[START-1,START,END-1,END]]+[{'stage':'lookup','address':START,'empty_store':True}]+[{'stage':'type2','empty_store':v}for v in[True,False]]
 configs +=[{'stage':'callback','object_class':4,'entry_bit3':b,'global_flag':g,'map_kind':m}for g in[0,1]for m in['null','page12','page14']for b in[False,True]]+[{'stage':'callback','object_class':3,'entry_bit3':False,'global_flag':0,'map_kind':'page14'},{'stage':'callback','object_class':4,'entry_bit3':False,'global_flag':0,'map_kind':'page14','null_object':True}]
 for c in configs:
  r=Probe(im,c,src,seed).run();rows.append(r);print(json.dumps({'case':len(rows)-1,'configuration':c,'boundary':r['boundary'],'visits':len(r['source_visits'])}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[PREFIX+'_source.json','rpc502_reply_copyin_profiles.json','probe_rpc502_vm_handoff.py','probe_rpc502_reply_copyin.py','probe_kernel_vm_mig.py','kernel_vm_mig_tools.py']},'cases':rows,'native_target_executed':False,'native_VM_effects_executed':False,'native_IPC_executed':False,'native_retirement_executed':False,'native_namespace_conversion_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'complete_FairPlay_round_trip_established':False,'full_goal_complete':False};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
