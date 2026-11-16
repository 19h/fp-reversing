#!/usr/bin/env python3
"""Continuous original main and phase-one callbacks to UUID formatter call.
O(visits+journals+mapped bytes+callback outputs) time/space. No new return model.
"""
import json,struct
from hashlib import sha256
from unicorn import arm64_const as ar
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read
from probe_rpc502_vm_handoff import compressed
from probe_kernel_vm_mig import Probe as Core,P,SIZE,SP
import probe_kernel_startup_registry_abi as B
import recover_kernel_tunable_batch_execution as R
NEW_APIS=[t for t in R.PHASE1 if t!=R.B.TUNABLE]+[R.UUID]

def merge(regions):
 out=[]
 for a,n in sorted(regions):
  if out and a<=out[-1][0]+out[-1][1]:p,m=out.pop();out.append((p,max(p+m,a+n)-p))
  else:out.append((a,n))
 return out

def complement(wanted,existing):
 out=[]
 for a,n in merge(wanted):
  spans=[(a,a+n)]
  for lo,m in merge(existing):
   spans=[q for p,z in spans for q in ([(p,min(z,lo))] if p<lo<z else [])+([(max(p,lo+m),z)] if p<lo+m<z else [])+([(p,z)] if z<=lo or p>=lo+m else [])]
  out += [(p,z-p) for p,z in spans if p<z]
 return out

class Probe(B.Probe):
 def __init__(self,image,c,mutate=None):
  super().__init__(image,c);self.mutate=mutate;self.first_boundary=None;self.callback_entries=[];self.callback_returns=[];self.current_callback=None
  self.e=json.loads(read(ROOT/(R.P+'_checks.json')));self.options={int(o['descriptor'],16):o for o in self.e['option_descriptors']};self.pointer_args={int(o['slot'],16):o for o in self.e['per_CPU_pointer_arguments']};self.indexed={int(o['descriptor'],16):o for o in self.e['indexed_descriptors']};self.tree_options={int(o['descriptor'],16):o for o in json.loads(read(ROOT/(R.B.P+'_checks.json')))['tunable_descriptors']}
  desired=[*R.GLOBAL_REGIONS,*[(int(o['destination_pointer']['target'],16),o['size_bytes']) for o in self.options.values()],*[(a,8) for a in self.pointer_args],*[(int(r['argument_pointer']['target'],16)+0x10,8) for r in json.loads(read(ROOT/(R.B.P+'_checks.json')))['registry']['entries'] if int(r['callback_pointer']['target'],16)==0xfffffe000c62f35c]]
  self.phase_regions=complement(desired,self.regions);self.regions+=self.phase_regions
  for a,n in self.phase_regions:
   raw=b''.join(image.logical_page(pg) for pg in range(a&~4095,(a+n+4095)&~4095,4096));off=a&4095;self.image_fixture(a,raw[off:off+n],'Original logical phase-one descriptor destinations before main entry; native lifetime unknown')
  self.allowed=[(int(f['start'],16),int(f['end'],16)) for f in self.e['functions']];self.before=bytes(self.u.mem_read(P,SIZE));self.initial_pages={pg:bytes(self.u.mem_read(pg,4096)) for pg in self.pages}
  if mutate is not None:self.ensure(mutate,4);self.u.mem_write(mutate,bytes.fromhex('1f2003d5'))
 def full_snapshot(self,a):
  row=super().full_snapshot(a);row['phase_one_image_globals']=[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()} for a,n in self.phase_regions];return row
 def outputs(self,target,arg):
  if target==R.OPTION:o=self.options[arg];return [(int(o['destination_pointer']['target'],16),o['size_bytes'])]
  if target==R.B.TUNABLE:
   o=self.tree_options[arg];return [(int(o['destination'],16),o['size_bytes'])]
  if target==R.ADJUST:return [(arg,8)]
  if target==R.INDEXED:return [(0xfffffe000cadce28+96*self.indexed[arg]['selector_u32'],96)]
  return {R.TIMER:[(0xfffffe000cb62e78,4),(0xfffffe000cb62e80,8)],R.CHOSEN:[(0xfffffe0007ef8e68,2)],R.POLICY:[(0xfffffe0007f12c60,4)],R.TRACE_CONFIG:[(0xfffffe0007f19d90,4),(0xfffffe000cb29c18,8),(0xfffffe000cb2a71c,4),(0xfffffe000cb29df0,259),(0xfffffe000cb29ef4,259),(0xfffffe000cb29ff8,259)],R.WATCHDOG:[(0xfffffe000ca92374,4),(0xfffffe0007e66e28,4)]}.get(target,[])
 def code(self,u,a,n,d):
  self.flush()
  while self.active and self.entries[self.active[-1]]['return_PC']==hex(a) and self.entries[self.active[-1]]['entry_SP']==hex(u.reg_read(ar.UC_ARM64_REG_SP)):
   self.returns.append({'entry_index':self.active.pop(),'before_visit':len(self.visits),'return_value':hex(self.reg(0))})
  if a==R.STOP:return self.stop('before_original_UUID_formatter_call')
  if a==0xfffffe000c630370:
   target,arg=self.reg(8),self.reg(0);cursor=int.from_bytes(u.mem_read(R.B.CURSOR,8),'little');phase,rank,stored,argument=struct.unpack('<IIQQ',u.mem_read(cursor,24));index=(cursor-R.B.BASE)//24
   assert target in R.PHASE1 and phase==1 and stored==target and argument==arg and self.reg(17)==0x2abe
   row={'before_visit':len(self.visits),'sorted_index':index,'cursor':hex(cursor),'phase_u32':phase,'rank_u32':rank,'target':hex(target),'argument':hex(arg),'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'thread':hex(self.system['tpidr_el1'])};self.callback_entries.append(row);self.current_callback=row
   if index==0:return super().code(u,a,n,d)
   raw=bytes(u.mem_read(a,4));assert raw==self.image.k.read(a,4);i=next(self.image.k.cs.disasm(raw,a));assert i.mnemonic=='blraa' and i.op_str=='x8, x17'
   self.logical.append({'PC':hex(a),'kind':'blraa','scope':'original_registry_callback','operands':i.op_str,'before_visit':len(self.visits),'system_before':dict(self.system),'system_after':dict(self.system),'target':hex(target),'modifier_X17':hex(self.reg(17)),'argument_X0':hex(arg)});self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});self.set(30,a+4);u.reg_write(ar.UC_ARM64_REG_PC,target);return
  if a==0xfffffe000c630374:
   c=self.current_callback;assert c and c['SP']==hex(u.reg_read(ar.UC_ARM64_REG_SP));target,arg=int(c['target'],16),int(c['argument'],16)
   self.callback_returns.append({'sorted_index':c['sorted_index'],'before_visit':len(self.visits),'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'observed_regions':[{'address':hex(p),'bytes_hex':bytes(u.mem_read(p,m)).hex()} for p,m in self.outputs(target,arg)]});self.current_callback=None
   if c['sorted_index']!=0:return Core.code(self,u,a,n,d)
  if a==0xfffffe000c63037c:
   if self.first_boundary is None:
    self.first_boundary=self.full_snapshot(a);self.first_boundary['mapped_page_sha256']={hex(pg):sha256(bytes(u.mem_read(pg,4096))).hexdigest() for pg in sorted(self.pages)}
   return Core.code(self,u,a,n,d)
  if a in NEW_APIS:
   self.active.append(len(self.entries));self.entries.append({'PC':hex(a),'entry_SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'arguments6':[hex(self.reg(j)) for j in range(6)],'return_PC':hex(self.reg(30)),'before_visit':len(self.visits)})
  return super().code(u,a,n,d)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=3000000);self.flush();assert self.reason is not None,self.boundary
  return {'configuration':self.c,'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_NZCV':self.entry_NZCV,'entry_registers31':self.entry_regs,'initial_vectors':['0x0']*32,'initial_system':B.INITIAL_SYSTEM,'final_system':self.system,'private_RAM':{'address':hex(P),'size_bytes':SIZE,'initial_byte':0},'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,'initial_private_RAM':compressed(self.before),'final_private_RAM':compressed(bytes(self.u.mem_read(P,SIZE))),'initial_image_pages':[{'address':hex(pg),'bytes_hex':raw.hex()} for pg,raw in sorted(self.initial_pages.items())],'final_image_globals':[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()} for a,n in self.regions],'final_page_sha256':{hex(pg):sha256(bytes(self.u.mem_read(pg,4096))).hexdigest() for pg in sorted(self.pages)},'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'logical_effects':self.logical,'original_call_entries':self.events,'original_API_entries':self.entries,'original_API_returns':self.returns,'unfinished_API_entry_indices':self.active,'prefix_checkpoint':self.prefix,'original_platform_return':self.platform_return,'pre_enumeration_checkpoint':self.join,'original_enumeration_return':self.enumerated,'original_post_helper_return':self.post,'declared_selector0e_calls':self.wrapper,'bootstrap_state_checkpoint':self.bootstrap,'sort_entry_checkpoint':self.sort_entry,'dispatch_entry_checkpoint':self.dispatch_entry,'first_callback_dispatch_checkpoint':self.callback_dispatch,'first_callback_return_checkpoint':self.callback_return,'first_callback_boundary':self.first_boundary,'callback_entries':self.callback_entries,'callback_returns':self.callback_returns,'fixture_extent_bytes':len(self.blob),'fixture_node_addresses':{k:hex(v) for k,v in self.nodes.items()},'final_vectors':[hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j)))) for j in range(32)],'boundary':self.boundary,'source_word_mutated_to_NOP':hex(self.mutate) if self.mutate else None,**{n:False for n in R.FALSE}}

def cases():
 return [{'label':'continuous_default_phase_one_batch','CPUs':[{}],'boot_text':''},
 {'label':'numeric_boolean_and_string_options','CPUs':[{}],'boot_text':'thid_should_crash=2 bootprofile_type=xyz nbuf=17'},
 {'label':'selected_CPU_ordinal1_and_chosen_property','CPUs':[{'state':'stopped'},{'state':'running'}],'boot_text':'','chosen':{'kernel-ctrr-to-be-enabled':[1,4]}}]
