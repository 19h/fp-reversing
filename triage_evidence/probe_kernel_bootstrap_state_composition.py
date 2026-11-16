#!/usr/bin/env python3
"""Continuous original main through topology and thread setup in private RAM.
O(visits+journals+mapped bytes) time/space. No native kernel, receiver or IPC.
"""
import json,struct
from hashlib import sha256
from unicorn import arm64_const as ar
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read
from probe_rpc502_vm_handoff import compressed
from probe_kernel_vm_mig import Probe as Core,P,SIZE,SP
import probe_kernel_platform_environment_execution as B
from probe_kernel_secure_dt_execution import serialize,description,scalar
import recover_kernel_bootstrap_state_composition as R
K=R.K;T=R.T
EXTRA_REGIONS=[(K.TEMPLATE,1472),(K.THREAD,1472),(K.CPU_MAP,256),(K.SLOT,8),(0xfffffe0007f8b4f0,4)]
REGIONS=B.REGIONS+EXTRA_REGIONS
NEW_APIS=[K.ENUM,K.SCALAR,K.SETTER,T.POST]
INITIAL_SYSTEM={**B.INITIAL_SYSTEM,'tpidr_el0':0x123456789abcdef0,'tpidrro_el0':0x23456789abcdef01,'tpidr_el1':0x3456789abcdef012,'contextidr_el1':0x456789abcdef0123,'s3_4_c15_c10_4':0x56789abcdef01234}

class Probe(B.Probe):
 def __init__(self,image,c,mutate=None):
  super().__init__(image,c);self.mutate=mutate;self.system=dict(INITIAL_SYSTEM);self.join=None;self.enumerated=None;self.post=None;self.wrapper=[]
  if c.get('topology'):
   root=B.fixture(c);cpus=next(x for x in root['children'] if bytes.fromhex(x['properties'][0][1]['bytes_hex'])==b'cpus\0')
   assert len(cpus['children'])==len(c['topology'])
   for node,properties in zip(cpus['children'],c['topology']):
    node['properties']=[p for p in node['properties'] if p[0] not in properties]
    node['properties'] += [[key,value if isinstance(value,dict) else scalar(value)] for key,value in properties.items()]
   blob,nodes=serialize(root);self.fixture(B.TREE,bytes(max(len(self.blob),len(blob))));self.fixture(B.TREE,blob);self.blob,self.nodes=blob,nodes;self.c['extent']=len(blob)
   args=bytearray(self.u.mem_read(B.INPUT,1152));struct.pack_into('<I',args,0x68,len(blob));self.fixture(B.INPUT,bytes(args))
  if not c.get('retain_prior_zero_topology_page'):
   self.image_fixture(0xfffffe0007ef8000,image.logical_page(0xfffffe0007ef8000),'Original logical initialized topology page before entry, including recorded format-8 pointers; native lifetime unknown')
  for a,n in EXTRA_REGIONS:self.ensure(a,n)
  self.ensure(K.SLOT_PTR,8)
  self.allowed=[(int(f['start'],16),int(f['end'],16)) for f in json.loads(read(ROOT/(R.P+'_checks.json')))['functions']]
  self.before=bytes(self.u.mem_read(P,SIZE));self.initial_pages={pg:bytes(self.u.mem_read(pg,4096)) for pg in self.pages}
  if mutate is not None:self.ensure(mutate,4);self.u.mem_write(mutate,bytes.fromhex('1f2003d5'))
 def write(self,u,t,a,n,v,d):
  assert P<=a<a+n<=P+SIZE or any(lo<=a<a+n<=lo+length for lo,length in REGIONS),(hex(a),n)
  e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e)
 def full_snapshot(self,a):
  row=self.snapshot(a);row['additional_image_globals']=[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()} for a,n in EXTRA_REGIONS];row['vectors']=[hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j)))) for j in range(32)];return row
 def code(self,u,a,n,d):
  self.flush()
  while self.active and self.entries[self.active[-1]]['return_PC']==hex(a) and self.entries[self.active[-1]]['entry_SP']==hex(u.reg_read(ar.UC_ARM64_REG_SP)):
   self.returns.append({'entry_index':self.active.pop(),'before_visit':len(self.visits),'return_value':hex(self.reg(0))})
  if a==0xfffffe000c639cb8:
   self.join=self.full_snapshot(a);self.join['API_entries_completed']=len(self.entries);self.join['API_returns_completed']=len(self.returns)
   return Core.code(self,u,a,n,d)
  if a==0xfffffe000c639cbc:self.enumerated=self.full_snapshot(a)
  if a==0xfffffe000c639cc0:self.post=self.full_snapshot(a)
  if a==0xfffffe000c639dd8:return self.stop('original_bootstrap_thread_setup_complete')
  if a==0xfffffe000be83324 and self.reg(26)==0:return self.stop('before_null_record_store_from_zero_initialized_pointer')
  if a==0xfffffe000be83d2c and self.reg(8)==0:return self.stop('before_missing_boot_record_dereference')
  if a==T.WRAPPER:
   self.wrapper.append({'PC':hex(a),'arguments8':[hex(self.reg(j)) for j in range(8)],'before_visit':len(self.visits)})
   return self.model(a,'declared_selector0e_wrapper_no_RAM_return',0)
  if a in NEW_APIS:
   self.active.append(len(self.entries));self.entries.append({'PC':hex(a),'entry_SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'arguments6':[hex(self.reg(j)) for j in range(6)],'return_PC':hex(self.reg(30)),'before_visit':len(self.visits)})
  raw=bytes(u.mem_read(a,4));ins=next(self.image.k.cs.disasm(raw,a))
  if ins.mnemonic=='pacda':
   assert raw==self.image.k.read(a,4);self.logical.append({'PC':hex(a),'kind':'pacda','operands':ins.op_str,'before_visit':len(self.visits),'system_before':dict(self.system),'system_after':dict(self.system),'X16':hex(self.reg(16)),'X17':hex(self.reg(17))});self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  return super().code(u,a,n,d)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=300000);self.flush();assert self.reason in ['original_bootstrap_thread_setup_complete','before_null_record_store_from_zero_initialized_pointer','before_missing_boot_record_dereference','before_original_diagnostic'],self.boundary
  assert self.prefix is not None and self.platform_return is not None and self.join is not None
  return {'configuration':self.c,'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_NZCV':self.entry_NZCV,'entry_registers31':self.entry_regs,'initial_vectors':['0x0']*32,'initial_system':INITIAL_SYSTEM,'final_system':self.system,'private_RAM':{'address':hex(P),'size_bytes':SIZE,'initial_byte':0},'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,'initial_private_RAM':compressed(self.before),'final_private_RAM':compressed(bytes(self.u.mem_read(P,SIZE))),'initial_image_pages':[{'address':hex(pg),'bytes_hex':raw.hex()} for pg,raw in sorted(self.initial_pages.items())],'final_image_globals':[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()} for a,n in REGIONS],'final_page_sha256':{hex(pg):sha256(bytes(self.u.mem_read(pg,4096))).hexdigest() for pg in sorted(self.pages)},'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'logical_effects':self.logical,'original_call_entries':self.events,'original_API_entries':self.entries,'original_API_returns':self.returns,'unfinished_API_entry_indices':self.active,'prefix_checkpoint':self.prefix,'original_platform_return':self.platform_return,'pre_enumeration_checkpoint':self.join,'original_enumeration_return':self.enumerated,'original_post_helper_return':self.post,'declared_selector0e_calls':self.wrapper,'fixture_extent_bytes':len(self.blob),'fixture_node_addresses':{k:hex(v) for k,v in self.nodes.items()},'final_vectors':[hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j)))) for j in range(32)],'boundary':self.boundary,'source_word_mutated_to_NOP':hex(self.mutate) if self.mutate else None,**{n:False for n in R.FALSE}}

def cases():
 freq={'timebase-frequency':24000000,'bus-frequency':100000000,'clock-frequency':800000000}
 def case(label,topology,boot_text='',**kwargs):return {'label':label,'CPUs':[{**freq,'state':p.pop('_state','running')} for p in [dict(x) for x in topology]],'topology':[{k:v for k,v in p.items() if k!='_state'} for p in topology],'boot_text':boot_text,**kwargs}
 return [
  {'label':'prior_zero_page_stops_before_null_record_store','CPUs':[{}],'boot_text':'','retain_prior_zero_topology_page':True},
  {'label':'initialized_page_default_thread','CPUs':[{}],'boot_text':''},
  case('three_clusters_running_middle',[{'reg':4,'_state':'stopped'},{'reg':0x102},{'reg':0x201,'_state':'stopped'}]),
  case('mask_reservation_and_parser',[{'reg':0,'_state':'stopped'},{'reg':0x101},{'reg':0x202,'_state':'stopped'}],'cpus=2 cpumask=0x4 cluster_power=7 siq_realtime_thread_mode=3'),
  case('sixteen_CPUs_running_last',[{'reg':j,'_state':'stopped' if j<15 else 'running'} for j in range(16)],'cpus=0x10'),
  case('post_helper_control4_diagnostic',[{'reg':0x100}],'siq_realtime_thread_mode=4'),
  case('no_running_CPU_stops_before_null_boot_record',[{'reg':0x100,'_state':'stopped'}]),
  case('CPU_limit0_stops_before_null_boot_record',[{'reg':0x100}],'cpus=0'),
  case('identity_options_and_mixed_PM',[{'reg':0x100,'cluster-type':0x50},{'reg':0x101,'cluster-type':0x4d}], 'assertions=1 statistics=1 cpu-factor=17 wfe_events_sec=20 user_ts_jop=0 cluster_power=7 siq_realtime_thread_mode=3',chosen={'debug-enabled':[1,4]},target='t'*24,model='m'*24),
 ]
