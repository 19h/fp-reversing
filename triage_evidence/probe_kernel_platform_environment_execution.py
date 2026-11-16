#!/usr/bin/env python3
"""Continuous original main/platform/tree/option execution in private RAM.
O(visits+journals+mapped bytes) time/space. No native kernel or IPC.
"""
import json,struct
from hashlib import sha256
from unicorn import arm64_const as ar
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read
from probe_rpc502_vm_handoff import compressed
from probe_kernel_vm_mig import Probe as Core,P,SIZE,SP
from probe_kernel_boot_environment_publication import Probe as Parent,INPUT,HEADER_INPUT,CPU,REGIONS as PRIOR_REGIONS,LEAVES
from probe_kernel_secure_dt_execution import tree_node,serialize,description,scalar
import recover_kernel_platform_environment_execution as R
E=R.E;O=R.O;TREE=P+0x10000;REGIONS=PRIOR_REGIONS+[(0xfffffe000cb5c000,4096),(0xfffffe000cba4000,4096),(0xfffffe000caac000,4096),(0xfffffe0007ef8000,4096),(0xfffffe000cb50000,4096)]
TREE_APIS=[O.B.B.LOOKUP,O.B.B.PROPERTY,O.B.B.ITERATE,O.B.B.FIND,O.B.SKIP,O.B.STRCMP]
OPTION_APIS=[O.PARSE,O.NUMBER,O.FLAG,O.SPACE,O.STRLEN]
TRACKED=[*TREE_APIS,*OPTION_APIS,E.STRLCPY,E.COPY,E.PLATFORM,R.CLOCK,R.ANCHOR,R.FLAGS,R.TIMER]
INITIAL_SYSTEM={'s3_1_c15_c1_5':0,'s3_4_c15_c14_6':0,'s3_4_c15_c9_6':0x1200,'cntkctl_el1':0x100,'actlr_el1':0x11223fff}

def fixture(c):
 children=[tree_node('unused',[('odd',description(b'abc'))],[tree_node('unused-child')])]
 cpus=[]
 for j,p in enumerate(c.get('CPUs',[{}])):
  props=[('reg',scalar(0x100+j)),('state',description(p.get('state','running').encode()+b'\0'))]
  for key,value in p.items():
   if key!='state':props.append((key,scalar(value,c.get('frequency_width',4))))
  cpus.append(tree_node('cpu'+str(j),props))
 children.append(tree_node('cpus',[],cpus))
 if not c.get('no_arm_io'):children.append(tree_node('bridge',[],[tree_node('arm-io',[('device_type',description(b'private-io\0')),('ranges',description(struct.pack('<QQ',0,c.get('anchor',0x80000000))))])]))
 if c.get('product',True):children.append(tree_node('product',[('unique-model',description(c.get('model','private-model').encode()+b'\0')),('sub-product-type',description(c.get('subproduct','private-subproduct').encode()+b'\0'))]))
 if c.get('chosen') is not None:
  props=[]
  for key,value in c['chosen'].items():props.append((key,description(value.encode()+b'\0') if isinstance(value,str) else scalar(value[0],value[1])))
  children.append(tree_node('chosen',props))
 props=[('target-type',description(c.get('target','private-target').encode()+b'\0'))]
 if c.get('fpga'):props.append(('target-is-fpga',description(b'')))
 return tree_node('device-tree',props,children)

class Probe(Parent):
 def ensure(self,a,n=1):
  super().ensure(a,n)
  if hasattr(self,'initial_pages'):
   for pg in self.pages-self.initial_pages.keys():self.initial_pages[pg]=bytes(self.u.mem_read(pg,4096))
 def __init__(self,image,c,mutate=None):
  self.blob,self.nodes=serialize(fixture(c));c={**c,'base':TREE,'extent':len(self.blob),'main':True};super().__init__(image,c,mutate=None)
  self.mutate=mutate;self.system=dict(INITIAL_SYSTEM);self.logical=[];self.entries=[];self.returns=[];self.active=[];self.prefix=None;self.platform_return=None;self.snapshots=[]
  self.fixture(TREE,self.blob);args=bytearray(self.u.mem_read(INPUT,1152));text=c.get('boot_text','').encode()+b'\0';assert len(text)<=256;args[0x6c:0x6c+len(text)]=text;self.fixture(INPUT,bytes(args))
  for a,n in REGIONS[len(PRIOR_REGIONS):]:self.image_fixture(a,bytes(n),'Declared zero private mutable platform state; native owner extents unknown')
  for a,b in [(0xfffffe0007f8b5c8,bytes(4)),(0xfffffe0007ef9164,bytes(4)),(0xfffffe000caac7d0,struct.pack('<I',3))]:self.u.mem_write(a,b)
  if c.get('cached_anchor') is not None:
   self.u.mem_write(0xfffffe000cba40f8,struct.pack('<Q',0xfffffe000cba4100));self.u.mem_write(0xfffffe000cba4100,b'cached-io\0');self.u.mem_write(0xfffffe000cba4120,struct.pack('<Q',c['cached_anchor']))
  for r in self.image_initial:r['bytes_hex']=bytes(self.u.mem_read(int(r['address'],16),len(bytes.fromhex(r['bytes_hex'])))).hex()
  e=json.loads(read(ROOT/(R.P+'_checks.json')));self.allowed=[(int(f['start'],16),int(f['end'],16)) for f in e['functions']]
  self.before=bytes(self.u.mem_read(P,SIZE));self.initial_pages={pg:bytes(self.u.mem_read(pg,4096)) for pg in self.pages}
  if mutate is not None:self.ensure(mutate,4);self.u.mem_write(mutate,bytes.fromhex('1f2003d5'))
 def write(self,u,t,a,n,v,d):
  assert P<=a<a+n<=P+SIZE or any(lo<=a<a+n<=lo+length for lo,length in REGIONS),(hex(a),n)
  e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e)
 def snapshot(self,a):
  return {'PC':hex(a),'before_visit':len(self.visits),'registers31':[hex(self.reg(j)) for j in range(31)],'SP':hex(self.u.reg_read(ar.UC_ARM64_REG_SP)),'NZCV':hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV)),
   'private_RAM':compressed(bytes(self.u.mem_read(P,SIZE))),'image_globals':[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()} for a,n in REGIONS],'system':dict(self.system)}
 def code(self,u,a,n,d):
  self.flush()
  while self.active and self.entries[self.active[-1]]['return_PC']==hex(a) and self.entries[self.active[-1]]['entry_SP']==hex(u.reg_read(ar.UC_ARM64_REG_SP)):
   self.returns.append({'entry_index':self.active.pop(),'before_visit':len(self.visits),'return_value':hex(self.reg(0))})
  if a==E.NEXT_TREE and self.prefix is None:self.prefix=self.snapshot(a);self.prefix['original_call_entries']=list(self.events);self.prefix['API_models']=list(self.models)
  if a==0xfffffe000c639b9c:
   self.platform_return=self.snapshot(a)
   if self.c.get('platform_only'):return self.stop('original_platform_return_before_main_timer')
  if a==0xfffffe000c639cb8:return self.stop('original_main_reaches_CPU_enumeration_call')
  if a in [0xfffffe000c62a2b0,0xfffffe000c63a268,0xfffffe000c5e6afc]:return self.stop('before_original_diagnostic')
  if a in LEAVES:return self.model(a,LEAVES[a],0)
  assert any(lo<=a<hi for lo,hi in self.allowed),hex(a)
  if a in [E.PLATFORM,E.STRLCPY,E.STRLEN,E.COPY]:self.events.append({'PC':hex(a),'arguments3':[hex(self.reg(j)) for j in range(3)],'return_PC':hex(self.reg(30)),'source_visit_index':len(self.visits)})
  if a in TRACKED:
   self.active.append(len(self.entries));self.entries.append({'PC':hex(a),'entry_SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'arguments6':[hex(self.reg(j)) for j in range(6)],'return_PC':hex(self.reg(30)),'before_visit':len(self.visits)})
  raw=bytes(u.mem_read(a,4));assert raw==(bytes.fromhex('1f2003d5') if a==self.mutate else self.image.k.read(a,4));ins=list(self.image.k.cs.disasm(raw,a));assert ins;i=ins[0]
  if i.mnemonic in ['paciza','xpaci','pacia','blraa','mrs','msr','isb']:
   event={'PC':hex(a),'kind':i.mnemonic,'operands':i.op_str,'before_visit':len(self.visits),'system_before':dict(self.system)};self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()})
   target=a+4
   if i.mnemonic in ['mrs','msr']:
    left,right=i.op_str.split(', ')
    if i.mnemonic=='mrs':assert right in self.system;self.set(int(left[1:]),self.system[right])
    else:self.system[left]=0 if right=='xzr' else self.reg(int(right[1:]))
   elif i.mnemonic=='blraa':
    assert self.reg(19)==O.SPACE and self.reg(17)==0xba5;target=self.reg(19);self.set(30,a+4);event['target']=hex(target);event['modifier_X17']=hex(self.reg(17))
   event['system_after']=dict(self.system);self.logical.append(event);u.reg_write(ar.UC_ARM64_REG_PC,target);return
  if a==self.mutate:self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});return
  return Core.code(self,u,a,n,d)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=200000);self.flush();assert self.reason in ['original_main_reaches_CPU_enumeration_call','original_platform_return_before_main_timer','before_original_diagnostic'],self.boundary
  assert not self.active and self.prefix is not None and self.platform_return is not None
  return {'configuration':self.c,'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_NZCV':self.entry_NZCV,'entry_registers31':self.entry_regs,'initial_vectors':['0x0']*32,'initial_system':INITIAL_SYSTEM,'final_system':self.system,
   'private_RAM':{'address':hex(P),'size_bytes':SIZE,'initial_byte':0},'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,
   'initial_private_RAM':compressed(self.before),'final_private_RAM':compressed(bytes(self.u.mem_read(P,SIZE))),
   'initial_image_pages':[{'address':hex(pg),'bytes_hex':raw.hex()} for pg,raw in sorted(self.initial_pages.items())],
   'final_image_globals':[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()} for a,n in REGIONS],
   'final_page_sha256':{hex(pg):sha256(bytes(self.u.mem_read(pg,4096))).hexdigest() for pg in sorted(self.pages)},
   'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'logical_effects':self.logical,'original_call_entries':self.events,
   'original_API_entries':self.entries,'original_API_returns':self.returns,'prefix_checkpoint':self.prefix,'original_platform_return':self.platform_return,
   'fixture_extent_bytes':len(self.blob),'fixture_node_addresses':{k:hex(v) for k,v in self.nodes.items()},
   'final_vectors':[hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j)))) for j in range(32)],'boundary':self.boundary,'source_word_mutated_to_NOP':hex(self.mutate) if self.mutate else None,**{n:False for n in R.FALSE}}

def cases():
 freq={'timebase-frequency':24000000,'bus-frequency':100000000,'memory-frequency':200000000,'peripheral-frequency':12000000,'fixed-frequency':25000000,'clock-frequency':800000000}
 return [
  {'label':'defaults_with_original_platform_return','CPUs':[{}]},
  {'label':'all_clock_and_identity_properties32','CPUs':[freq],'target':'t'*24,'model':'m'*24,'subproduct':'s'*40,'chosen':{'debug-enabled':[1,1],'system-firmware-version':'F'*140,'firmware-version':'V'*140,'unique-chip-id':[0x1122334455667788,8],'dram-vendor-id':[0x12345678,4]}},
  {'label':'last_running_CPU_and_u64_bus_cap','frequency_width':8,'CPUs':[{'state':'stopped',**freq},freq,{**freq,'bus-frequency':0x100000001,'clock-frequency':0x200000000,'timebase-frequency':48000000}]},
  {'label':'option_overrides_and_zero_timer_divisor','CPUs':[freq],'chosen':{'debug-enabled':[1,4]},'boot_text':'assertions=1 statistics=1 diagnostic_api=0 cpu-factor=17 wfe_events_sec=0 icdsb=5 user_ts_jop=0 diversify_user_jop=7 sptm_stability_hacks=1'},
  {'label':'root_FPGA_factor_fallback','CPUs':[freq],'fpga':True,'boot_text':'assertions=0 statistics=0 diagnostic_api=1 wfe_events_sec=20'},
  {'label':'cached_range_anchor','CPUs':[freq],'cached_anchor':0x90000000,'boot_text':'wfe_events_sec=999999999'},
  {'label':'missing_arm_io_stops_after_platform_return','CPUs':[freq],'no_arm_io':True,'platform_only':True},
  {'label':'no_running_CPU_clock_defaults','CPUs':[{'state':'stopped'}]},
  {'label':'missing_later_frequency_retains_prior_value','CPUs':[freq,{'state':'running'}],'chosen':{'debug-enabled':[0,4]},'boot_text':'diagnostic_api=1 cpu-factor=9'}]
