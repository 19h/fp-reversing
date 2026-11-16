#!/usr/bin/env python3
"""Fresh source/CPU replay with independent DC and opaque-leaf contracts.
O(visits + journals + RAM) time/space. No producer/audit imports or native effects.
"""
from unicorn import arm64_const as ar
from replay_kernel_magazine_bootstrap import Replay as Parent
import recover_kernel_mapping_context as R
P=0x6500000000;BITMAP=P+0x40000;RESULT=P+0x30000;THREAD=P+0x10000

class Replay(Parent):
 def __init__(self,image,row,parent=None):
  super().__init__(image,row,parent);self.di=0;self.events=[];self.clears=[];self.conversions=[]
  if parent is not None:
   expected={}
   for f in parent['final_image_globals']:
    a=int(f['address'],16)
    for j,v in enumerate(bytes.fromhex(f['bytes_hex'])):expected[a+j]=v
   inherited=row['initial_image_fixtures'][:len(parent['final_image_globals'])]
   assert [(r['address'],r['bytes_hex']) for r in inherited]==[(r['address'],r['bytes_hex']) for r in parent['final_image_globals']]
   assert len(row['initial_image_fixtures'])==len(inherited)+int(row['phase']=='cpu' and row['configuration'].get('cpu_conversion_fail',False))
   for f in row['initial_image_fixtures']:
    a=int(f['address'],16);raw=bytes.fromhex(f['bytes_hex'])
    if f['provenance'].startswith('Declared feature change'):assert row['configuration'].get('cpu_conversion_fail') and a==R.CONV_GLOBALS and raw==bytes(1)
    else:assert raw==bytes(expected[a+j] for j in range(len(raw)))
 def code(self,u,a,n,d):
  self.finish();c=self.p['configuration'];phase=self.p['phase']
  if a==R.Z.BZERO:self.clears.append({'pc':hex(a),'source_visit_index':self.seq,'arguments2':[hex(self.reg(j)) for j in range(2)]})
  if a in [R.P2V,R.V2P]:self.conversions.append({'pc':hex(a),'source_visit_index':self.seq,'arguments2':[hex(self.reg(j)) for j in range(2)]})
  if self.mi<len(self.models) and a==int(self.models[self.mi]['pc'],16):
   m=self.models[self.mi];names={0xfffffe000bd037e0:('declared_lock_initialization_no_RAM_effect',0),
    0xfffffe000be71258:('declared_initializer_leaf_no_RAM_effect',0),0xfffffe000c5e48a4:('declared_boot_parser_absent_no_RAM_effect',0),
    0xfffffe000c620a08:('declared_capability_query_failure_no_RAM_effect',1),R.T.CHECK:('declared_validation_no_RAM_effect',0),
    R.IDENT:('declared_SPTM_identifier',c['transport_id']),R.RESULT:('declared_SPTM_result_pointer',RESULT),
    R.T.WRAPPERS[1]:('declared_opaque_mapping_status_no_RAM_effect',c['status'])}
   name,value=names[a];assert m['symbol']==name and int(m['return_value'],16)==value
   assert phase==('cpu' if a in [R.IDENT,R.RESULT] else 'backend' if a==R.T.WRAPPERS[1] else 'gate' if a==R.T.CHECK else 'context')
   for j in range(18):
    expected=value if j==0 else ((j+1)*0x123456789abcdef)^(self.mi+1)*0x8b3dc651
    assert int(m['after_registers31'][j],16)==expected&((1<<64)-1)
   self.counts['declared_model_semantic_contracts_checked']+=1
   if a in [R.IDENT,R.RESULT,R.T.WRAPPERS[1]]:
    block=R.T.CPU_BASE+c['cpu']*16384
    self.events.append({'pc':hex(a),'source_visit_index':self.seq,'arguments8':[hex(self.reg(j)) for j in range(8)],
     'thread_nesting':int.from_bytes(bytes(u.mem_read(THREAD+0x1c8,4)),'little'),
     'epoch_and_active_hex':bytes(u.mem_read(block+0x1270,16)).hex()})
  if self.di<len(self.p['logical_DC_ZVA_effects']):
   e=self.p['logical_DC_ZVA_effects'][self.di]
   if e['source_visit_index']==self.seq and e['pc']==hex(a):
    raw=bytes(u.mem_read(a,4));i=next(self.image.k.cs.disasm(raw,a));at=self.reg(3)&~63
    assert raw==self.image.k.read(a,4) and self.p['source_visits'][self.seq]=={'pc':hex(a),'bytes_hex':raw.hex()}
    assert i.mnemonic=='dc' and i.op_str=='zva, x3' and BITMAP<=at<at+64<=BITMAP+65536
    assert e['address']==hex(at) and e['before_hex']==bytes(u.mem_read(at,64)).hex() and e['after_hex']==bytes(64).hex()
    self.current=self.seq;self.seq+=1;self.rc=self.wc=0;self.di+=1;self.counts['source_visits_checked']+=1;self.counts['logical_DC_ZVA_steps_checked']+=1
    u.mem_write(at,bytes(64));u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  return super().code(u,a,n,d)
 def run(self):
  super().run();assert self.di==len(self.p['logical_DC_ZVA_effects']) and self.events==self.p['transport_entries'] and self.clears==self.p['original_clear_entries'] and self.conversions==self.p['original_conversion_entries']
  self.counts['transport_entries_reconstructed']+=len(self.events);self.counts['original_clear_entries_reconstructed']+=len(self.clears)
  self.counts['original_conversion_entries_reconstructed']+=len(self.conversions)
  return dict(self.counts)
