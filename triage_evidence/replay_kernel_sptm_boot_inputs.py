#!/usr/bin/env python3
"""Fresh private CPU/source replay, including nested entry and leaf contracts.
O(visits + journals + RAM) time/space; no executor/audit imports or native effects.
"""
from unicorn import arm64_const as ar
from replay_kernel_magazine_bootstrap import Replay as Parent
import recover_kernel_sptm_boot_inputs as R
P=0x6500000000;BACKING=P+0x40000;EXTENT=0xa0000;RESULT=P+0x2c000;THREAD=P+0x10000

class Replay(Parent):
 def __init__(self,image,row,parent=None):
  super().__init__(image,row,parent);self.di=0;self.events=[];self.clears=[];self.conversions=[];self.nested=[]
  if parent is not None:assert [(r['address'],r['bytes_hex']) for r in row['initial_image_fixtures']]==[(r['address'],r['bytes_hex']) for r in parent['final_image_globals']]
 def code(self,u,a,n,d):
  self.finish();c=self.p['configuration'];phase=self.p['phase'];C=R.C;T=C.T
  if a in [R.POOL,R.DT,C.CPUINIT]:self.nested.append({'pc':hex(a),'source_visit_index':self.seq,'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'return_PC':hex(self.reg(30)),'arguments2':[hex(self.reg(j)) for j in range(2)]})
  if a==C.Z.BZERO:self.clears.append({'pc':hex(a),'source_visit_index':self.seq,'arguments2':[hex(self.reg(j)) for j in range(2)]})
  if a in [C.P2V,C.V2P]:self.conversions.append({'pc':hex(a),'source_visit_index':self.seq,'arguments2':[hex(self.reg(j)) for j in range(2)]})
  if self.mi<len(self.models) and a==int(self.models[self.mi]['pc'],16):
   m=self.models[self.mi];names={0xfffffe000bd037e0:('declared_lock_initialization_no_RAM_effect',0),
    0xfffffe000c5e48a4:('declared_boot_parser_absent_no_RAM_effect',0),0xfffffe000c620a08:('declared_capability_query_failure_no_RAM_effect',1),
    T.CHECK:('declared_validation_no_RAM_effect',0),0xfffffe000c662324:('declared_SecureDT_lookup_no_output_no_RAM_effect',0),
    0xfffffe000c662110:('declared_DT_property_absent_no_RAM_effect',0),C.IDENT:('declared_SPTM_identifier',c['transport_id']),
    C.RESULT:('declared_SPTM_result_pointer',RESULT),T.WRAPPERS[1]:('declared_opaque_mapping_status_no_RAM_effect',c['status'])}
   name,value=names[a];assert m['symbol']==name and int(m['return_value'],16)==value
   assert phase==('backend' if a==T.WRAPPERS[1] else 'gate' if a==T.CHECK else 'context')
   for j in range(18):
    expected=value if j==0 else ((j+1)*0x123456789abcdef)^(self.mi+1)*0x8b3dc651
    assert int(m['after_registers31'][j],16)==expected&((1<<64)-1)
   assert int(m['after_NZCV'],16)==(0xf0000000 if (self.mi+1)&1 else 0)
   self.counts['declared_model_semantic_contracts_checked']+=1
   if a in [C.IDENT,C.RESULT,T.WRAPPERS[1]]:
    block=T.CPU_BASE+c['cpu']*16384
    self.events.append({'pc':hex(a),'source_visit_index':self.seq,'arguments8':[hex(self.reg(j)) for j in range(8)],
     'thread_nesting':int.from_bytes(bytes(u.mem_read(THREAD+0x1c8,4)),'little'),'epoch_and_active_hex':bytes(u.mem_read(block+0x1270,16)).hex(),
     'transport_flag':bytes(u.mem_read(T.TRANSPORT_FLAG,1)).hex()})
  if self.di<len(self.p['logical_DC_ZVA_effects']):
   e=self.p['logical_DC_ZVA_effects'][self.di]
   if e['source_visit_index']==self.seq and e['pc']==hex(a):
    raw=bytes(u.mem_read(a,4));i=next(self.image.k.cs.disasm(raw,a));at=self.reg(3)&~63
    assert raw==self.image.k.read(a,4) and self.p['source_visits'][self.seq]=={'pc':hex(a),'bytes_hex':raw.hex()}
    assert i.mnemonic=='dc' and i.op_str=='zva, x3' and BACKING<=at<at+64<=BACKING+EXTENT
    assert e['address']==hex(at) and e['before_hex']==bytes(u.mem_read(at,64)).hex() and e['after_hex']==bytes(64).hex()
    self.current=self.seq;self.seq+=1;self.rc=self.wc=0;self.di+=1;self.counts['source_visits_checked']+=1;self.counts['logical_DC_ZVA_steps_checked']+=1
    u.mem_write(at,bytes(64));u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  return super().code(u,a,n,d)
 def run(self):
  super().run();assert self.di==len(self.p['logical_DC_ZVA_effects']) and self.events==self.p['transport_entries'] and self.clears==self.p['original_clear_entries'] and self.conversions==self.p['original_conversion_entries'] and self.nested==self.p['nested_source_entries']
  self.counts['transport_entries_reconstructed']+=len(self.events);self.counts['original_clear_entries_reconstructed']+=len(self.clears)
  self.counts['original_conversion_entries_reconstructed']+=len(self.conversions);self.counts['nested_source_entries_reconstructed']+=len(self.nested)
  return dict(self.counts)
