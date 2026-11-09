#!/usr/bin/env python3
"""Strict private execution of the actual40-byte caller record into46EF4C.
Only source-produced/explicit bytes are defined. Additional writable-image
backing is a declared private environment, not native runtime state. Stop
before imports, unavailable private data, unknown owners or a caller return.
O(cases*visits + fixture expressions) time, O(one private map/journal) space.
"""
import json,struct
import z3
import unicorn as uc
from unicorn import arm64_const as ar
import probe_daemon_descriptor_producers as prior
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from capture_daemon_record720 import sha
from prove_daemon_operation_heads import variables
from validate_daemon_record720_spill import parse_value
ENTRY=0x1004c4648;CALLEE=0x10046ef4c;RETURN=0x1004c464c
class Run(prior.Run):
 def __init__(self,index,stage,mode='strict'):
  self.model_mode=mode;self.api_models=[];self.import_word_models={prior.IMPORTS['CoreFoundation/_kCFAllocatorDefault']:('CoreFoundation/_kCFAllocatorDefault',[0,1,(1<<64)-1,prior.P+0x9000][index]),prior.IMPORTS['CoreFoundation/_kCFAllocatorNull']:('CoreFoundation/_kCFAllocatorNull',[prior.P+0xa000,0,0x12345678,(1<<64)-1][index])}
  config={'nonnull':True,'probe':'fast','counter64':0,'placement':0,'controllers':[(0,0),(0xffffffff,0x87654321),(0x12345678,0x9abcdef0),(0x87654321,0xffffffff)][index],'pattern':[0x5a5a5a5a5a5a5a5a,0xa5a5a5a5a5a5a5a5,0,0xffffffffffffffff][index]};super().__init__(config);self.known=bytearray(prior.SIZE);self.initial=[];self.image_fixtures=[];self.u.mem_write(prior.P,bytes([config['pattern']&255])*prior.SIZE);v=variables(stage);data=bytearray((index*37+j*73)&255 for j in range(72))
  for off in [0,56,64]:data[off:off+8]=(int.from_bytes(data[off:off+8],'little')or 1).to_bytes(8,'little')
  replacement=[]
  for name,x in v.items():
   if z3.is_bool(x):value=z3.BoolVal(False)
   elif name.startswith('head_a70e6eb4_input_'):value=z3.BitVecVal(data[int(name.rsplit('_',1)[1],16)],8)
   elif name.startswith('core_export_address_'):
    old=json.loads((ROOT/'daemon_core_dispatch_symbolic.json').read_text());symbol=next(r['symbol']for r in old['export_variables']if r['variable']==name);value=z3.BitVecVal(prior.IMPORTS[symbol],64)
   elif name=='core_dispatch_operation32':value=z3.BitVecVal(0xa70e6eb4,32)
   else:raise AssertionError(('unassigned source input',name))
   replacement.append((x,value))
  def ev(s,bits):
   val=z3.simplify(z3.substitute(parse_value(s,bits,v),*replacement));assert z3.is_bv_value(val),val;return val.as_long()
  for row in stage['final_defined_bytes']:
   a=int(row['address'],16);b=bytes([ev(row['expression'],8)])
   if prior.P<=a<prior.P+prior.SIZE:self.fixture(a,b)
   else:self.ensure(a);self.u.mem_write(a,b);self.image_fixtures.append({'address':hex(a),'bytes_hex':b.hex(),'provenance':'source-established parent state'})
  for j in range(31):self.set(j,ev(stage['end_GPR_expressions']['x'+str(j)],64))
  self.C=ev(stage['end_GPR_expressions']['sp'],64);self.R=self.C+0x10cb8;self.FP=self.reg(29);self.u.reg_write(ar.UC_ARM64_REG_SP,self.C);self.u.reg_write(ar.UC_ARM64_REG_NZCV,[0,0xa0000000,0x50000000,0xf0000000][index])
  for a,value in [(0x1010c4eb0,config['controllers'][0]),(0x1010c4670,config['controllers'][1])]:
   self.ensure(a,4);b=struct.pack('<I',value);self.u.mem_write(a,b);self.image_fixtures.append({'address':hex(a),'bytes_hex':b.hex(),'provenance':'declared callee controller state; native value unknown'})
  self.c['API_model_mode']=mode
  if mode!='strict':
   for address,(symbol,value)in self.import_word_models.items():self.ensure(address,8);self.image_fixtures.append({'address':hex(address),'bytes_hex':value.to_bytes(8,'little').hex(),'symbol':symbol,'provenance':'explicit imported-data word model; native contents unknown'})
  self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_Q=[hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))))for j in range(32)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV));self.record_before=self.snapshot(self.R,40);self.source_index=index
 def ensure(self,a,n=1):
  words=getattr(self,'import_word_models',{})
  if getattr(self,'model_mode','strict')!='strict'and a in words:
   pg=a&~4095
   if pg not in self.pages:self.u.mem_map(pg,4096);self.pages.add(pg)
   for address,(_,value)in words.items():
    if address&~4095==pg:self.u.mem_write(address,value.to_bytes(8,'little'))
   return
  return super().ensure(a,n)
 def preflight(self,ins):
  if ins.address in [0x1003336f8,0x10033374c]:
   base='x12'if ins.address==0x1003336f8 else'x11';address=self.register(base);assert address in self.import_word_models
   if self.model_mode=='strict':self.stop('before_unavailable_imported_data',{'symbol':self.import_word_models[address][0],'logical_export_address':hex(address),'size_bytes':8,'instruction':ins.mnemonic+' '+ins.op_str});return False
   self.ensure(address,8)
  return super().preflight(ins)
 def code(self,u,a,n,d):
  if a==RETURN and self.seq>0:self.flush();return self.stop('returned_to_original_caller')
  ins=next(self.cs.disasm(IMAGE.read(a,4),a))
  if ins.mnemonic in ['blraa','blraaz','blr']:
   parts=[x.strip()for x in ins.op_str.split(',')];target=self.register(parts[0]);symbol=next((name for name,value in prior.IMPORTS.items()if value==target),None);result=None
   if symbol=='CoreFoundation/_CFStringCreateWithCStringNoCopy'and self.model_mode in ['string_null','string_nonnull','task_null','task_nonnull']:result=0 if self.model_mode=='string_null'else prior.P+0x9000
   elif symbol=='Security/_SecTaskCreateWithAuditToken'and self.model_mode in ['task_null','task_nonnull']:result=0 if self.model_mode=='task_null'else prior.P+0xa000
   elif symbol=='CoreFoundation/_CFRelease'and self.model_mode not in ['strict','allocator_words']:
    if self.reg(0)==0:self.flush();return self.stop('before_CFRelease_null_model_argument',{'symbol':symbol})
    result=0
   if result is not None:
    self.flush();slotrow=next(e for e in reversed(self.reads)if e['size_bytes']==8 and int(e['address'],16)in FIXUPS and FIXUPS[int(e['address'],16)]['target']==symbol);slot=int(slotrow['address'],16);modifier=self.register(parts[1])if len(parts)>1 else 0;raw=int.from_bytes(IMAGE.read(slot,8),'little');assert raw>>63==1 and(raw>>32)&65535==modifier and(raw>>48)&7==0
    event={'pc':hex(a),'source_visit_index':self.seq,'symbol':symbol,'target':hex(target),'slot':hex(slot),'modifier':hex(modifier),'arguments8':[hex(self.reg(j))for j in range(8)],'SP':hex(self.u.reg_read(ar.UC_ARM64_REG_SP)),'return_value':hex(result),'native_effects_executed':False}
    if symbol=='CoreFoundation/_CFStringCreateWithCStringNoCopy':
     event['cstring']=self.snapshot(self.reg(1),30);assert all(bytes.fromhex(event['cstring']['known_mask_hex']))and bytes.fromhex(event['cstring']['bytes_hex'])==b'com.apple.private.fpsd.client\0'
    if symbol=='Security/_SecTaskCreateWithAuditToken':
     event['audit_argument']=self.snapshot(self.reg(1),32);assert all(bytes.fromhex(event['audit_argument']['known_mask_hex']));event['original_token']=self.snapshot(prior.P+0x1000+24,32);assert event['audit_argument']['bytes_hex']==event['original_token']['bytes_hex']
    self.visits.append({'pc':hex(a),'source_visit_index':self.seq,'bytes_hex':IMAGE.read(a,4).hex(),'image':'daemon'});self.seq+=1
    for j in range(18):self.set(j,((0x123456789abcdef*(j+1))^(self.source_index*0x8b3dc651))&((1<<64)-1))
    self.set(0,result);self.set(30,a+4);self.u.reg_write(ar.UC_ARM64_REG_NZCV,[0,0xa0000000,0x50000000,0xf0000000][self.source_index]);event['after_registers31']=[hex(self.reg(j))for j in range(31)];event['after_NZCV']=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV));self.api_models.append(event);return self.u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  return super().code(u,a,n,d)
 def run(self):
  self.ensure(ENTRY)
  try:self.u.emu_start(ENTRY,0,count=50000)
  except uc.UcError:
   if self.reason is None:raise
  self.flush()
  if self.reason is None:self.stop('source_visit_limit')
  return {'configuration':self.c,'source_index':self.source_index,'entry_PC':hex(ENTRY),'entry_SP':hex(self.C),'entry_FP':hex(self.FP),'record_address':hex(self.R),'record_before':self.record_before,'entry_registers31':self.entry_regs,'entry_Q_registers32':self.entry_Q,'entry_NZCV':self.entry_NZCV,'entry_TPIDRRO_EL0':hex(prior.TLS),'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_fixtures,'image_backing_premise':'Additional file-backed/BSS writable bytes are declared private image state with logical fixups; not observed native state','source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'logical_edges':self.edges,'source_calls':self.calls,'API_model_events':self.api_models,'checkpoints':self.checkpoints,'boundary':self.boundary,'final_record':self.snapshot(self.R,40),'fixture_PC_transitions':0,'native_target_executed':False,'full_goal_complete':False}
def main():
 data=json.loads((ROOT/'daemon_mig_handover_symbolic.json').read_text());stage=next(c for c in data['cases']if c['path_class']=='allnonnull');rows=[]
 for mode in ['strict','allocator_words','string_null','string_nonnull','task_null','task_nonnull']:
  for j in range(4):
   r=Run(j,stage,mode).run();rows.append(r);print(json.dumps({'mode':mode,'case':j,'visits':len(r['source_visits']),'boundary':r['boundary']}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['daemon_mig_handover_symbolic.json','probe_daemon_descriptor_producers.py','daemon_descriptor_producers_source.json']},'cases':rows,'native_target_executed':False,'idb_mutated':False,'host_API_executed':False,'full_goal_complete':False};(ROOT/'daemon_record40_consumer_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
