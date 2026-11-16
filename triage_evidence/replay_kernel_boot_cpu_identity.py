#!/usr/bin/env python3
"""Independent fresh instruction/journal replay and semantic byte formulas.
O(visits + journals + mapped bytes) time/space; no executor import.
"""
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE
from unicorn import arm64_const as ar
import recover_kernel_boot_cpu_identity as R
P=0x6500000000;SP=P+0xf000;HALT=P+0xe000;VALUE=P+0x2000;OTHER=P+0x4000;MASK=(1<<64)-1
def regno(j):return getattr(ar,'UC_ARM64_REG_X'+str(j))
def pages(rows):return {int(r['address'],16):bytearray.fromhex(r['bytes_hex']) for r in rows}
def get(memory,a,n):return bytes(memory[(a+j)&~4095][(a+j)&4095] for j in range(n))
def put(memory,a,n,value):
 data=value.to_bytes(n,'little') if isinstance(value,int) else value
 assert len(data)==n
 for j,b in enumerate(data):memory[(a+j)&~4095][(a+j)&4095]=b

def oracle(row):
 c=row['configuration'];expected=pages(row['initial_pages']);actual=pages(row['final_pages']);checks=[];system=dict(row['initial_system']);models=[]
 def u(a,n):return int.from_bytes(get(expected,a,n),'little')
 def w(a,n,v):put(expected,a,n,v)
 def ok(label,predicate):assert predicate,('semantic_oracle',label);checks.append(label)
 if c['phase']=='bootstrap':
  ordinal=c['ordinal'];ok('fixture_record_distinguishes_ordinal_and_physical_identifier',u(R.RECORD_PTR,8)==R.ARRAY+ordinal*136 and u(R.ARRAY+ordinal*136,4)==ordinal and u(R.ARRAY+ordinal*136+4,4)==c['physical'])
  w(0xfffffe0007f8b4f0,4,ordinal);w(R.CPU,2,ordinal&65535)
  for at,value in [(0x10,0xfffffe000cbb4000),(0x20,0xfffffe000cbbc000)]:w(R.CPU+at,16,value.to_bytes(8,'little')*2)
  w(R.CPU_MAP+ordinal*16+8,8,R.CPU);w(R.CPU_MAP+ordinal*16,8,(c['phys_base']+R.CPU-c['virt_base'])&MASK)
  template=bytearray(get(expected,R.TEMPLATE,0x5c0));template[0x328:0x338]=bytes(16);w(R.TEMPLATE,0x5c0,template);w(R.THREAD,0x5c0,template)
  w(R.THREAD+0x214,2,0x5f);w(R.SLOT,8,R.THREAD);w(R.THREAD+0x518,4,0xfffff)
  w(R.THREAD+0x1b8,8,ordinal&65535);w(R.THREAD+0x1c0,8,R.CPU);w(R.THREAD+0x1c8,4,0)
  w(R.CPU+0x30,8,R.THREAD);system['tpidr_el1']=R.THREAD
  system['tpidr_el0']=(system['tpidr_el0']&0xffff000000000000)|(u(R.CPU+0xa38,8)&0x0000ffffffffffff)
  system['tpidrro_el0']=u(R.THREAD+0x148,8);system['contextidr_el1']=u(R.THREAD+0x510,8)
  ok('original_full_template_copy_request',len(row['original_copy_entries'])==1 and row['original_copy_entries'][0]['arguments3']==list(map(hex,[R.THREAD,R.TEMPLATE,1472])))
  ok('same_RAM_explicit_caller_epoch_preserves_source_thread_registers',len(row['epochs'])==1 and row['epochs'][0]['system']==system)
  ok('boot_thread_field_has_zero_signed_ASR16_offset',(u(R.THREAD+0x1b8,8)>>16)==0)
 if c['phase'] in ['bootstrap','caller']:
  cpu=u(R.THREAD+0x1c0,8);magic=u(cpu+4,4);panic=False
  if magic!=0x0100000c:
   w(cpu+4,4,0x0100000c);w(cpu+0x118,16,(cpu+0x118).to_bytes(8,'little')*2);w(cpu+0x140,8,0x44000000);w(cpu+0x128,8,0);w(cpu+0x148,16,(0x144).to_bytes(8,'little')+MASK.to_bytes(8,'little'))
   if cpu==R.CPU:
    w(0xfffffe0007ef81c8,4,(system['midr_el1']&0xfff0ffff)|0xd0000);w(0xfffffe000cb8ab70,12,(1).to_bytes(4,'little')*3)
   else:models.append('declared_SPTM_CPU_initializer_no_RAM')
   models.append('declared_cache_initializer_no_RAM')
   dfr=system['id_aa64dfr0_el1']
   if dfr&15:w(0xfffffe000cb8ab68,8,(((dfr>>20)&15)+1).to_bytes(4,'little')+(((dfr>>12)&15)+1).to_bytes(4,'little'))
   nibble=(u(0xfffffe0007ef81c8,4)>>16)&15;index=(nibble-12)&0xffffffff
   if index>=3:panic=True
   else:w(cpu+8,8,[1,2,12][index].to_bytes(4,'little')+bytes(4));models.append('declared_CPU_context_initializer_no_RAM')
  if not panic:
   for offset in [0x890,0x8a0,0x8b0]:w(cpu+offset,8,0)
   w(cpu+0x69,1,1);w(cpu+0x1e0,4,u(cpu+0x1dc,4));w(cpu+0x1dc,4,0)
   args=list(map(int,row['boundary']['registers'][:5], [16]*5))
   ok('original_tail_call_ABI',args==[0,u(cpu,2),cpu+0x238,cpu+0x2d8,1])
  ok('CPU_address_and_magic_select_exact_helper_sequence',[m['name'] for m in row['declared_models']]==models)
  if cpu!=R.CPU and magic!=0x0100000c:ok('nonboot_SPTM_argument_is_thread_low16',int(row['declared_models'][0]['registers_before'][0],16)==u(R.THREAD+0x1b8,2))
  ok('CPU_capability_diagnostic_or_tail_boundary',int(row['boundary']['PC'],16)==(R.PANIC if panic else R.TAIL))
 elif c['phase']=='scalar':
  valid=c['length'] in [1,2,4,8];panic=c['present'] and not valid or not c['present'] and c['fallback']==MASK
  if not panic:
   value=int.from_bytes(bytes.fromhex(c['value_hex'])[:c['length']],'little') if c['present'] else c['fallback']
   ok('scalar_unsigned_little_endian_width_or_full64_fallback',int(row['boundary']['registers'][0],16)==value)
  ok('scalar_missing_mandatory_or_invalid_width_diagnostic',int(row['boundary']['PC'],16)==(R.PANIC if panic else HALT))
  ok('one_declared_property_output_contract',len(row['declared_models'])==1 and row['declared_models'][0]['name']=='declared_SecureDT_property_output')
 elif c['phase']=='setter':
  cpu=OTHER;w(cpu+0x30,8,R.THREAD);system.update(tpidr_el1=R.THREAD,tpidr_el0=(c['tpidr0']&0xffff000000000000)|(c['cpu_low48']&0xffffffffffff),tpidrro_el0=c['ro'],contextidr_el1=c['context'])
  ok('setter_return_boundary',int(row['boundary']['PC'],16)==HALT)
 ok('all_logical_system_register_results',row['final_system']==system)
 count=0
 for pg in expected:
  if pg==P+0xe000:continue # Stack page is checked byte-for-byte by fresh replay.
  ok('nonstack_page_'+hex(pg),expected[pg]==actual[pg]);count+=4096
 return {'checks':checks,'independent_nonstack_bytes_checked':count}

class Replay:
 def __init__(self,image,row):
  self.image=image;self.row=row;self.u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);self.seq=0;self.ri=0;self.wi=0;self.mi=0;self.ei=0;self.epoch=0;self.pending=[];self.system=dict(row['initial_system']);self.stopped=False;self.copy_entries=[]
  for pg,raw in pages(row['initial_pages']).items():self.u.mem_map(pg,4096);self.u.mem_write(pg,bytes(raw))
  for j,v in enumerate(row['initial_registers']):self.u.reg_write(regno(j),int(v,16))
  self.u.reg_write(ar.UC_ARM64_REG_SP,int(row['initial_SP'],16))
  self.u.hook_add(UC_HOOK_CODE,self.code);self.u.hook_add(UC_HOOK_MEM_READ,self.read);self.u.hook_add(UC_HOOK_MEM_WRITE,self.write)
 def regs(self):return [self.u.reg_read(regno(j)) for j in range(31)]
 def finish(self):
  for w in self.pending:assert bytes(self.u.mem_read(int(w['address'],16),w['size_bytes'])).hex()==w['after_hex']
  self.pending=[]
 def read(self,u,access,a,n,value,d):
  expected=self.row['reads'][self.ri];assert expected=={'visit':self.seq-1,'address':hex(a),'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()};self.ri+=1
 def write(self,u,access,a,n,value,d):
  w=self.row['writes'][self.wi];assert (w['visit'],w['address'],w['size_bytes'],w['before_hex'])==(self.seq-1,hex(a),n,bytes(u.mem_read(a,n)).hex());self.pending.append(w);self.wi+=1
 def code(self,u,a,n,d):
  self.finish()
  if a==int(self.row['boundary']['PC'],16):
   assert self.seq==len(self.row['source_visits']) and list(map(hex,self.regs()))==self.row['boundary']['registers'];self.stopped=True;u.emu_stop();return
  if self.epoch<len(self.row['epochs']) and a==int(self.row['epochs'][self.epoch]['PC'],16):
   epoch=self.row['epochs'][self.epoch];assert epoch['before_visit']==self.seq and epoch['writes_completed']==self.wi and epoch['system']==self.system and epoch['registers']==list(map(hex,self.regs()))
   self.epoch+=1;u.reg_write(ar.UC_ARM64_REG_SP,SP);u.reg_write(regno(30),HALT);u.reg_write(ar.UC_ARM64_REG_PC,R.CALLER);return
  if self.mi<len(self.row['declared_models']) and a==int(self.row['declared_models'][self.mi]['PC'],16):
   m=self.row['declared_models'][self.mi];before=self.regs();assert m['before_visit']==self.seq and m['registers_before']==list(map(hex,before)) and m['SP']==hex(u.reg_read(ar.UC_ARM64_REG_SP));expected_writes=[];c=self.row['configuration']
   if a==R.PROPERTY:
    assert m['name']=='declared_SecureDT_property_output' and before[0]==P+0x1000 and before[1]==R.STRINGS[0]
    treebase=int.from_bytes(u.mem_read(0xfffffe0007f8b508,8),'little');treeend=int.from_bytes(u.mem_read(0xfffffe0007f8b518,8),'little')
    assert before[4]==treebase and before[5]==(treeend-treebase)&MASK
    result=int(c['present'])
    if result:expected_writes=[(before[2],VALUE.to_bytes(8,'little')),(before[3],c['length'].to_bytes(4,'little'))]
   else:
    assert {R.SPTM:'declared_SPTM_CPU_initializer_no_RAM',R.CACHE:'declared_cache_initializer_no_RAM',R.CONFIG:'declared_CPU_context_initializer_no_RAM'}[a]==m['name'];result=0
    if a==R.CONFIG:assert before[:2]==[0,int.from_bytes(u.mem_read(R.THREAD+0x1c0,8),'little')]
   assert len(expected_writes)==len(m['api_writes'])
   for w,(at,data) in zip(m['api_writes'],expected_writes):
    assert w=={'address':hex(at),'before_hex':bytes(u.mem_read(at,len(data))).hex(),'after_hex':data.hex()};u.mem_write(at,data)
   for j in range(18):u.reg_write(regno(j),result if j==0 else ((j+1)*0x123456789abcdef^(self.mi+1)*0x8b3dc651)&MASK)
   u.reg_write(ar.UC_ARM64_REG_NZCV,0xf0000000 if self.mi%2==0 else 0)
   assert m['registers_after']==list(map(hex,self.regs())) and m['return_value']==hex(result) and m['NZCV_after']==hex(u.reg_read(ar.UC_ARM64_REG_NZCV))
   self.mi+=1;u.reg_write(ar.UC_ARM64_REG_PC,before[30]);return
  visit=self.row['source_visits'][self.seq];raw=bytes(u.mem_read(a,4));assert visit=={'PC':hex(a),'bytes_hex':raw.hex()} and raw==self.image.k.read(a,4);i=next(self.image.k.cs.disasm(raw,a));index=self.seq;self.seq+=1
  if a==R.COPY:self.copy_entries.append({'PC':hex(a),'arguments3':list(map(hex,self.regs()[:3])),'return_PC':hex(self.regs()[30]),'visit':index})
  if i.mnemonic in ['mrs','msr']:
   before=dict(self.system);left,right=i.op_str.split(', ')
   if i.mnemonic=='mrs':u.reg_write(getattr(ar,'UC_ARM64_REG_'+left.upper()),self.system[right])
   else:self.system[left]=0 if right=='xzr' else u.reg_read(getattr(ar,'UC_ARM64_REG_'+right.upper()))
   assert self.row['logical_effects'][self.ei]=={'visit':index,'PC':hex(a),'kind':'logical_system','mnemonic':i.mnemonic,'operands':i.op_str,'before':before,'after':dict(self.system)}
  elif i.mnemonic in ['pacibsp','autibsp','pacda','retab']:
   assert self.row['logical_effects'][self.ei]=={'visit':index,'PC':hex(a),'kind':'logical_PAC','mnemonic':i.mnemonic,'operands':i.op_str}
  else:return
  self.ei+=1;u.reg_write(ar.UC_ARM64_REG_PC,self.regs()[30] if i.mnemonic=='retab' else a+4)
 def run(self):
  self.u.emu_start(int(self.row['start'],16),0,count=10000);self.finish();assert self.stopped
  assert (self.ri,self.wi,self.mi,self.ei,self.epoch)==tuple(len(self.row[key]) for key in ['reads','writes','declared_models','logical_effects','epochs'])
  assert self.system==self.row['final_system'] and self.copy_entries==self.row['original_copy_entries']
  for pg,raw in pages(self.row['final_pages']).items():assert bytes(self.u.mem_read(pg,4096))==raw
  return {'source_visits_checked':self.seq,'reads_checked':self.ri,'writes_checked':self.wi,'declared_models_checked':self.mi,
   'logical_effects_checked':self.ei,'same_RAM_epochs_checked':self.epoch,'whole_mapped_bytes_checked':len(self.row['final_pages'])*4096}
