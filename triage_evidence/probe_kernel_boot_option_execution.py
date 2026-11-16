#!/usr/bin/env python3
"""Original option scanner/converter composed with original tree/topology.
O(visits + journals + mapped bytes + fixtures) time/space. Private execution;
callback authentication and privileged effects are logical envelopes.
"""
import bisect
from unicorn import arm64_const as ar
from probe_kernel_secure_dt_execution import Probe as Parent,P,SP,HALT,WORK,TREE,rid,MASK,node,scalar,description
import recover_kernel_boot_option_execution as R
K=R.B.B.B;EXTRA=[R.PARSE,R.NUMBER,R.FLAG,R.SPACE,R.STRLEN];LIMIT=100000
class Probe(Parent):
 def __init__(self,image,c,mutate=None):
  super().__init__(image,c,None);self.mutate=mutate;self.option_entries=[];self.option_returns=[];self.option_stack=[]
  for a in [R.STRLEN,R.FLAG,R.NUMBER,R.SPACE]:
   end=image.k.starts[bisect.bisect_left(image.k.starts,a)+1]
   for pg in range(a&~4095,(end+4095)&~4095,4096):self.map(pg)
  raw=c.get('boot_text','').encode('ascii')+bytes(1);assert len(raw)<=256;self.put(K.ARGS+0x6c,raw)
  for j,op in enumerate(self.operations):
   assert op['kind']=='boot_parse' and op['width'] in [0,1,2,3,4,8,16,32]
   self.put(WORK+0x3000+j*0x100,op['text'].encode('ascii')+bytes(1))
  if mutate is not None:self.put(mutate,bytes.fromhex('1f2003d5'))
  for j in range(32):self.u.reg_write(getattr(ar,'UC_ARM64_REG_Q'+str(j)),0)
  self.initial_registers=self.regs();self.initial_pages={pg:bytes(self.u.mem_read(pg,4096)) for pg in self.pages}
 def next_operation(self):
  j=self.step;op=self.operations[j];args=[WORK+0x3000+j*0x100,WORK+0x480+j*0x200,WORK+j*64,op['width'],op.get('string_mode',0)]
  self.call(HALT,R.PARSE,'explicit_boot_option_API_call',args);self.step+=1
 def code(self,u,a,n,d):
  self.finish()
  while self.option_stack and a==int(self.option_entries[self.option_stack[-1]]['return_PC'],16) and u.reg_read(ar.UC_ARM64_REG_SP)==int(self.option_entries[self.option_stack[-1]]['entry_SP'],16):
   self.option_returns.append({'entry_index':self.option_stack.pop(),'before_visit':len(self.visits),'return_value':hex(self.regs()[0])})
  if a in EXTRA:
   self.option_stack.append(len(self.option_entries));self.option_entries.append({'PC':hex(a),'entry_SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'arguments6':list(map(hex,self.regs()[:6])),'return_PC':hex(self.regs()[30]),'before_visit':len(self.visits)})
  raw=self.im.k.read(a,4) if a not in [HALT,K.TAIL,K.PANIC] else None
  ins=next(self.im.k.cs.disasm(raw,a)) if raw is not None else None
  if a==R.PARSE or ins is not None and ins.mnemonic in ['pacia','blraa']:
   actual=bytes.fromhex('1f2003d5') if a==self.mutate else raw;ins=next(self.im.k.cs.disasm(actual,a));self.current=len(self.visits);self.visits.append({'PC':hex(a),'bytes_hex':actual.hex()});assert len(self.visits)<LIMIT
   if ins.mnemonic=='blraa':
    regs=self.regs();assert regs[19]==R.SPACE and regs[17]==0xba5
    self.events.append({'visit':self.current,'PC':hex(a),'kind':'logical_authenticated_call','target':hex(regs[19]),'discriminator':hex(regs[17]),'return_PC':hex(a+4)})
    u.reg_write(rid(30),a+4);u.reg_write(ar.UC_ARM64_REG_PC,regs[19]);return
   assert ins.mnemonic in ['pacibsp','pacia'];self.events.append({'visit':self.current,'PC':hex(a),'kind':'logical_PAC','mnemonic':ins.mnemonic,'operands':ins.op_str});u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  return super().code(u,a,n,d)
 def run(self):
  r=super().run();r['dedicated_option_API_returns']=r.pop('tree_API_returns');r.update(original_option_API_entries=self.option_entries,original_option_call_returns=self.option_returns,initial_vectors=['0x0']*32,final_vectors=[hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j)))) for j in range(32)],final_SP=hex(self.u.reg_read(ar.UC_ARM64_REG_SP)),final_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV)));assert not self.option_stack;return r

def cases():
 rows=[]
 def add(label,nodes,boot_text='',**extra):rows.append(dict(label=label,phase='original_options',nodes=nodes,boot_text=boot_text,**extra))
 add('default_options',[node(0x100)])
 add('decimal_CPU_limit',[node(0,b'stopped'),node(0x100,b'stopped'),node(0x201)],'cpus=1')
 add('hex_mask_and_limit',[node(0,b'stopped'),node(0x101),node(0x202,b'stopped')],'cpus=2 cpumask=0x4')
 add('binary_mask_and_octal_limit',[node(0,b'stopped'),node(0x101),node(0x202,b'stopped')],'cpus=02 cpumask=0b100')
 add('duplicate_last_values',[node(0,b'stopped'),node(0x101),node(0x202,b'stopped')],'cpus=3 cpus=2 cpumask=1 cpumask=0x4')
 add('tabs_bare_power_flag_and_thread_mode',[node(0x100)],'\t enable_skstb\tcluster_power=7 siq_realtime_thread_mode=3  ',io_found=True,chip=scalar(7))
 add('option_name_prefix_is_not_match',[node(0x100)],'cpus_extra=0 cpus=1 cpumask_extra=0')
 add('sixteen_CPUs_from_hex',[node(i,b'stopped') for i in range(15)]+[node(15)],'cpus=0x10')
 add('zero_CPU_limit',[node(0x100)],'cpus=0')
 # Dedicated well-formed calls keep output storage at least 64 B per call.
 groups=[
 ('radices_and_suffixes',[('n=17',4,0),('n=021',4,0),('n=0x11',4,0),('n=0b10001',4,0),('n=-17',8,0),('n=2K',8,0),('n=3m',8,0),('n=1G',8,0)]),
 ('numeric_widths',[('n=0x12345678',1,0),('n=0x12345678',2,0),('n=0x12345678',3,0),('n=0x12345678',4,0),('n=0x123456789abcdef0',8,0)]),
 ('presence_and_matching',[('n',0,0),('n=7',0,0),('n_extra=7',4,0),('absent=3',4,0),('n=1 n=7',4,0),('n= 7',4,0),('n =7',4,0)]),
 ('flags_and_strings',[('-n',1,0),('-n',2,0),('-n',3,0),('-n',4,0),('-n',8,0),('n=auto',16,0),('n=17',16,1),('n',16,1)])]
 for label,ops in groups:
  records=[dict(kind='boot_parse',text=text,key='-n' if text=='-n' else 'n',width=width,string_mode=mode) for text,width,mode in ops]
  if label=='presence_and_matching':records.append(dict(kind='boot_parse',text='n=7',key='n_extra',width=4,string_mode=0))
  add('API_'+label,[node(0x100)],operations=records)
 return rows
