#!/usr/bin/env python3
"""Time-output/four-word seed material into original state-mixing source.
O(prefix+visits+effects+serialized SSA bytes) time/space. Independent
API return/output inputs, zero native operations, fail-closed address/control.
"""
import z3
from daemon_entropy_return_symbolic import EntropyReturn
from daemon_entropy_return_restore import restore
from daemon_context_transfer_symbolic import IMAGE
from replay_daemon_context_transfer import unpack
from lskd_values_symbolic import resize
TIME=0x1002dc308;R2=0x1002dc3a0;R3=0x1002dc400

def decode(s,F):
 if'hex'in s:return z3.BitVecVal(int.from_bytes(bytes.fromhex(s['hex']),'little'),8*len(bytes.fromhex(s['hex'])))
 if'terms'in s:
  xs=[z3.BitVecVal(x,8)if isinstance(x,int)else z3.BitVec('unknown_'+hex(F+x['origin']),8)for x in reversed(s['terms'])];return xs[0]if len(xs)==1 else z3.Concat(*xs)
 symbols={n:z3.BitVec(n,b)for n,b in s['symbols']};out=z3.BitVec('__decoded',s['bits']);return z3.parse_smt2_string('(assert (= __decoded '+s['expr']+'))',decls={'__decoded':out,**symbols})[0].arg(1)

def apply_journal(v,t):
 for row in t['steps']:
  pc=int(row['pc'],16);assert IMAGE.read(pc,4).hex()==row['bytes_hex']
  for e in row['events']:
   a=int(e['address'],16);n=e['size_bytes'];value=decode(e['value'],v.F)
   for j in range(n):
    b=z3.simplify(z3.Extract(8*j+7,8*j,value))
    if e['kind']=='read'and a+j in v.bytes:assert z3.is_true(z3.simplify(v.bytes[a+j]==b)),(row['pc'],hex(a+j))
    v.bytes[a+j]=b
  for reg,s in row['registers_after'].items():v.regs[v.key(reg)]=decode(s,v.F)
  if'NZCV_after'in row:v.n,v.z,v.carry,v.overflow=[z3.BoolVal(bool(row['NZCV_after']&(1<<(31-j))))for j in range(4)]
 for j,s in enumerate(t['boundary']['registers31']):assert z3.is_true(z3.simplify(v.read('x'+str(j))==decode(s,v.F)))
 assert v.concrete(v.read('sp'),'SP')==int(t['boundary']['SP'],16)

class Material(EntropyReturn):
 def one(self,i):
  if i.mnemonic in ['csinc','csinv','csneg']:
   self.pc=i.address;o=i.operands;dest=i.reg_name(o[0].reg);n=self.width(dest);a=self.operand(i,o[1],n);b=self.operand(i,o[2],n);cc=i.op_str.rsplit(',',1)[1].strip();other=b+1 if i.mnemonic=='csinc'else ~b if i.mnemonic=='csinv'else -b;self.write(dest,z3.If(self.condition(cc),a,other));return
  if i.mnemonic=='ccmp':
   self.pc=i.address;o=i.operands;n=self.width(i.reg_name(o[0].reg));cond=self.condition(i.op_str.rsplit(',',1)[1].strip());a=self.operand(i,o[0],n);b=self.operand(i,o[1],n);fallback=o[2].imm;self.flags(a,b,a-b,True);self.n,self.z,self.carry,self.overflow=[z3.simplify(z3.If(cond,x,z3.BoolVal(bool(fallback&(1<<(3-j))))))for j,x in enumerate([self.n,self.z,self.carry,self.overflow])];return
  if i.mnemonic=='cinc':
   self.pc=i.address;o=i.operands;reg=i.reg_name(o[0].reg);n=self.width(reg);self.write(reg,z3.If(self.condition(i.op_str.rsplit(',',1)[1].strip()),self.operand(i,o[1],n)+1,self.operand(i,o[1],n)));return
  return super().one(i)
 @classmethod
 def from_sealed(cls,base,prefix,entropy):
  v=restore(base,prefix);v.__class__=cls;t=unpack(entropy);v.definitions=t['definitions'].copy()
  for reg,s in t['api_effects'].items():v.regs[v.key(reg)]=decode(s,v.F)
  apply_journal(v,t);v.steps=[];v.pool={};v.fixups=set();v.zero_reads=[];v.changed=set();v.api_models=[];v.phases=[];v.time_input_unknown=[];return v
 def api(self,pc,prefix,low32,writes=()):
  self.pc=pc;self.written={};self.events=[];self.definition_stage='API';before={k:self.shape(self.read(k),8)for k in ['sp']+['x'+str(j)for j in range(18,30)]}
  for at,n,value in writes:self.store(z3.BitVecVal(at,64),n,value,pc)
  self.write('x0',z3.Concat(z3.BitVec(prefix+'upper_x0',32),low32))
  for j in range(1,18):self.write('x'+str(j),z3.BitVec(prefix+'x'+str(j),64))
  for j in range(32):
   low=z3.Extract(63,0,self.read('q'+str(j)))if 8<=j<16 else None
   self.write('q'+str(j),z3.Concat(z3.BitVec(prefix+'q'+str(j)+'_upper',64),low)if low is not None else z3.BitVec(prefix+'q'+str(j),128))
  self.write('x30',z3.BitVecVal(pc+4,64));self.n,self.z,self.carry,self.overflow=[z3.Bool(prefix+x)for x in ['N','Z','C','V']]
  after={k:self.shape(self.read(k),8)for k in before};assert before==after
  self.api_models.append({'pc':hex(pc),'source_bytes_hex':IMAGE.read(pc,4).hex(),'prefix':prefix,'arguments':{'x0':hex(self.F+0x680),'x1':'0x0'}if pc==TIME else{},'argument_count':2 if pc==TIME else 0,'preserved_before':before,'preserved_after':after,'events':self.events.copy(),'register_effects':{k:self.shape(x,16 if k.startswith('q')else 8)for k,x in self.written.items()},'after_source_visits':len(self.steps),'native_target_executed':False})
 def model_time(self):
  assert all(self.F+0x680+j not in self.bytes for j in range(16));self.time_input_unknown=list(range(16))
  self.api(TIME,'api_time_',z3.BitVec('api_time_status32',32),[(self.F+0x680,8,z3.BitVec('api_time_seconds64',64)),(self.F+0x688,4,z3.BitVec('api_time_microseconds32',32))])
 def run_from(self,start,limit=1000000):
  pc=start;self.definition_stage='source';first=len(self.steps)
  for step in range(limit):
   if pc not in self.cache:self.cache[pc]=next(self.dec.disasm(IMAGE.read(pc,4),pc))
   i=self.cache[pc];self.pc=pc;self.events=[];self.written={};self.flag_change=False;row={'pc':hex(pc),'bytes_hex':bytes(i.bytes).hex(),'mnemonic':i.mnemonic};self.pool[hex(pc)]={**row,'operands':i.op_str}
   if i.mnemonic in ['braa','blraa','b','ret']:
    target=i.operands[0].imm if i.mnemonic=='b'else self.concrete(self.read('x30'if i.mnemonic=='ret'else i.reg_name(i.operands[0].reg)),'unknown-dependent branch target')
    if i.mnemonic=='blraa'and target not in [0x100427514,0x10041a5e0]:
     b={'pc':hex(pc),'target':hex(target),'registers31':[self.shape(self.read('x'+str(j)),8)for j in range(31)],'SP':hex(self.concrete(self.read('sp'),'SP'))};self.phases.append({'start':hex(start),'source_visits':len(self.steps)-first,'boundary':b});return b
    row['target']=hex(target)
    if i.mnemonic in ['braa','blraa']:row['modifier16']=hex(self.concrete(self.read(i.reg_name(i.operands[1].reg)),'modifier'))
    if i.mnemonic=='blraa':self.write('x30',z3.BitVecVal(pc+4,64))
    nextpc=target
   else:self.one(i);nextpc=pc+4
   row['events']=self.events;row['registers_after']={k:self.shape(x,16 if k.startswith('q')else 8)for k,x in self.written.items()}
   if self.flag_change:
    vals=[z3.simplify(x)for x in [self.n,self.z,self.carry,self.overflow]];assert all(z3.is_true(x)or z3.is_false(x)for x in vals),('unknown flags',hex(pc));row['NZCV_after']=sum(1<<(31-j)for j,x in enumerate(vals)if z3.is_true(x))
   self.steps.append(row);pc=nextpc
   if len(self.steps)%25000==0:print('source visits',len(self.steps),'PC',hex(pc),flush=True)
  raise AssertionError(('visit budget',hex(pc)))
 def run_material(self):
  self.model_time();b=self.run_from(TIME+4);assert b['pc']==hex(R2);self.api(R2,'api_second_',z3.BitVec('api_second_entropy32',32));b=self.run_from(R2+4);assert b['pc']==hex(R3);self.api(R3,'api_third_',z3.BitVec('api_third_entropy32',32));return self.run_from(R3+4)
