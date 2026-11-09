"""Original-source continuation; imports and PAC are not executed."""
import z3
from daemon_context_transfer_symbolic import IMAGE
def run_path(self,start,limit=200000):
 pc=start;self.definition_stage='source';first=len(self.steps)
 for step in range(limit):
  if pc not in self.cache:self.cache[pc]=next(self.dec.disasm(IMAGE.read(pc,4),pc))
  i=self.cache[pc];self.pc=pc;self.events=[];self.written={};self.flag_change=False;row={'pc':hex(pc),'bytes_hex':bytes(i.bytes).hex(),'mnemonic':i.mnemonic};self.pool[hex(pc)]={**row,'operands':i.op_str}
  if i.mnemonic in ['braa','blraa','b','ret']:
   target=i.operands[0].imm if i.mnemonic=='b'else self.concrete(self.read('x30'if i.mnemonic=='ret'else i.reg_name(i.operands[0].reg)),'unknown-dependent branch target')
   if i.mnemonic=='blraa'and target not in [0x100427514,0x10041a5e0,0x100444d6c]:
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
  if row['pc']=='0x100350624':self.export_count+=1
  if self.export_count==2:
   self.pc=pc
   return {'pc':hex(pc),'kind':'two_prng_heap_updates_complete','registers31':[self.shape(self.read('x'+str(j)),8)for j in range(31)],'SP':hex(self.concrete(self.read('sp'),'SP'))}
  if len(self.steps)%25000==0:print('source visits',len(self.steps),'PC',hex(pc),flush=True)
 self.pc=pc
 raise AssertionError(('visit budget',hex(pc)))
