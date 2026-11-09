"""Source-bound u32/u64 lift extension for conditional selectors and CLZ queries."""
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from prove_daemon_prng_output import OutLift
from lskd_values_symbolic import resize
class GlobalLift(OutLift):
 def run(self,label):
  row=next(s for s in self.c['spans']if s['label']==label);cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;old=self.c
  for i in cs.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   self.pc=i.address
   if i.mnemonic=='csel':
    cc=i.op_str.rsplit(',',1)[1].strip();o=i.operands;n=self.width(i.reg_name(o[0].reg));conditions={'eq':self.equal,'ne':z3.Not(self.equal),'lo':z3.ULT(self.sleft,self.sright),'hs':z3.UGE(self.sleft,self.sright),'hi':z3.UGT(self.sleft,self.sright),'ls':z3.ULE(self.sleft,self.sright)};assert cc in conditions;self.write(i.reg_name(o[0].reg),z3.If(conditions[cc],self.operand(i,o[1],n),self.operand(i,o[2],n)));self.count+=1
   else:self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};OutLift.run(self,'one')
  self.c=old;return self
