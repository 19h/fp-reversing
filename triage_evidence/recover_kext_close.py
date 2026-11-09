#!/usr/bin/env python3
"""Source-pinned close-wrapper token/record lifts and exact bank bindings.

Only local reviewed GPR operations and declared loads are interpreted. Five
bounded scalar proofs do not establish valid registry state or finalization.
No native target/API or IDB operation. O(B+I+F), plus timeout-bounded solvers.
"""
import hashlib,json,re,struct,subprocess
from pathlib import Path
import z3
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,POOL,TABLE,qword,selected

class ALU:
 def __init__(self,regs,loads=None):self.r={int(k[1:]):z3.BitVecVal(v,64)if isinstance(v,int)else(z3.ZeroExt(32,v)if v.size()==32 else v)for k,v in regs.items()};self.loads=loads or{}
 def val(self,s,width):
  if s.startswith('#'):return z3.BitVecVal(int(s[1:],0)&((1<<width)-1),width)
  if s in['wzr','xzr']:return z3.BitVecVal(0,width)
  assert re.fullmatch('[wx][0-9]+',s),s;v=self.r[int(s[1:])];return z3.Extract(31,0,v)if width==32 else v
 def run(self,a,z):
  for i in CS.disasm(IMAGE.read(a,z-a),a):
   m=i.mnemonic;v=[x.strip()for x in i.op_str.split(',')];dst=v[0];assert re.fullmatch('[wx][0-9]+',dst),(hex(i.address),i.op_str);w=32 if dst[0]=='w'else 64
   if m=='ldr':res=self.loads[', '.join(v[1:])];res=z3.Extract(31,0,res)if w==32 and res.size()==64 else res
   elif m=='mov':res=self.val(v[1],w)
   elif m=='movk':
    shift=int(v[2].split('#')[-1],0)if len(v)>2 else 0;res=(self.val(dst,w)&z3.BitVecVal(((1<<w)-1)^(65535<<shift),w))|(self.val(v[1],w)<<shift)
   else:
    x=self.val(v[1],w);y=self.val(v[2],w)
    if len(v)>3:assert v[3].startswith('lsl #');y=y<<int(v[3].split('#')[1],0)
    if m=='add':res=x+y
    elif m=='sub':res=x-y
    elif m=='eor':res=x^y
    elif m=='orr':res=x|y
    elif m=='orn':res=x|~y
    elif m=='and':res=x&y
    elif m=='mul':res=x*y
    elif m=='lsl':res=x<<(y&(w-1))
    else:raise ValueError((hex(i.address),m,i.op_str))
   self.r[int(dst[1:])]=z3.ZeroExt(32,res)if w==32 else res
  return self
 def w(self,n):return z3.Extract(31,0,self.r[n])
def token(T):return ALU({'w28':0x34d9d269},{'[sp, #0x30]':T}).run(0xfffffe000a5c095c,0xfffffe000a5c099c).w(8)
def producer(P):return ALU({'x20':P}).run(0xfffffe000a5c099c,0xfffffe000a5c09d0).w(9)
def consumer(P):return ALU({'x0':P}).run(0xfffffe000a5b0894,0xfffffe000a5b08e0).w(9)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 P=z3.BitVec('argument_address64',64);T=z3.BitVec('token_input64',64);p=z3.Extract(31,0,P);t=z3.Extract(31,0,T);K=producer(P);N=z3.BitVec('token_biased_word32',32);Q=z3.BitVec('address_key_word32',32);queries=[('token_compact',token(T)!=t+0x7a2abb13),('producer_compact',K!=(p^0x280834b2)*0xf87ec353),('consumer_equivalence',consumer(P)!=K),('token_roundtrip',(N^Q)^Q!=N),('operation_index',(Q+0xc18)-Q!=0xc18)];proofs=[]
 for name,claim in queries:
  s=z3.Solver();s.set(timeout=60000);s.add(claim);path=ROOT/f'kext_close_{name}.smt2';path.write_text('(set-option :timeout 60000)\n'+s.to_smt2());r=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);assert r.stdout.strip()=='unsat'and not r.stderr;proofs.append({'name':name,'path':path.name,'sha256':sha(path),'result':'unsat','domain':'All32-bit codec words,composed with the preceding proven source identities.'if name in['token_roundtrip','operation_index']else'All64-bit token/address inputs;local scalar GPR identities with recorded fixed W28 seed.'})
 banks=[]
 for name,l,r,k,a,b,bias in[('warm prepare',0xfffffe0007941f60,0xfffffe000794a0d0,0x6d,0xf2b,TABLE,0),('warm record dispatcher',qword(POOL+0x4f0)-4,qword(POOL+0x578)-4,0xef,0xec5,TABLE,0),('registry cell',qword(POOL+0xb70),qword(POOL+0xa10),0x92,0xb5,POOL,0),('record dispatcher table',0xfffffe000792fdc0,0xfffffe00079392f0,0x93,-0xb9,POOL,-12)]:
  e=selected(l,r,k,a,b,bias);e.update(label=name,left256_hex=IMAGE.read(l,256).hex(),right256_hex=IMAGE.read(r,256).hex(),original_slot_word_hex=IMAGE.read(int(e['slot'],16),8).hex());banks.append(e)
 assert [e['target']for e in banks]==['0xfffffe000a66acb0','0xfffffe000a5b07f4','0xfffffe000cccca58','0xfffffe0008472f20']
 ranges=[]
 for a,z in[(0xfffffe000a5bff88,0xfffffe000a5c0178),(0xfffffe000a5c0868,0xfffffe000a5c0a88),(0xfffffe000a5b07f4,0xfffffe000a5b0ae0),(0xfffffe000a5c1600,0xfffffe000a5c16f8),(0xfffffe000a66acb0,0xfffffe000a66af20)]:
  raw=IMAGE.read(a,z-a);ranges.append({'start':hex(a),'end':hex(z),'bytes':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest(),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(raw,a)]})
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in['probe_kext_close.py','kext_close_profiles.json','kext_port_tools.py','kernel_collection_interfaces.json']},'source_ranges':ranges,'banks':banks,'proofs':proofs,'null_registry_base_index':hex(0xc18),'null_registry_target':hex(qword(TABLE+0xc18*8)),'tag85150332_nonnull_target':hex(qword(TABLE+0xeac*8)),'tag85150332_wrapper_association':'unknown','native_target_executed':False,'complete_finalization_proved':False,'full_goal_complete':False};(ROOT/'kext_close_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'source_ranges':len(ranges),'banks_256':len(banks),'proofs_unsat':len(proofs)}),flush=True)
if __name__=='__main__':main()
