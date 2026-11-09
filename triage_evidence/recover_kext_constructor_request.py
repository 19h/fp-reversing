#!/usr/bin/env python3
"""Original constructor-to-request contracts and two local full-word identities.
O(image bytes+instructions), O(image bytes); timeout-bounded scalar proofs.
No native target, Mach, VM, allocator, PAC or IDB operation.
"""
import hashlib,json,struct,subprocess
import z3
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT,IMAGE
from recover_kext_close import ALU
P='kext_constructor_request'
def sha(p):
 with open(p,'rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def identities():
 m=z3.BitVec('copy_extent32',32);p=z3.BitVec('page_shift32',32)
 a=ALU({'x12':z3.ZeroExt(32,m)+0x3332e642601efea0,'w26':0xfffffffe},{'[sp, #0x138]':z3.BitVecVal(0,64),'[x8]':p}).run(0xfffffe000a60af44,0xfffffe000a60b014).run(0xfffffe000a60b018,0xfffffe000a60b460)
 actual=a.r[9]^a.r[8]^0x0160484004008104;mask=(z3.BitVecVal(1,64)<<z3.ZeroExt(32,p&31))-1
 alloc=z3.BitVec('allocation_extent64',64);extent=z3.BitVec('copy_extent64',64)
 b=ALU({'x27':alloc^0x0160484004008104,'w26':0x3e784ff5,'x25':extent+0x3332e642601efea0}).run(0xfffffe000a60b624,0xfffffe000a60b6ac)
 return [('staging_extent',actual!=((z3.ZeroExt(32,m)+mask)&~mask),'All u32 copy extents and u32 page-shift words, using low5 shift bits and original W26=FFFFFFFE; local load/encoded-extent premises.'),('fill_extent',b.r[8]+0x293f20ca16fd596f!=alloc-extent,'All u64 allocation/copy extents under original encoded-allocation, encoded-copy and W26=3E784FF5 premises; modular difference, not validity proof.')]
def main():
 im=Image();k=im.k;ranges=[]
 for a,z in [(0xfffffe000a66a7e0,0xfffffe000a66acb0),(0xfffffe000a606728,0xfffffe000a606d88),(0xfffffe000a607608,0xfffffe000a607704),(0xfffffe000a60a920,0xfffffe000a60b8bc),(0xfffffe000a5a2064,0xfffffe000a5a20fc),(0xfffffe000a5a22d4,0xfffffe000a5a236c),(0xfffffe000a60d334,0xfffffe000a60d3d0),(0xfffffe000a687d64,0xfffffe000a687ecc),(0xfffffe000bcf5f18,0xfffffe000bcf5f24)]:
  raw=k.read(a,z-a)
  if a<0xfffffe000b000000:assert IMAGE.read(a,z-a)==raw
  ranges.append({'start':hex(a),'end':hex(z),'bytes_hex':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest(),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in k.cs.disasm(raw,a)]})
 views=[]
 for a in [0xfffffe000847bea0,0xfffffe000847bd60]:
  raw=k.read(a,64);ptr=im.pointer(a+16);name=k.read(int(ptr['target'],16),100).split(b'\0')[0];views.append({'address':hex(a),'bytes64_hex':raw.hex(),'name_pointer':ptr,'name':name.decode(),'flags':struct.unpack_from('<I',raw,40)[0],'size_bytes':struct.unpack_from('<I',raw,44)[0]})
 proofs=[]
 for name,claim,domain in identities():
  s=z3.Solver();s.set(timeout=30000);s.add(claim);p=ROOT/(P+'_'+name+'.smt2');p.write_text('(set-option :timeout 30000)\n'+s.to_smt2());q=subprocess.run(['z3',str(p)],capture_output=True,text=True,check=True);assert q.stdout.strip()=='unsat'and not q.stderr,(name,q.stdout);proofs.append({'name':name,'path':p.name,'sha256':sha(p),'result':'unsat','domain':domain})
 targets=[0xfffffe000c4b9a08,0xfffffe000c4ba154,0xfffffe000c4ba60c,0xfffffe000c647f10,0xfffffe000bc9db70,0xfffffe000bcf27ac,0xfffffe000bcf258c,0xfffffe000bcf5f18,0xfffffe000bcf5e28]
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['recover_kext_close.py','kext_port_tools.py','kernel_vm_mig_tools.py','kext_port_vm_contracts.json']},'kernel_sha256':k.sha256,'ranges':ranges,'views':views,'exact_symbols':k.symbols(targets),'proofs':proofs,'native_target_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'full_goal_complete':False}
 (ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'ranges':len(ranges),'instructions':sum(len(r['instructions'])for r in ranges),'views':len(views),'proofs_unsat':len(proofs)}),flush=True)
if __name__=='__main__':main()
