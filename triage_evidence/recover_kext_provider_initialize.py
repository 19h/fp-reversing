#!/usr/bin/env python3
"""Original provider-start initialization, table publication and masked-load bound.
O(image bytes+instructions+256*banks), O(image bytes); timeout-bounded SMT.
No native target, allocator, lock, clock, hardware, IPC, PAC or IDB operation.
"""
import hashlib,json,subprocess,struct
import z3
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT,IMAGE,POOL,selected
from recover_kext_constructor_request import sha
P='kext_provider_initialize'
def main():
 im=Image();k=im.k;ranges=[]
 for a,z in [(0xfffffe000a50ab58,0xfffffe000a50abe4),(0xfffffe000a5a38cc,0xfffffe000a5a3d08),(0xfffffe000a606e50,0xfffffe000a607000),(0xfffffe000a62784c,0xfffffe000a627d54),(0xfffffe000a616d58,0xfffffe000a616fc8),(0xfffffe000a66af38,0xfffffe000a6721c0),(0xfffffe000a5b4314,0xfffffe000a5b6280),(0xfffffe000a6236bc,0xfffffe000a623764),(0xfffffe000a508cc4,0xfffffe000a508cec)]:
  raw=k.read(a,z-a);assert IMAGE.read(a,z-a)==raw;ranges.append({'start':hex(a),'end':hex(z),'bytes_hex':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest(),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in k.cs.disasm(raw,a)]})
 banks=[]
 for name,l,r,key,add,bias in [('table_base_cell',0xfffffe000792fcc0,0xfffffe00079391f0,0x87,-0x6d,-4),('table_mask_cell',0xfffffe0007949dd0,0xfffffe000792fbc0,0x73,0x67,0)]:
  b=selected(l,r,key,add,POOL,bias);b.update(name=name,left256_hex=k.read(l,256).hex(),right256_hex=k.read(r,256).hex(),original_pointer=im.pointer(int(b['slot'],16)));banks.append(b)
 assert[b['target']for b in banks]==['0xfffffe000cccda68','0xfffffe000ccceaf8']
 a=z3.BitVec('derived_address64',64);low=z3.Extract(31,0,a&~z3.BitVecVal(7,64));index=z3.SignExt(32,(low+0xc9011056)&0xff)&~z3.BitVecVal(7,64);reference=(a+0x50)&0xf8;s=z3.Solver();s.set(timeout=30000);s.add(z3.Or(index!=reference,z3.UGT(index,248),(index&7)!=0,z3.UGT(index+8,256)));p=ROOT/(P+'_masked_lookup.smt2');p.write_text('(set-option :timeout 30000)\n'+s.to_smt2());r=subprocess.run(['z3',str(p)],capture_output=True,text=True,check=True);assert r.stdout.strip()=='unsat'and not r.stderr
 # Check the manually translated local source operands verbatim.
 expected=[('and','x12, x11, #0xfffffffffffffff8'),('ldr','w13, [x13]'),('mov','w14, #0x1056'),('movk','w14, #0xc901, lsl #16'),('add','w14, w12, w14'),('and','w13, w14, w13'),('sxtw','x13, w13'),('ldr','x14, [sp, #0x98]'),('ldr','x14, [x14]'),('and','x13, x13, #0xfffffffffffffff8'),('add','x13, x14, x13')];actual=[(i.mnemonic,i.op_str)for i in k.cs.disasm(k.read(0xfffffe000a5b5154,0x2c),0xfffffe000a5b5154)];assert actual==expected
 symbols=k.symbols([0xfffffe000a5a38cc,0xfffffe000c4b9a08,0xfffffe000c4ba154,0xfffffe000c4ba60c,0xfffffe000c4b9428,0xfffffe000c4bb23c,0xfffffe000bd040f0,0xfffffe000bd054c4,0xfffffe000c4bb2c4,0xfffffe000c4ba368,0xfffffe000c4b9a24,0xfffffe000c4ba84c,0xfffffe000c4b94b8,0xfffffe000c4babac,0xfffffe000bce3a8c]);views=[]
 for address in [0xfffffe000847bea0,0xfffffe000847ba60]:
  raw=k.read(address,64);ptr=im.pointer(address+16);name=k.read(int(ptr['target'],16),100).split(b'\0')[0];views.append({'address':hex(address),'bytes64_hex':raw.hex(),'name_pointer':ptr,'name':name.decode(),'size_bytes':struct.unpack_from('<I',raw,44)[0]})
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['kernel_vm_mig_tools.py','kext_port_tools.py','kext_constructor_reply_state_source.json','kext_constructor_request_source.json']},'kernel_sha256':k.sha256,'ranges':ranges,'banks':banks,'views':views,'exact_symbols':symbols,'consumer_operand_checks':expected,'proofs':[{'name':'masked_lookup','path':p.name,'sha256':sha(p),'result':'unsat','domain':'All u64 derived addresses, under source-produced maskFF and the captured alignment/add/mask/sign-extension sequence; offset is(a+50)&F8, aligned8 and <=248. Base/owner validity is separate.'}],'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'ranges':len(ranges),'instructions':sum(len(r['instructions'])for r in ranges),'banks256':len(banks),'views':len(views),'proofs_unsat':1}),flush=True)
if __name__=='__main__':main()
