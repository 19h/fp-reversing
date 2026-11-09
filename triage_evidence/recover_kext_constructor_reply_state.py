#!/usr/bin/env python3
"""Original post-reply allocation/startup/entropy-state contracts and scalar proof.
O(image bytes+instructions+256*banks), O(image bytes); bounded SMT cost.
No target, IPC, VM, hardware, PAC or IDB operation.
"""
import hashlib,json,struct,subprocess
import z3
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT,IMAGE,POOL,TABLE,selected
from recover_kext_close import ALU
from recover_kext_constructor_request import sha
P='kext_constructor_reply_state'
def recurrence():
 t=z3.BitVec('previous_xor_shift30',32);i=z3.BitVec('seed_index32',32)
 a=ALU({'w11':t,'w1':0x539d4b96,'w2':0x2b00b9e7,'w3':0xc140ea2c,'w4':0xb9dd185d,'w5':0x92dda1ba,'w6':0xea4053cb,'w15':0x6c078965,'w8':i,'w9':i+0x95d9e06b,'w16':0x95d9e06b}).run(0xfffffe000a5b4eb8,0xfffffe000a5b4ee8)
 return z3.Or(a.w(11)!=0x6c078965*t+i,a.w(0)!=a.w(11))
def main():
 im=Image();k=im.k;ranges=[]
 for a,z in [(0xfffffe000a60d334,0xfffffe000a60d708),(0xfffffe000a61230c,0xfffffe000a6126cc),(0xfffffe000a6110d0,0xfffffe000a6114d0),(0xfffffe000a5b4314,0xfffffe000a5b5a00),(0xfffffe000a627d54,0xfffffe000a628060),(0xfffffe000a508cc4,0xfffffe000a508cec),(0xfffffe000bce3a8c,0xfffffe000bce3b90),(0xfffffe000a508030,0xfffffe000a5081b0)]:
  raw=k.read(a,z-a)
  if a<0xfffffe000b000000:assert IMAGE.read(a,z-a)==raw
  ranges.append({'start':hex(a),'end':hex(z),'bytes_hex':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest(),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in k.cs.disasm(raw,a)]})
 views=[]
 for a in [0xfffffe000847baa0,0xfffffe000847c220,0xfffffe000847ba20,0xfffffe000847b460]:
  b=k.read(a,64);ptr=im.pointer(a+16);name=k.read(int(ptr['target'],16),100).split(b'\0')[0];views.append({'address':hex(a),'bytes64_hex':b.hex(),'name_pointer':ptr,'name':name.decode(),'flags':struct.unpack_from('<I',b,40)[0],'size_bytes':struct.unpack_from('<I',b,44)[0]})
 banks=[]
 for name,l,r,key,add,base,bias in [('owner_allocation_view',0xfffffe0007949ed0,0xfffffe000792fec0,0x92,0x111,POOL,-12),('shared_allocation_view',0xfffffe0007949dd0,0xfffffe000792fbc0,0x73,0x19c,POOL,0),('later_filename_lookup_helper',0xfffffe0007949fd0,0xfffffe000792ffc0,0x37,0xf6b,TABLE,0)]:
  b=selected(l,r,key,add,base,bias);b.update(name=name,left256_hex=k.read(l,256).hex(),right256_hex=k.read(r,256).hex(),original_pointer=im.pointer(int(b['slot'],16)));banks.append(b)
 assert[b['target']for b in banks]==['0xfffffe000847c220','0xfffffe000847baa0','0xfffffe000a509114']
 s=z3.Solver();s.set(timeout=30000);s.add(recurrence());path=ROOT/(P+'_seed_recurrence.smt2');path.write_text('(set-option :timeout 30000)\n'+s.to_smt2());q=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);assert q.stdout.strip()=='unsat'and not q.stderr
 pointers=[im.pointer(a)for a in [0xfffffe0008472290,0xfffffe0008472470]];symbols=k.symbols([0xfffffe000a508cc4,0xfffffe000c4babac,0xfffffe000bce3a8c,0xfffffe000c4ece88,0xfffffe000a509114])
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['recover_kext_close.py','recover_kext_constructor_request.py','kext_port_tools.py','kernel_vm_mig_tools.py','kext_constructor_request_source.json','rpc502_reply_bridge_source.json','daemon_entropy_return_contracts.json']},'kernel_sha256':k.sha256,'ranges':ranges,'views':views,'banks':banks,'global_pool_pointers':pointers,'initial_global_bytes':{hex(a):k.read(a,n).hex()for a,n in [(0xfffffe000cccda68,8),(0xfffffe000ccceaf8,4)]},'strings':{hex(a):k.read(a,100).split(b'\0')[0].decode()for a in [0xfffffe000790caf5,0xfffffe000790ba3c]},'exact_symbols':symbols,'proofs':[{'name':'seed_recurrence','path':path.name,'sha256':sha(path),'result':'unsat','domain':'All u32 previous_xor_shift30 and u32 indices under recorded original loop constants; proves source stored word and next W0 equal 6C078965*t+index modulo2^32. Shift30 and loop bounds are separate source instructions.'}],'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False}
 (ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'ranges':len(ranges),'instructions':sum(len(r['instructions'])for r in ranges),'views':len(views),'banks256':len(banks),'proofs_unsat':1}),flush=True)
if __name__=='__main__':main()
