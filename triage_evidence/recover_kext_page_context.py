#!/usr/bin/env python3
"""Original page wrapper, linked token lookup and page-consumer gate evidence.
O(image bytes+instructions+256*banks), O(image bytes), timeout-bounded proofs.
"""
import hashlib,json,struct,subprocess
from pathlib import Path
import z3
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT,IMAGE,POOL,TABLE,qword,selected
from recover_kext_close import ALU,consumer
P='kext_page_context'
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 im=Image();k=im.k;spans=[(0xfffffe000a5a4bc0,0xfffffe000a5a5020),(0xfffffe000a5b07f4,0xfffffe000a5b0ae0),(0xfffffe000a606728,0xfffffe000a606d68),(0xfffffe000a609f50,0xfffffe000a60a0b0),(0xfffffe000a60cb84,0xfffffe000a60cc4c),(0xfffffe000a60dc40,0xfffffe000a60e100)];ranges=[]
 for a,z in spans:
  raw=k.read(a,z-a);assert IMAGE.read(a,z-a)==raw;ranges.append({'start':hex(a),'end':hex(z),'bytes_hex':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest(),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in k.cs.disasm(raw,a)]})
 T=z3.BitVec('token32',32);N=z3.BitVec('node_word4_u32',32);A=z3.BitVec('record_pointer64',64)
 bt=ALU({'w21':0x90b},{'[x28]':T}).run(0xfffffe000a609f54,0xfffffe000a609f84).w(8)
 val=ALU({'w13':z3.ZeroExt(32,T+0x7a2abb13)},{'[x8, #4]':N}).run(0xfffffe000a5b09b4,0xfffffe000a5b0a14).w(13)
 OFF=z3.BitVec('page_offset64',64);O=z3.BitVec('owner_pointer64',64);mask=ALU({'w19':0x362},{'[x27]':O,'[x28, #8]':OFF}).run(0xfffffe000a60a060,0xfffffe000a60a084).r[11]
 queries=[('page_token_bias',bt!=T+0x7a2abb13),('node_token_match',(val==0xabd8bb79)!=(N==(T^0x31ae0066))),('record_address_key',consumer(A)!=((z3.Extract(31,0,A)^0x280834b2)*0xf87ec353)),('offset_mask',mask!=0xfffff00000000fff),('offset_domain',((OFF&0xfffff00000000fff)==0)!=z3.And((OFF&4095)==0,z3.ULT(OFF,1<<44)))]
 proofs=[]
 for name,claim in queries:
  s=z3.Solver();s.set(timeout=60000);s.add(claim);path=ROOT/f'{P}_{name}.smt2';path.write_text('(set-option :timeout 60000)\n'+s.to_smt2());r=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);assert r.stdout.strip()=='unsat'and not r.stderr,(name,r.stdout);proofs.append({'name':name,'path':path.name,'sha256':sha(path),'result':'unsat','domain':'All u32 token/node fields or u64 record addresses; local GPR/load contracts, fixed page producer W21=0x90b; no native lookup/reachability proof.'})
 views=[]
 for a in [0xfffffe000847bea0,0xfffffe000847ba60,0xfffffe000847b760,0xfffffe000847c320]:
  raw=k.read(a,64);p=im.pointer(a+0x10);name=k.read(int(p['target'],16),100).split(b'\0')[0];views.append({'address':hex(a),'bytes64_hex':raw.hex(),'name_pointer':p,'name':name.decode(),'flags':struct.unpack_from('<I',raw,0x28)[0],'size_bytes':struct.unpack_from('<I',raw,0x2c)[0]})
 banks=[]
 for name,l,r,key,add,base,bias in [('dispatcher',qword(POOL+0x840),qword(POOL+0xbb8),0xb4,0xeb9,TABLE,0),('shared_lookup',qword(POOL+0x458)-8,qword(POOL+0x638)-12,0x87,0xe47,TABLE,0),('registry_cell',qword(POOL+0xb70),qword(POOL+0xa10),0x92,0xb5,POOL,0)]:
  b=selected(l,r,key,add,base,bias);b.update(name=name,original_pointer=im.pointer(int(b['slot'],16)),left_bytes256_hex=k.read(l,256).hex(),right_bytes256_hex=k.read(r,256).hex());banks.append(b)
 assert[b['target']for b in banks]==['0xfffffe000a606728','0xfffffe000a5b07f4','0xfffffe000cccca58']
 return {'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['recover_kext_close.py','kext_port_tools.py','kernel_vm_mig_tools.py','kext_security_record_source.json']},'kernel_sha256':k.sha256,'ranges':ranges,'views':views,'banks':banks,'proofs':proofs,'native_target_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'full_goal_complete':False}
if __name__=='__main__':
 out=main();(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'ranges':len(out['ranges']),'instructions':sum(len(r['instructions'])for r in out['ranges']),'views':len(out['views']),'banks256':len(out['banks']),'proofs_unsat':len(out['proofs'])}),flush=True)
