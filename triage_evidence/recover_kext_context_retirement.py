#!/usr/bin/env python3
"""Original KBCrypt close, list removal and bounded overwrite evidence.
O(image bytes+instructions+256*banks), O(image bytes), bounded scalar proof.
"""
import hashlib,json,struct,subprocess
from pathlib import Path
import z3
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT,IMAGE,POOL,TABLE,qword,selected
from recover_kext_close import ALU
P='kext_context_retirement'
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def byte_ref(v):
 # All intermediates below are bytes; original source uses u32 operations.
 a=v^0xf8;b=v&0x9e;c=(v^0xdc)&(b<<1);b^=c;d=(((a<<1)^0xcc)&a)^((a<<1)&0x66);c=(d^0x40)&(b<<2);b^=c;c=((d<<2)^0x80)&(d^0x40)&(b<<4);b^=c;return((v^(b<<1)^0x24)*(v+0xaf))&255
def byte_source(v):
 r={'w9':v,'w12':0x52a4eef8,'w13':0x61d8a19e,'w15':0x5194addc,'w16':0x66f89ecc,'w0':0x337c4f66,'w28':0x02600e40,'w2':0x44110480,'w3':0x22780e40,'w4':0x24}
 return ALU(r).run(0xfffffe000a5c14c8,0xfffffe000a5c1520).w(17)
def main():
 im=Image();k=im.k;ranges=[]
 for a,z in [(0xfffffe000a5bff88,0xfffffe000a5c16fc),(0xfffffe000a5b07f4,0xfffffe000a5b0ae0),(0xfffffe000a5bfc6c,0xfffffe000a5bff88),(0xfffffe000a66acb0,0xfffffe000a66af38),(0xfffffe000a68789c,0xfffffe000a687b04),(0xfffffe000a6165d0,0xfffffe000a616660)]:
  raw=k.read(a,z-a);assert IMAGE.read(a,z-a)==raw;ranges.append({'start':hex(a),'end':hex(z),'bytes_hex':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest(),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in k.cs.disasm(raw,a)]})
 v=z3.BitVec('overwrite_counter32',32);x=z3.Extract(7,0,v);proof=z3.Solver();proof.set(timeout=60000);proof.add(z3.Extract(7,0,byte_source(v))!=byte_ref(x));path=ROOT/(P+'_overwrite_byte.smt2');path.write_text('(set-option :timeout 60000)\n'+proof.to_smt2());res=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);assert res.stdout.strip()=='unsat'and not res.stderr
 views=[]
 for a in [0xfffffe000847ba20,0xfffffe000847bc60]:
  raw=k.read(a,64);ptr=im.pointer(a+0x10);name=k.read(int(ptr['target'],16),100).split(b'\0')[0];flags,size=struct.unpack_from('<II',raw,0x28);views.append({'address':hex(a),'bytes64_hex':raw.hex(),'name_pointer':ptr,'name':name.decode(),'flags':flags,'size_bytes':size})
 assert[(v['name'],v['size_bytes'])for v in views]==[('site.KBCrypt',1088),('site.FPAppSecurityInfo',152)]
 banks=[]
 for name,key,add,base,bias in [('owner_free',0x92,0xe89,TABLE,0),('owner_view',0x32,0x38,POOL,0)]:
  l=qword(POOL+0xb70);r=qword(POOL+0xa10);b=selected(l,r,key,add,base,bias);b.update(name=name,left_bytes256_hex=k.read(l,256).hex(),right_bytes256_hex=k.read(r,256).hex(),original_pointer=im.pointer(int(b['slot'],16)));banks.append(b)
 assert[b['target']for b in banks]==['0xfffffe000c4ba368','0xfffffe000847ba20']
 return {'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['recover_kext_close.py','kext_port_tools.py','kernel_vm_mig_tools.py','kext_page_context_source.json','kext_mapped_cleanup_source.json']},'kernel_sha256':k.sha256,'ranges':ranges,'views':views,'banks':banks,'proofs':[{'name':'overwrite_byte','path':path.name,'sha256':sha(path),'result':'unsat','domain':'All u32 counter words under original fixed loop constants; low byte equals the separate byte reference.'}],'byte_table256_hex':bytes(byte_ref(n)for n in range(256)).hex(),'native_target_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'full_goal_complete':False}
if __name__=='__main__':
 out=main();(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'ranges':len(out['ranges']),'instructions':sum(len(r['instructions'])for r in out['ranges']),'views':len(out['views']),'banks256':len(out['banks']),'proofs_unsat':len(out['proofs'])}),flush=True)
