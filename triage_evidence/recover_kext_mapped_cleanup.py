#!/usr/bin/env python3
"""Original-file capture of FairPlay close mapped-region cleanup.
Read only target files. O(image bytes+instructions+256*banks), O(image bytes).
Scalar proofs are fixed-page component contracts, not native reachability.
"""
import hashlib,json,re,struct,subprocess
from pathlib import Path
import z3
from kernel_vm_mig_tools import Image as KC
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,POOL,TABLE,qword,selected
PREFIX='kext_mapped_cleanup'
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def capture(k,a,z):
 raw=k.read(a,z-a)
 if 0xfffffe000a500000<=a<0xfffffe000a700000:assert IMAGE.read(a,z-a)==raw
 return {'start':hex(a),'end':hex(z),'bytes_hex':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest(),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(raw,a)]}
def scalar(p):
 """Interpret reviewed source GPR words; each load has an explicit contract."""
 A=z3.BitVec('mapped_address64',64);L=z3.BitVec('mapped_extent32',32)
 r={8:A,21:z3.BitVecVal(0x962,64),15:z3.BitVecVal(0xa41a4d891208c018,64),19:z3.BitVecVal(0,64)}
 loads={0xe48:z3.BitVecVal(1,64),0xe70:z3.ZeroExt(32,z3.BitVec('ambient_a32',32)),0xe74:z3.ZeroExt(32,z3.BitVec('ambient_b32',32)),0xe90:z3.BitVecVal(0,64),0xe98:z3.ZeroExt(56,z3.BitVec('bank_byte0',8)),0xea4:z3.ZeroExt(56,z3.BitVec('bank_byte1',8)),0xebc:z3.BitVecVal(0,64),0xec0:z3.BitVecVal(p,64),0xef4:z3.ZeroExt(32,L),0xf44:z3.ZeroExt(56,z3.BitVec('bank_byte2',8)),0xf50:z3.BitVecVal(0,64),0xf54:z3.ZeroExt(56,z3.BitVec('bank_byte3',8)),0xf68:z3.BitVecVal(0,64)}
 def value(s,w):
  if s.startswith('#'):return z3.BitVecVal(int(s[1:],0)&((1<<w)-1),w)
  assert re.fullmatch('[wx][0-9]+',s),s
  return z3.Extract(31,0,r[int(s[1:])])if w==32 else r[int(s[1:])]
 for i in CS.disasm(IMAGE.read(0xfffffe000a5c0e38,0x144),0xfffffe000a5c0e38):
  m=i.mnemonic;v=[s.strip()for s in i.op_str.split(',')]
  if m=='bti':continue
  w=32 if v[0][0]=='w'else 64;d=int(v[0][1:]);off=i.address-0xfffffe000a5c0000
  if m in ['ldr','ldrb','ldrsw']:res=loads[off];res=z3.Extract(31,0,res)if w==32 else res
  elif m=='mov':res=value(v[1],w)
  elif m=='movk':
   n=int(v[2].split('#')[1],0)if len(v)>2 else 0;res=(value(v[0],w)&z3.BitVecVal(((1<<w)-1)^(65535<<n),w))|(value(v[1],w)<<n)
  elif m=='mvn':res=~value(v[1],w)
  else:
   x=value(v[1],w);y=value(v[2],w)
   if len(v)>3:assert v[3].startswith('lsl #');y=y<<int(v[3].split('#')[1],0)
   if m=='add':res=x+y
   elif m=='sub':res=x-y
   elif m=='eor':res=x^y
   elif m=='and':res=x&y
   elif m=='mul':res=x*y
   elif m=='lsl':res=x<<(y&(w-1))
   else:raise AssertionError((hex(i.address),m))
  r[d]=z3.ZeroExt(32,res)if w==32 else res
 mask=z3.BitVecVal(((1<<64)-1)^((1<<p)-1),64)
 return [(f'start_p{p}',r[1]!=(A&mask)),(f'end_p{p}',r[2]!=((A+z3.ZeroExt(32,L)+(1<<p)-1)&mask))]
def main():
 im=KC();k=im.k;banks=[]
 specs=[('unwire',0xfffffe0007949fd0,0xfffffe000792ffc0,0xac,0xf82,TABLE,0),('deallocate',0xfffffe0007949dd0,0xfffffe000792fbc0,0x5c,0xe0b,TABLE,0),('kernel_map_cell',0xfffffe0007949dd0,0xfffffe000792fbc0,0x5c,0x90,POOL,-4),('page_shift_cell',0xfffffe000792fcc0,0xfffffe00079391f0,0x47,0x108,POOL,0),('typed_record_free',0xfffffe0007949dd0,0xfffffe000792fbc0,0x3e,0xed7,TABLE,0),('type_descriptor',0xfffffe0007949dd0,0xfffffe000792fbc0,0x16,0x34,POOL,-8)]
 for name,l,r,key,add,base,bias in specs:
  e=selected(l,r,key,add,base,bias);e['name']=name
  for n,a in [('left',l),('right',r)]:assert k.read(a,256)==IMAGE.read(a,256);e[n+'_bytes256_hex']=k.read(a,256).hex()
  e['original_pointer']=im.pointer(int(e['slot'],16));banks.append(e)
 assert [x['target']for x in banks]==['0xfffffe000a508e14','0xfffffe000a508e1c','0xfffffe0007f860a8','0xfffffe0007e6d9c0','0xfffffe000c4ba368','0xfffffe000847bc60']
 roots=[]
 for off,bias in [(0x458,-8),(0x638,-12),(0x840,0),(0xbb8,0),(0x4f0,-4),(0x578,-4)]:
  p=im.pointer(POOL+off);assert int(p['target'],16)==qword(POOL+off);roots.append({'pool_offset':hex(off),'bias':bias,'pointer':p,'bank_root':hex(qword(POOL+off)+bias)})
 spans=[(0xfffffe000a5bff88,0xfffffe000a5c0178),(0xfffffe000a5c0868,0xfffffe000a5c0870),(0xfffffe000a5c0adc,0xfffffe000a5c0b80),(0xfffffe000a5c0d50,0xfffffe000a5c119c),(0xfffffe000a508e14,0xfffffe000a508e24),(0xfffffe000a69f444,0xfffffe000a69f454),(0xfffffe000a69f484,0xfffffe000a69f494),(0xfffffe000be2d068,0xfffffe000be2d070),(0xfffffe000bdc1ec0,0xfffffe000bdc1f18),(0xfffffe000bdcfd5c,0xfffffe000bdcfd6c),(0xfffffe000c4ba368,0xfffffe000c4ba370),(0xfffffe000a61240c,0xfffffe000a612424)]
 spans.extend([(0xfffffe000a60ab40,0xfffffe000a60ab7c),(0xfffffe000a60ae40,0xfffffe000a60ae4c),(0xfffffe000a6110d0,0xfffffe000a6110e0),(0xfffffe000a6165d0,0xfffffe000a616600)])
 ranges=[capture(k,a,z)for a,z in spans];proofs=[];store_candidates=[];scanned=0
 for va,off,n in IMAGE.segments:
  if not 0xfffffe000a500000<=va<0xfffffe000a700000:continue
  for j in range(0,n-3,4):
   w=struct.unpack_from('<I',IMAGE.data,off+j)[0];scanned+=1
   if w&0xffc00000==0xf9000000 and(w>>10)&0xfff==0x5d:
    a=va+j;assert k.read(a,4)==IMAGE.read(a,4);i=next(CS.disasm(k.read(a,4),a));store_candidates.append({'pc':hex(a),'word':hex(w),'mnemonic':i.mnemonic,'operands':i.op_str,'source_register':w&31,'base_register':(w>>5)&31,'base_is_SP':(w>>5)&31==31})
 assert len(store_candidates)==14
 for p in [12,14,16]:
  for name,claim in scalar(p):
   solver=z3.Solver();solver.set(timeout=60000);solver.add(claim);path=ROOT/f'{PREFIX}_{name}.smt2';path.write_text('(set-option :timeout 60000)\n'+solver.to_smt2());r=subprocess.run(['z3',str(path)],text=True,capture_output=True,check=True);assert r.stdout.strip()=='unsat'and not r.stderr,(name,r.stdout,r.stderr);proofs.append({'name':name,'path':path.name,'sha256':sha(path),'result':'unsat','domain':'All u64 mapped addresses and u32 extents, modular A64 arithmetic, fixed source control seed 0x962; declared memory loads and exhaustive bank identities; no reachability/PAC premise proved.'})
 pointers=[im.pointer(a)for a in [0xfffffe000847c550,0xfffffe000847c570]]
 symbols=k.symbols([0xfffffe000a5bff88,0xfffffe000a508e14,0xfffffe000a508e1c,0xfffffe000be2d068,0xfffffe000bdcfd5c,0xfffffe000c4ba368,0xfffffe0007e6d9c0,0xfffffe0007f860a8])
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['kernel_vm_mig_tools.py','kext_port_tools.py','kernel_native_reader.py']},'original_kernel_sha256':k.sha256,'normalized_kext_sha256':sha(SOURCE),'ranges':ranges,'banks':banks,'bank_roots':roots,'import_pointers':pointers,'symbols':symbols,'proofs':proofs,'unsigned_STR64_2e8_candidates':store_candidates,'instruction_words_scanned':scanned,'scan_boundary':'Only aligned unsigned-offset STR Xn,[Xm/SP,#0x2e8] encodings in normalized A5-A6 segments, original bytes rechecked; no STUR/STP/indirect/alias completeness claim.','page_shift_original_bytes_hex':k.read(0xfffffe0007e6d9c0,4).hex(),'native_page_shift':'unknown','native_target_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'full_goal_complete':False}
 return out
if __name__=='__main__':
 out=main();(ROOT/f'{PREFIX}_source.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'ranges':len(out['ranges']),'instructions':sum(len(r['instructions'])for r in out['ranges']),'banks256':len(out['banks']),'proofs_unsat':len(out['proofs'])}),flush=True)
