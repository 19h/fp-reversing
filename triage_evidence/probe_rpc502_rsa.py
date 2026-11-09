#!/usr/bin/env python3
"""Observe original Montgomery-call and limb-kernel boundaries after startup.

Extends frozen callback/worker/auth observers. No internal PC/frame/register,
branch,readiness or record interventions. APIs/PAC inherit explicit models.
Rows retain actual pre-state,source-read words and original post-store bytes;
models do not supply arithmetic results. No native target/API or IDB action.
O(B+V+E+S) bounded time/space;per-call kernel rows are compressed on return.
"""
import base64,hashlib,struct,sys,zlib
from array import array
from pathlib import Path
from probe_rpc502_auth import AuthProbe,ROOT,SOURCE,ar

ENTRIES={0x100539ea0:'square',0x10094593c:'product'};KERNEL=0x1005fc0d0;POST=0x1005fc124;PRODUCT_KERNEL=0x10097fbc8;PRODUCT_POST=0x10097fc24
PRODUCT_COLUMNS=['pre_X26','pre_X22','W13','W10','W19','W6','W27','encoded_Tj','encoded_Aj','encoded_Nj','W5','W15','X0','post_X26','post_X22','encoded_store']
COLUMNS=['pre_X13','pre_X5','W6','W3','W19','W30','encoded_Tj','encoded_Aj','encoded_Nj','post_X13','post_X5','encoded_store']

class RsaProbe(AuthProbe):
 def __init__(self,raw,fixture):
  self.mont_calls=[];self.mont_active=[];self.pending_kernel=None;self.rsa_points=[];self.mont_reads=[]
  super().__init__(raw,fixture)
 def snapshot_record(self,p):
  b=self.observe(p,96);views={}
  if b:
   raw=bytes.fromhex(b)
   for off in range(0,96,8):
    q=struct.unpack_from('<Q',raw,off)[0];v=self.view(q,0x220)
    if v is None:continue
    pointers={};data=bytes.fromhex(v['bytes_hex'])
    for d in [0,8,16]:
     if len(data)<d+8:continue
     ptr=struct.unpack_from('<Q',data,d)[0];vv=self.view(ptr,0x210)
     if vv:pointers[str(d)]=vv
    views[str(off)]={'prefix':v,'nested_views':pointers}
  return {'pointer':hex(p),'prefix96_hex':b,'pointed_views':views}
 def hook(self,u,a,n,d):
  self.flush()
  if self.mont_active and a==int(self.mont_calls[self.mont_active[-1]]['return_pc'],16):
   idx=self.mont_active.pop();c=self.mont_calls[idx];assert self.pending_kernel is None
   data=c.pop('_rows');assert data.itemsize==8 and sys.byteorder=='little';c.update(return_step=self.steps,return_SP=hex(u.reg_read(ar.UC_ARM64_REG_SP)),return_X0=hex(self.reg(0)),returned_record=self.snapshot_record(int(c['argument'],16)),rows_zlib_base64=base64.b64encode(zlib.compress(data.tobytes())).decode(),kernel_rows=len(data)//len(c['row_columns']),seed_after_hex=self.observe(int(c['seed_pointer'],16),8),complete_return=True)
  if a in ENTRIES:
   p=self.reg(0);c={'kind':ENTRIES[a],'row_columns':COLUMNS if ENTRIES[a]=='square'else PRODUCT_COLUMNS,'entry':hex(a),'step':self.steps,'argument':hex(p),'return_pc':hex(self.reg(30)),'entry_SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'entry_record':self.snapshot_record(p),'entry_registers':[hex(self.reg(j))for j in range(31)],'seed_pointer':hex(self.reg(1)),'seed_before_hex':self.observe(self.reg(1),8),'_rows':array('Q')};self.mont_calls.append(c);self.mont_active.append(len(self.mont_calls)-1)
  if a==KERNEL:
   assert self.mont_active and self.pending_kernel is None
   c=self.mont_calls[self.mont_active[-1]];regs=[self.reg(j)for j in range(31)];mask=0xffffffff
   constants={j:regs[j]for j in [0,2,4,7,9,12,20,21,22,23,24,27,28]}
   if 'kernel_constants'not in c:c['kernel_constants']={str(j):hex(v)for j,v in constants.items()};c['kernel_SP']=hex(u.reg_read(ar.UC_ARM64_REG_SP))
   else:assert c['kernel_constants']=={str(j):hex(v)for j,v in constants.items()},'changed reviewed kernel constants'
   src=(regs[19]+regs[22])&mask;dst=(regs[19]+regs[28])&mask
   sx=lambda v:v-(1<<32)if v>>31 else v
   addresses=[regs[23]+sx(src)*4,regs[2]+sx(src)*4,regs[21]+sx(src)*4];words=[int.from_bytes(u.mem_read(p,4),'little')for p in addresses]
   self.pending_kernel={'call':self.mont_active[-1],'row':[regs[13],regs[5],regs[6]&mask,regs[3]&mask,regs[19]&mask,regs[30]&mask,*words],'store_address':regs[23]+sx(dst)*4}
  if a==POST:
   assert self.pending_kernel is not None;p=self.pending_kernel;c=self.mont_calls[p['call']];c['_rows'].extend(p['row']+[self.reg(13),self.reg(5),int.from_bytes(u.mem_read(p['store_address'],4),'little')]);self.pending_kernel=None
  if a==PRODUCT_KERNEL:
   assert self.mont_active and self.pending_kernel is None
   c=self.mont_calls[self.mont_active[-1]];assert c['kind']=='product';regs=[self.reg(j)for j in range(31)];mask=0xffffffff
   constants={j:regs[j]for j in [4,9,12,14,21]}
   if 'kernel_constants'not in c:c['kernel_constants']={str(j):hex(v)for j,v in constants.items()};c['kernel_SP']=hex(u.reg_read(ar.UC_ARM64_REG_SP))
   else:assert c['kernel_constants']=={str(j):hex(v)for j,v in constants.items()},'changed reviewed product pointers/codec'
   src=(regs[19]+regs[6])&mask;dst=(regs[19]+regs[27])&mask;sx=lambda v:v-(1<<32)if v>>31 else v
   addresses=[regs[9]+sx(src)*4,regs[4]+sx(src)*4,regs[12]+sx(src)*4];words=[int.from_bytes(u.mem_read(p,4),'little')for p in addresses]
   self.pending_kernel={'call':self.mont_active[-1],'row':[regs[26],regs[22],regs[13]&mask,regs[10]&mask,regs[19]&mask,regs[6]&mask,regs[27]&mask,*words,regs[5]&mask,regs[15]&mask,regs[0]],'store_address':regs[9]+sx(dst)*4}
  if a==PRODUCT_POST:
   assert self.pending_kernel is not None;p=self.pending_kernel;c=self.mont_calls[p['call']];c['_rows'].extend(p['row']+[self.reg(26),self.reg(22),int.from_bytes(u.mem_read(p['store_address'],4),'little')]);self.pending_kernel=None
  if a in [0x10097531c,0x100950fd8,0x100896930]:
   self.rsa_points.append({'pc':hex(a),'step':self.steps,'registers':[hex(self.reg(j))for j in range(31)],'X9_record600':self.view(self.reg(9),0x600)if a==0x10097531c else None,'X11_record600':self.view(self.reg(11),0x600)if a==0x10097531c else None})
  return super().hook(u,a,n,d)
 def read_hook(self,u,access,a,n,value,d):
  if self.mont_active:
   c=self.mont_calls[self.mont_active[-1]];p=int(c['argument'],16)
   if a<p+96 and a+n>p:self.mont_reads.append({'call_index':self.mont_active[-1],'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'step':self.steps,'offset_bytes':a-p,'size_bytes':n,'bytes_hex':self.observe(a,n)})
  return super().read_hook(u,access,a,n,value,d)
 def finish(self,r):
  for c in self.mont_calls:
   if '_rows'in c:
    data=c.pop('_rows');c.update(rows_zlib_base64=base64.b64encode(zlib.compress(data.tobytes())).decode(),kernel_rows=len(data)//len(c['row_columns']),complete_return=False)
  r=super().finish(r);r.update(rsa_scope=__doc__,rsa_generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),montgomery_calls=self.mont_calls,kernel_row_columns={'square':COLUMNS,'product':PRODUCT_COLUMNS},pending_kernel_at_stop=self.pending_kernel,montgomery_argument_reads=self.mont_reads,rsa_points=self.rsa_points);return r
