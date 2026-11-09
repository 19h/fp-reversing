#!/usr/bin/env python3
"""Independent A64 replay of every symbolic register/memory/control effect.
Unknown source bytes remain unknown across copies. Four physical patterns
per source context; imports/PAC not executed. O(C*(B+V+byte events)) time,
O(largest trace+owner bytes) space. Concrete backing bits are not definitions.
"""
import base64,hashlib,json,struct,zlib
from pathlib import Path
from collections import Counter
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,IMAGE,FIXUPS,SOURCE
from daemon_context_transfer_symbolic import loaded_bytes,ENTRY,P
from probe_daemon_arena_storage import Storage
def unpack(r):return json.loads(zlib.decompress(base64.b64decode(r['payload_zlib_base64'])))
def evaluate(s,backing):return bytes.fromhex(s['hex'])if'hex'in s else bytes(x if isinstance(x,int)else backing[x['origin']]for x in s['terms'])
def known(s):return bytes([1])*len(bytes.fromhex(s['hex']))if'hex'in s else bytes(int(isinstance(x,int))for x in s['terms'])
class Replay(Storage):
 def __init__(self,c,trace,pattern):
  self.forward=False;self.trace=trace;self.pattern=pattern;self.index=0;self.previous=None;self.counts=Counter();self.loader_pages=[];self.backing={};super().__init__(c)
 def page(self,a):
  pg=a&~4095
  if pg in self.pages:return
  try:IMAGE.read(pg,4096)
  except ValueError:
   raw=bytearray(loaded_bytes(pg,4096));before=hashlib.sha256(raw).hexdigest();self.u.mem_map(pg,4096);self.pages.add(pg)
   for at,r in FIXUPS.items():
    if pg<=at<pg+4096:raw[at-pg:at-pg+8]=struct.pack('<Q',r['target']if isinstance(r['target'],int)else 0x7c100000)
   self.u.mem_write(pg,bytes(raw));self.loader_pages.append({'page':hex(pg),'pre_fixup_sha256':before,'rule':'Readable original segment file bytes plus zero-filled VM tail.'});return
  return super().page(a)
 def fullreg(self,name):return self.u.reg_read(ar.UC_ARM64_REG_SP if name=='sp'else getattr(ar,'UC_ARM64_REG_'+name.upper()))
 def finish(self):
  if self.previous is None:return
  row=self.previous;assert self.rcursor==len(self.rflat)and self.wcursor==len(self.wflat),(row['pc'],'memory access count',self.rcursor,len(self.rflat),self.wcursor,len(self.wflat))
  for reg,shape in row['registers_after'].items():
   expected=int.from_bytes(evaluate(shape,self.backing),'little');assert self.fullreg(reg)==expected,('register',row['pc'],reg,hex(self.fullreg(reg)),hex(expected));self.counts['register_effects_checked']+=1
  if'NZCV_after'in row:assert self.u.reg_read(ar.UC_ARM64_REG_NZCV)&0xf0000000==row['NZCV_after'];self.counts['NZCV_effects_checked']+=1
  for e in row['events']:
   if e['kind']!='write':continue
   a=int(e['address'],16);n=e['size_bytes'];assert bytes(self.u.mem_read(a,n))==evaluate(e['value'],self.backing);mask=known(e['value'])
   if P<=a<a+n<=P+0x10000:
    self.known[a-P:a-P+n]=mask;self.prov[a-P:a-P+n]=bytes(1 if b else 4 for b in mask)
   elif self.H<=a<a+n<=self.H+90000:self.heap_known[a-self.H:a-self.H+n]=mask;self.heap_prov[a-self.H:a-self.H+n]=bytes(1 if b else 4 for b in mask)
   self.counts['source_write_effects_checked']+=1;self.counts['unknown_copied_bytes_checked']+=mask.count(0)
  self.previous=None
 def code(self,u,a,n,d):
  if not self.forward:return super().code(u,a,n,d)
  self.finish()
  if self.index==len(self.trace['steps']):
   b=self.trace['boundary'];assert a==int(b['pc'],16)and self.fullreg('sp')==int(b['SP'],16)
   for j,shape in enumerate(b['registers31']):assert self.reg(j)==int.from_bytes(evaluate(shape,self.backing),'little')
   self.forward_done=True;return u.emu_stop()
  row=self.trace['steps'][self.index];assert a==int(row['pc'],16)and bytes(u.mem_read(a,4)).hex()==row['bytes_hex'],('source sequence',self.index,hex(a),row['pc']);self.index+=1;self.counts['source_visits']+=1;self.previous=row;self.rflat=[];self.wflat=[];self.rcursor=self.wcursor=0
  for e in row['events']:
   arr=self.rflat if e['kind']=='read'else self.wflat;a0=int(e['address'],16);value=evaluate(e['value'],self.backing);arr.extend((a0+j,b)for j,b in enumerate(value))
  if'target'in row:
   target=int(row['target'],16);m=row['mnemonic']
   if m in ['braa','blraa']:
    from daemon_receive_tools import CS
    ins=next(CS.disasm(IMAGE.read(a,4),a));reg,mod=[x.strip()for x in ins.op_str.split(',',1)];assert self.fullreg(reg)==target and self.fullreg(mod)==int(row['modifier16'],16)
   elif m=='ret':assert self.reg(30)==target
   if m=='blraa':self.set(30,a+4)
   self.page(target);return u.reg_write(ar.UC_ARM64_REG_PC,target)
 def read(self,u,access,a,n,value,d):
  if not self.forward:return super().read(u,access,a,n,value,d)
  actual=bytes(u.mem_read(a,n));expected=self.rflat[self.rcursor:self.rcursor+n];assert expected==[(a+j,b)for j,b in enumerate(actual)],('read',self.previous['pc'],hex(a),n);self.rcursor+=n;self.counts['read_bytes_checked']+=n
 def write(self,u,access,a,n,v,d):
  if not self.forward:return super().write(u,access,a,n,v,d)
  expected=self.wflat[self.wcursor:self.wcursor+n];assert [j for j,b in expected]==list(range(a,a+n)),('write address',self.previous['pc'],hex(a),n);self.wcursor+=n;self.counts['write_bytes_checked']+=n
 def run_forward(self):
  prefix=Storage.run(self);assert prefix['boundary']['pc']==hex(ENTRY)
  for o in self.trace['origins']:
   off=o['offset'];a=self.F+off;assert self.known[a-P]==0
   self.backing[off]=[0,0xa5,0xff,(off*73+19)&255][self.pattern];self.u.mem_write(a,bytes([self.backing[off]]))
  self.forward=True;self.forward_done=False;self.u.emu_start(ENTRY,0,count=len(self.trace['steps'])+10);assert self.forward_done and self.index==len(self.trace['steps']);assert len(self.backing)==112
  fields=[]
  for item in self.trace['final_source_fields']:
   off=int(item['offset_bytes'],16);shape=item['final_value'];assert bytes(self.u.mem_read(self.F+off,8))==evaluate(shape,self.backing);assert bytes(self.known[self.F+off-P:self.F+off-P+8])==known(shape);fields.append({'offset_bytes':item['offset_bytes'],'bytes_hex':bytes(self.u.mem_read(self.F+off,8)).hex(),'known_mask_hex':bytes(self.known[self.F+off-P:self.F+off-P+8]).hex()})
  return {'input':self.c,'pattern':self.pattern,'verified_counts':dict(self.counts),'final_source_fields':fields,'loader_pages':self.loader_pages,'boundary':self.trace['boundary'],'native_target_executed':False}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=json.loads((ROOT/'daemon_context_transfer_profiles.json').read_text());base=json.loads((ROOT/'daemon_arena_storage_profiles.json').read_text());rows=[]
 for context in p['cases']:
  trace=unpack(context);cfg=base['cases'][context['prior_case_index']]['input']
  for pattern in range(4):
   r=Replay(cfg,trace,pattern).run_forward();r['prior_case_index']=context['prior_case_index'];rows.append(r);print(json.dumps({'case':r['prior_case_index'],'pattern':pattern,'counts':r['verified_counts']}),flush=True)
 deps=['daemon_context_transfer_profiles.json','daemon_arena_storage_profiles.json','daemon_context_transfer_symbolic.py','probe_daemon_arena_storage.py','probe_daemon_arena_entry.py','probe_daemon_frame_entry.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'cases':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_context_transfer_replays.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(r['verified_counts']['source_visits']for r in rows)}),flush=True)
if __name__=='__main__':main()
