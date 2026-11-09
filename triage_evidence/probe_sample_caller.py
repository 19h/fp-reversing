#!/usr/bin/env python3
"""Original caller paths with declared records and descriptor-helper results.

Private Unicorn only. Authentication abstracted; known descriptor helper calls
are recorded and modeled at caller sites. Unknown calls and system operations
stop. No task, mapping, crypto, native reference or IPC operation executes.
"""
import hashlib,json,struct
from pathlib import Path
import unicorn as uc
from unicorn import arm64_const as ar
from probe_kext_close import Close,STACK,HALT
from kext_port_tools import ROOT,SOURCE,IMAGE,CS
from recover_sample_descriptor import GROUPS
ENTRY=0xfffffe000a6247a4
END=0xfffffe000a626648
GUARD=0xfffffe000a687ecc
ACTORS={v:(g,k)for g,r in GROUPS.items()for k,v in r.items()if k not in('global','options')}
ACTORS[0xfffffe000a508030]=('hardware','initialize')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def key(record):return ((record^0x97099bc0)*0xef54ff65)&0xffffffff
def key64(record):return ((record^0x0f6f4af997099bc0)*0xef54ff65)&((1<<64)-1)
class Caller(Close):
 def __init__(self,case):
  super().__init__(0,0);self.case=case;self.observations=[];self.record_reads=[];self.known=bytearray(0x21000);self.undefined_reads=[];self.record=STACK+case['record_offset'];self.fixture=bytearray(0x80)
  fields={0:case['object64'],0x18:case['address64'],0x20:STACK+0x3000,0x28:case['pointer28'],0x30:case['pointer30'],0x38:case['task64'],0x48:case['limit64'],0x58:case['pointer58']}
  for off,v in fields.items():struct.pack_into('<Q',self.fixture,off,v)
  struct.pack_into('<Q',self.fixture,0x10,(case['sample_length64']-key64(self.record)-0xecb67a32353f2154)&((1<<64)-1))
  struct.pack_into('<I',self.fixture,0x40,(case['selector32']-key(self.record))&0xffffffff)
  struct.pack_into('<I',self.fixture,0x50,(case['element_count32']-0x8899d805+key(self.record))&0xffffffff)
  self.u.mem_write(self.record,bytes(self.fixture));self.u.mem_write(STACK+0x3000,bytes(0x30));self.u.mem_write(STACK+0x302c,struct.pack('<I',case['secondary_word2c']));self.u.mem_write(STACK+0x4000,bytes(0x140));self.setreg(0,self.record)
  for a,n in[(self.record,0x80),(STACK+0x3000,0x30),(STACK+0x4000,0x140)]:self.known[a-STACK:a-STACK+n]=b'\1'*n
 def hook(self,u,a,n,d):
  if self.reason:return
  if a==HALT:return super().hook(u,a,n,d)
  if not ENTRY<=a<END and not GUARD<=a<GUARD+20:
   return self.stop('outside_declared_source',target=hex(a))
  i=next(CS.disasm(IMAGE.read(a,4),a))
  if i.mnemonic=='brk':return self.stop('source_BRK_boundary',pc=hex(a),operands=i.op_str)
  if i.mnemonic in('blraa','blr','bl','blrab'):
   t=int(i.op_str[1:],16)if i.mnemonic=='bl'else self.reg(int(i.op_str.split(',')[0][1:]))
   obs={'pc':hex(a),'target':hex(t),'source_visit_index':len(self.visits),'registers8':[hex(self.reg(j))for j in range(8)],'registers31':[hex(self.reg(j))for j in range(31)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP))}
   if t==GUARD:
    obs['kind']='bounds_helper_source';self.observations.append(obs)
   elif t in ACTORS:
    group,kind=ACTORS[t];obs.update(group=group,kind=kind,helper_executed=False)
    result_key=group+'.'+kind if group+'.'+kind in self.case['modeled_results']else kind
    if result_key not in self.case['modeled_results']:
     self.observations.append(obs);return self.stop('unmodeled_helper',**obs)
    result=self.case['modeled_results'][result_key];obs['result64']=hex(result);obs['result_key']=result_key;self.observations.append(obs)
    self.flush();raw=IMAGE.read(a,4);assert bytes(u.mem_read(a,4))==raw;self.pool[a]=raw;self.visits.append(a)
    if self.case['clobber_callersaved']:
     for j in range(1,18):self.setreg(j,0xa5a5000000000000+j)
    self.setreg(0,result);self.setreg(30,a+4);u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
   else:self.observations.append(dict(obs,kind='unknown_call'));return self.stop('unknown_call_boundary',**obs)
  return super().hook(u,a,n,d)
 def read(self,u,access,a,n,value,d):
  super().read(u,access,a,n,value,d)
  if STACK<=a<a+n<=STACK+0x21000 and not all(self.known[a-STACK:a-STACK+n]):
   self.undefined_reads.append({'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'address':hex(a),'size_bytes':n});return self.stop('undefined_private_read',**self.undefined_reads[-1])
  if self.record<=a<a+n<=self.record+len(self.fixture):self.record_reads.append({'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'offset':a-self.record,'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()})
 def write(self,u,access,a,n,value,d):
  super().write(u,access,a,n,value,d)
  if STACK<=a<a+n<=STACK+0x21000:self.known[a-STACK:a-STACK+n]=b'\1'*n
 def run(self):
  try:self.u.emu_start(ENTRY,0,count=20000)
  except uc.UcError as e:
   if self.reason is None:self.reason='unicorn_error';self.events.append({'kind':self.reason,'message':str(e)})
  self.flush();self.reason=self.reason or'instruction_budget'
  return {'input':self.case,'entry':hex(ENTRY),'record':hex(self.record),'record_fixture_hex':self.fixture.hex(),'final_record_hex':bytes(self.u.mem_read(self.record,len(self.fixture))).hex(),'scope':__doc__,'stop_reason':self.reason,'source_visits':[hex(a)for a in self.visits],'helper_observations':self.observations,'record_reads':self.record_reads,'source_writes':self.writes,'events':self.events,'undefined_private_reads':self.undefined_reads,'return_X0':hex(self.reg(0)),'native_target_executed':False,'native_API_executed':False,'complete_lifecycle_proved':False}
def case(count=0,selector=0x507,create=0,prepare=0,offset=0x1000):
 return {'record_offset':offset,'object64':STACK+0x4000,'limit64':STACK+0x4140,'address64':0x1234567887654321,'task64':0xabcdef0112345678,'pointer28':0,'pointer30':0,'pointer58':0x8765432112345678,'selector32':selector,'element_count32':count,'sample_length64':0x100000010,'secondary_word2c':0,'clobber_callersaved':False,'modeled_results':{'create':create,'prepare':prepare,'release':0xfeedfacecafe0000}}
def cases():
 for count in [0,1,2,0x7fffffff,0x80000000,0xffffffff,0x8899d805,0x8899d804]:
  for off in[0x1000,0x17f8]:
   for create,prepare in[(0,0),(0,0xffff5bd4),(0xffff5bd4,0),(0x100000000,0),(0,0x100000000)]:yield case(count,create=create,prepare=prepare,offset=off)
 for prepare in[0,1,0xffff5bd4]:
  c=case(0,prepare=prepare);c['clobber_callersaved']=True;yield c
 for delta in[-1,1]:
  c=case(1);c['limit64']+=delta;yield c
 for obj,limit in[(0,0x140),(0xffffffffffffff00,0x40),(0xffffffffffffff00,0x3f)]:
  c=case(0,create=0xffff5bd4);c.update(object64=obj,limit64=limit);yield c
 for tag in[1,0xffffffff]:
  c=case(0);c['secondary_word2c']=tag;yield c
 for count in[0,1,2]:
  for initialize in[0,0xffffffd8,0xffffffea]:
   c=case(count);c['modeled_results'].update(initialize=initialize,complete=0);yield c
 for tag in[1,0xffffffff]:
  for complete in[0,0xe00002c2,0x100000000]:
   c=case(0);c['secondary_word2c']=tag;c['modeled_results']['complete']=complete;yield c
 for task in[0,1,0x100000000]:
  c=case(0,create=0xffff5bd4);c['task64']=task;yield c
 for sample_length in[0,1,0xffffffff,0x100000000,0xffffffffffffffff]:
  c=case(0);c['sample_length64']=sample_length;c['modeled_results'].update(initialize=0,**{'samples.create':0xffff5bd4,'complete':0});yield c
def main():
 rows=[];pool={}
 for c in cases():
  q=Caller(c);r=q.run();rows.append(r);pool.update(q.pool)
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in['probe_kext_close.py','recover_sample_descriptor.py','kext_port_tools.py']},'cases':rows,'source_instructions':[{'ea':hex(a),'bytes_hex':b.hex(),'mnemonic':next(CS.disasm(b,a)).mnemonic,'operands':next(CS.disasm(b,a)).op_str}for a,b in sorted(pool.items())],'native_target_executed':False,'full_goal_complete':False}
 (ROOT/'sample_caller_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'stops':{s:sum(r['stop_reason']==s for r in rows)for s in sorted({r['stop_reason']for r in rows})},'source_visits':sum(len(r['source_visits'])for r in rows)}),flush=True)
if __name__=='__main__':main()
