#!/usr/bin/env python3
"""Private original-A64 selector21 wrapper/entry replay with allocator models.

Two register-only allocation models return distinct mapped owners; successful
allocations are premises. Free effects are omitted. Original ordering guards
and dispatcher execute in the guest. Accepted paths stop before processing.
PAC/RET authentication is abstract; no native target, API or IPC executes.
O(C*(B+V+E)) time/space with a 2000 instruction bound per case.
"""
import json,struct
from collections import Counter
import unicorn as uc
from unicorn import arm64_const as ar
from kext_port_tools import ROOT,IMAGE,CS
from verify_daemon_reader_record_payloads_publication import sha
import recover_versioned_core_entry as R

P=0x6300000000;W=P+0x4000;A=P+0xc000;Q=P+0x2000;HALT=P+0x1f000
GLOBALS=[0xfffffe000ccc7758,0xfffffe000ccc32f8,0xfffffe000ccc3650]
CALLS={0xfffffe000a5a2d78:(0xfffffe000c4b9a08,0xca0c,'allocate_workspace',W),0xfffffe000a5a2e14:(0xfffffe000c4ba154,0xd0c8,'allocate_auxiliary',A),0xfffffe000a5a2fe4:(0xfffffe000c4ba368,0x4d6a,'free_auxiliary',0),0xfffffe000a5a3030:(0xfffffe000c4b9a24,0x84ff,'free_workspace',0)}

class Run:
 def __init__(self,k,regions,c):
  self.k=k;self.case=c;self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);self.u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);pages=set()
  for va,off,n in IMAGE.segments:
   for page in range(va&~4095,(va+n+4095)&~4095,4096):
    if page not in pages:self.u.mem_map(page,4096);pages.add(page)
   self.u.mem_write(va,IMAGE.data[off:off+n])
  self.u.mem_map(P,0x20000);self.u.mem_write(P,bytes([c['pattern']])*0x20000);self.known=set();self.initial={};self.ranges=[(int(r['start'],16),int(r['end'],16))for r in regions];self.visits=[];self.reads=[];self.writes=[];self.pending=[];self.calls=[];self.boundary=None;self.stage=None;self.snapshots={}
  self.sp0=P+0x18000+c['placement'];self.F=self.sp0-256
  for j,a in enumerate(GLOBALS):self.seed(a,k.read(a,8)if c['global_fixture']=='original'else struct.pack('<Q',(0x23456789abcdef01+j*0x21314151)&((1<<64)-1)))
  self.seed(Q,struct.pack('<I',c['count32']));self.seed(self.sp0,struct.pack('<QQ',P+0x1600,Q))
  self.args=[P+0x500,c['mode32'],c['marker32'],0xfedcba98,P+0x1000,P+0x1200,16,P+0x1400]
  for j in range(31):self.setreg(j,0x112200000000+j*0x1111)
  for j,a in enumerate(self.args):self.setreg(j,a)
  self.setreg(30,HALT);self.saved=[self.reg(j)for j in range(19,30)];self.u.reg_write(ar.UC_ARM64_REG_SP,self.sp0)
  self.u.hook_add(uc.UC_HOOK_CODE,self.code);self.u.hook_add(uc.UC_HOOK_MEM_READ,self.read);self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.write)
 def reg(self,j):return self.u.reg_read(getattr(ar,'UC_ARM64_REG_X'+str(j)))
 def setreg(self,j,v):self.u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),v&((1<<64)-1))
 def seed(self,a,b):
  self.u.mem_write(a,b);self.initial[hex(a)]=b.hex()
  if P<=a<a+len(b)<=P+0x20000:self.known.update(range(a,a+len(b)))
 def snapshot(self,a,n):return {'address':hex(a),'size_bytes':n,'bytes_hex':bytes(self.u.mem_read(a,n)).hex(),'known_mask_hex':bytes(int(j in self.known)for j in range(a,a+n)).hex()}
 def flush(self):
  for e in self.pending:e['after_hex']=bytes(self.u.mem_read(int(e['address'],16),e['size_bytes'])).hex()
  self.pending=[]
 def read(self,u,access,a,n,value,data):
  assert not P<=a<P+0x20000 or all(j in self.known for j in range(a,a+n)),('undefined private read',hex(u.reg_read(ar.UC_ARM64_REG_PC)),hex(a),n)
  self.reads.append({'visit':len(self.visits)-1,'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'address':hex(a),'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()})
 def write(self,u,access,a,n,value,data):
  assert P<=a<a+n<=P+0x20000 or any(g<=a<a+n<=g+8 for g in GLOBALS),('write escape',hex(a),n)
  if P<=a<a+n<=P+0x20000:self.known.update(range(a,a+n))
  e={'visit':len(self.visits)-1,'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e)
 def code(self,u,a,n,data):
  self.flush()
  if a in [R.ACCEPT,R.ALTERNATE,HALT]:
   self.boundary={'kind':'returned_rejection'if a==HALT else'initial_scalar_gate_admitted_before_processing','pc':hex(a),'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'registers31':[hex(self.reg(j))for j in range(31)]};return u.emu_stop()
  assert any(x<=a<a+4<=z for x,z in self.ranges),('source escape',hex(a));raw=self.k.read(a,4);assert raw==IMAGE.read(a,4)==bytes(u.mem_read(a,4));i=next(CS.disasm(raw,a));self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});m=i.mnemonic
  if a==R.DISPATCH:
   self.snapshots={'workspace_record':self.snapshot(W,56),'argument_record':self.snapshot(self.F+0x48,68)}
   for snap in self.snapshots.values():snap['before_visit']=len(self.visits)-1
  if m=='blraa':
   target=self.reg(10)if i.op_str.startswith('x10,')else self.reg(8);mod=self.reg(17);row={'pc':hex(a),'target':hex(target),'modifier':hex(mod),'arguments8':[hex(self.reg(j))for j in range(8)],'visit':len(self.visits)-1,'target_executed_in_guest':a not in CALLS}
   self.calls.append(row)
   if a in CALLS:
    t,d,role,result=CALLS[a];assert(target,mod)==(t,d);row.update(role=role,model_result=hex(result),memory_effects_modeled=False)
    if role=='allocate_workspace':assert [self.reg(0),self.reg(1)]==[16384,64]
    if role=='allocate_auxiliary':assert self.reg(0)==0xfffffe000847bea0
    if role=='free_auxiliary':assert [self.reg(0),self.reg(1)]==[0xfffffe000847ba60,A]
    if role=='free_workspace':assert [self.reg(0),self.reg(1)]==[W,16384]
    for j in range(18):self.setreg(j,0xf000000000000000+j*0x10101)
    self.setreg(0,result);u.reg_write(ar.UC_ARM64_REG_NZCV,0xf0000000);self.setreg(30,a+4);return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
   assert(target,mod)in[(R.DISPATCH,0x1e46),(0xfffffe000a687ecc,0x4d6a)];self.setreg(30,a+4);return u.reg_write(ar.UC_ARM64_REG_PC,target)
  if m in ['pacibsp','bti']:return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  if m=='retab':return u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
  assert m not in ['braa','br','blr','bl','svc','hvc','smc','brk']and not m.startswith(('pac','aut','xpac')),(hex(a),m)
 def run(self):
  self.u.emu_start(R.ENTRY,0,count=2000);self.flush();assert self.boundary is not None
  mode,marker=self.case['mode32'],self.case['marker32'];special=mode in [2,5,8]and marker in R.SPECIAL;alternate=mode in [4,7]and marker in R.OTHER;expected=R.ACCEPT if special else R.ALTERNATE if alternate else HALT;assert int(self.boundary['pc'],16)==expected
  arg=bytes.fromhex(self.snapshots['argument_record']['bytes_hex']);assert struct.unpack_from('<Q',arg,0)[0]==self.args[0]and struct.unpack_from('<III',arg,8)==tuple(self.args[1:4])and struct.unpack_from('<QQ',arg,24)==tuple(self.args[4:6])and struct.unpack_from('<I',arg,40)[0]==16 and struct.unpack_from('<QQI',arg,48)==(self.args[7],P+0x1600,self.case['count32'])
  workspace=bytes.fromhex(self.snapshots['workspace_record']['bytes_hex']);assert struct.unpack_from('<Q',workspace,8)[0]==A and struct.unpack_from('<I',workspace,16)[0]==(((W^0x97099bc0)*0xef54ff65+0x3da4b356)&0xffffffff)and struct.unpack_from('<QQQQ',workspace,24)==(A+4096,self.F+0x48,W+16384,W+64)
  if expected==HALT:assert self.reg(0)==0xffff5b37 and self.u.reg_read(ar.UC_ARM64_REG_SP)==self.sp0 and [self.reg(j)for j in range(19,30)]==self.saved
  assert bytes(self.u.mem_read(Q,4))==struct.pack('<I',self.case['count32'])
  assert not any(P+0x1000<=int(e['address'],16)<P+0x1800 for e in self.reads),'input/output payload consumed before boundary'
  return {'configuration':self.case,'entry_SP':hex(self.sp0),'frame_SP':hex(self.F),'entry_arguments8':[hex(n)for n in self.args],'initial_cells':self.initial,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'source_calls':self.calls,'snapshots':self.snapshots,'count_cell_at_boundary':self.snapshot(Q,4),'boundary':self.boundary,'native_target_executed':False,'model_memory_writes':0,'complete_core_processing_executed':False}

def cases():
 profiles=[(m,0xb4d3a486)for m in [*range(10),0xffffffff]]+[(2,n)for n in R.SPECIAL]+[(4,n)for n in R.OTHER]+[(m,n)for m in [2,5,8]for n in [0xb4d3a485,0xb4d3a487]]
 for epoch in [0,1]:
  for mode,marker in profiles:yield {'mode32':mode,'marker32':marker,'epoch':epoch,'pattern':0xa5 if epoch==0 else 0x3c,'placement':epoch*0x100,'global_fixture':'original'if epoch==0 else'declared_noise','count32':512 if epoch==0 else 0x10203040}

def audit_bytes(row,k):
 state={};known=set();events={};pattern=row['configuration']['pattern'];count=Counter()
 for a,raw in row['initial_cells'].items():
  a=int(a,16);raw=bytes.fromhex(raw)
  for j,b in enumerate(raw,a):state[j]=b;known.add(j)
 def at(a,n):return bytes(state[j]if j in state else pattern if P<=j<P+0x20000 else IMAGE.read(j,1)[0]for j in range(a,a+n))
 for field,kind in [('source_reads','read'),('source_writes','write')]:
  for e in row[field]:events.setdefault(e['visit'],[]).append((kind,e))
 def snapshot(snap):
  a=int(snap['address'],16);n=snap['size_bytes'];assert at(a,n).hex()==snap['bytes_hex']and bytes(int(j in known)for j in range(a,a+n)).hex()==snap['known_mask_hex']
 for j,v in enumerate(row['source_visits']):
  for snap in row['snapshots'].values():
   if snap['before_visit']==j:snapshot(snap)
  assert k.read(int(v['pc'],16),4).hex()==v['bytes_hex'];count['source_instruction_visits']+=1
  for kind,e in events.get(j,[]):
   assert e['pc']==v['pc'];a=int(e['address'],16);n=e['size_bytes']
   if kind=='read':
    assert at(a,n).hex()==e['bytes_hex'];assert not P<=a<P+0x20000 or all(x in known for x in range(a,a+n));count['read_bytes_checked']+=n
   else:
    raw=bytes.fromhex(e['after_hex']);assert len(raw)==n
    for x,b in enumerate(raw,a):state[x]=b;known.add(x)
    count['write_bytes_checked']+=n
 snapshot(row['count_cell_at_boundary'])
 return count

def build():
 k,regions=R.source();rows=[];totals=Counter();targets=Counter()
 for c in cases():
  v=Run(k,regions,c);row=v.run();rows.append(row);totals.update(audit_bytes(row,k));targets[row['boundary']['kind']]+=1
 return {'scope':__doc__,'generator_sha256':sha(__file__),'source_generator_sha256':sha(ROOT/('recover_'+R.P+'.py')),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'kernel_collection_sha256':k.sha256,'dependencies':{n:sha(ROOT/n)for n in R.DEPS},'cases':rows,'verified_counts':{'cases':len(rows),**totals},'boundary_counts':dict(targets),'all_checks_pass':True,'native_target_executed':False,'model_memory_writes':0,'complete_core_processing_executed':False,'full_goal_complete':False}

if __name__=='__main__':
 obj=build();(ROOT/(R.P+'_replays.json')).write_text(json.dumps(obj,indent=2)+'\n');print(json.dumps({'verified_counts':obj['verified_counts'],'boundaries':obj['boundary_counts']}),flush=True)
