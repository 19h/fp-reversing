#!/usr/bin/env python3
"""Original CF DoSource1 -> perform -> original daemon/application composition.
Runtime objects/locks/retain-release/boost and stack helpers are explicit
contracts. No native run loop, receive, loader, PAC, IPC or API executes.
O(image+source visits+RAM+journals) time/space. Normal extended trailers only.
"""
import hashlib,json,struct
import unicorn as uc
from unicorn import arm64_const as A
from daemon_receive_tools import ROOT,CS
from probe_daemon_request_application import Probe as Parent,B,USER,OOL,REPLY,STACK,STACK_SIZE,HALT
from recover_cf_daemon_request import P,FLAGS,sha,HELPERS
from recover_cf_receive import DO_SOURCE,SOURCE_CALL,PERFORM
OBJ=B+0x90000;RL=B+0xa0000;MODE=B+0xa4000;SRC=B+0xa8000;OUT=B+0xac000;ALLOC=B+0xb0000;GUARD=B+0xb2000;CF_STACK=0x60000f0000
POINTS={DO_SOURCE,0x184758e20,SOURCE_CALL,PERFORM,0x18478416c,0x100425f78,0x184784170,0x184758efc,0x184758e24}
class Probe(Parent):
 def __init__(self,index,row,source):
  super().__init__(index,row,source);self.cf_frames=[];self.cf_models=[];self.cf_pac=[];self.cf_initial=[];self.cf_globals=[];self.cf_ranges=[(int(f['start'],16),int(f['end'],16))for f in source['CF_functions']]
  for page in source['CF_original_pages']:
   a=int(page['address'],16);self.u.mem_map(a,4096);self.u.mem_write(a,bytes.fromhex(page['bytes_hex']))
  def put(a,b):self.u.mem_write(a,b);self.cf_initial.append({'address':hex(a),'bytes_hex':b.hex()})
  for a,n in[(OBJ,160),(RL,8192),(MODE,128),(SRC,256)]:put(a,bytes(n))
  for a,v in[(OBJ+0x30,0x100425f78),(SRC+8,8),(SRC+0x70,OBJ),(SRC+0xa8,PERFORM),(GUARD,0x6a39c82e1d4075b0)]:put(a,struct.pack('<Q',v))
  put(OUT,b'\xa5'*8)
  for a,b in[(0x1ed891742,b'\x02'),(0x1e01c88a8,struct.pack('<Q',GUARD)),(0x1e0261ea0,struct.pack('<Q',ALLOC)),(0x1e21210e0,struct.pack('<Q',CF_STACK))]:
   self.cf_globals.append({'address':hex(a),'before_hex':bytes(self.u.mem_read(a,len(b))).hex(),'after_hex':b.hex()});self.u.mem_write(a,b)
  assert CF_STACK not in self.imports;self.imports[CF_STACK]='framework/private_stack_probe'
  for j in range(31):self.setreg(j,0)
  for j,v in enumerate((RL,MODE,SRC,USER,80,OUT)):self.setreg(j,v)
  self.setreg(30,HALT);self.u.reg_write(A.UC_ARM64_REG_SP,STACK+0x78000);self.u.reg_write(A.UC_ARM64_REG_NZCV,0x40000000);self.entry=self.frame('CF_DoSource1_entry')
 def hook(self,u,a,n,d):
  self.flush()
  if a==HALT:return self.finish('CF_source_returned',a)
  if a in POINTS:self.cf_frames.append({'pc':hex(a),**self.frame('CF_daemon_handoff'),'user148_hex':bytes(u.mem_read(USER,148)).hex(),'generic_reply8_hex':bytes(u.mem_read(OUT,8)).hex(),'CF_object160_hex':bytes(u.mem_read(OBJ,160)).hex(),'source256_hex':bytes(u.mem_read(SRC,256)).hex()})
  if a==CF_STACK or a in HELPERS:
   preserve=a==CF_STACK;result=self.reg(0)if a==0x1846db030 else 0;e={'name':'framework/private_stack_probe'if preserve else HELPERS[a],'pc':hex(a),'before_source_visit_index':len(self.visits),'before':self.frame('before_import'),'return_pc':hex(self.reg(30)),'result':None if preserve else hex(result),'model':'preserve all CPU/RAM'if preserve else'declared primitive return; volatile GP/NZCV clobbers; no memory effects'};self.events.append(e);self.cf_models.append(e);target=self.reg(30)
   if not preserve:
    for j in range(18):self.setreg(j,((j+1)*0x123456789abcdef)^0x8b3dc651)
    self.setreg(0,result);u.reg_write(A.UC_ARM64_REG_NZCV,0xf0000000)
   u.reg_write(A.UC_ARM64_REG_PC,target);e['after']=self.frame('after_import');return
  if any(lo<=a<hi for lo,hi in self.cf_ranges):
   raw=bytes(u.mem_read(a,4));f=next(f for f in self.source['CF_functions']if int(f['start'],16)<=a<int(f['end'],16));off=a-int(f['start'],16);assert raw==bytes.fromhex(f['bytes'])[off:off+4];i=next(CS.disasm(raw,a));self.current=len(self.visits);self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()})
   if i.mnemonic in ('pacibsp','autibsp','paciza','autia','xpaci','retab','blraa','blraaz'):
    self.cf_pac.append({'pc':hex(a),'source_visit_index':self.current,'mnemonic':i.mnemonic,'operands':i.op_str,'registers31':[hex(self.reg(j))for j in range(31)],'SP':hex(u.reg_read(A.UC_ARM64_REG_SP))})
    if i.mnemonic=='retab':u.reg_write(A.UC_ARM64_REG_PC,self.reg(30))
    elif i.mnemonic.startswith('blr'):
     j=int(i.op_str.split(',')[0].strip()[1:]);target=self.reg(j);self.setreg(30,a+4);u.reg_write(A.UC_ARM64_REG_PC,target)
    else:u.reg_write(A.UC_ARM64_REG_PC,a+4)
   else:assert i.mnemonic not in('svc','hvc','smc','brk')and not i.mnemonic.startswith(('pac','aut','xpac')),(hex(a),i.mnemonic)
   return
  return super().hook(u,a,n,d)
 def run(self):
  self.u.emu_start(DO_SOURCE,0,count=30000);self.flush();assert self.boundary is not None and self.boundary['kind']in('CF_source_returned','before_pthread_self')
  out={'kernel_case_index':self.index,'configuration':self.input['configuration'],'entry_PC':hex(DO_SOURCE),'entry':self.entry,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.write_events,'imports':self.events,'handoffs':self.frames,'boundary':self.boundary,'final_user8192_hex':bytes(self.u.mem_read(USER,8192)).hex(),'final_OOL16384_hex':bytes(self.u.mem_read(OOL,16384)).hex(),'reply384_hex':bytes(self.u.mem_read(REPLY,384)).hex(),'final_stack524288_sha256':hashlib.sha256(bytes(self.u.mem_read(STACK,STACK_SIZE))).hexdigest(),'final_private1048576_sha256':hashlib.sha256(bytes(self.u.mem_read(B,0x100000))).hexdigest(),'application_handoff':self.application_handoff,'application_frames':self.application_frames,'stack_check_contracts':self.stack_checks,'logical_library_binding':self.binding,'CF_initial_private_overlays':self.cf_initial,'CF_runtime_global_overlays':self.cf_globals,'CF_frames':self.cf_frames,'CF_models':self.cf_models,'CF_logical_PAC':self.cf_pac,'final_generic_reply8_hex':bytes(self.u.mem_read(OUT,8)).hex(),'final_CF_object160_hex':bytes(self.u.mem_read(OBJ,160)).hex(),'final_source256_hex':bytes(self.u.mem_read(SRC,256)).hex(),'final_CF_runtime_globals':[{'address':e['address'],'bytes_hex':bytes(self.u.mem_read(int(e['address'],16),len(e['after_hex'])//2)).hex()}for e in self.cf_globals]}
  if self.audit_record is not None:out.update(argument_record_address=hex(self.audit_record),final_argument_record120_hex=bytes(self.u.mem_read(self.audit_record,120)).hex())
  return out
if __name__=='__main__':
 src=json.loads((ROOT/(P+'_source.json')).read_text());old=json.loads((ROOT/'kernel_request_delivery_profiles.json').read_text());rows=[]
 for j in(1,3,5,7):
  r=Probe(j,old['cases'][j],src).run();rows.append(r);print(j,r['boundary']['kind'],len(r['source_visits']),len(r['CF_models']),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in [P+'_source.json','kernel_request_delivery_profiles.json','probe_daemon_request_application.py','probe_daemon_request_consumption.py','recover_'+P+'.py']},'cases':rows,**FLAGS};(ROOT/(P+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'visits':sum(len(r['source_visits'])for r in rows)}),flush=True)
