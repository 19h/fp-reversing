#!/usr/bin/env python3
"""Compose original CF factory/wake with original packing, aux and retry bodies.
All SVC instructions are intercepted: declared status stream changes X0 only.
No native IPC/kernel/concurrency/PAC effects. Linear in image+visits+RAM+journal.
"""
import hashlib,json,struct
from unicorn import arm64_const as A
from daemon_receive_tools import ROOT,CS
from probe_cf_runloop_wake_port import CFProbe as Parent
from probe_cf_source_scheduling import B,RL
from probe_cf_mode_construction import TLS
from recover_cf_wake_send_wrapper import P,FLAGS,sha,MACH,OVERWRITE,INTERNAL,TRAP,SVC,AUX
from probe_cf_runloop_handoff import LOW,LOW_SIZE
VOUCHER=B+0xbb000;SELECTED={MACH,OVERWRITE,INTERNAL,TRAP,AUX};RETURN=0x18473af34
class Probe(Parent):
 def __init__(self,c,k,s):
  super().__init__(c,k,s);self.wrapper_frames=[];self.wrapper_returns=[];self.svc_returns=[];self.si=0;self.msg=None
  self.u.mem_write(TLS+0xe0,struct.pack('<Q',VOUCHER if c.get('aux')else 0));v=bytearray(72);struct.pack_into('<Q',v,0x30,0x1122334455667788);v[0x38:0x48]=bytes(range(1,17));self.u.mem_write(VOUCHER,bytes(v));self.wrapper_initial=[{'address':hex(TLS+0xe0),'bytes_hex':bytes(self.u.mem_read(TLS+0xe0,8)).hex()},{'address':hex(VOUCHER),'bytes_hex':bytes(v).hex()}]
 def wrapper_frame(self,a):return{'pc':hex(a),**self.frame('wrapper_stage'),'original_header24_hex':None if self.msg is None else bytes(self.u.mem_read(self.msg,24)).hex(),'hook_root8_hex':bytes(self.u.mem_read(0x1ed83e8d8,8)).hex(),'voucher_TLS8_hex':bytes(self.u.mem_read(TLS+0xe0,8)).hex()}
 def hashes(self):return{'private_RAM_sha256':hashlib.sha256(bytes(self.u.mem_read(B,0x100000))).hexdigest(),'lower_stack_sha256':hashlib.sha256(bytes(self.u.mem_read(LOW,LOW_SIZE))).hexdigest()}
 def hook(self,u,a,n,d):
  self.flush()
  if a==MACH and self.phase=='wakeup':
   x=[self.reg(j)for j in range(7)];self.msg=x[0];raw=bytes(u.mem_read(self.msg,24));assert x[1:]==[0x11,24,0,0,0,0]and raw==struct.pack('<6I',0x13,24,0x807,0,0,0);self.wake_send.append({'before':self.wake_frame(a),'arguments7':[hex(v)for v in x],'header24_hex':raw.hex(),'expected_wrapper_status_under_declared_SVC_stream':hex(self.config['trap_results'][-1])})
  if a in(OVERWRITE,INTERNAL,TRAP,AUX,0x18055091c,0x180550a24,0x18055a8dc,0x18055a918):self.wrapper_frames.append(self.wrapper_frame(a))
  if a==RETURN:self.wrapper_returns.append(self.wrapper_frame(a));assert self.si==len(self.config['trap_results'])and self.reg(0)==self.config['trap_results'][-1]
  f=next((f for f in self.source['CF_functions']if int(f['start'],16)in SELECTED and int(f['start'],16)<=a<int(f['end'],16)),None)
  if f and not(a==MACH and self.phase!='wakeup'):
   raw=bytes(u.mem_read(a,4));assert raw==bytes.fromhex(f['bytes'])[a-int(f['start'],16):a-int(f['start'],16)+4];i=next(CS.disasm(raw,a));self.current=len(self.visits)
   if a==SVC:
    assert(i.mnemonic,i.op_str)==('svc','#0x80')and self.reg(16)==(1<<64)-47 and self.si<len(self.config['trap_results']);x=[self.reg(j)for j in range(8)];vec=bytes(u.mem_read(x[0],48)).hex()if x[1]&(1<<32)else None;auxptr=int.from_bytes(bytes.fromhex(vec)[24:32],'little')if vec else None;status=self.config['trap_results'][self.si];e={'before':self.wrapper_frame(a),'arguments8':[hex(v)for v in x],'selector_signed':-47,'original_header_pointer':hex(self.msg),'vector48_hex':vec,'aux40_hex':bytes(u.mem_read(auxptr,40)).hex()if auxptr else None,'declared_status':hex(status),'memory_before':self.hashes()};self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});self.si+=1;self.setreg(0,status);u.reg_write(A.UC_ARM64_REG_PC,a+4);e['after']=self.wrapper_frame(a+4);e['memory_after']=self.hashes();self.svc_returns.append(e);return
   self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});op=i.mnemonic
   if op in('pacibsp','autibsp','paciza','autia','autda','pacia','pacda','xpaci','xpacd'):u.reg_write(A.UC_ARM64_REG_PC,a+4)
   elif op=='retab':u.reg_write(A.UC_ARM64_REG_PC,self.reg(30))
   elif op in('blraa','blraaz','braa','braaz'):
    j=int(i.op_str.split(',')[0].strip()[1:]);target=self.reg(j)
    if op.startswith('blr'):self.setreg(30,a+4)
    u.reg_write(A.UC_ARM64_REG_PC,target)
   elif op=='mrs':assert i.op_str in('x19, tpidrro_el0','x8, tpidrro_el0')and u.reg_read(A.UC_ARM64_REG_TPIDRRO_EL0)==TLS
   else:assert op not in('svc','hvc','smc','brk','msr')and not op.startswith(('pac','aut','xpac')),(hex(a),op)
   return
  return super().hook(u,a,n,d)
 def run(self):
  r=super().run();assert self.si==len(self.config['trap_results']);r.update(wrapper_initial_fixtures=self.wrapper_initial,wrapper_frames=self.wrapper_frames,wrapper_returns=self.wrapper_returns,SVC_return_contracts=self.svc_returns,final_voucher72_hex=bytes(self.u.mem_read(VOUCHER,72)).hex());return r
if __name__=='__main__':
 s=json.loads((ROOT/(P+'_source.json')).read_text());prior=json.loads((ROOT/'cf_runloop_wake_port_profiles.json').read_text());rows=[]
 cases=[('suppressed',[],False),('success',[0],False),('timeout',[0x10000004],False),('interrupted_success',[0x10000007,0],False),('twice_interrupted_timeout',[0x10000007,0x10000007,0x10000004],False),('invalid_data',[0x10000002],False),('aux_success',[0],True),('aux_interrupted_timeout',[0x10000007,0x10000004],True)]
 cs={**s['CF_source'],'root_caller_options':s['root_caller_options']}
 for label,results,aux in cases:
  c={'kernel_case':2,'mode':'schedule_then_run','repeat':1,'wake_case':'suppressed'if label=='suppressed'else'waiting','send_status':0,'label':label,'trap_results':results,'aux':aux};r=Probe(c,prior['kernel_cases'][2],cs).run();rows.append(r);print(label,len(r['source_visits']),len(r['SVC_return_contracts']),r['boundary']['kind'],flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json','cf_runloop_wake_port_profiles.json','probe_cf_runloop_wake_port.py','recover_'+P+'.py']},'cases':rows,**{k:False for k in FLAGS}};(ROOT/(P+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
