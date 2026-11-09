#!/usr/bin/env python3
"""Nine original record emitters followed continuously through the actual
adapter, entry and selected record-save island in private A64 state. Declared
bank roots, caller phase, frame/counter/controller cells and original stack-probe
snapshot are premises. No target import, native process, Mach/IOKit or PAC executes.
O(cases*source visits + source bytes) time, O(one private map + journals) space.
"""
import json,struct
from collections import Counter
from unicorn import arm64_const as ar
import probe_daemon_descriptor_producers as prior
from daemon_receive_tools import ROOT,SOURCE,TABLE
from capture_daemon_record720 import sha
P=prior.P
SPECS=[
 {'label':'2BE','start':0x1002be620,'record_end':0x1002be680,'key_start':0x1002be628,'key_end':0x1002be660,'key_reg':'w9','call':0x1002be6d8,'layout':'FP100','aux':0xbad70e19,'input_offset':0x2330,'cursor_kind':'SP','cursor_offset':0x2488,'left':0x100fc4130,'right':0x101031ea0,'key':0xbb,'add':0xcc73,'spill':0x10064cea8},
 {'label':'39C','start':0x10039c894,'record_end':0x10039c8d4,'key_start':0x10039c898,'key_end':0x10039c8b4,'key_reg':'w9','call':0x10039c92c,'layout':'FP100','aux':0x2be18a5d,'input_offset':0x2328,'cursor_kind':'SP','cursor_offset':0x2480,'left':0x100e99a00,'right':0x100f4e390,'key':0x78,'add':0xcc8d,'spill':0x10097c778},
 {'label':'4F6','start':0x1004f6738,'record_end':0x1004f67ac,'key_start':0x1004f6748,'key_end':0x1004f6784,'key_reg':'w10','call':0x1004f682c,'layout':'SP10CB8','aux':0x2be18a5d,'input_offset':0xaac8,'cursor_kind':'SP','cursor_offset':0xbb90,'left':0x100fc4130,'right':0x101031ea0,'left_slot':0x968,'right_slot':0x960,'key':0x4e,'add':0xcc2f,'spill':0x10097c778},
 {'label':'5C8','start':0x1005c82f4,'record_end':0x1005c835c,'key_start':0x1005c8318,'key_end':0x1005c8338,'key_reg':'w10','call':0x1005c83dc,'layout':'SP10CB8','aux':0xd79bc5de,'input_offset':0xa8f0,'cursor_kind':'SP','cursor_offset':0xbba0,'left':0x100fc4130,'right':0x101031ea0,'left_slot':0x968,'right_slot':0x960,'key':0x4e,'add':0xcc2f,'spill':0x100b74138},
 {'label':'5DE','start':0x1005dedfc,'record_end':0x1005dee70,'key_start':0x1005dee0c,'key_end':0x1005dee48,'key_reg':'w10','call':0x1005deef0,'layout':'SP10CB8','aux':0x38acbb2a,'input_offset':0xa8b8,'cursor_kind':'SP','cursor_offset':0xbb98,'left':0x100e99700,'right':0x100f4e190,'left_slot':0x870,'right_slot':0x868,'key':0x81,'add':0xcce6,'spill':0x100b2cf64},
 {'label':'654','start':0x100654bf8,'record_end':0x100654c74,'key_start':0x100654c14,'key_end':0x100654c50,'key_reg':'w11','call':0x100654cc8,'layout':'FPA8','aux':0x2be18a5d,'input_offset':0x30,'cursor_kind':'FP','cursor_offset':-0xc0,'left':0x100e99800,'right':0x100f4e290,'left_slot':0x80,'key':0x61,'add':0xcd15,'spill':0x10097c778},
 {'label':'7FA','start':0x1007fa8d0,'record_end':0x1007fa944,'key_start':0x1007fa8e0,'key_end':0x1007fa91c,'key_reg':'w10','call':0x1007fa9c4,'layout':'SP10CB8','aux':0xbad70e19,'input_offset':0xa980,'cursor_kind':'SP','cursor_offset':0xbb88,'left':0x100fc4130,'right':0x101031ea0,'left_slot':0x968,'right_slot':0x960,'key':0xa3,'add':0xccbc,'spill':0x10064cea8},
 {'label':'857','start':0x100857ae4,'record_end':0x100857b7c,'key_start':0x100857b18,'key_end':0x100857b58,'key_reg':'w10','call':0x100857bfc,'layout':'SP10CB8','aux':0xeedd0b20,'input_offset':0xa910,'cursor_kind':'SP','cursor_offset':0xbba8,'left':0x101031da0,'right':0x100e99900,'left_slot':0x5f0,'right_slot':0x5e0,'key':0x86,'add':0xccd6,'spill':0x100a2e3a0},
 {'label':'933','start':0x100933248,'record_end':0x1009332b8,'key_start':0x10093325c,'key_end':0x100933294,'key_reg':'w11','call':0x100933310,'layout':'FPA8','aux':0xbad70e19,'input_offset':0x38,'cursor_kind':'FP','cursor_offset':-0xb8,'left':0x100e99a00,'right':0x100f4e390,'left_slot':0xa0,'right_slot':0x98,'key':0x54,'add':0xcc78,'spill':0x10064cea8},
]
def record_address(s,S,FP):return S+0x10cb8 if s['layout']=='SP10CB8'else FP-(0x100 if s['layout']=='FP100'else 0xa8)
class Run(prior.Run):
 def __init__(self,s,c):
  self.spec=s;super().__init__(c);self.known=bytearray(prior.SIZE);self.initial=[];self.u.mem_write(P,bytes([c['pattern']&255])*prior.SIZE);self.R=record_address(s,self.C,self.FP)
  self.fixture(self.C+s['input_offset'],struct.pack('<Q',self.TOKEN));self.fixture(self.countercell,struct.pack('<Q',c['counter64']));self.fixture(prior.GUARD,struct.pack('<Q',0xf1e2d3c4b5a69788));self.fixture(prior.TLS-48,struct.pack('<Q',self.helper_SP+1 if c['probe']=='fast'else 0));self.fixture(prior.TLS-40,struct.pack('<Q',self.helper_SP-0x40000));self.set(8,self.countercell)
  if s['layout']=='SP10CB8':
   self.fixture(self.C+0x9d0,struct.pack('<Q',(c['phase_high32']<<32)|0x6cf4));self.fixture(self.C+0x2b8,struct.pack('<Q',self.countercell));self.fixture(self.C+0x9c8,struct.pack('<Q',0x1010b66a8));self.fixture(self.C+0x9c0,struct.pack('<Q',0x1010c4670));self.fixture(self.C+0x9d8,struct.pack('<Q',TABLE));self.fixture(self.C+s['left_slot'],struct.pack('<Q',s['left']));self.fixture(self.C+s['right_slot'],struct.pack('<Q',s['right']))
  elif s['layout']=='FP100':
   self.set(26,0x1010b66a8);self.set(27,0x1010c4670);self.set(25,0xa6);self.set(30,0xa5cd4cf);self.set(28,TABLE)
   if s['label']=='39C':self.fixture(self.C+0xb30,struct.pack('<Q',s['left']));self.set(1,s['right'])
   else:self.set(12,s['left']);self.set(11,s['right'])
  else:
   self.fixture(self.C+0x6c,struct.pack('<I',0x8ab1));self.set(22,0x1010b66a8);self.set(23,0x1010c4670);self.set(19,0xa6);self.set(24,0xa5cd4cf);self.set(27,TABLE);self.fixture(self.C+s['left_slot'],struct.pack('<Q',s['left']))
   if s['label']=='654':self.set(28,s['right'])
   else:self.fixture(self.C+s['right_slot'],struct.pack('<Q',s['right']))
  self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_Q=[hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))))for j in range(32)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))
 def code(self,u,a,n,d):
  if a==self.spec['spill']+4:
   self.flush();return self.stop('after_original_record_spill',{'spill_PC':hex(self.spec['spill']),'caller_record':hex(self.R)})
  return super().code(u,a,n,d)
 def run(self,limit=20000):
  self.ensure(self.spec['start']);self.u.emu_start(self.spec['start'],0,count=limit);self.flush()
  if self.reason is None:self.stop('source_visit_limit')
  out={'configuration':self.c,'entry_PC':hex(self.spec['start']),'entry_SP':hex(self.C),'entry_FP':hex(self.FP),'record_address':hex(self.R),'entry_registers31':self.entry_regs,'entry_Q_registers32':self.entry_Q,'entry_NZCV':self.entry_NZCV,'entry_TPIDRRO_EL0':hex(prior.TLS),'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_fixtures,'image_backing_premise':'frozen original file/fixups and explicit private image fixtures; native roots/epochs unknown','source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'logical_edges':self.edges,'source_calls':self.calls,'checkpoints':self.checkpoints,'boundary':self.boundary,'final_record':self.snapshot(self.R,24),'fixture_PC_transitions':0,'native_target_executed':False,'full_goal_complete':False}
  return out

def configurations():
 for j in range(4):yield {'nonnull':True,'probe':'walk'if j&1 else'fast','counter64':[0,0x123456789abcdef0,0xffffffffffffffff,1][j],'placement':j*256,'controllers':[(0,0),(0xffffffff,0x87654321),(0x12345678,0x9abcdef0),(0x2468ace0,0x13579bdf)][j],'phase_high32':[0,0xf1e2d3c4,0x80000000,0xffffffff][j],'pattern':[0x5a5a5a5a5a5a5a5a,0xa5a5a5a5a5a5a5a5,0,0xffffffffffffffff][j]}
if __name__=='__main__':
 rows=[]
 for s in SPECS:
  for c in configurations():
   r=Run(s,c).run();assert r['boundary']['kind']=='after_original_record_spill',(s['label'],r['boundary']);assert r['source_calls'][0]['target']=='0x100abca64'and r['source_calls'][1]['target']=='0x100a59bb4';rows.append({'site':s['label'],'profile':r});print(s['label'],c['placement'],len(r['source_visits']),r['boundary']['pc'],flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['probe_daemon_descriptor_producers.py','daemon_descriptor_producers_source.json','daemon_receive_tools.py']},'source_sha256':sha(SOURCE),'specifications':SPECS,'cases':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_aux_callers_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
