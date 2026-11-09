#!/usr/bin/env python3
"""Strict original shared-core prologue/setup profiles. A declared protected
record carries tag6CF4 and operation word; only source-written/explicit private
bytes may be read, apart from unused original stack-probe touch values.
Image initial backing is a declared private environment, not native state.
O(cases*visits) time, O(one CPU map+journal) space; no target APIs/ports/PAC.
"""
import json,struct
from unicorn import arm64_const as ar
import probe_daemon_descriptor_producers as prior
from capture_daemon_record720 import sha
from daemon_receive_tools import ROOT,SOURCE
ENTRY=0x10061a2d0;END=0x1004c3634
FIELDS=[0x9d0,0x9d8,0x9c0,0x9c8,0x960,0x968,0x5e0,0x5f0,0x868,0x870]
EXPECTED={0x9d0:0x6cf4,0x9d8:0x101039ef0,0x9c0:0x1010c4670,0x9c8:0x1010b8dc8,0x960:0x101031ea0,0x968:0x100fc4130,0x5e0:0x100e99900,0x5f0:0x101031da0,0x868:0x100f4e190,0x870:0x100e99700}
WRITERS=[0x10061a75c,0x10061a764,0x10061a97c,0x10061a980,0x1004c2534,0x1004c2b30]
class Run(prior.Run):
 def __init__(self,c):
  self.writer_registers=[];super().__init__(c);self.known=bytearray(prior.SIZE);self.initial=[];self.u.mem_write(prior.P,bytes([c['pattern']&255])*prior.SIZE);self.R=self.C+0x4000;K=(((self.R&0xffffffff)^0xeaae0ac9)*0x7398180b)&0xffffffff
  self.fixture(self.R,struct.pack('<QIIQ',c['counter64']^0x1c0b9f7ce10f2255,K^0x6cf4,K^c['operation32'],prior.P+0x1000));self.fixture(self.countercell,struct.pack('<Q',c['counter64']));self.fixture(prior.GUARD,struct.pack('<Q',0xf1e2d3c4b5a69788));self.fixture(prior.TLS-48,struct.pack('<Q',self.C-128+1 if c['probe']=='fast'else 0));self.fixture(prior.TLS-40,struct.pack('<Q',self.C-128-0x40000));self.set(0,self.R);self.set(1,self.countercell)
  at=0x1010b8dc8;self.ensure(at,8);b=struct.pack('<Q',c['controllers'][0]);self.u.mem_write(at,b);self.image_fixtures.append({'address':hex(at),'bytes_hex':b.hex(),'provenance':'declared shared-core controller environment'})
  self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_Q=[hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))))for j in range(32)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))
 def code(self,u,a,n,d):
  if a in WRITERS:self.writer_registers.append({'pc':hex(a),'source_visit_index':self.seq,'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'registers31':[hex(self.reg(j))for j in range(31)]})
  if a==END:self.flush();return self.stop('before_shared_setup_branch')
  return super().code(u,a,n,d)
 def run(self):
  self.ensure(ENTRY);self.u.emu_start(ENTRY,0,count=20000);self.flush()
  if self.reason is None:self.stop('source_visit_limit')
  F=self.u.reg_read(ar.UC_ARM64_REG_SP);fields=[]
  for off in FIELDS:fields.append({'offset_bytes':off,'address':hex(F+off),'value':hex(int.from_bytes(bytes(self.u.mem_read(F+off,8)),'little')),'defined_mask_hex':self.known[F+off-prior.P:F+off-prior.P+8].hex()})
  return {'configuration':self.c,'entry_PC':hex(ENTRY),'entry_SP':hex(self.C),'entry_FP':hex(self.FP),'record_address':hex(self.R),'entry_registers31':self.entry_regs,'entry_Q_registers32':self.entry_Q,'entry_NZCV':self.entry_NZCV,'entry_TPIDRRO_EL0':hex(prior.TLS),'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_fixtures,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'logical_edges':self.edges,'source_calls':self.calls,'checkpoints':self.checkpoints,'writer_registers':self.writer_registers,'boundary':self.boundary,'frame_base':hex(F),'fields':fields,'fixture_PC_transitions':0,'native_target_executed':False,'full_goal_complete':False}
def cases():
 for j in range(4):
  for op in[0xbc84919b,0x80000000]:yield {'nonnull':True,'probe':'walk'if j&1 else'fast','counter64':[0,0x123456789abcdef0,0xffffffffffffffff,1][j],'placement':j*256,'controllers':[(0,0),(0xffffffff,0x87654321),(0x12345678,0x9abcdef0),(0xffffffffffffffff,0x13579bdf)][j],'pattern':[0x5a5a5a5a5a5a5a5a,0xa5a5a5a5a5a5a5a5,0,0xffffffffffffffff][j],'operation32':op}
if __name__=='__main__':
 rows=[]
 for c in cases():
  r=Run(c).run();assert r['boundary']['kind']=='before_shared_setup_branch',r['boundary'];assert int(r['frame_base'],16)==int(r['entry_SP'],16)-0x10dd0
  for f in r['fields']:assert int(f['value'],16)==EXPECTED[f['offset_bytes']]and f['defined_mask_hex']=='0101010101010101'
  rows.append(r);print(c['placement'],hex(c['operation32']),len(r['source_visits']),r['boundary']['registers31'][8],flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['probe_daemon_descriptor_producers.py','daemon_descriptor_producers_source.json','daemon_rpc502_contracts.json']},'expected_fields':{hex(a):hex(v)for a,v in EXPECTED.items()},'cases':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_shared_roots_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
