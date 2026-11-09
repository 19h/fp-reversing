#!/usr/bin/env python3
"""Original second-reader prefix versus full-width compact branch-index formula.
Declared RO bank roots select G; incoming phase reachability is not asserted.
Execution stops before the dynamic target load. O(cases*source instructions)
time, O(mapped pages+case records) space; no API/PAC/native target executes.
"""
import json,hashlib,struct
from pathlib import Path
import unicorn as uc
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
START=0x100a636ec;END=0x100a63790;G=0x1010c8218;POOL=0x1010a1960

def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def expected(phase,pointer):
 flag=(phase&1)^int(pointer==0);return (((phase-0x4c6f)&0xffffffff)^((flag*((phase-0x8a85)&0xffffffff))&0xffffffff))&0xffffffff

def main():
 u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);pages=set();rows=[];F=0x70001000
 def page(pg):
  if pg in pages:return
  u.mem_map(pg,4096);pages.add(pg)
  if 0x100000000<=pg<0x102000000:
   b=bytearray(4096)if pg==G&~4095 else bytearray(IMAGE.read(pg,4096))
   for a,r in FIXUPS.items():
    if pg<=a<pg+4096:b[a-pg:a-pg+8]=struct.pack('<Q',r['target']if isinstance(r['target'],int)else 0x7c100000)
   u.mem_write(pg,bytes(b))
 for pg in [START&~4095,0x100fc4000,0x101031000,0x101032000,0x1010a4000,0x1010c4000,G&~4095,F]:page(pg)
 u.mem_write(F+0x48,struct.pack('<QQ',0x101031fa0,0x100fc4230))
 def invalid(u,t,a,n,v,d):
  print(('unmapped access',hex(u.reg_read(ar.UC_ARM64_REG_PC)),hex(a),n),flush=True);return False
 u.hook_add(uc.UC_HOOK_MEM_INVALID,invalid)
 for high in [0,0x123456,0xffffff]:
  for low in range(256):
   phase=(high<<8)|low
   for pointer in [0,0x6600003000,0xffffffffffffffff]:
    for state in [0,0xffffffff]:
     u.mem_write(G+16,struct.pack('<Q',pointer));u.mem_write(0x1010c4e18,struct.pack('<I',state));u.mem_write(0x1010c4670,struct.pack('<I',(state^0x87654321)&0xffffffff))
     for name,v in [('SP',F),('X22',0x1010c4e18),('X26',POOL),('W24',phase)]:u.reg_write(getattr(ar,'UC_ARM64_REG_'+name),v)
     u.emu_start(START,END,count=50);index=u.reg_read(ar.UC_ARM64_REG_W9);assert u.reg_read(ar.UC_ARM64_REG_PC)==END and u.reg_read(ar.UC_ARM64_REG_X21)==G and index==expected(phase,pointer)
     rows.append({'phase32':hex(phase),'buffer_pointer64':hex(pointer),'controller32':hex(state),'index32':hex(index),'all_checks_pass':True})
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':sha(SOURCE),'source_span':{'start':hex(START),'end':hex(END),'bytes_hex':IMAGE.read(START,END-START).hex(),'sha256':hashlib.sha256(IMAGE.read(START,END-START)).hexdigest()},'bank_root_premises':{'SP+0x48':'0x101031fa0','SP+0x50':'0x100fc4230','X26':hex(POOL)},'cases':rows,'verified_counts':{'isolated_guard_cases':len(rows),'distinct_phase32_values':768,'buffer_pointer64_values':3,'controller32_pairs':2,'source_instructions_per_case':41},'all_checks_pass':True,'native_target_executed':False,'full_goal_complete':False};assert len(rows)==4608;(ROOT/'daemon_descriptor_guard_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out['verified_counts']),flush=True)
if __name__=='__main__':main()
