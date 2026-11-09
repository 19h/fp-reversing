#!/usr/bin/env python3
"""Compact byte-reader contract against isolated original A64 on varied inputs.
O(cases+selected window bytes) time, O(selected window+mapped pages) space.
Native target, imported calls, PAC and Mach/IOKit are not executed.
"""
import hashlib,json,struct
from pathlib import Path
import unicorn as uc
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,SOURCE,IMAGE
M=0xffffffff

def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 c=json.loads((ROOT/'daemon_callback_revisit_contracts.json').read_text());A=int(c['selected_code_address'],16);code=IMAGE.read(A,32768);u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);pages=set()
 def write(a,b):
  for pg in range(a&~4095,(a+len(b)+4095)&~4095,4096):
   if pg not in pages:u.mem_map(pg,4096);pages.add(pg)
  u.mem_write(a,b)
 write(0x100a0c000,IMAGE.read(0x100a0c000,4096));write(A,code);F=0x70000000;O=0x70001100;D=0x71000000
 write(F+0x160,struct.pack('<QQ',0x1010c67d4,0x1010c8268));write(0x1010c67d4,struct.pack('<I',255));write(0x1010c8268,struct.pack('<Q',D));write(0x1010c6800,struct.pack('<Q',32767^0xfff0c012a7a730ec));write(0x1010ca2a8,struct.pack('<Q',A^0x12af5504870a589f));write(O,bytes(256));rows=[]
 for n in range(64):
  q=struct.unpack('<8I',hashlib.sha256(str(n).encode()).digest());P,B,V,T,off=q[:5];off&=255;position=(O+off)&M;t=(T+position)&M;idx1=(t+(P^0x0ba37f51))&32767;idx2=(t+0x0ba3ccca)&32767;tag=(B^((31*position)&M)^code[idx1]^code[idx2])&255;out=tag^(V&255)^6
  write(D+200,struct.pack('<I',T))
  for r,v in [('SP',F),('X4',O),('X15',off),('W13',P),('W14',B),('W11',V)]:u.reg_write(getattr(ar,'UC_ARM64_REG_'+r),v)
  u.emu_start(0x100a0c9bc,0x100a0ca78,count=60);assert bytes(u.mem_read(O+off,1))==bytes([out])and u.reg_read(ar.UC_ARM64_REG_W14)==tag and u.reg_read(ar.UC_ARM64_REG_X15)==O+off
  rows.append({'case':n,'table_word':hex(T),'position':hex(O+off),'input_P32':hex(P),'input_B32':hex(B),'input_V32':hex(V),'code_offsets':[idx1,idx2],'tag8':hex(tag),'output8':hex(out),'all_checks_pass':True})
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{'daemon_callback_revisit_contracts.json':sha(ROOT/'daemon_callback_revisit_contracts.json')},'source_sha256':sha(SOURCE),'cases':rows,'verified_counts':{'isolated_A64_byte_reader_cases':64,'table_offset_bytes':200,'code_byte_reads_per_case':2},'all_checks_pass':True,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_callback_reader_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out['verified_counts']),flush=True)
if __name__=='__main__':main()
