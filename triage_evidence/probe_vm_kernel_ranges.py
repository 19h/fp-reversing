#!/usr/bin/env python3
"""Private CPU checks of two original kernel arithmetic fragments only.
All 256 page-shift bytes and eight address/size pairs; no kernel entry,
VM helper, SVC, PAC or native target executes. Each case executes ten
original instructions against a private mapped page-field byte.
O(256*8) time, O(one private CPU map + records) space.
"""
import json
import unicorn as uc
from unicorn import arm64_const as ar
from kernel_native_reader import Kernel
from daemon_receive_tools import ROOT
from capture_daemon_record720 import sha
M=(1<<64)-1;START=0xfffffe000bdc1ecc;MAP=0x6500000000
def main():
 k=Kernel();u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);pg=START&~4095;u.mem_map(pg,4096,uc.UC_PROT_READ|uc.UC_PROT_EXEC);u.mem_write(pg,k.read(pg,4096));u.mem_map(MAP,4096);rows=[]
 def reg(j):return u.reg_read(getattr(ar,'UC_ARM64_REG_X'+str(j)))
 for page in range(256):
  for address,size in [(0,0),(0,1),(1,1),(0,4096),(4095,2),(M,1),(M-4095,4096),(M,M)]:
   u.mem_write(MAP+0x2c,bytes([page]));u.reg_write(ar.UC_ARM64_REG_X0,MAP);u.reg_write(ar.UC_ARM64_REG_X1,address);u.reg_write(ar.UC_ARM64_REG_X2,size);u.emu_start(START,START+4,count=1);total=(address+size)&M;carry=(u.reg_read(ar.UC_ARM64_REG_NZCV)>>29)&1;assert reg(8)==total and carry==int(address+size>M);u.emu_start(0xfffffe000bdc1ed4,0xfffffe000bdc1ef8,count=9);mask=(1<<(page&31))-1;first=address&(~mask&M);last=((total+mask)&M)&(~mask&M);flags=u.reg_read(ar.UC_ARM64_REG_NZCV);ls=not((flags>>29)&1)or bool((flags>>30)&1);assert reg(1)==first and reg(2)==last and ls==(last<=first);rows.append({'page_shift_byte':page,'address':hex(address),'size':hex(size),'sum':hex(total),'sum_carry':carry,'start':hex(first),'end':hex(last),'end_at_most_start':ls})
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{'kernel_native_reader.py':sha(ROOT/'kernel_native_reader.py')},'kernel_sha256':k.sha256,'source_fragments':[{'start':hex(START),'bytes_hex':k.read(START,4).hex()},{'start':'0xfffffe000bdc1ed4','bytes_hex':k.read(0xfffffe000bdc1ed4,36).hex()}],'cases':rows,'case_count':len(rows),'page_shift_values':256,'source_visits':len(rows)*10,'native_kernel_executed':False,'native_VM_executed':False,'all_checks_pass':True};(ROOT/'daemon_vm_cleanup_kernel_components.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':out['source_visits'],'page_values':256,'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
