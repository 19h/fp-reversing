#!/usr/bin/env python3
"""Independent compact context codec versus original A64, fixed 2184-byte extent.
O(cases*extent) time, O(extent+emulated pages) space. No native API/PAC.
"""
import hashlib,json,struct
from pathlib import Path
import unicorn as uc
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,SOURCE,IMAGE
MASK=0xffffffff

def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def byte_mask(seed,i):return (seed^(((i+seed)*(i-seed))&MASK))&255
def shuffle_index(seed,i):return ((((seed+i)&MASK)^seed)*0x01000193&MASK)%i

def encode(data,seed):
 b=bytearray(((v^byte_mask(seed,i))*0x93)&255 for i,v in enumerate(data));w=list(struct.unpack('<273Q',b))
 for i in range(272,0,-1):j=shuffle_index(seed,i);assert 0<=j<i;w[i],w[j]=w[j],w[i]
 return struct.pack('<273Q',*w)
def decode(data,seed):
 w=list(struct.unpack('<273Q',data))
 for i in range(1,273):j=shuffle_index(seed,i);w[i],w[j]=w[j],w[i]
 return bytes(((v*0x9b)&255)^byte_mask(seed,i)for i,v in enumerate(struct.pack('<273Q',*w)))
def source(data,seed,constants):
 u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX)
 for pg in [0x100462000,0x100e2c000,0x100fc4000]:u.mem_map(pg,4096);u.mem_write(pg,IMAGE.read(pg,4096))
 D=0x70000100;u.mem_map(0x70000000,4096);u.mem_write(D-16,bytes([0xa5])*16+data+bytes([0x5a])*16)
 for r,v in constants.items():u.reg_write(getattr(ar,'UC_ARM64_REG_'+r.upper()),int.from_bytes(bytes.fromhex(v['hex']),'little'))
 u.reg_write(ar.UC_ARM64_REG_X15,D);u.reg_write(ar.UC_ARM64_REG_X16,seed);u.reg_write(ar.UC_ARM64_REG_X11,0)
 u.emu_start(0x100462818,0x100462974,count=20000)
 assert u.reg_read(ar.UC_ARM64_REG_PC)==0x100462974 and bytes(u.mem_read(D-16,16))==bytes([0xa5])*16 and bytes(u.mem_read(D+2184,16))==bytes([0x5a])*16
 return bytes(u.mem_read(D,2184))
def main():
 c=json.loads((ROOT/'daemon_callback_revisit_contracts.json').read_text());p=c['context_payload'];rows=[]
 for n in range(33):
  seed=int(p['seed32'],16)if n==0 else [0,1,0x7fffffff,0x80000000,0xffffffff][n-1]if n<6 else int.from_bytes(hashlib.sha256(str(n).encode()).digest()[:4],'little')
  b=bytes.fromhex(p['before_hex'])if n==0 else bytes(2184)if n==1 else bytes([255])*2184 if n==2 else bytes((i*73+n*31)&255 for i in range(2184));actual=source(b,seed,p['vector_constants']);expected=encode(b,seed);assert actual==expected and decode(actual,seed)==b
  if n==0:assert actual.hex()==p['after_hex']
  perm=list(range(273))
  for i in range(272,0,-1):j=shuffle_index(seed,i);perm[i],perm[j]=perm[j],perm[i]
  visited=set();i=0
  while i not in visited:visited.add(i);i=perm[i]
  assert len(visited)==273 and i==0
  rows.append({'case':n,'seed32':hex(seed),'input_sha256':hashlib.sha256(b).hexdigest(),'output_sha256':hashlib.sha256(actual).hexdigest(),'inverse_matches':True,'single_cycle_words':273,'all_checks_pass':True})
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{'daemon_callback_revisit_contracts.json':sha(ROOT/'daemon_callback_revisit_contracts.json')},'source_sha256':sha(SOURCE),'source_span':{'start':'0x100462818','end':'0x100462974','sha256':hashlib.sha256(IMAGE.read(0x100462818,0x15c)).hexdigest()},'cases':rows,'verified_counts':{'A64_codec_cases':len(rows),'bytes_per_case':2184,'word_swaps_per_case':272,'inverse_cases':len(rows)},'all_checks_pass':True,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_callback_payload_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out['verified_counts']),flush=True)
if __name__=='__main__':main()
