#!/usr/bin/env python3
"""Compact 552-byte context codec and inverse versus original isolated A64.
O(cases*552) time, O(552+emulated pages) space. Source byte codec followed
by68 u64 swaps. Pointer publication postlude/native authentication excluded.
"""
import json,hashlib,struct
from pathlib import Path
import unicorn as uc
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,SOURCE,IMAGE

def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def mask(s,i):return (s^((i+s)*(i-s)))&255
def pick(s,i):return ((((s+i)&0xffffffff)^s)*0x01000193&0xffffffff)%i
def encode(b,s):
 a=bytearray(((x^mask(s,i))*0x93)&255 for i,x in enumerate(b));w=list(struct.unpack('<69Q',a))
 for i in range(68,0,-1):j=pick(s,i);w[i],w[j]=w[j],w[i]
 return struct.pack('<69Q',*w)
def decode(b,s):
 w=list(struct.unpack('<69Q',b))
 for i in range(1,69):j=pick(s,i);w[i],w[j]=w[j],w[i]
 return bytes(((x*0x9b)&255)^mask(s,i)for i,x in enumerate(struct.pack('<69Q',*w)))
def source(b,s,row):
 u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX)
 for pg in [0x1003c4000,0x100fc4000]:u.mem_map(pg,4096);u.mem_write(pg,IMAGE.read(pg,4096))
 D=0x70000100;F=0x70001000;u.mem_map(0x70000000,8192);u.mem_write(D-16,bytes([0xa5])*16+b+bytes([0x5a])*16);u.mem_write(F+0x30,bytes.fromhex(row['stack_index_vectors_hex']))
 for name,v in row['vector_constants'].items():
  if 'hex'in v:bv=bytes.fromhex(v['hex'])
  else:
   assert name=='q15'and all(isinstance(x,int)for x in v['terms'][:8]);bv=bytes(v['terms'][:8])+bytes([s&255])*8
  u.reg_write(getattr(ar,'UC_ARM64_REG_'+name.upper()),int.from_bytes(bv,'little'))
 for name,v in [('SP',F),('X16',D),('W17',s),('X12',0)]:u.reg_write(getattr(ar,'UC_ARM64_REG_'+name),v)
 u.emu_start(0x1003c41dc,0x1003c4324,count=6000);assert u.reg_read(ar.UC_ARM64_REG_PC)==0x1003c4324 and bytes(u.mem_read(D-16,16))==bytes([0xa5])*16 and bytes(u.mem_read(D+552,16))==bytes([0x5a])*16;return bytes(u.mem_read(D,552))
def main():
 c=json.loads((ROOT/'daemon_context_seal_contracts.json').read_text());rows=[];base=c['cases'][0]
 for row in c['cases']:
  b=bytes.fromhex(row['before_hex']);s=int(row['seed32'],16);out=source(b,s,row);assert out.hex()==row['after_hex']and encode(b,s)==out and decode(out,s)==b;rows.append({'class':'retained_source_context','name':row['name'],'seed32':hex(s),'all_checks_pass':True})
 for n in range(33):
  s=[0,1,0x7fffffff,0x80000000,0xffffffff][n]if n<5 else int.from_bytes(hashlib.sha256(str(n).encode()).digest()[:4],'little');b=bytes(552)if n==0 else bytes([255])*552 if n==1 else bytes((j*73+n*29)&255 for j in range(552));out=source(b,s,base);assert out==encode(b,s)and decode(out,s)==b;rows.append({'class':'varied_seed_and_input','case':n,'seed32':hex(s),'all_checks_pass':True})
 deps=['daemon_context_seal_contracts.json'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'cases':rows,'verified_counts':{'retained_context_codec_cases':13,'varied_context_codec_cases':33,'total_isolated_context_codec_cases':46,'context_extent_bytes':552,'context_words':69,'word_swaps_per_context':68},'all_checks_pass':True,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_context_seal_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out['verified_counts']),flush=True)
if __name__=='__main__':main()
