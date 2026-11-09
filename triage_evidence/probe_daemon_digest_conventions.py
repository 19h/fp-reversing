#!/usr/bin/env python3
"""Isolated original-A64 checks of paired digest register/frame conventions.
O(total case visits+effects) time; space includes one private map and all
retained case journals in the output artifact.
Stops precede dispatch/API calls; original logical table cells are read only.
No native caller, allocation, digest completion, IPC or hardware PAC executes.
"""
import json,itertools
from pathlib import Path
import unicorn as uc
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,SOURCE,IMAGE,TABLE
from recover_daemon_object_creation import sha
from validate_daemon_object_clock import logical_read
P=0x6900000000;SIZE=0x100000
RANGES={'encoded_update':(0x100a0aad0,0x100a0ab34),'wrapped_pad':(0x100ac0fe8,0x100ac1038),'inline_pad':(0x100bb2284,0x100bb22dc),'wrapped_finalize':(0x100c03b20,0x100c03b64),'new_finalize_caller':(0x10094dec4,0x10094defc),'fixed20_caller':(0x100be25b8,0x100be25fc),'saved_finalize_caller':(0x100baaf1c,0x100baaf54),'identity_reserve':(0x100baff8c,0x100baffb8),'post_finalize':(0x100a0e340,0x100a0e3d4),'malloc_arg':(0x100bb030c,0x100bb0314)}
def cases():
 for n,h,p in itertools.product([0,1,20,44,63,64,65],[0,1,55,56,63,64,0xffffffff],[0xb5d,0xb75]):yield {'kind':'encoded_update','N32':n,'H32':h,'return_index':p,'offset':0 if p==0xb5d else 0x100}
 for kind,high,h in itertools.product(['wrapped_pad','inline_pad'],[False,True],range(64)):yield {'kind':kind,'H32':h|(0xffffffc0 if high else 0),'offset':0x100 if high else 0}
 for p,present in itertools.product([0x9b,0x9c],[False,True]):yield {'kind':'wrapped_finalize','return_index':p,'output_present':present,'offset':0 if p==0x9b else 0x100}
 for kind,offset in itertools.product(['new_finalize_caller','fixed20_caller','saved_finalize_caller'],[0,0x100]):yield {'kind':kind,'offset':offset}
 for q,offset in itertools.product([0,0x2f0],[0,0x100]):yield {'kind':'identity_reserve','cursor':q,'offset':offset}
 for a,b,o in itertools.product([False,True],repeat=3):yield {'kind':'post_finalize','A_present':a,'B_present':b,'output_present':o,'offset':0}
 yield {'kind':'malloc_arg','offset':0}
def execute(cfg):
 kind=cfg['kind'];start,end=RANGES[kind];F=P+0x40000+cfg['offset'];C=P+0x10000;O=P+0x20000;I=P+0x30000;u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);u.mem_map(P,SIZE);u.mem_write(P,bytes([0x5a if cfg['offset']else 0xa5])*SIZE);pages=set();defined=set();initial=[];steps=[];events=[];pending=[]
 def reg(n):return getattr(ar,'UC_ARM64_REG_'+n.upper())
 def get(n):return u.reg_read(reg(n))
 def putreg(n,v):u.reg_write(reg(n),v&((1<<64)-1))
 def fixture(a,n,v):b=v.to_bytes(n,'little');u.mem_write(a,b);defined.update(range(a,a+n));initial.append({'address':hex(a),'bytes_hex':b.hex()})
 def mapimage(a,n):
  for pg in range(a&~4095,((a+n-1)&~4095)+4096,4096):
   if pg not in pages:u.mem_map(pg,4096);u.mem_write(pg,logical_read(pg,4096));pages.add(pg)
 for j in range(31):putreg('x'+str(j),((j+1)*0x123456789abcdef)^cfg['offset'])
 putreg('sp',F);putreg('nzcv',0xa0000000 if cfg['offset']else 0x50000000)
 if kind=='encoded_update':
  for n,v in [('x30',TABLE),('x19',0x9930),('x20',cfg['return_index']),('x4',C),('x21',I),('x5',(cfg['N32']+0x1ad72f12)&0xffffffff)]:putreg(n,v)
  fixture(C+0x44,4,cfg['H32']);mapimage(TABLE+8*cfg['return_index'],8)
 elif kind in ['wrapped_pad','inline_pad']:
  putreg('x8',0x3b if kind=='wrapped_pad'else 0x18);putreg('x4',C);putreg('x10',O);fixture(C+0x44,4,cfg['H32'])
 elif kind=='wrapped_finalize':
  for n,v in [('x10',F+0x200),('x11',F+0x208),('x9',cfg['return_index']),('x30',TABLE),('x13',0x471c)]:putreg(n,v)
  fixture(F+0x200,8,C);fixture(F+0x208,8,O if cfg['output_present']else 0);mapimage(TABLE+8*cfg['return_index'],8)
 elif kind in ['new_finalize_caller','fixed20_caller','saved_finalize_caller']:
  fixture(F+0x273c,4,0x471c);putreg('x22'if kind!='saved_finalize_caller'else'x19',TABLE);mapimage(TABLE+8*(0x49c6 if kind=='fixed20_caller'else 0xac2e),8)
  if kind=='fixed20_caller':fixture(F+0x2f08,8,I);fixture(F+0x30b8,8,C)
 elif kind=='identity_reserve':fixture(F+0x3238,8,C);fixture(F+0x3620,8,cfg['cursor']);fixture(F+0x2f00,8,I)
 elif kind=='post_finalize':
  putreg('x13',0x471c);fixture(F+0x31c8,8,O if cfg['output_present']else 0);fixture(F+0x3648,8,I if cfg['A_present']else 0);fixture(F+0x35a8,8,17 if cfg['B_present']else 0)
 else:assert kind=='malloc_arg'
 mapimage(start,end-start);entry=[hex(get('x'+str(j)))for j in range(31)]
 def flush():
  for e in pending:e['after_hex']=bytes(u.mem_read(int(e['address'],16),e['size_bytes'])).hex()
  pending.clear()
 def code(u,a,n,d):flush();raw=bytes(u.mem_read(a,4));assert raw==IMAGE.read(a,4);steps.append((a,raw.hex()))
 def read(u,t,a,n,v,d):
  if P<=a<a+n<=P+SIZE:assert all(x in defined for x in range(a,a+n)),('undefined read',hex(a),n)
  else:assert bytes(u.mem_read(a,n))==logical_read(a,n)
  events.append({'kind':'read','pc':hex(get('pc')),'address':hex(a),'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()})
 def write(u,t,a,n,v,d):
  assert P<=a<a+n<=P+SIZE;defined.update(range(a,a+n));e={'kind':'write','pc':hex(get('pc')),'address':hex(a),'size_bytes':n};events.append(e);pending.append(e)
 u.hook_add(uc.UC_HOOK_CODE,code);u.hook_add(uc.UC_HOOK_MEM_READ,read);u.hook_add(uc.UC_HOOK_MEM_WRITE,write);u.emu_start(start,end,count=1000);flush();assert get('pc')==end and len(steps)==(end-start)//4
 return {'configuration':cfg,'entry_PC':hex(start),'end_PC':hex(end),'SP':hex(F),'context':hex(C),'output':hex(O),'input':hex(I),'entry_registers31':entry,'final_registers31':[hex(get('x'+str(j)))for j in range(31)],'initial_fixtures':initial,'steps':steps,'events':events,'source_visits':len(steps),'native_target_executed':False,'native_path_reachability_established':False,'full_goal_complete':False}
def main():
 rows=[execute(x)for x in cases()];assert len(rows)==377;deps=['daemon_digest_conventions_contracts.json','validate_daemon_object_clock.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'cases':rows,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_digest_conventions_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'isolated_A64_cases':len(rows),'source_visits':sum(x['source_visits']for x in rows),'reads':sum(e['kind']=='read'for x in rows for e in x['events']),'writes':sum(e['kind']=='write'for x in rows for e in x['events'])}),flush=True)
if __name__=='__main__':main()
