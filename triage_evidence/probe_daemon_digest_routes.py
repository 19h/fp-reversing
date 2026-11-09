#!/usr/bin/env python3
"""Independent A64 checks of isolated argument/routing/capture fragments.
O(cases*(source visits+effects)) time, O(one private map+journal) space.
Each fragment stops before its branch/table dispatch. No native caller or PAC
is executed; callee capture only loads and saves an original logical table cell.
"""
import json,struct
from pathlib import Path
import unicorn as uc
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,SOURCE,IMAGE,TABLE
from recover_daemon_object_creation import sha
from validate_daemon_object_clock import logical_read
P=0x6900000000;SIZE=0x100000
PHASES=[0,0x202,0x32b,0x240,0x371,0x9f6f,0x12340202,0xffff9f6f]
CALLEE_PHASES=[0,1,0x202,0x240,0x471c,0x6eca,0xffffffff,0xfffffefe]
RANGES={'new_context':(0x100b5c580,0x100b5c614),'existing_prefix':(0x100bae14c,0x100bae15c),'existing_route':(0x100bae15c,0x100bae168),'existing_args':(0x100bae16c,0x100bae178),'callee_capture':(0x100aee3a4,0x100aee3c0),'saved_continuation':(0x100bb2278,0x100bb2280)}
def cases():
 for offset in [0,0x100]:
  for phase in PHASES:
   for word in [0,44,256]:yield {'kind':'new_context','offset':offset,'phase32':phase,'word32':word}
   for kind in ['existing_prefix','existing_route','existing_args']:yield {'kind':kind,'offset':offset,'phase32':phase,'word32':44}
  for phase in CALLEE_PHASES:
   for kind in ['callee_capture','saved_continuation']:yield {'kind':kind,'offset':offset,'phase32':phase,'word32':44}
def execute(cfg):
 kind=cfg['kind'];start,end=RANGES[kind];F=P+0x40000+cfg['offset'];O=P+0x10000;CTX=P+0x20000;INPUT=P+0x18000;cursor=48 if not cfg['offset']else 704;pattern=0xa5 if not cfg['offset']else 0x5a;u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);u.mem_map(P,SIZE);u.mem_write(P,bytes([pattern])*SIZE);pages=set();defined=set();initial=[];steps=[];events=[];pending=[]
 def reg(name):return getattr(ar,'UC_ARM64_REG_'+name.upper())
 def get(name):return u.reg_read(reg(name))
 def setreg(name,value):u.reg_write(reg(name),value)
 def mapimage(a,n):
  for pg in range(a&~4095,((a+n-1)&~4095)+4096,4096):
   if pg in pages:continue
   u.mem_map(pg,4096);u.mem_write(pg,logical_read(pg,4096));pages.add(pg)
 def fixture(a,n,v):
  b=v.to_bytes(n,'little');u.mem_write(a,b);defined.update(range(a,a+n));initial.append({'address':hex(a),'bytes_hex':b.hex()})
 for j in range(31):setreg('x'+str(j),(((j+1)*0x123456789abcdef)^pattern)&((1<<64)-1))
 setreg('sp',F);setreg('nzcv',0xa0000000 if cfg['offset']else 0x50000000);setreg('x9',cfg['phase32'])
 if kind=='new_context':
  for a,n,v in [(F+0x2df8,8,INPUT),(F+0x2b38,8,O),(O+0xe0,4,cfg['word32']),(F+0x2d70,8,0x1122334455667788),(F+0x3640,8,0x8877665544332211),(F+0x3620,8,cursor)]:fixture(a,n,v)
 elif kind=='existing_args':
  for a,n,v in [(F+0x2988,8,0x101031fa0),(F+0x2a70,8,CTX),(F+0x2a68,4,cfg['word32'])]:fixture(a,n,v)
 elif kind=='existing_prefix':fixture(F+0x2a60,8,O);fixture(O+0x6c,4,cfg['word32'])
 elif kind=='callee_capture':
  signed=cfg['phase32']-(1<<32)if cfg['phase32']>>31 else cfg['phase32'];slot=TABLE+signed*8;mapimage(slot,8);setreg('x30',TABLE);setreg('x4',CTX);setreg('x2',0xabcdef1200000000|cfg['word32']);setreg('x8',INPUT)
 elif kind=='saved_continuation':fixture(F+0x2f48,8,0x1234567800000000|cfg['phase32'])
 mapimage(start,end-start);entry=[hex(get('x'+str(j)))for j in range(31)]
 def flush():
  for e in pending:e['after_hex']=bytes(u.mem_read(int(e['address'],16),e['size_bytes'])).hex()
  pending.clear()
 def code(u,a,n,d):
  flush();raw=bytes(u.mem_read(a,4));assert raw==IMAGE.read(a,4);steps.append((a,raw.hex()))
 def read(u,t,a,n,v,d):
  if P<=a<a+n<=P+SIZE:assert all(x in defined for x in range(a,a+n)),('undefined private read',hex(a),n)
  else:assert bytes(u.mem_read(a,n))==logical_read(a,n)
  events.append({'kind':'read','pc':hex(get('pc')),'address':hex(a),'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()})
 def write(u,t,a,n,v,d):
  assert P<=a<a+n<=P+SIZE;defined.update(range(a,a+n));e={'kind':'write','pc':hex(get('pc')),'address':hex(a),'size_bytes':n};events.append(e);pending.append(e)
 u.hook_add(uc.UC_HOOK_CODE,code);u.hook_add(uc.UC_HOOK_MEM_READ,read);u.hook_add(uc.UC_HOOK_MEM_WRITE,write);u.emu_start(start,end,count=1000);flush();assert get('pc')==end and len(steps)==(end-start)//4
 return {'configuration':cfg,'entry_PC':hex(start),'end_PC':hex(end),'SP':hex(F),'entry_registers31':entry,'final_registers31':[hex(get('x'+str(j)))for j in range(31)],'initial_fixtures':initial,'source_visits':len(steps),'steps':steps,'events':events,'cursor_input':cursor,'context_pointer':hex(F+0x39f0+cursor)if kind=='new_context'else hex(CTX),'original_table_slot':hex(slot)if kind=='callee_capture'else None,'native_target_executed':False,'native_path_reachability_established':False,'full_goal_complete':False}
def main():
 rows=[execute(c)for c in cases()];assert len(rows)==128;deps=['daemon_digest_routes_contracts.json','validate_daemon_object_clock.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'cases':rows,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_digest_routes_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'isolated_A64_cases':len(rows),'source_visits':sum(x['source_visits']for x in rows),'source_reads':sum(e['kind']=='read'for x in rows for e in x['events']),'source_writes':sum(e['kind']=='write'for x in rows for e in x['events'])}),flush=True)
if __name__=='__main__':main()
