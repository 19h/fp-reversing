#!/usr/bin/env python3
"""Isolated original-A64 local compositions with declared cutpoint fixtures.
O(total visits+effects) time; O(retained output journals+one private map) space.
BRAA dispatch is modeled from original logical cells; no hardware PAC/API/IPC
executes. Retained unknown-frame frontiers are never resumed.
"""
import itertools,json
from pathlib import Path
import unicorn as uc
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,TABLE,FIXUPS
from recover_daemon_object_creation import sha
from recover_daemon_compression_frame import SPECS,K
from validate_daemon_object_clock import logical_read
P=0x6a00000000;SIZE=0x100000
LABELS={'copy':['long_prepare','copy_loop','copy_finish'],'selector':['compression_entry','selector_gate','selector_high','selector_low'],'frame':['frame_common'],'short':['short_call'],'post':['long_return','next_block_gate'],'return':['compression_return']}
def cases():
 for h,o in itertools.product(range(64),[0,0x100]):yield {'kind':'copy','H32':h,'offset':o}
 for b,ret in itertools.product(range(256),[0xe,0x58]):yield {'kind':'selector','selector':b,'return_index':ret,'offset':0 if ret==0xe else 0x100}
 for v,o in itertools.product(range(4),[0,0x100]):yield {'kind':'frame','pattern':v,'offset':o}
 for o in [0,0x100]:yield {'kind':'short','offset':o}
 for n,l in itertools.product([0,1,2,20,44,63,64,65,127,128,129,200,255,256,0xfffffffe,0xffffffff],[1,2,63,64]):yield {'kind':'post','N32':n,'L32':l,'offset':0}
 for p in [0xe,0x58]:yield {'kind':'return','return_index':p,'offset':0}
def execute(cfg):
 kind=cfg['kind'];F=P+0x40000+cfg['offset'];C=P+0x10000;I=P+0x30000;u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);u.mem_map(P,SIZE);u.mem_write(P,bytes([0xa5 if cfg['offset']==0 else 0x5a])*SIZE);defined=set();fixtures=[];pages=set();steps=[];events=[];edges=[];pending=[]
 def rid(n):return getattr(ar,'UC_ARM64_REG_'+n.upper())
 def get(n):return u.reg_read(rid(n))
 def put(n,v):u.reg_write(rid(n),v&((1<<64)-1))
 def fixture(a,b):u.mem_write(a,b);defined.update(range(a,a+len(b)));fixtures.append({'address':hex(a),'bytes_hex':b.hex()})
 def word(a,n,v):fixture(a,(v&((1<<(8*n))-1)).to_bytes(n,'little'))
 def mapimage(a,n):
  for pg in range(a&~4095,((a+n-1)&~4095)+4096,4096):
   if pg not in pages:u.mem_map(pg,4096);u.mem_write(pg,logical_read(pg,4096));pages.add(pg)
 for j in range(31):put('x'+str(j),((j+1)*0x123456789abcdef)^cfg['offset'])
 put('sp',F);put('nzcv',0x50000000 if cfg['offset']==0 else 0xa0000000);put('x30',TABLE)
 if kind=='copy':
  put('x10',0x6f67867f);put('x8',cfg['H32']);put('x4',C);put('x21',I);length=64-cfg['H32'];fixture(I,bytes(((j*37+cfg['offset']//16)^0x5a)&255 for j in range(length)))
 elif kind=='selector':
  put('x4',C);put('x1',0x318c);put('x20',cfg['return_index']);word(F+0x3620,8,0x310 if cfg['return_index']==0x58 else 0x2f0)
  for j,v in enumerate([0x93bc0ef6,0x1b34867e,0x6c43f109,0xe4cb7981]):word(C+0x48+4*j,4,v)
  word(C+0x60,1,cfg['selector'])
 elif kind=='frame':
  p=cfg['pattern'];put('x8',0x471c);put('x15',0x471c);put('x4',C)
  for off,n,v in [(0x31dc,4,(0x1ad72f12+p*63)&0xffffffff),(0x2f50,8,I),(0x2e50,8,[0,C,(1<<64)-1,0x123456789abcdef0][p]),(0x2c8c,4,[0,1,64,0xffffffff][p]),(0x3490,8,[0,I,(1<<64)-1,0xabcdef9876543210][p])]:word(F+off,n,v)
 elif kind=='short':put('x8',0x471c);put('x4',C)
 elif kind=='return':
  put('x2',TABLE)
  for off,nb,v in [(0x3620,8,0x2f0+320),(0x2de0,8,FIXUPS[TABLE+cfg['return_index']*8]['target']),(0x273c,4,0x471c),(0x2978,8,I),(0x2980,8,C)]:word(F+off,nb,v)
 else:
  assert kind=='post';n,l=cfg['N32'],cfg['L32']
  for off,nb,v in [(0x2a10,4,0x42),(0x2a60,4,(n+K)&0xffffffff),(0x30fc,4,l),(0x2a38,4,K),(0x2a40,4,0xa34a),(0x2a58,8,I),(0x2a50,8,C),(0x2a30,4,0xa351),(0x2a28,4,64)]:word(F+off,nb,v)
 blocks={a:(z,n)for n,a,z in SPECS if n in LABELS[kind]};start=next(a for n,a,z in SPECS if n==LABELS[kind][0]);entry=[hex(get('x'+str(j)))for j in range(31)]
 def flush():
  for e in pending:e['after_hex']=bytes(u.mem_read(int(e['address'],16),e['size_bytes'])).hex()
  pending.clear()
 def code(u,a,n,d):flush();raw=bytes(u.mem_read(a,4));assert raw==IMAGE.read(a,4);steps.append([a,raw.hex()])
 def read(u,t,a,n,v,d):
  if P<=a<a+n<=P+SIZE:assert all(x in defined for x in range(a,a+n)),('undefined private read',hex(a),n)
  else:assert bytes(u.mem_read(a,n))==logical_read(a,n)
  events.append({'kind':'read','pc':hex(get('pc')),'address':hex(a),'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()})
 def write(u,t,a,n,v,d):
  assert P<=a<a+n<=P+SIZE;defined.update(range(a,a+n));e={'kind':'write','pc':hex(get('pc')),'address':hex(a),'size_bytes':n};events.append(e);pending.append(e)
 def fault(u,t,a,n,v,d):assert not P<=a<P+SIZE;mapimage(a,n);return True
 u.hook_add(uc.UC_HOOK_CODE,code);u.hook_add(uc.UC_HOOK_MEM_READ,read);u.hook_add(uc.UC_HOOK_MEM_WRITE,write);u.hook_add(uc.UC_HOOK_MEM_READ_UNMAPPED,fault)
 pc=start
 while pc in blocks:
  end,label=blocks[pc];branch=end-4;mapimage(pc,end-pc);before=len(steps);u.emu_start(pc,branch,count=1000);flush();assert get('pc')==branch and len(steps)-before==(branch-pc)//4
  ins=next(CS.disasm(IMAGE.read(branch,4),branch));assert ins.mnemonic=='braa';target_reg,modifier_reg=ins.op_str.split(', ');target=get(target_reg);modifier=get(modifier_reg);slot=TABLE+cfg['return_index']*8 if kind=='return'else next(int(e['address'],16)for e in reversed(events)if e['kind']=='read'and int(e['address'],16)in FIXUPS and int.from_bytes(bytes.fromhex(e['bytes_hex']),'little')==target);fix=FIXUPS[slot];assert fix['target']==target and f'div=0x{modifier:04X} 'in fix['annotation'];steps.append([branch,IMAGE.read(branch,4).hex()]);edges.append({'pc':hex(branch),'target':hex(target),'slot':hex(slot),'modifier':hex(modifier),'hardware_authentication_executed':False,'target_origin':'saved_continuation_fixture'if kind=='return'else'original_logical_cell_read'});pc=target;assert len(edges)<=70
 return {'configuration':cfg,'SP':hex(F),'context':hex(C),'input':hex(I),'entry_registers31':entry,'final_registers31':[hex(get('x'+str(j)))for j in range(31)],'initial_fixtures':fixtures,'steps':steps,'events':events,'edges':edges,'frontier_PC':hex(pc),'source_visits':len(steps),'modeled_dispatch_visits':len(edges),'native_target_executed':False,'full_goal_complete':False}
def main():
 rows=[execute(c)for c in cases()];assert len(rows)==716;deps=['daemon_compression_frame_contracts.json','validate_daemon_object_clock.py','recover_daemon_compression_frame.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'cases':rows,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_compression_frame_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'isolated_cases':len(rows),'source_visits':sum(r['source_visits']for r in rows),'reads':sum(e['kind']=='read'for r in rows for e in r['events']),'writes':sum(e['kind']=='write'for r in rows for e in r['events'])}),flush=True)
if __name__=='__main__':main()
