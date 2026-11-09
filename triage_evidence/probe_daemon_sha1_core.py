#!/usr/bin/env python3
"""Source-pinned isolated SHA-1 core traces with GPR/byte definedness.
O(total visits+effects) time; O(compressed outputs+one decoded journal+map)
space. Native caller/PAC/IPC and identity-to-cache joins remain unproved.
"""
import base64,json,struct,hashlib,zlib,random
from pathlib import Path
import unicorn as uc
from unicorn import arm64_const as ar
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from daemon_receive_tools import IMAGE,SOURCE,TABLE,FIXUPS
from resolve_kernel_collection_interfaces import commands
from validate_daemon_object_clock import logical_read
from daemon_receive_tools import ROOT
from recover_daemon_object_creation import sha
from daemon_sha1_core_model import IV,pad

def cases():
 messages=[b'',b'a',b'abc','é'.encode(),bytes(range(31)),bytes(55),bytes([255])*55,bytes((j*37+19)&255 for j in range(55))]
 rng=random.Random(0x53484131)
 blocks=[bytes(64),bytes([255])*64,bytes(range(64)),bytes(reversed(range(64))),bytes([0x55,0xaa])*32,bytes([0x80])+bytes(63),bytes(63)+b'\x01',rng.randbytes(64)]
 base=[{'kind':'padded_message','message_hex':m.hex(),'block_hex':pad(m).hex(),'initial_state5':IV}for m in messages]
 for b in blocks:
  base.append({'kind':'raw_block','block_hex':b.hex(),'initial_state5':IV})
  base.append({'kind':'custom_state','block_hex':b.hex(),'initial_state5':[rng.getrandbits(32)for j in range(5)]})
 for j,b in enumerate(base):
  for ret in [0xe,0x58]:yield {**b,'return_index':ret,'offset':0 if ret==0xe else 0x100,'counter64':(j*0x123456789abc)&((1<<64)-1),'ambient_count32':[0,64,0xffffffff,256][j%4],'ambient_raw64':[0,0xffffffffffffffff,0x123456789abcdef0,0x6b00030000][j%4],'cursor64':0x2f0 if ret==0xe else 0x310}

def execute(cfg):
 P=0x6b00000000;F=P+0x40000+cfg['offset'];C=P+0x10000;I=P+0x30000;SIZE=0x100000
 u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);u.mem_map(P,SIZE);u.mem_write(P,bytes([0xa5 if cfg['offset']==0 else 0x5a])*SIZE);fixtures=[];entry_gprs={};defined=set();known=set();steps=[];events=[];edges=[];pending=[];boundary=None;pages=set();cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;pool={};round_entries=[];round_exits=[];helper_entries=[];raw=SOURCE.read_bytes();sections=[]
 for at,cmd,n in commands(raw,0):
  if cmd==0x19:
   for j in range(struct.unpack_from('<I',raw,at+64)[0]):
    s=at+72+80*j;name=raw[s:s+16].split(b'\0')[0].decode();seg=raw[s+16:s+32].split(b'\0')[0].decode();a,sz=struct.unpack_from('<QQ',raw,s+32);sections.append((a,a+sz,seg,name))
 def reg(n):return getattr(ar,'UC_ARM64_REG_'+n.upper())
 def get(n):return u.reg_read(reg(n))
 def key(n):return 'x'+n[1:]if n.startswith('w')else {'fp':'x29','lr':'x30'}.get(n,n)
 def put(n,v):u.reg_write(reg(n),v);known.add(key(n));entry_gprs[n]=hex(v)
 def fixture(a,b):u.mem_write(a,b);defined.update(range(a,a+len(b)));fixtures.append({'address':hex(a),'bytes_hex':b.hex()})
 def word(a,n,v):fixture(a,v.to_bytes(n,'little'))
 put('sp',F)
 for n,v in [('x8',0x471c),('x15',0x471c),('x4',C),('x12',C),('x20',cfg['return_index']),('x30',TABLE)]:put(n,v)
 block=bytes.fromhex(cfg['block_hex']);ctx=bytearray(100);ctx[:64]=bytes(x^0x98 for x in block)
 for j,v in enumerate(cfg['initial_state5']):struct.pack_into('<I',ctx,0x48+4*j,v^0xf4f92df7)
 struct.pack_into('<Q',ctx,0x40,cfg['counter64']);struct.pack_into('<II',ctx,0x5c,20,2);fixture(C,bytes(ctx))
 for off,n,v in [(0x31dc,4,(0x1ad72f12+cfg['ambient_count32'])&0xffffffff),(0x2f50,8,I),(0x2e50,8,C),(0x2c8c,4,cfg['ambient_count32']),(0x3490,8,cfg['ambient_raw64']),(0x3620,8,cfg['cursor64']),(0x273c,4,0x471c)]:word(F+off,n,v)
 def mapimage(a,n):
  for pg in range(a&~4095,((a+n-1)&~4095)+4096,4096):
   if pg not in pages:u.mem_map(pg,4096);u.mem_write(pg,logical_read(pg,4096));pages.add(pg)
 def stop(kind,detail):
  nonlocal boundary
  boundary={'pc':hex(get('pc')),'kind':kind,'detail':detail};u.emu_stop()
 def flush():
  for e in pending:e['after_hex']=bytes(u.mem_read(e['address'],e['size'])).hex()
  pending.clear()
 def code(u,a,n,d):
  flush()
  if a==0x100bdfaf0:stop('before_return_epilogue',{});return
  if a in [0x100968c04,0x100ba8ba4,0x100a0dd8c,0x100d30e74,0x100acc478,0x100d30c74,0x100908450,0x100bdf3bc]:helper_entries.append({'pc':hex(a),'registers31':[get('x'+str(j))for j in range(31)]})
  if a in [0x100a0dd8c,0x100d30e74,0x100acc478,0x100d30c74,0x100908450]:round_entries.append({'pc':hex(a),'registers31':[get('x'+str(j))for j in range(31)]})
  b=bytes(u.mem_read(a,4));assert b==IMAGE.read(a,4);ins=pool.get(a)
  if ins is None:ins=next(cs.disasm(b,a));pool[a]=ins
  reads,writes=ins.regs_access();missing=[cs.reg_name(r)for r in reads if cs.reg_name(r)not in ['xzr','wzr']and key(cs.reg_name(r))not in known]
  if missing:stop('undefined_register',{'instruction':ins.mnemonic+' '+ins.op_str,'registers':missing});return
  if ins.mnemonic in ['blraa','blr','bl','ret','retab']:stop('unmodeled_control',ins.mnemonic+' '+ins.op_str);return
  steps.append((a,b.hex()));known.update(key(cs.reg_name(r))for r in writes)
  if a in [0x100a0e070,0x100d31024,0x100acc6bc,0x100d30e18]:round_exits.append({'pc':hex(a),'registers31':[get('x'+str(j))for j in range(31)]})
  if ins.mnemonic=='braa':
   r,m=ins.op_str.split(', ');target,mod=get(r),get(m);slots=[e['address']for e in events if e['kind']=='read'and e['address']in FIXUPS and int.from_bytes(bytes.fromhex(e['hex']),'little')==target and f'div=0x{mod:04X} 'in FIXUPS[e['address']]['annotation']]
   if not slots:stop('no_original_branch_provenance',{'target':hex(target),'modifier':hex(mod)});return
   edges.append((a,target,slots[-1],mod));mapimage(target,4);u.reg_write(reg('pc'),target)
 def read(u,t,a,n,v,d):
  if P<=a<a+n<=P+SIZE:
   if not all(x in defined for x in range(a,a+n)):stop('undefined_private_read',{'address':hex(a),'size':n});return
  else:
   section=next((s for s in sections if s[0]<=a and a+n<=s[1]),None)
   if section is None or section[2]not in ['__TEXT','__DATA_CONST','__AUTH_CONST']:stop('mutable_or_unknown_image_read',{'address':hex(a),'size':n,'section':section});return
   assert bytes(u.mem_read(a,n))==logical_read(a,n)
  events.append({'kind':'read','pc':get('pc'),'address':a,'size':n,'hex':bytes(u.mem_read(a,n)).hex()})
 def write(u,t,a,n,v,d):
  if not P<=a<a+n<=P+SIZE:stop('outside_private_write',{'address':hex(a),'size':n});return
  defined.update(range(a,a+n));e={'kind':'write','pc':get('pc'),'address':a,'size':n};events.append(e);pending.append(e)
 def fault(u,t,a,n,v,d):mapimage(a,n);return True
 u.hook_add(uc.UC_HOOK_CODE,code);u.hook_add(uc.UC_HOOK_MEM_READ,read);u.hook_add(uc.UC_HOOK_MEM_WRITE,write);u.hook_add(uc.UC_HOOK_MEM_READ_UNMAPPED,fault);u.hook_add(uc.UC_HOOK_MEM_FETCH_UNMAPPED,fault);mapimage(0x100abee44,4)
 u.emu_start(0x100abee44,0,count=500000);flush();out=bytes(u.mem_read(C,100));decoded=b''.join(((struct.unpack_from('<I',out,0x48+4*j)[0]^0xf4f92df7)&0xffffffff).to_bytes(4,'big')for j in range(5));result={'boundary':boundary,'steps':steps,'edges':edges,'events':events,'context_before':bytes(ctx).hex(),'context_after':out.hex(),'decoded_state20':decoded.hex(),'configuration':cfg,'SP':hex(F),'context':hex(C),'workspace':hex(F+0x39f0+cfg['cursor64']),'entry_defined_GPRs':entry_gprs,'initial_fixtures':fixtures,'registers':{n:hex(get(n))for n in ['sp']+['x'+str(j)for j in range(31)]},'helper_entries':helper_entries,'round_entries':round_entries,'round_exits':round_exits,'source_pool':{hex(a):bytes(i.bytes).hex()for a,i in pool.items()}}
 assert boundary['kind']=='before_return_epilogue',boundary
 return result

def main():
 rows=[]
 for cfg in cases():
  result=execute(cfg);raw=json.dumps(result,separators=(',',':')).encode();rows.append({'configuration':cfg,'payload_sha256':hashlib.sha256(raw).hexdigest(),'payload_zlib_base64':base64.b64encode(zlib.compress(raw,9)).decode(),'source_visits':len(result['steps']),'modeled_BRAA_visits':len(result['edges']),'reads':sum(e['kind']=='read'for e in result['events']),'writes':sum(e['kind']=='write'for e in result['events'])})
 assert len(rows)==48
 deps=['daemon_sha1_core_model.py','validate_daemon_object_clock.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'cases':rows,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_sha1_core_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'visits':sum(r['source_visits']for r in rows),'BRAA':sum(r['modeled_BRAA_visits']for r in rows),'reads':sum(r['reads']for r in rows),'writes':sum(r['writes']for r in rows)}),flush=True)
if __name__=='__main__':main()
