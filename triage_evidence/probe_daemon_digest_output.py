#!/usr/bin/env python3
"""Source-pinned isolated digest serializers with GPR/byte definedness.
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
from daemon_digest_output_access import register_access
from daemon_digest_output_inputs import pipeline_configurations
from replay_daemon_descriptor_producers import unpack
from probe_daemon_sha1_core import execute as core_execute

def execute(cfg):
 P=0x6b00000000;F=P+0x40000+cfg['offset'];C=P+0x10000;I=P+0x30000;SIZE=0x100000
 u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);u.mem_map(P,SIZE);u.mem_write(P,bytes([0xa5 if cfg['offset']==0 else 0x5a])*SIZE);fixtures=[];entry_gprs={};defined=set();known=set();steps=[];events=[];edges=[];pending=[];boundary=None;pages=set();cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;pool={};round_entries=[];round_exits=[];helper_entries=[];serializer_entries=[];serializer_exits=[];raw=SOURCE.read_bytes();sections=[]
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
 O=P+0x20000
 put('sp',F);put('x30',TABLE)
 ctx=bytearray(100)
 for j,v in enumerate(cfg['state5']):struct.pack_into('<I',ctx,0x48+4*j,v^0xf4f92df7)
 struct.pack_into('<II',ctx,0x5c,cfg.get('output_size',20),cfg.get('selector',2));fixture(C+0x48,bytes(ctx[0x48:]))
 for off,n,v in [(0x273c,4,0x471c),(0x2f40,8,C),(0x2fe0,8,O)]:word(F+off,n,v)
 context_before_snapshot=bytes(u.mem_read(C,100)).hex();context_input_mask100=[C+j in defined for j in range(100)]
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
  if cfg.get('decision_only')and a in [0x100b57120,0x100be71bc,0x100bb1574]:stop('before_serializer_or_common_continuation',{'target':hex(a)});return
  if a in [0x100b57120,0x100b30004,0x100be71bc,0x1008b6060]:serializer_entries.append({'pc':hex(a),'registers31':[get('x'+str(j))for j in range(31)]})
  if a==0x100bb15d0:stop('before_unknown_frame_read',{'address':hex(F+0x3050),'size_bytes':8,'instruction':'ldr x12, [sp, #0x3050]'});return
  if a in [0x100968c04,0x100ba8ba4,0x100a0dd8c,0x100d30e74,0x100acc478,0x100d30c74,0x100908450,0x100bdf3bc]:helper_entries.append({'pc':hex(a),'registers31':[get('x'+str(j))for j in range(31)]})
  if a in [0x100a0dd8c,0x100d30e74,0x100acc478,0x100d30c74,0x100908450]:round_entries.append({'pc':hex(a),'registers31':[get('x'+str(j))for j in range(31)]})
  b=bytes(u.mem_read(a,4));assert b==IMAGE.read(a,4);ins=pool.get(a)
  if ins is None:ins=next(cs.disasm(b,a));pool[a]=ins
  reads,writes=register_access(ins)
  missing=[cs.reg_name(r)for r in reads if cs.reg_name(r)not in ['xzr','wzr']and key(cs.reg_name(r))not in known]
  if missing:stop('undefined_register',{'instruction':ins.mnemonic+' '+ins.op_str,'registers':missing});return
  if ins.mnemonic in ['blraa','blr','bl','ret','retab']:stop('unmodeled_control',ins.mnemonic+' '+ins.op_str);return
  steps.append((a,b.hex()));known.update(key(cs.reg_name(r))for r in writes)
  if a in [0x100a0e070,0x100d31024,0x100acc6bc,0x100d30e18]:round_exits.append({'pc':hex(a),'registers31':[get('x'+str(j))for j in range(31)]})
  if a in [0x100b571e8,0x100b30108,0x100be7290,0x1008b616c]:serializer_exits.append({'pc':hex(a),'registers31':[get('x'+str(j))for j in range(31)]})
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
 u.hook_add(uc.UC_HOOK_CODE,code);u.hook_add(uc.UC_HOOK_MEM_READ,read);u.hook_add(uc.UC_HOOK_MEM_WRITE,write);u.hook_add(uc.UC_HOOK_MEM_READ_UNMAPPED,fault);u.hook_add(uc.UC_HOOK_MEM_FETCH_UNMAPPED,fault);mapimage(0x1009de090,4)
 u.emu_start(0x1009de090,0,count=100000);flush();out=bytes(u.mem_read(C,100));decoded=b''.join(((struct.unpack_from('<I',out,0x48+4*j)[0]^0xf4f92df7)&0xffffffff).to_bytes(4,'big')for j in range(5));result={'boundary':boundary,'steps':steps,'edges':edges,'events':events,'context_before':context_before_snapshot,'context_input_mask100':context_input_mask100,'context_after':out.hex(),'decoded_state20':decoded.hex(),'configuration':cfg,'SP':hex(F),'context':hex(C),'entry_defined_GPRs':entry_gprs,'initial_fixtures':fixtures,'registers':{n:hex(get(n))for n in ['sp']+['x'+str(j)for j in range(31)]},'serializer_entries':serializer_entries,'serializer_exits':serializer_exits,'source_pool':{hex(a):bytes(i.bytes).hex()for a,i in pool.items()}}
 result['output_hex32']=bytes(u.mem_read(O,32)).hex();result['output_defined_mask32']=[O+j in defined for j in range(32)];result['output']=hex(O)
 return result



def configurations():
 rng=random.Random(0x44494745)
 patterns=[[0]*5,[0xffffffff]*5,[0x01020304+j*0x11111111 for j in range(5)],[0xa9993e36,0x4706816a,0xba3e2571,0x7850c26c,0x9cd0d89d],[0xda39a3ee,0x5e6b4b0d,0x3255bfef,0x95601890,0xafd80709]]+[[rng.getrandbits(32)for j in range(5)]for k in range(3)]
 for j,state in enumerate(patterns):
  for selector,size in [(1,16),(2,20),(1,0),(2,0)]:
   for offset in [0,0x100]:yield {'kind':'serializer','pattern_index':j,'state5':state,'selector':selector,'output_size':size,'offset':offset,'cursor64':0}

def decision_configurations():
 for high in [0,0xffffff00]:
  for b in range(256):yield {'kind':'decision_only','offset':0 if high==0 else 0x100,'state5':[0x01020304+j for j in range(5)],'selector':high|b,'output_size':16 if b==1 else 20,'cursor64':0,'decision_only':True}
def execute_pipeline(cfg):
 ctx=bytes.fromhex(cfg['prepared_context100_hex']);initial=[x^0xf4f92df7 for x in struct.unpack_from('<5I',ctx,0x48)]
 core_cfg={'kind':'retained_prepared_block_component','block_hex':bytes(x^0x98 for x in ctx[:64]).hex(),'initial_state5':initial,'return_index':0x58,'offset':cfg['offset'],'counter64':int.from_bytes(ctx[0x40:0x48],'little'),'ambient_count32':len(bytes.fromhex(cfg['message_hex'])),'ambient_raw64':0,'cursor64':0x310}
 core=core_execute(core_cfg);after=bytes.fromhex(core['context_after']);state=[x^0xf4f92df7 for x in struct.unpack_from('<5I',after,0x48)]
 size,selector=struct.unpack_from('<II',after,0x5c)
 fmt_cfg={'kind':'source_state_value_boundary','offset':cfg['offset'],'state5':state,'selector':selector,'output_size':size,'cursor64':0}
 fmt=execute(fmt_cfg)
 return {'configuration':cfg,'core_input_contract':core_cfg,'core_trace':core,'serializer_input_contract':fmt_cfg,'serializer_trace':fmt,'composition_scope':'Source-produced state crosses a value boundary between separate declared private contexts; no native or retained-frontier continuation.','native_target_executed':False,'full_goal_complete':False}
def packed(t):
 raw=json.dumps(t,separators=(',',':')).encode();return {'configuration':t['configuration'],'payload_sha256':hashlib.sha256(raw).hexdigest(),'payload_zlib_base64':base64.b64encode(zlib.compress(raw,9)).decode()}
def main():
 rows=[packed(execute(cfg))for cfg in configurations()];decisions=[packed(execute(cfg))for cfg in decision_configurations()];pipelines=[packed(execute_pipeline(cfg))for cfg in pipeline_configurations()]
 assert len(rows)==64 and len(pipelines)==6
 deps=['daemon_digest_output_access.py','daemon_digest_output_inputs.py','validate_daemon_object_clock.py','probe_daemon_sha1_core.py','daemon_sha1_core_checks.json','daemon_identity_cache_profiles.json'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'cases':rows,'decision_cases':decisions,'conditional_pipelines':pipelines,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_digest_output_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'serializer_cases':len(rows),'conditional_pipelines':len(pipelines),'selector_decisions':len(decisions)}),flush=True)
if __name__=='__main__':main()
