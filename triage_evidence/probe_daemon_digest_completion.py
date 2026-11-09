#!/usr/bin/env python3
"""Source-pinned isolated digest completion and single overwrite iterations.
O(total visits+effects) time; O(compressed outputs+one decoded journal+map)
space. Native caller/PAC/IPC and identity-to-cache joins remain unproved.
"""
import base64,json,struct,hashlib,zlib
from pathlib import Path
import unicorn as uc
from unicorn import arm64_const as ar
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from daemon_receive_tools import IMAGE,SOURCE,TABLE,FIXUPS
from resolve_kernel_collection_interfaces import commands
from validate_daemon_object_clock import logical_read
from daemon_receive_tools import ROOT
from recover_daemon_object_creation import sha
from daemon_digest_completion_model import seed,CONSTANTS,SAVED,pattern
from daemon_digest_output_access import register_access
from replay_daemon_descriptor_producers import unpack

def execute(cfg):
 P=0x6b00000000;F=P+0x40000+cfg['offset'];C=F+0x3c70 if cfg.get('layout')=='retained'else P+0x10000;I=F+0x3c30 if cfg.get('layout')=='retained'else P+0x30000;SIZE=0x100000
 u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);u.mem_map(P,SIZE);u.mem_write(P,bytes([0xa5 if cfg['offset']==0 else 0x5a])*SIZE);fixtures=[];entry_gprs={};defined=set();known=set();steps=[];events=[];edges=[];pending=[];boundary=None;pages=set();cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;pool={};raw=SOURCE.read_bytes();sections=[]
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
 O=F+0x3ce0 if cfg.get('layout')=='retained'else P+0x20000
 Flag=0x1010c67f8
 put('sp',F)
 if cfg['kind']=='overwrite_iteration':
  for name,v in CONSTANTS.items():put(name,v)
  put('x6',C);put('x11',cfg['seed64']);put('x1',cfg['count64'])
 else:
  for name,v in {'x30':TABLE,'w27':0x471c,'w11':0x8204ce66,
    'w2':0x7e8c,'x8':0x3705faa50a75fa00,'w9':0xbb74a819,'x13':seed(F)}.items():put(name,v)
  for off,v in SAVED.items():word(F+off,4 if off==0x2edc else 8,v)
  for off,v in [(0x2a70,C),(0x3610,C),(0x31a8,O),(0x32e8,I),(0x3620,cfg['cursor64']),(0x26e0,Flag)]:word(F+off,8,v)
  word(C+0x5c,4,cfg['output_size']);word(C+0x60,4,cfg['selector'])
  if cfg['output_size']:fixture(O,bytes.fromhex(cfg['encoded_output_hex']))
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
  if cfg['kind']=='overwrite_iteration'and steps and a in [0x100a1bf1c,0x100abd000]:stop('after_one_source_iteration',{'target':hex(a)});return
  if cfg['kind']!='overwrite_iteration'and a==0x100b687f4:stop('before_unknown_saved_owner',{'address':hex(F+0x3650),'size_bytes':8});return
  if a==0x100bb15d0:stop('before_unknown_frame_read',{'address':hex(F+0x3050),'size_bytes':8,'instruction':'ldr x12, [sp, #0x3050]'});return
  b=bytes(u.mem_read(a,4));assert b==IMAGE.read(a,4);ins=pool.get(a)
  if ins is None:ins=next(cs.disasm(b,a));pool[a]=ins
  reads,writes=register_access(ins)
  missing=[cs.reg_name(r)for r in reads if cs.reg_name(r)not in ['xzr','wzr']and key(cs.reg_name(r))not in known]
  if missing:stop('undefined_register',{'instruction':ins.mnemonic+' '+ins.op_str,'registers':missing});return
  if ins.mnemonic in ['blraa','blr','bl','ret','retab']:stop('unmodeled_control',ins.mnemonic+' '+ins.op_str);return
  steps.append((a,b.hex()));known.update(key(cs.reg_name(r))for r in writes)
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
  if not(P<=a<a+n<=P+SIZE or (a==Flag and n==1 and get('pc')==0x100a53644)):stop('outside_private_write',{'address':hex(a),'size':n});return
  defined.update(range(a,a+n));e={'kind':'write','pc':get('pc'),'address':a,'size':n};events.append(e);pending.append(e)
 def fault(u,t,a,n,v,d):mapimage(a,n);return True
 u.hook_add(uc.UC_HOOK_CODE,code);u.hook_add(uc.UC_HOOK_MEM_READ,read);u.hook_add(uc.UC_HOOK_MEM_WRITE,write);u.hook_add(uc.UC_HOOK_MEM_READ_UNMAPPED,fault);u.hook_add(uc.UC_HOOK_MEM_FETCH_UNMAPPED,fault);start=0x100a1bf1c if cfg['kind']=='overwrite_iteration'else 0x100bb1620;mapimage(start,4);mapimage(Flag,1)
 u.emu_start(start,0,count=100000);flush();out=bytes(u.mem_read(C,100));result={'boundary':boundary,'steps':steps,'edges':edges,'events':events,'context_before':context_before_snapshot,'context_input_mask100':context_input_mask100,'context_after':out.hex(),'configuration':cfg,'SP':hex(F),'context':hex(C),'entry_defined_GPRs':entry_gprs,'initial_fixtures':fixtures,'registers':{n:hex(get(n))for n in ['sp']+['x'+str(j)for j in range(31)]},'source_pool':{hex(a):bytes(i.bytes).hex()for a,i in pool.items()}}
 result['output_hex32']=bytes(u.mem_read(O,32)).hex();result['output_defined_mask32']=[O+j in defined for j in range(32)];result['output']=hex(O)
 result['destination']=hex(I);result['destination_hex64']=bytes(u.mem_read(I,64)).hex();result['destination_defined_mask64']=[I+j in defined for j in range(64)]
 result['context_defined_mask100']=[C+j in defined for j in range(100)];result['completion_flag_address']=hex(Flag);result['completion_flag_defined']=Flag in defined;result['completion_flag_byte']=bytes(u.mem_read(Flag,1)).hex()
 result['cursor_after_hex']=bytes(u.mem_read(F+0x3620,8)).hex();return result



def configurations():
 p=json.loads((ROOT/'daemon_digest_output_profiles.json').read_text())
 for j,row in enumerate(p['cases']):
  t=unpack(row);cfg=t['configuration'];n=cfg['output_size']
  for layout in ['separate','retained']:yield {'layout':layout,'kind':'completion','parent_group':'cases','parent_index':j,'parent_payload_sha256':row['payload_sha256'],'offset':cfg['offset'],'selector':cfg['selector'],'output_size':n,'cursor64':0x310,'encoded_output_hex':t['output_hex32'][:n*2]}
 for j,row in enumerate(p['conditional_pipelines']):
  t=unpack(row);fmt=t['serializer_trace'];cfg=fmt['configuration'];n=cfg['output_size']
  for layout in ['separate','retained']:yield {'layout':layout,'kind':'completion','parent_group':'conditional_pipelines','parent_index':j,'parent_payload_sha256':row['payload_sha256'],'message_hex':t['configuration']['message_hex'],'offset':cfg['offset'],'selector':cfg['selector'],'output_size':n,'cursor64':0x310,'encoded_output_hex':fmt['output_hex32'][:n*2]}
 for s in range(256):yield {'kind':'overwrite_iteration','seed64':((0x9abcdef012345600 if s&1 else 0)+s),'count64':1+s%92,'offset':0 if s<128 else 0x100}
def packed(t):
 raw=json.dumps(t,separators=(',',':')).encode();return {'configuration':t['configuration'],'payload_sha256':hashlib.sha256(raw).hexdigest(),'payload_zlib_base64':base64.b64encode(zlib.compress(raw,9)).decode()}
def main():
 rows=[packed(execute(c))for c in configurations()];assert len(rows)==396
 deps=['daemon_digest_completion_model.py','daemon_digest_output_access.py','daemon_digest_output_profiles.json','daemon_digest_output_checks.json','validate_daemon_object_clock.py']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'cases':rows,'new_port_emission_established':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False}
 (ROOT/'daemon_digest_completion_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows)}),flush=True)
if __name__=='__main__':main()
