#!/usr/bin/env python3
"""Declared source extensions for certificate fields and name records.
Malloc/free are library models; IA transfers including zero-modifier callbacks
are checked against original fixups. O(visits+effects+unique decode) time and
O(largest case+decoder cache) space. No native PAC, allocator or IPC executes.
"""
import json,struct,hashlib
from functools import lru_cache
import unicorn as uc
from unicorn import arm64_const as ar
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64_const import ARM64_OP_MEM,ARM64_OP_REG,ARM64_EXT_SXTW,ARM64_EXT_SXTX
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,TABLE
from replay_daemon_descriptor_producers import IMPORTS
from daemon_import_bindings import binding
from recover_daemon_object_clock import sections
from capture_daemon_object_clock import memory_width
from daemon_digest_output_access import register_access,key
from validate_daemon_object_clock import logical_read
P=0x6800000000;SIZE=0x100000;MASK=(1<<64)-1
CS=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);CS.detail=True
SECTIONS=sections();WRITABLE=[s for s in SECTIONS if s['segment']=='__DATA']
REGS={n:getattr(ar,'UC_ARM64_REG_'+n.upper())for n in ['sp','pc','nzcv']+['x'+str(j)for j in range(31)]+['w'+str(j)for j in range(31)]}
@lru_cache(maxsize=None)
def instruction(a):
 i=next(CS.disasm(IMAGE.read(a,4),a));rr,ww=register_access(i)
 return i,[key(i.reg_name(r))for r in rr if i.reg_name(r)not in ['xzr','wzr']],[key(i.reg_name(r))for r in ww],{'bytes_hex':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str}
@lru_cache(maxsize=None)
def image_page(a):
 try:return logical_read(a,4096)
 except ValueError:
  assert any(s['start']<=a+4095 and a<s['start']+s['size_bytes']for s in WRITABLE),hex(a)
  return bytes(4096)
@lru_cache(maxsize=None)
def pointer(slot):
 r=FIXUPS[slot];word=int.from_bytes(IMAGE.read(slot,8),'little')
 target=IMPORTS[r['target']]+binding(slot)['total_addend']if isinstance(r['target'],str)else r['target']
 return word,target
def execute(context,cfg,limit=300000):
 u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);u.mem_map(P,SIZE);u.mem_write(P,bytes([cfg['physical_pattern']])*SIZE);pages=set(range(P,P+SIZE,4096));F=int(context['SP'],16);defined=set();known=set();steps=[];events=[];edges=[];apis=[];fix=set();pool={};pending=[];boundary=None;origins={};spills={};previous=None;snapshots=[]
 allocated={int(a,16):n for a,n in context['allocated_owners'].items()}
 owners=[(F-0x4000,0x14000)]+list(allocated.items())+[(int(g['address'],16),len(g['bytes_hex'])//2)for g in context['known_byte_groups']if P<=int(g['address'],16)<P+SIZE]
 def get(n):return 0 if n in ['xzr','wzr']else u.reg_read(REGS[{'fp':'x29','lr':'x30','wsp':'sp'}.get(n,n)])
 def put(n,v):u.reg_write(REGS[n],v)
 def ensure(a,n):
  for pg in range(a&~4095,((a+n-1)&~4095)+4096,4096):
   if pg in pages:continue
   if 0x100000000<=pg<0x102000000:b=image_page(pg)
   else:
    assert any(int(g['address'],16)<pg+4096 and pg<int(g['address'],16)+len(g['bytes_hex'])//2 for g in context['known_byte_groups']),('unmapped owner',hex(pg))
    b=bytes(4096)
   u.mem_map(pg,4096);u.mem_write(pg,b);pages.add(pg)
 for a,h in context['owner_snapshots'].items():u.mem_write(int(a,16),bytes.fromhex(h))
 for g in context['known_byte_groups']:
  a=int(g['address'],16);b=bytes.fromhex(g['bytes_hex']);ensure(a,len(b));u.mem_write(a,b);defined.update(range(a,a+len(b)))
 for n,v in context['entry_defined_GPRs'].items():put(n,int(v,16));known.add(key(n))
 def stop(kind,detail):
  nonlocal boundary
  boundary={'pc':hex(get('pc')),'kind':kind,'detail':detail,'SP':hex(get('sp')),'registers31':[hex(get('x'+str(j)))for j in range(31)]};u.emu_stop()
 def flush():
  for e in pending:e['after_hex']=bytes(u.mem_read(int(e['address'],16),e['size_bytes'])).hex()
  pending.clear()
 def finish():
  nonlocal previous
  if previous is None:return
  i,start,before=previous;es=events[start:];rr,ww=register_access(i)
  for r in ww:origins.pop(key(i.reg_name(r)),None)
  for e in es:
   if e['kind']=='write':
    a=int(e['address'],16);n=e['size_bytes']
    for at in list(spills):
     if a<at+8 and at<a+n:spills.pop(at)
  if i.mnemonic in ['ldr','ldur']and i.reg_name(i.operands[0].reg).startswith('x'):
   ee=[e for e in es if e['kind']=='read'and e['size_bytes']==8]
   if len(ee)==1:
    a=int(ee[0]['address'],16);o=a if a in FIXUPS else spills.get(a)
    if o is not None:origins[key(i.reg_name(i.operands[0].reg))]=o
  elif i.mnemonic=='mov'and len(i.operands)==2 and i.operands[1].type==ARM64_OP_REG:
   o=before.get(key(i.reg_name(i.operands[1].reg)))
   if o is not None:origins[key(i.reg_name(i.operands[0].reg))]=o
  elif i.mnemonic in ['str','stur']and i.reg_name(i.operands[0].reg).startswith('x'):
   ee=[e for e in es if e['kind']=='write'and e['size_bytes']==8];o=before.get(key(i.reg_name(i.operands[0].reg)))
   if o is not None and len(ee)==1:spills[int(ee[0]['address'],16)]=o
  elif i.mnemonic in ['ldp','stp']and all(i.reg_name(o.reg).startswith('x')for o in i.operands[:2]):
   kind='read'if i.mnemonic=='ldp'else'write';ee=[e for e in es if e['kind']==kind];assert sum(e['size_bytes']for e in ee)==16;first=int(ee[0]['address'],16)
   for j,o in enumerate(i.operands[:2]):
    at=first+j*8;name=key(i.reg_name(o.reg));origin=(at if at in FIXUPS else spills.get(at))if kind=='read'else before.get(name)
    if origin is not None:
     if kind=='read':origins[name]=origin
     else:spills[at]=origin
  previous=None
 def address(i,o):
  a=get(i.reg_name(o.mem.base))+o.mem.disp
  if o.mem.index:
   v=get(i.reg_name(o.mem.index))
   if o.ext in [ARM64_EXT_SXTW,ARM64_EXT_SXTX]:bits=32 if o.ext==ARM64_EXT_SXTW else 64;v&=(1<<bits)-1;v-=1<<bits if v>>(bits-1)else 0
   a+=v<<o.shift.value
  return a&MASK
 def preflight(i):
  o=next((o for o in i.operands if o.type==ARM64_OP_MEM),None)
  if o is None:return True
  a=address(i,o);n=memory_width(i);load=i.mnemonic.startswith(('ldr','ldur','ldp','ldnp','ldar','ldax'))or i.mnemonic=='casal';store=i.mnemonic.startswith(('str','stur','stp','stnp','stlr','stlx'))or i.mnemonic=='casal';
  if not(load or store):stop('before_unsupported_memory_instruction',{'instruction':i.mnemonic+' '+i.op_str,'address':hex(a),'size_bytes':n});return False
  if P<=a<a+n<=P+SIZE:
   if not any(h<=a<a+n<=h+nb for h,nb in owners):stop('before_unowned_private_access',{'address':hex(a),'size_bytes':n,'instruction':i.mnemonic+' '+i.op_str});return False
   if load and not all(a+j in defined for j in range(n)):stop('before_undefined_owned_read',{'address':hex(a),'size_bytes':n});return False
  elif any(s['start']<=a<a+n<=s['start']+s['size_bytes']for s in WRITABLE):
   if load and not all(a+j in defined for j in range(n)):stop('before_unmodeled_runtime_global',{'address':hex(a),'size_bytes':n,'instruction':i.mnemonic+' '+i.op_str});return False
   ensure(a,n)
  elif all(a+j in defined for j in range(n)):ensure(a,n)
  else:
   if store:stop('before_unowned_external_write',{'address':hex(a),'size_bytes':n});return False
   try:ensure(a,n)
   except(AssertionError,ValueError)as e:stop('before_unknown_external_read',{'address':hex(a),'size_bytes':n,'reason':str(e)});return False
  return True
 def api(a,raw,slot):
  b=binding(slot);name=b['symbol'];argument=get('x0');before={n:get(n)for n in ['sp']+['x'+str(j)for j in range(18,30)]}
  if name not in ['_malloc','_free']:stop('before_unmodeled_import',{'slot':hex(slot),'symbol':name});return
  if name=='_malloc':
   if a!=0x100bae048 or argument!=720:stop('before_unmodeled_allocation',{'slot':hex(slot),'requested_bytes':argument});return
   returned=cfg['allocation_return64'];detail={'requested_bytes':720}
   if returned:allocated[returned]=720;owners.append((returned,720));defined.difference_update(range(returned,returned+720))
  else:
   if argument not in allocated or a!=0x1001c6100:stop('before_unmodeled_free',{'slot':hex(slot),'argument':hex(argument)});return
   nb=allocated.pop(argument);assert nb==720;defined.difference_update(range(argument,argument+nb));owners[:]=[(h,n)for h,n in owners if not(argument<=h and h+n<=argument+nb)];returned=cfg['void_result64'];detail={'arguments1':[hex(argument)],'invalidated_range':{'address':hex(argument),'size_bytes':nb},'effect':'source free request; private owner retired, native allocator/lifetime unknown'}
  for j in range(18):put('x'+str(j),cfg['clobber_pattern'])
  for j in list(range(18))+[30]:origins.pop('x'+str(j),None)
  put('x0',returned);put('x30',a+4);put('nzcv',cfg['NZCV_after']);known.update(['x'+str(j)for j in range(18)]+['x30','nzcv'])
  assert all(get(n)==v for n,v in before.items());apis.append({'pc':hex(a),'binding':b,**detail,'returned_X0':hex(returned),'preserved_GPR_SP':before,'native_call_executed':False});fix.add(slot);steps.append((a,raw));put('pc',a+4)
 def code(u,a,n,d):
  nonlocal previous
  flush();finish()
  if a in cfg.get('snapshot_PCs',[]):snapshots.append({'pc':hex(a),'SP':hex(get('sp')),'known_GPRs':{n:hex(get(n))for n in ['x'+str(j)for j in range(31)]+['nzcv']if n in known}})
  if not 0x100000000<=a<0x100e2c000:stop('before_external_code',{'target':hex(a)});return
  i,rr,ww,row=instruction(a);pool[hex(a)]=row
  missing=[r for r in rr if r not in known]
  if missing:stop('before_undefined_GPR',{'instruction':i.mnemonic+' '+i.op_str,'registers':missing});return
  if not preflight(i):return
  m=i.mnemonic;raw=row['bytes_hex']
  if m=='pacibsp':steps.append((a,raw));edges.append({'pc':hex(a),'kind':'logical_pacibsp','target':hex(a+4)});put('pc',a+4);return
  if m in ['braa','blraa','braaz','blraaz','br','blr','ret','retab','retaa']:
   names=i.op_str.split(', ');ret=m.startswith('ret');target=get('x30')if ret else get(names[0]);mod=0 if m in ['braaz','blraaz']else get(names[1])if len(names)>1 else None;slot=None if ret else origins.get(key(names[0]));call=m.startswith('bl')
   if not ret:
    r=FIXUPS.get(slot);assert r is not None,(hex(a),hex(target),names);word,expected=pointer(slot);assert target==expected and word>>63==1 and((word>>32)&65535)==mod and((word>>48)&7)==0
   if call and target in IMPORTS.values():api(a,raw,slot);return
   assert 0x100000000<=target<0x100e2c000;steps.append((a,raw));edges.append({'pc':hex(a),'target':hex(target),'modifier':hex(mod)if mod is not None else None,'slot':hex(slot)if slot is not None else None,'kind':m});known.update(ww)
   if call:put('x30',a+4)
   ensure(target,4);put('pc',target);return
  assert m not in ['svc','hvc','smc','bl'];steps.append((a,raw));previous=(i,len(events),origins.copy());known.update(ww)
 def read(u,t,a,n,v,d):
  events.append({'kind':'read','pc':hex(get('pc')),'address':hex(a),'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()})
  if a in FIXUPS and n==8:fix.add(a)
 def write(u,t,a,n,v,d):
  defined.update(range(a,a+n));e={'kind':'write','pc':hex(get('pc')),'address':hex(a),'size_bytes':n};events.append(e);pending.append(e)
 def fault(u,t,a,n,v,d):ensure(a,n);return True
 u.hook_add(uc.UC_HOOK_CODE,code);u.hook_add(uc.UC_HOOK_MEM_READ,read);u.hook_add(uc.UC_HOOK_MEM_WRITE,write);u.hook_add(uc.UC_HOOK_MEM_READ_UNMAPPED,fault);u.hook_add(uc.UC_HOOK_MEM_WRITE_UNMAPPED,fault);u.hook_add(uc.UC_HOOK_MEM_FETCH_UNMAPPED,fault);start=int(context['entry_PC'],16);ensure(start,4);u.emu_start(start,0,count=limit);flush();finish()
 if boundary is None:boundary={'pc':hex(get('pc')),'kind':'source_visit_limit','detail':None,'SP':hex(get('sp')),'registers31':[hex(get('x'+str(j)))for j in range(31)]}
 owner=int(context['allocation_owner_address'],16);R=F+0xde90
 return {'case_index':context['case_index'],'parent_context_sha256':hashlib.sha256(json.dumps(context,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'configuration':cfg,'entry_PC':hex(start),'entry_SP':hex(F),'entry_defined_GPRs':context['entry_defined_GPRs'],'steps':steps,'events':events,'API_models':apis,'edges':edges,'boundary':boundary,'source_pool':pool,'used_fixups':[hex(a)for a in sorted(fix)],'allocation_owner':hex(owner),'allocation_defined_mask720':[owner+j in defined for j in range(720)],'allocation_hex720':bytes(u.mem_read(owner,720)).hex(),'record_address':hex(R),'record_defined_mask32':[R+j in defined for j in range(32)],'record_hex32':bytes(u.mem_read(R,32)).hex(),'allocated_owners':{hex(a):n for a,n in allocated.items()},'ABI_snapshots':snapshots,'native_target_executed':False,'full_goal_complete':False}

