#!/usr/bin/env python3
"""Independent phase-one data contracts and fresh original-instruction replay.
O(visits+journals+mapped bytes) space; API timeline sorting O(J log J).
The new executor is not imported. Native startup and formatting remain unknown.
"""
import json,struct,re
from collections import Counter
from hashlib import sha256
from unicorn import arm64_const as ar
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read
from probe_rpc502_vm_handoff import decode as uncompress
from replay_kernel_boot_cpu_identity import pages,get,put
from replay_kernel_boot_option_execution import parse,number,write_number,DELIMITERS
import replay_kernel_startup_registry_abi as B
from replay_kernel_vm_mig import Replay as Core
import recover_kernel_tunable_batch_execution as R
P=B.P;SIZE=B.SIZE;SP=B.SP;MASK=(1<<64)-1
NEW_APIS=[t for t in R.PHASE1 if t!=R.B.TUNABLE]+[R.UUID]

def publication_row(row,image):
 """Reference original pages containing path strings; never alter target bytes."""
 from verify_lskd_vector_origin_publication import path_hygiene
 out=dict(row);out['initial_image_pages']=[]
 for p in row['initial_image_pages']:
  raw=bytes.fromhex(p['bytes_hex'])
  try:path_hygiene(raw)
  except AssertionError:
   assert raw==image.logical_page(int(p['address'],16))
   p={'address':p['address'],'original_logical_page_sha256':sha256(raw).hexdigest()}
  out['initial_image_pages'].append(p)
 return out

def hydrate(row,image=None):
 """Restore hash-bound original page references for contract evaluation/replay."""
 if not any('original_logical_page_sha256' in p for p in row['initial_image_pages']):return row
 if image is None:
  from kernel_vm_mig_tools import Image
  image=Image()
 assert image.k.sha256=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 out=dict(row);out['initial_image_pages']=[]
 for p in row['initial_image_pages']:
  if 'original_logical_page_sha256' in p:
   assert set(p)=={'address','original_logical_page_sha256'}
   raw=image.logical_page(int(p['address'],16));assert sha256(raw).hexdigest()==p['original_logical_page_sha256'];p={'address':p['address'],'bytes_hex':raw.hex()}
  out['initial_image_pages'].append(p)
 return out

def first_row(row):
 c=row['first_callback_boundary'];end=c['before_visit'];out=dict(row);out['source_visits']=row['source_visits'][:end]
 for key in ['source_reads','source_writes']:out[key]=[w for w in row[key] if w['source_visit_index']<end]
 out['API_models']=[m for m in row['API_models'] if m['before_source_visit_index']<end];out['logical_effects']=[m for m in row['logical_effects'] if m['before_visit']<end]
 out['original_API_entries']=[m for m in row['original_API_entries'] if m['before_visit']<end];out['original_API_returns']=[m for m in row['original_API_returns'] if m['before_visit']<=end];returned={m['entry_index'] for m in out['original_API_returns']}
 out.update(final_private_RAM=c['private_RAM'],final_image_globals=c['image_globals']+c['additional_image_globals']+c['registry_image_globals'],final_system=c['system'],final_vectors=c['vectors'],final_page_sha256=c['mapped_page_sha256'],unfinished_API_entry_indices=[j for j in range(len(out['original_API_entries'])) if j not in returned],boundary={'pc':c['PC'],'kind':'original_first_registry_callback_return_and_cursor_publication','registers31':c['registers31'],'SP':c['SP'],'NZCV':c['NZCV']})
 return out

def option_contracts(row):
 old=B.B.B.legacy(row);memory=pages(old['initial_pages']);events=[];pending={};checks=[];hist={};outputs=[];O=R.B.B.B.O
 def ok(label,p):assert p,('batch_option_contract',label);checks.append(label)
 def u(a,n):return int.from_bytes(get(memory,a,n),'little')
 def string(a):
  raw=bytearray()
  for j in range(512):
   v=u(a+j,1)
   if not v:return bytes(raw)
   raw.append(v)
  raise AssertionError('unterminated_option_contract_input')
 for j,w in enumerate(old['writes']):events.append((w['visit'],2,j,'write',w))
 for j,e in enumerate(old['original_option_API_entries']):events.append((e['before_visit'],1,j,'entry',e))
 for j,e in enumerate(old['original_option_call_returns']):events.append((e['before_visit'],0,j,'return',e))
 for _,_,index,kind,e in sorted(events,key=lambda x:x[:3]):
  if kind=='write':raw=bytes.fromhex(e['after_hex']);put(memory,int(e['address'],16),len(raw),raw);continue
  if kind=='return':
   result,regions=pending.pop(e['entry_index']);ok('return_'+str(e['entry_index']),int(e['return_value'],16)==result)
   for a,raw in regions:ok('output_'+str(e['entry_index']),get(memory,a,len(raw))==raw)
   continue
  a=int(e['PC'],16);v=[int(x,16) for x in e['arguments6']];regions=[];hist[hex(a)]=hist.get(hex(a),0)+1
  if a==O.PARSE:
   width=v[3]&0xffffffff;mode=v[4]&0xffffffff;assert 0<=width<=256 and width!=3 and mode in [0,1]
   before=get(memory,v[2],width);raw=string(v[0]);key=string(v[1]) if raw.strip(b' \t') else b'';result,after=parse(raw+b'\0',key,width,mode,before);regions=[(v[2],after)] if width else [];outputs.append({'entry_index':index,'key':key.decode('ascii'),'width':width,'string_mode':mode,'status':result,'expected_output_hex':after.hex()})
  elif a==O.NUMBER:
   result,value=number(string(v[0])+b'\0',v[3]&0xffffffff);regions=[(v[1],value.to_bytes(8,'little') if result==0 else get(memory,v[1],8))]
  elif a==O.SPACE:result=int(v[0]&0xffffffff in DELIMITERS)
  elif a==O.STRLEN:result=len(string(v[0]))
  elif a==O.FLAG:
   width=v[1]&0xffffffff;n=width if width in [1,2,8] else 4;result=v[0];regions=[(v[0],write_number(get(memory,v[0],n),width,1))]
  else:raise AssertionError(hex(a))
  pending[index]=(result,regions)
 ok('all_original_option_calls_returned',not pending and len(old['original_option_API_entries'])==len(old['original_option_call_returns']))
 return {'checks':checks,'API_calls':len(old['original_option_API_entries']),'entry_histogram':hist,'parser_results':outputs}

def static_contracts(e,image):
 prior=json.loads(read(ROOT/(R.B.P+'_checks.json')));checks=[];base=int(prior['fixup_base'],16)
 def ok(label,p):assert p,('phase_one_static_contract',label);checks.append(label)
 def ptr(a,p):
  raw=image.k.read(a,8);word=int.from_bytes(raw,'little');target=base+(word&0x3fffffff);ok('pointer_'+hex(a),p['slot']==hex(a) and int(p['raw'],16)==word and p['format']==8 and int(p['target'],16)==target and (word>>30)&3==0);return target
 for f in e['functions']:ok('original_body_'+f['start'],image.k.read(int(f['start'],16),int(f['end'],16)-int(f['start'],16)).hex()==f['bytes'] and sha256(bytes.fromhex(f['bytes'])).hexdigest()==f['sha256'])
 for o in e['option_descriptors']:
  a=int(o['descriptor'],16);raw=image.k.read(a,24);key=ptr(a,o['key_pointer']);ptr(a+8,o['destination_pointer']);ok('option_'+hex(a),raw.hex()==o['raw_hex'] and image.k.read(key,256).split(b'\0')[0].decode('ascii')==o['name'] and struct.unpack('<IBB',raw[16:22])==(o['size_bytes'],o['normalize_byte14'],o['string_byte15']) and prior['registry']['entries'][o['registry_index']]['callback_pointer']['target']==hex(R.OPTION))
 for o in e['per_CPU_pointer_arguments']:
  a=int(o['slot'],16);ok('per_CPU_slot_'+hex(a),image.k.read(a,8).hex()==o['raw_hex'] and prior['registry']['entries'][o['registry_index']]['callback_pointer']['target']==hex(R.ADJUST))
  if o['pointer']:ptr(a,o['pointer'])
 for o in e['indexed_descriptors']:
  a=int(o['descriptor'],16);raw=image.k.read(a,32);ok('indexed_'+hex(a),raw.hex()==o['raw_hex'] and int.from_bytes(raw[:4],'little')==o['selector_u32']<18)
  for j,p in enumerate(o['pointers']):
   if p:ptr(a+8+8*j,p)
   else:ok('indexed_null_'+hex(a+8+8*j),raw[8+8*j:16+8*j]==bytes(8))
  for label in o['labels']:ok('SFI_label_'+label['address'],image.k.read(int(label['address'],16),256).split(b'\0')[0]+b'\0'==bytes.fromhex(label['bytes_hex']) and bytes.fromhex(label['bytes_hex'])[:-1].decode('ascii')==label['text'])
 h=e['kernel_MachO_header'];at=int(h['address'],16);raw=image.k.read(at,32);ok('original_MachO_header',h['bytes_hex']==raw.hex() and raw[:4]==bytes.fromhex('cffaedfe'));at+=32
 for c in h['load_commands']:ok('load_command_'+str(c['index']),c['address']==hex(at) and image.k.read(at,c['size_bytes']).hex()==c['bytes_hex'] and struct.unpack('<II',bytes.fromhex(c['bytes_hex'])[:8])==(c['command'],c['size_bytes']));at+=c['size_bytes']
 ok('complete_load_command_extent',at-int(h['address'],16)-32==int.from_bytes(raw[20:24],'little') and len(h['load_commands'])==int.from_bytes(raw[16:20],'little'))
 return {'checks':checks,'option_descriptors_checked':237,'per_CPU_arguments_checked':101,'indexed_descriptors_checked':17,'original_function_bodies_checked':len(e['functions'])}

def oracle(row,e):
 row=hydrate(row)
 prior=json.loads(read(ROOT/(R.B.P+'_checks.json')));prefix=B.oracle(first_row(row),prior);old=B.B.B.legacy(row);tree=B.B.B.decode_tree(old);tree_checks=B.B.B.tree_contracts(old,tree);option_checks=option_contracts(row);copies=B.B.copy_contracts(row,old);strings=B.string_contracts(row,old)
 memory=pages(old['initial_pages']);cut=row['first_callback_boundary'];raw=uncompress(cut['private_RAM']);checks=[];compared=0;families=Counter();tree_options={int(o['descriptor'],16):o for o in prior['tunable_descriptors']};options={int(o['descriptor'],16):o for o in e['option_descriptors']};indexed={int(o['descriptor'],16):o for o in e['indexed_descriptors']}
 for j in range(0,SIZE,4096):memory[P+j]=bytearray(raw[j:j+4096])
 for r in cut['image_globals']+cut['additional_image_globals']+cut['registry_image_globals']:put(memory,int(r['address'],16),len(bytes.fromhex(r['bytes_hex'])),bytes.fromhex(r['bytes_hex']))
 def u(a,n):return int.from_bytes(get(memory,a,n),'little')
 def w(a,n,v):put(memory,a,n,v)
 def ok(label,p):assert p,('batch_contract',label,row['configuration']['label']);checks.append(label)
 for r in cut['phase_one_image_globals']:ok('new_storage_unchanged_at_preserved_boundary_'+r['address'],get(memory,int(r['address'],16),len(bytes.fromhex(r['bytes_hex']))).hex()==r['bytes_hex'])
 text=get(memory,R.B.B.K.ARGS+0x6c,256)
 def parse_into(key,address,size,mode=0):
  before=get(memory,address,size);status,value=parse(text,key.encode(),size,mode,before)
  if size:w(address,size,value)
  return status
 def present(key):return parse(text,key.encode(),0,0,b'')[0]
 def prop(path,key):
  node=tree['nodes'].get(path);p=next((p for p in node['properties'] if p['key']==key),None) if node else None;return p['value'] if p else None
 def scalar(path,key,n):
  value=prop(path,key)
  if value is None:return None
  assert len(value)==n;return int.from_bytes(value,'little')
 records=bytes.fromhex(next(r['bytes_hex'] for r in cut['registry_image_globals'] if r['address']==hex(R.B.BASE)));returned=row['callback_returns'];entered=row['callback_entries'];ok('every_completed_callback_has_one_return_and_next_UUID_callback_is_active',len(entered)==len(returned)+1 and returned[0]['sorted_index']==0)
 for j,c in enumerate(entered):
  a=R.B.BASE+24*j;phase,rank,target,arg=struct.unpack('<IIQQ',records[24*j:24*j+24]);ok('entry_record_'+str(j),c['sorted_index']==j and c['cursor']==hex(a) and (phase,rank,hex(target),hex(arg))==(c['phase_u32'],c['rank_u32'],c['target'],c['argument']) and phase==1)
  if j==0:continue
  w(0xfffffe0007f8b5f0,4,0)
  if j==len(returned):
   ok('unfinished_callback_is_MachO_identity_initializer',target==R.IMAGE);uuid=e['kernel_MachO_header']['first_UUID_command'];w(0xfffffe000cb51120,8,int(uuid['address'],16)+8);break
  families[hex(target)]+=1
  if target==R.OPTION:
   o=options[arg];dst=int(o['destination_pointer']['target'],16);status=parse_into(o['name'],dst,o['size_bytes'],o['string_byte15']&1)
   if not o['string_byte15']&1 and status and o['normalize_byte14']&1:w(dst,1,int(bool(u(dst,1))))
  elif target==R.B.TUNABLE:
   o=tree_options[arg];dst=int(o['destination'],16);n=o['size_bytes'];value=prop(o['path'],o['property'])
   if value is not None:assert len(value)==n;w(dst,n,value)
   if o['option'] is not None:
    status=parse_into(o['option'],dst,n)
    if status and o['normalize_byte2c']&1:w(dst,1,int(bool(u(dst,1))))
  elif target==R.ADJUST:
   thread=row['final_system']['tpidr_el1'];ordinal=u(thread+0x1b8,2);w(arg,8,(u(arg,8)-(ordinal<<14))&MASK)
  elif target==R.TIMER:w(0xfffffe000cb62e78,4,5000);w(0xfffffe000cb62e80,8,(u(R.B.RATIO,4)*0x51eb851f)>>38)
  elif target==R.CHOSEN:
   value=scalar('/chosen','kernel-ctrr-to-be-enabled',4)
   if value is not None:w(0xfffffe0007ef8e68,1,1);w(0xfffffe0007ef8e69,1,int(value==0))
  elif target==R.POLICY:
   initial=scalar('/chosen/asmb','lp-sip0',8);flags=(initial or 0)&0xffffffff;internal=scalar('/chosen','internal-use-only-unit',4);iuos=scalar('/chosen/manifest-properties','iuos',4)
   if internal or iuos:
    if initial is None:flags|=16
   else:flags&=~16
   environment=prop('/chosen','osenvironment');environment=environment.split(b'\0')[0] if environment else None
   if present('-restore') or environment in [b'recoveryos',b'darwinos-ramdisk']:flags|=2
   if environment==b'recoveryos' or scalar('/chosen','csr-allow-device-configuration',4):flags|=128
   sip1=scalar('/chosen/asmb','lp-sip1',4);flags=(flags&~0x800)|(0x800 if sip1 else 0);w(0xfffffe0007f12c60,4,flags)
  elif target==R.INDEXED:
   o=indexed[arg];a=0xfffffe000cadce28+96*o['selector_u32'];ok('indexed_slot_empty_'+str(j),u(a+0x48,8)==0);w(a+0x24,4,0);w(a+0x28,4,1)
   for off,p in zip([0x48,0x50,0x58],o['pointers']):w(a+off,8,int(p['target'],16) if p else 0)
  elif target==R.TRACE_CONFIG:
   for key,mask in [('-s',2),('-x',256)]:
    if present(key):w(0xfffffe0007f19d90,4,u(0xfffffe0007f19d90,4)|mask)
   if parse_into('nbuf',0xfffffe000cb29c18,4):w(0xfffffe000cb29c1c,4,1)
   args=u(0xfffffe0007f8b6e8,8);w(0xfffffe000cb2a71c,4,u(args+0x470,4)&1 if args and u(args,2)>=2 else 0)
   for key,a in [('panic-on-proc-crash',0xfffffe000cb29df0),('panic-on-proc-exit',0xfffffe000cb29ef4),('panic-on-proc-spawn-fail',0xfffffe000cb29ff8)]:
    if parse_into(key,a+4,255,1) and get(memory,a+4,255).split(b'\0')[0]:w(a,4,1)
  elif target==R.WATCHDOG:
   a=0xfffffe000ca92374;value=u(a,4)
   if not 1<=value<=100:w(a,4,95)
   status,value=parse(text,b'wdt',4,0,bytes(4))
   if status and int.from_bytes(value,'little')==0xffffffff and not present('zet'):w(0xfffffe0007e66e28,4,0xffffffff)
  else:raise AssertionError(('uncovered_callback_family',hex(target)))
  returned_row=returned[j];ok('return_SP_'+str(j),returned_row['SP']==c['SP'])
  for r in returned_row['observed_regions']:
   a=int(r['address'],16);value=bytes.fromhex(r['bytes_hex']);ok('callback_output_'+str(j)+'_'+r['address'],get(memory,a,len(value))==value);compared+=len(value)
  w(R.B.CURSOR,8,R.B.BASE+24*(j+1))
 for r in row['final_image_globals']:
  a=int(r['address'],16);value=bytes.fromhex(r['bytes_hex']);ok('final_global_'+r['address'],get(memory,a,len(value))==value);compared+=len(value)
 ok('logical_system_unchanged_after_first_boundary',row['final_system']==cut['system']);ok('stopped_before_original_formatter_BL',row['boundary']['pc']==hex(R.STOP) and row['boundary']['kind']=='before_original_UUID_formatter_call')
 regs=[int(x,16) for x in row['boundary']['registers31']];uuid=bytes.fromhex(e['kernel_MachO_header']['first_UUID_command']['bytes_hex'])[8:24];stack=int(row['boundary']['SP'],16);after=uncompress(row['final_private_RAM']);varargs=after[stack-P:stack-P+128];ok('formatter_ABI',regs[:3]==[0xfffffe000cb2a1a0,37,0xfffffe00070d7f36] and struct.unpack('<16Q',varargs)==tuple(uuid))
 before=uncompress(cut['private_RAM']);ok('nonstack_private_RAM_preserved',before[:SP-P-0x1000]==after[:SP-P-0x1000] and before[SP-P+0x100:]==after[SP-P+0x100:]);ok('no_epochs','epochs' not in row)
 return {'checks':checks,'first_callback_contracts':prefix,'tree_API_contracts':tree_checks,'option_API_contracts':option_checks,'copy_contracts':copies,'string_contracts':strings,'completed_callbacks':len(returned),'completed_family_histogram':dict(families+Counter({hex(R.B.TUNABLE):1})),'mutable_bytes_compared':compared,'private_nonstack_bytes_checked':SIZE-0x1100,'UUID_bytes_hex':uuid.hex(),'formatter_expected_text':('-'.join([uuid[:4].hex(),uuid[4:6].hex(),uuid[6:8].hex(),uuid[8:10].hex(),uuid[10:].hex()])).upper(),'formatter_output_executed':False}

class Replay(B.Replay):
 def __init__(self,image,row):super().__init__(image,hydrate(row,image));self.callback_index=0;self.callback_return_index=0;self.first_boundary_seen=False
 def composition_checkpoint(self,c):
  super().composition_checkpoint(c)
  for r in c['phase_one_image_globals']:
   raw=bytes.fromhex(r['bytes_hex']);assert bytes(self.u.mem_read(int(r['address'],16),len(raw)))==raw;self.counts['whole_checkpoint_phase_one_bytes_checked']+=len(raw)
 def code(self,u,a,n,d):
  self.finish()
  while self.active and self.entries[self.active[-1]]['return_PC']==hex(a) and self.entries[self.active[-1]]['entry_SP']==hex(u.reg_read(ar.UC_ARM64_REG_SP)):
   self.returns.append({'entry_index':self.active.pop(),'before_visit':self.seq,'return_value':hex(self.reg(0))})
  if a==0xfffffe000c630370:
   c=self.p['callback_entries'][self.callback_index];assert c['before_visit']==self.seq and c['SP']==hex(u.reg_read(ar.UC_ARM64_REG_SP)) and c['target']==hex(self.reg(8)) and c['argument']==hex(self.reg(0));cursor=int.from_bytes(u.mem_read(R.B.CURSOR,8),'little');assert c['cursor']==hex(cursor) and cursor==R.B.BASE+24*self.callback_index
   phase,rank,target,arg=struct.unpack('<IIQQ',u.mem_read(cursor,24));assert phase==1 and target==self.reg(8) and arg==self.reg(0) and self.reg(17)==0x2abe;self.callback_index+=1;self.counts['callback_entries_checked']+=1
   if self.callback_index!=1:
    raw=bytes(u.mem_read(a,4));i=next(self.image.k.cs.disasm(raw,a));assert raw==self.image.k.read(a,4) and i.mnemonic=='blraa' and i.op_str=='x8, x17' and self.p['source_visits'][self.seq]=={'pc':hex(a),'bytes_hex':raw.hex()}
    event={'PC':hex(a),'kind':'blraa','scope':'original_registry_callback','operands':i.op_str,'before_visit':self.seq,'system_before':dict(self.system),'system_after':dict(self.system),'target':hex(target),'modifier_X17':hex(self.reg(17)),'argument_X0':hex(arg)};assert event==self.p['logical_effects'][len(self.logical)];self.logical.append(event);self.current=self.seq;self.seq+=1;self.rc=self.wc=0;self.counts['source_visits_checked']+=1;self.counts['logical_effects_checked']+=1;u.reg_write(ar.UC_ARM64_REG_X30,a+4);u.reg_write(ar.UC_ARM64_REG_PC,target);return
  if a==0xfffffe000c630374:
   c=self.p['callback_returns'][self.callback_return_index];assert c['before_visit']==self.seq and c['sorted_index']==self.callback_return_index and c['SP']==hex(u.reg_read(ar.UC_ARM64_REG_SP))
   for r in c['observed_regions']:
    raw=bytes.fromhex(r['bytes_hex']);assert bytes(u.mem_read(int(r['address'],16),len(raw)))==raw;self.counts['callback_output_bytes_checked']+=len(raw)
   self.callback_return_index+=1;self.counts['callback_returns_checked']+=1
   if self.callback_return_index!=1:return Core.code(self,u,a,n,d)
  if a==0xfffffe000c63037c and not self.first_boundary_seen:
   self.composition_checkpoint(self.p['first_callback_boundary']);wanted=self.p['first_callback_boundary']['mapped_page_sha256'];actual={hex(pg):sha256(bytes(u.mem_read(pg,4096))).hexdigest() for pg in sorted(self.pages)};assert wanted.keys()<=actual.keys() and all(actual[pg]==digest for pg,digest in wanted.items())
   for pg in actual.keys()-wanted.keys():assert bytes(u.mem_read(int(pg,16),4096))==self.image.logical_page(int(pg,16));self.counts['checkpoint_eager_original_page_bytes_checked']+=4096
   self.first_boundary_seen=True
  if a in NEW_APIS:
   self.active.append(len(self.entries));self.entries.append({'PC':hex(a),'entry_SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'arguments6':[hex(self.reg(j)) for j in range(6)],'return_PC':hex(self.reg(30)),'before_visit':self.seq})
  return super().code(u,a,n,d)
 def run(self):
  entry=int(self.p['entry_PC'],16);self.ensure(entry);self.u.emu_start(entry,0,count=len(self.p['source_visits'])+len(self.models)+10);self.finish()
  assert self.seq==len(self.p['source_visits']) and self.mi==len(self.models) and self.counts['final_boundaries_checked']==1
  assert self.entries==self.p['original_API_entries'] and self.returns==self.p['original_API_returns'] and self.active==self.p['unfinished_API_entry_indices']
  assert self.additional_checkpoints==9 and self.checkpoints==11 and self.callback_index==len(self.p['callback_entries']) and self.callback_return_index==len(self.p['callback_returns'])
  assert self.logical==self.p['logical_effects'] and self.system==self.p['final_system'] and bytes(self.u.mem_read(P,SIZE))==uncompress(self.p['final_private_RAM']);self.counts['whole_private_bytes_checked']+=SIZE
  assert {hex(pg):sha256(bytes(self.u.mem_read(pg,4096))).hexdigest() for pg in sorted(self.pages)}==self.p['final_page_sha256'];self.counts['whole_image_page_bytes_checked']+=len(self.pages)*4096
  for j,value in enumerate(self.p['final_vectors']):assert value==hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))));self.counts['vector_registers_checked']+=1
  self.counts['original_API_entries_and_returns_checked']+=len(self.returns);self.counts['unfinished_original_API_entries_checked']+=len(self.active);return dict(self.counts)
