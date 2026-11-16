#!/usr/bin/env python3
"""Independent registry/fixup/tunable contracts and fresh original-source replay.
O(source+registry+visits+journals+RAM) space; timeline sorting O(J log J).
No executor import, native target or callback-output model.
"""
import json,math,struct
from collections import Counter
from hashlib import sha256
from unicorn import arm64_const as ar
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read
from probe_rpc502_vm_handoff import decode as uncompress
from replay_kernel_boot_cpu_identity import pages,get,put
import replay_kernel_bootstrap_state_composition as B
from replay_kernel_vm_mig import Replay as Core
import recover_kernel_startup_registry_abi as R
P=B.P;SIZE=B.SIZE;SP=B.SP;MASK=(1<<64)-1
NEW_APIS=[*R.ADDITIONS,R.TUNABLE]

def registry_contracts(e,image):
 checks=[];base=int(e['fixup_base'],16);entries=e['registry']['entries'];targets=set();pointer_count=0
 def ok(label,p):assert p,('registry_contract',label);checks.append(label)
 def pointer(p,raw):
  nonlocal pointer_count
  word=int.from_bytes(raw,'little');target=base+(word&0x3fffffff);ok('pointer_'+p['slot'],((word>>30)&3)==0 and p['format']==8 and int(p['raw'],16)==word and int(p['target'],16)==target and p['auth']==word>>63 and int(p['diversity'],16)==((word>>32)&65535) and p['address_diversity']==((word>>48)&1) and p['key']==((word>>49)&3));pointer_count+=1;return target
 raw_table=bytearray();logical_table=bytearray()
 for j,r in enumerate(entries):
  a=R.BASE+24*j;raw=image.k.read(a,24);ok('record_'+str(j),r['index']==j and r['address']==hex(a) and r['raw_hex']==raw.hex());phase,rank=struct.unpack('<II',raw[:8]);target=pointer(r['callback_pointer'],raw[8:16]);arg=pointer(r['argument_pointer'],raw[16:24]) if r['argument_pointer'] else 0
  if not r['argument_pointer']:ok('null_argument_'+str(j),raw[16:24]==bytes(8))
  ok('fields_'+str(j),(phase,rank)==(r['phase_u32'],r['rank_u32']) and struct.pack('<IIQQ',phase,rank,target,arg).hex()==r['logical_hex']);p=r['callback_pointer'];ok('callback_auth_'+str(j),p['auth']==1 and p['diversity']=='0x2abe' and p['address_diversity']==0 and p['key']==0)
  owners={x['name'] for x in image.k.entries if any(s['address']<=target<s['address']+s['vm_size'] for s in x['segments'])};ok('owner_'+str(j),owners=={'com.apple.kernel'} and r['callback_owner']==['com.apple.kernel']);targets.add(target);raw_table+=raw;logical_table+=bytes.fromhex(r['logical_hex'])
 ok('complete_original_section',len(entries)==3519 and len(raw_table)==84456 and e['registry']['end']==hex(R.END) and e['registry']['section']['section']=='__init_entry_set')
 ok('raw_and_logical_hashes',sha256(raw_table).hexdigest()==e['registry']['raw_sha256'] and sha256(logical_table).hexdigest()==e['registry']['logical_sha256'])
 ok('callback_body_inventory',targets=={int(x['target'],16) for x in e['callback_inventory']} and len(targets)==115)
 for c in e['callback_inventory']:
  f=next(f for f in e['functions'] if f['start']==c['target']);ok('callback_source_'+c['target'],c['source_sha256']==sha256(image.k.read(int(f['start'],16),int(f['end'],16)-int(f['start'],16))).hexdigest()==f['sha256'])
 for t in e['tunable_descriptors']:
  a=int(t['descriptor'],16);raw=image.k.read(a,48);ok('descriptor_'+t['descriptor'],t['raw_hex']==raw.hex() and entries[t['registry_index']]['callback_pointer']['target']==hex(R.TUNABLE))
  for off,key in [(0,'path'),(8,'property'),(24,'option'),(32,'destination')]:
   p=t['pointers'][key];target=pointer(p,raw[off:off+8]) if p else 0
   if key!='destination':ok('descriptor_text_'+t['descriptor']+'_'+key,t[key]==(image.k.read(target,256).split(b'\0')[0].decode('ascii') if target else None))
   else:ok('descriptor_destination_'+t['descriptor'],t['destination']==hex(target))
  ok('descriptor_flags_width_'+t['descriptor'],t['path_flags_byte10']==raw[16] and t['size_bytes']==int.from_bytes(raw[40:44],'little') and t['normalize_byte2c']==raw[44])
 ok('MIG_initializer_registration',e['MIG_initializer_registration']['entry_index']==123 and entries[123]['callback_pointer']['target']=='0xfffffe000c62a46c' and entries[123]['phase_u32']==14 and entries[123]['rank_u32']==0 and e['phase_names'][14]['name']=='mach_ipc')
 for r in e['phase_names']:
  a=R.PHASE_NAMES+8*r['phase'];raw=image.k.read(a,8)
  if r['pointer']:
   target=pointer(r['pointer'],raw);text=image.k.read(target,256).split(b'\0')[0]+b'\0';ok('phase_name_'+str(r['phase']),r['bytes_hex']==text.hex() and r['name']==text[:-1].decode('ascii'))
  else:ok('null_phase_name_'+str(r['phase']),raw==bytes(8) and r['name'] is None)
 cursor=pointer(e['initial_cursor_pointer'],image.k.read(R.CURSOR,8));ok('initial_cursor_targets_section_base',cursor==R.BASE)
 return {'checks':checks,'registry_records':len(entries),'pointer_records_independently_decoded':pointer_count,'callback_bodies_checked':len(targets),'tunable_descriptors_checked':len(e['tunable_descriptors']),'logical_table_bytes_checked':len(logical_table)}

def bootstrap_row(row):
 c=row['bootstrap_state_checkpoint'];end=c['before_visit'];out=dict(row);out['source_visits']=row['source_visits'][:end]
 for key in ['source_reads','source_writes']:out[key]=[w for w in row[key] if w['source_visit_index']<end]
 out['API_models']=[m for m in row['API_models'] if m['before_source_visit_index']<end];out['logical_effects']=[m for m in row['logical_effects'] if m['before_visit']<end]
 out['original_API_entries']=[m for m in row['original_API_entries'] if m['before_visit']<end];out['original_API_returns']=[m for m in row['original_API_returns'] if m['before_visit']<=end]
 out.update(final_private_RAM=c['private_RAM'],final_image_globals=c['image_globals']+c['additional_image_globals'],final_system=c['system'],final_vectors=c['vectors'],unfinished_API_entry_indices=[],boundary={'pc':c['PC'],'kind':'original_bootstrap_thread_setup_complete','registers31':c['registers31'],'SP':c['SP'],'NZCV':c['NZCV']})
 return out

def string_contracts(row,old):
 memory=pages(old['initial_pages']);events=[];pending={};checks=[];calls=0;bytes_checked=0;targets=[R.STRNCHK,R.STRNLEN,R.MEMSET]
 for j,w in enumerate(row['source_writes']):events.append((w['source_visit_index'],2,j,'write',w))
 for j,e in enumerate(row['original_API_entries']):
  if int(e['PC'],16) in targets:events.append((e['before_visit'],1,j,'entry',e))
 for j,e in enumerate(row['original_API_returns']):
  if int(row['original_API_entries'][e['entry_index']]['PC'],16) in targets:events.append((e['before_visit'],0,j,'return',e))
 def ok(label,p):assert p,('string_contract',label);checks.append(label)
 for _,_,index,kind,e in sorted(events,key=lambda x:x[:3]):
  if kind=='write':raw=bytes.fromhex(e['after_hex']);put(memory,int(e['address'],16),len(raw),raw);continue
  if kind=='entry':
   v=[int(x,16) for x in e['arguments6']];calls+=1;outputs=[]
   if int(e['PC'],16)==R.STRNLEN:
    a,n=v[:2];assert n<=64;data=get(memory,a,n);result=data.index(0) if 0 in data else n
   elif int(e['PC'],16)==R.MEMSET:
    a,value,n=v[:3];assert n<=64;result=a;outputs=[(a,bytes([value&255])*n)]
   else:
    a,b,n,capacity=v[:4];assert n<=capacity<=64;raw=get(memory,b,n);text=raw.split(b'\0')[0];result=a;outputs=[(a,text+bytes(n-len(text)))]
   pending[index]=(result,outputs);continue
  result,outputs=pending.pop(e['entry_index']);ok('return_'+str(e['entry_index']),int(e['return_value'],16)==result)
  for a,raw in outputs:ok('output_'+str(e['entry_index']),get(memory,a,len(raw))==raw);bytes_checked+=len(raw)
 ok('all_original_checked_string_calls_returned',not pending)
 return {'checks':checks,'calls':calls,'destination_bytes_checked':bytes_checked}

def oracle(row,e):
 prefix=B.oracle(bootstrap_row(row),json.loads(read(ROOT/(R.B.P+'_checks.json'))));old=B.B.legacy(row);tree=B.B.decode_tree(old);tree_checks=B.B.tree_contracts(old,tree);option_checks=B.B.option_oracle(old);copies=B.copy_contracts(row,old);strings=string_contracts(row,old)
 memory=pages(old['initial_pages']);c=row['bootstrap_state_checkpoint'];checks=[];compared=0;system=dict(c['system']);raw=uncompress(c['private_RAM'])
 for j in range(0,SIZE,4096):memory[P+j]=bytearray(raw[j:j+4096])
 for r in c['image_globals']+c['additional_image_globals']:put(memory,int(r['address'],16),len(bytes.fromhex(r['bytes_hex'])),bytes.fromhex(r['bytes_hex']))
 def u(a,n):return int.from_bytes(get(memory,a,n),'little')
 def w(a,n,v):put(memory,a,n,v)
 def ok(label,p):assert p,('startup_contract',label,row['configuration']['label']);checks.append(label)
 def compare(snapshot,label):
  nonlocal compared
  for r in snapshot['image_globals']+snapshot.get('additional_image_globals',[])+snapshot.get('registry_image_globals',[]):
   a=int(r['address'],16);raw=bytes.fromhex(r['bytes_hex']);ok(label+'_'+r['address'],get(memory,a,len(raw))==raw);compared+=len(raw)
  ok(label+'_system',snapshot['system']==system)
 for r in c['registry_image_globals']:ok('additional_storage_unchanged_before_bootstrap_'+r['address'],get(memory,int(r['address'],16),len(bytes.fromhex(r['bytes_hex']))).hex()==r['bytes_hex'])
 frequency=u(0xfffffe000cb5c5f8,8);denominator=int(c['registers31'][25],16);assert 1<=denominator<=4 and frequency>=denominator
 product=(denominator*1000000000)&MASK;g=math.gcd(product,frequency);ratio=frequency//denominator
 w(R.CALLBACK,8,R.TIMEBASE);w(R.RATIO,16,struct.pack('<IIII',ratio&0xffffffff,((ratio&0xffffffff)*0x431bde83)>>50,(product//g)&0xffffffff,(frequency//g)&0xffffffff))
 trace_records=[]
 def trace(label):
  assert u(R.EVENT_STATE,1)==0 and u(R.EVENT_STATE+4,4)<=254
  thread=system['tpidr_el1'];ok('trace_uses_source_boot_thread_'+label.decode(),u(thread+0x1b8,2)==u(0xfffffe0007f8b4f0,4));index=u(R.EVENT_STATE+4,4);a=R.EVENTS+64*index
  stamp=(system['s3_4_c15_c10_6']+u(u(thread+0x1c0,8)+0x58,8))&MASK;w(a,8,stamp);w(a+8,32,(label+b'\0')[:32].ljust(32,b'\0'));w(a+40,8,0);w(a+48,4,0x07020010);w(R.EVENT_STATE+8,1,0);w(R.EVENT_STATE+4,4,index+1);trace_records.append({'index':index,'address':hex(a),'label':label.decode(),'timestamp_word':hex(stamp)})
 trace(b'kernel_startup_bootstrap');compare(row['sort_entry_checkpoint'],'before_original_sort')
 sorted_bytes=bytes.fromhex(next(r['bytes_hex'] for r in row['dispatch_entry_checkpoint']['registry_image_globals'] if r['address']==hex(R.BASE)));records=[sorted_bytes[j:j+24] for j in range(0,len(sorted_bytes),24)];original=[bytes.fromhex(r['logical_hex']) for r in e['registry']['entries']]
 ok('all_3519_logical_records_preserved',len(records)==3519 and Counter(records)==Counter(original));keys=[struct.unpack('<II',r[:8]) for r in records];ok('unsigned_phase_rank_order',keys==sorted(keys));w(R.BASE,len(sorted_bytes),sorted_bytes)
 ok('sort_tail_calls_original_dispatcher_with_phase3',row['dispatch_entry_checkpoint']['PC']==hex(R.DISPATCH) and int(row['dispatch_entry_checkpoint']['registers31'][0],16)==3);compare(row['dispatch_entry_checkpoint'],'original_sort_tail_dispatch')
 phase,rank,target,argument=struct.unpack('<IIQQ',records[0]);ok('first_record_is_admitted_phase1_tunable',phase==1 and phase<=3 and target==R.TUNABLE and row['first_callback_dispatch_checkpoint']['registers31'][8]==hex(target) and row['first_callback_dispatch_checkpoint']['registers31'][0]==hex(argument) and row['first_callback_dispatch_checkpoint']['registers31'][17]=='0x2abe')
 w(0xfffffe0007f8b5f0,4,(phase-1)&0xffffffff);assert u(R.LAST_PHASE,4)==0 and phase>0;trace(e['phase_names'][phase]['name'].encode());w(R.LAST_PHASE,4,phase);compare(row['first_callback_dispatch_checkpoint'],'before_original_tunable_call')
 descriptor=next(t for t in e['tunable_descriptors'] if int(t['descriptor'],16)==argument);assert descriptor['path_flags_byte10']==0;destination=int(descriptor['destination'],16);size=descriptor['size_bytes'];node=tree['nodes'].get(descriptor['path']);property_value=next((p['value'] for p in node['properties'] if p['key']==descriptor['property']),None) if node else None
 if property_value is not None:assert len(property_value)==size;w(destination,size,property_value)
 before_option=get(memory,destination,size);status,value=B.B.parse(get(memory,R.B.K.ARGS+0x6c,256),(descriptor['option'] or '').encode(),size,0,before_option)
 if status:
  w(destination,size,value)
  if descriptor['normalize_byte2c']&1:w(destination,1,int(bool(u(destination,1))))
 compare(row['first_callback_return_checkpoint'],'after_original_tunable_return');w(R.CURSOR,8,R.BASE+24);compare({'image_globals':row['final_image_globals'],'system':row['final_system']},'final_region')
 ok('actual_callback_return_preserves_dispatcher_frame',row['first_callback_return_checkpoint']['SP']==row['first_callback_dispatch_checkpoint']['SP']);ok('stop_after_original_cursor_publication',row['boundary']['pc']=='0xfffffe000c63037c' and int(row['boundary']['registers31'][24],16)==R.BASE+24)
 before=uncompress(c['private_RAM']);after=uncompress(row['final_private_RAM']);ok('nonstack_private_RAM_preserved',before[:SP-P-0x1000]==after[:SP-P-0x1000] and before[SP-P+0x100:]==after[SP-P+0x100:]);ok('no_call_frame_epoch','epochs' not in row)
 return {'checks':checks,'bootstrap_contracts':prefix,'tree_API_contracts':tree_checks,'option_API_contracts':option_checks,'copy_contracts':copies,'string_contracts':strings,'frequency_word':frequency,'denominator_word':denominator,'reduced_ratio_words':[product//g,frequency//g],'sorted_records':len(records),'trace_records':trace_records,'first_callback':{'phase':phase,'rank':rank,'target':hex(target),'argument':hex(argument),'descriptor_property':descriptor['property'],'option':descriptor['option'],'destination':hex(destination),'size_bytes':size,'tree_property_hex':property_value.hex() if property_value else None,'option_status':status,'final_hex':get(memory,destination,size).hex()},'whole_mutable_checkpoint_bytes_checked':compared,'private_nonstack_bytes_checked':SIZE-0x1100}

class Replay(B.Replay):
 def composition_checkpoint(self,c):
  super().composition_checkpoint(c)
  for r in c['registry_image_globals']:
   raw=bytes.fromhex(r['bytes_hex']);assert bytes(self.u.mem_read(int(r['address'],16),len(raw)))==raw;self.counts['whole_checkpoint_registry_image_bytes_checked']+=len(raw)
 def code(self,u,a,n,d):
  self.finish()
  while self.active and self.entries[self.active[-1]]['return_PC']==hex(a) and self.entries[self.active[-1]]['entry_SP']==hex(u.reg_read(ar.UC_ARM64_REG_SP)):
   self.returns.append({'entry_index':self.active.pop(),'before_visit':self.seq,'return_value':hex(self.reg(0))})
  for pc,key in [(0xfffffe000c639dd8,'bootstrap_state_checkpoint'),(R.SORT,'sort_entry_checkpoint'),(R.DISPATCH,'dispatch_entry_checkpoint'),(0xfffffe000c630370,'first_callback_dispatch_checkpoint'),(0xfffffe000c630374,'first_callback_return_checkpoint')]:
   if a==pc:self.composition_checkpoint(self.p[key])
  if a in NEW_APIS:
   self.active.append(len(self.entries));self.entries.append({'PC':hex(a),'entry_SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'arguments6':[hex(self.reg(j)) for j in range(6)],'return_PC':hex(self.reg(30)),'before_visit':self.seq})
  if self.seq<len(self.p['source_visits']):
   raw=bytes(u.mem_read(a,4));i=next(self.image.k.cs.disasm(raw,a))
   if i.mnemonic=='blraa' and (a==0xfffffe000c630370 or R.QUICKSORT<=a<0xfffffe000c61c630):
    callback=a==0xfffffe000c630370;reg=8 if callback else 19;target=R.TUNABLE if callback else R.COMPARE;modifier=0x2abe if callback else 0xe4fe
    assert raw==self.image.k.read(a,4) and i.op_str==('x8, x17' if callback else 'x19, x17') and self.reg(reg)==target and self.reg(17)==modifier
    assert self.p['source_visits'][self.seq]=={'pc':hex(a),'bytes_hex':raw.hex()}
    event={'PC':hex(a),'kind':'blraa','scope':'original_registry_callback' if callback else 'registry_comparator','operands':i.op_str,'before_visit':self.seq,'system_before':dict(self.system),'system_after':dict(self.system),'target':hex(target),'modifier_X17':hex(modifier)}
    if callback:event['argument_X0']=hex(self.reg(0))
    assert event==self.p['logical_effects'][len(self.logical)];self.logical.append(event);self.current=self.seq;self.seq+=1;self.rc=self.wc=0;self.counts['source_visits_checked']+=1;self.counts['logical_effects_checked']+=1;u.reg_write(ar.UC_ARM64_REG_X30,a+4);u.reg_write(ar.UC_ARM64_REG_PC,target);return
  if a==0xfffffe000c639dd8:return Core.code(self,u,a,n,d)
  return super().code(u,a,n,d)
 def run(self):
  entry=int(self.p['entry_PC'],16);self.ensure(entry);self.u.emu_start(entry,0,count=len(self.p['source_visits'])+len(self.models)+10);self.finish()
  assert self.seq==len(self.p['source_visits']) and self.mi==len(self.models) and self.counts['final_boundaries_checked']==1
  assert self.entries==self.p['original_API_entries'] and self.returns==self.p['original_API_returns'] and self.active==self.p['unfinished_API_entry_indices']
  assert self.additional_checkpoints==8 and self.checkpoints==10
  assert self.logical==self.p['logical_effects'] and self.system==self.p['final_system']
  assert bytes(self.u.mem_read(P,SIZE))==uncompress(self.p['final_private_RAM']);self.counts['whole_private_bytes_checked']+=SIZE
  assert {hex(pg):sha256(bytes(self.u.mem_read(pg,4096))).hexdigest() for pg in sorted(self.pages)}==self.p['final_page_sha256'];self.counts['whole_image_page_bytes_checked']+=len(self.pages)*4096
  for j,value in enumerate(self.p['final_vectors']):assert value==hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))));self.counts['vector_registers_checked']+=1
  self.counts['original_API_entries_and_returns_checked']+=len(self.returns);self.counts['unfinished_original_API_entries_checked']+=len(self.active);return dict(self.counts)
