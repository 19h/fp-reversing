#!/usr/bin/env python3
"""Fresh shared-engine repeat plus separately written compact semantic oracles.
Execution repeat shares Engine, loader and lower models; it is NOT an independent
emulator implementation. State/record/ownership/cleanup model below is separate.
O(V+J+H*R), O(S+J+R). No target execution or native IPC.
"""
import json,struct,zlib,base64,hashlib
from probe_cf_mach_port_retirement import Engine,configs,B,RAM,PORT,INFO,SOURCE,MONITOR,INVALID_CB
def cleanup(flags,name):
 out=[]
 if flags&16:out.append(('receive',name))
 if flags&8:out.append(('send',name))
 if flags&32:
  if flags&128:out.append(('receive',name))
  if flags&64:out.append(('send',name))
 return out
def semantic(p):
 c=p['config'];name=c.get('name',0x303)&0xffffffff;tag=c.get('client',0)&255;key=name|(tag<<32);records={};state=c.get('initial_state',0);owner=c.get('ownership',0)if c.get('seed_object')else 0;monitor=info=cached=callback=0;registry=[hex(PORT)]if c.get('registry_seed')else[];cbptr=0;object_name=name if c.get('seed_object')else 0;counts={'semantic_phase_oracles':0,'record_flags_and_keys_checked':0,'cleanup_request_arguments_checked':0,'cleanup_flag_inputs_checked':0}
 def record_dealloc(k,send,receive,ns=False):
  if not name or ns and not(send or receive):return[]
  if k not in records:return cleanup((32|(send<<6)|(receive<<7))if ns else((send<<3)|(receive<<4)),name)
  f=records[k]
  if ns:
   assert f&32
   if not f&4:records[k]=(f&0x39)|(send<<6)|(receive<<7)|2;return[]
   records.pop(k);return cleanup((f&0x3f)|(send<<6)|(receive<<7),name)
  if not f&4:records[k]=(f&0xe3)|(send<<3)|(receive<<4)|2;return[]
  records.pop(k);return cleanup((f&0xe7)|(send<<3)|(receive<<4),name)
 def source_invalid(k):
  assert k in records;f=records[k]
  if f&2:records.pop(k);return cleanup(f,name)
  records[k]=f|4;return[]
 for e in p['entries']:
  action=e['action'];expected=[]
  if action in('create','wrap'):
   failed=c.get('allocate_status',0)if action=='create'else 0
   if action=='create'and not failed and c.get('insert_status'):expected=[('receive',name)];failed=True
   if not failed and c.get('runtime_fail'):
    failed=True
    if action=='create':expected=[('receive',name),('send',name)]
   if not failed:
    owner=6 if action=='create'else 0;state=0;object_name=name;cbptr=0x100425f78;info=INFO if c.get('context')else 0;registry=[hex(PORT)];monitor=MONITOR if c['types']&0x50000 and not c.get('monitor_null')else 0
    if c['types']&0x50000:records[name]=1
   assert int(e['returned']['X31'][0],16)==(0 if failed else PORT)
  elif action=='wrap_again':assert int(e['returned']['X31'][0],16)==PORT
  elif action=='attach':callback=INVALID_CB if c.get('callback')else 0;cached=SOURCE if c.get('cached_source')else 0
  elif action=='invalidate':
   if state==0:state=2;monitor=info=cached=0;registry=[]
  elif action=='destroy':
   if state==0:monitor=info=cached=0
   state=3;expected=record_dealloc(name,(owner>>2)&1,(owner>>1)&1)
  elif action=='cancel':expected=source_invalid(name)
  elif action=='intent':
   if name:records.setdefault(key,1)
  elif action=='record':expected=record_dealloc(key,c.get('send',1)&1,c.get('receive',1)&1)
  elif action=='source_invalid':expected=source_invalid(key)
  elif action=='dead':
   assert key in records;records[key]&=~16
  elif action=='ns_interest':
   if key in records:records[key]|=32
  elif action=='ns_record':expected=record_dealloc(key,c.get('ns_send',1)&1,c.get('ns_receive',1)&1,True)
  elif action=='cleanup':expected=cleanup(c['flags'],name);counts['cleanup_flag_inputs_checked']+=1
  else:raise AssertionError(action)
  after=e['state']if action=='attach'else e['state_after'];raw=bytes.fromhex(after['object128_hex']);assert struct.unpack_from('<II',raw,16)==(state,object_name);assert struct.unpack_from('<Q',raw,8)[0]&6==owner;assert struct.unpack_from('<Q',raw,24)[0]==monitor;assert struct.unpack_from('<Q',raw,40)[0]==cached;assert struct.unpack_from('<Q',raw,64)[0]==info;assert struct.unpack_from('<Q',raw,32)[0]==callback;assert struct.unpack_from('<Q',raw,48)[0]==cbptr;assert after['registry']==registry and after['locks']==[]
  got={}
  for k,v in after['records'].items():
   r=bytes.fromhex(after['record_bytes'][v]);assert int.from_bytes(r[:5],'little')==int(k,16);assert r[6:]==b'\0\0';got[int(k,16)]=r[5];counts['record_flags_and_keys_checked']+=1
  assert got==records,(c['label'],action,got,records)
  events=[]if action=='attach'else p['lower_events'][e['event_start']:e['event_end']];actual=[]
  for row in events:
   if row['name']not in('_mach_port_mod_refs','_mach_port_deallocate'):continue
   args=[int(v,16)for v in row['arguments8']];assert args[0]&0xffffffff==0x103
   if row['name']=='_mach_port_mod_refs':assert[args[2]&0xffffffff,args[3]&0xffffffff]==[1,0xffffffff];actual.append(('receive',args[1]&0xffffffff))
   else:actual.append(('send',args[1]&0xffffffff))
   counts['cleanup_request_arguments_checked']+=1
  assert actual==expected,(c['label'],action,actual,expected)
  counts['semantic_phase_oracles']+=1
 assert bytes.fromhex(p['final_state']['object128_hex'])==bytes.fromhex((p['entries'][-1].get('state_after')or p['entries'][-1]['state'])['object128_hex'])
 for r in p['final_regions']:
  b=zlib.decompress(base64.b64decode(r['zlib_base64']));assert len(b)==r['size_bytes']and hashlib.sha256(b).hexdigest()==r['sha256']
 return counts
def replay(s,p):
 assert[c['config']for c in p['cases']]==configs();counts={};visits=reads=writes=frames=ram=0
 for case in p['cases']:
  fresh=Engine(s,case['config']).run();assert fresh==case,case['config']['label'];own=semantic(case)
  for k,v in own.items():counts[k]=counts.get(k,0)+v
  visits+=len(case['source_visits']);reads+=len(case['reads']);writes+=len(case['writes']);frames+=len(case['original_entry_frames'])+sum(2 for e in case['entries']if e['action']!='attach')+2*len(case['lower_events']);ram+=sum(r['size_bytes']for r in case['final_regions'])
 return{**counts,'cases_reexecuted':len(p['cases']),'original_instruction_visits_repeated':visits,'ordered_reads_repeated':reads,'ordered_writes_and_after_images_repeated':writes,'tracked_CPU_frames_repeated':frames,'complete_final_RAM_bytes_repeated':ram,'shared_engine_and_lower_models':True,'independent_compact_semantic_model':True}
