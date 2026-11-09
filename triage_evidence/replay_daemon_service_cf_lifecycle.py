#!/usr/bin/env python3
"""Shared-engine fresh repeat plus independent service identity/state oracles.
Repeat shares the engine and lower models; no independent emulator claim.
O(S+V*F+J+H*R), O(S+J+R). No native IPC or lifetime proof.
"""
import copy,struct,zlib,base64,hashlib
from collections import Counter
from probe_daemon_service_cf_lifecycle import Probe,configs,SOBJ,SSRC,SARG,SNAME,SBAG,ARRAY,BOOTSTRAP,B,FDO,HEADER,RL,MODE,SRC,SET0,SET1,HALT,DICT
from probe_daemon_cf_descriptor_bridge import HEAP
def q(b,o):return struct.unpack_from('<Q',b,o)[0]
def w(b,o):return struct.unpack_from('<I',b,o)[0]
def decode(e):
 b=zlib.decompress(base64.b64decode(e['zlib_base64']));assert len(b)==e['size_bytes']and hashlib.sha256(b).hexdigest()==e['sha256'];return b
def semantic(r):
 c=r['configuration'];count=Counter();name=c.get('service_name',0xe03);stop=c['ident']==15 if'ident'in c else True;registered=not(c.get('bootstrap_status')or c.get('service_object_null')or c.get('service_source_null'));constructed=not(c.get('bootstrap_status')or c.get('service_object_null'));entry=r['service_component_entries'];assert len(entry)==1;e=entry[0];initial=bytes.fromhex(e['entry']['record40_hex']);returned=e['returned'];record=bytes.fromhex(returned['record40_hex']);header=bytes.fromhex(returned['header96_hex']);obj=bytes.fromhex(returned['object128_hex']);source=bytes.fromhex(returned['service_source184_hex'])
 assert q(initial,0)==HEADER+0x18 and q(initial,8)==SNAME and q(initial,16)==q(initial,24)==0
 assert(w(initial,32)+0x316f29c1*((SARG&0xffffffff)^0x987eac8a))&0xffffffff==0x2e4c
 assert record[:16]==initial[:16]and record[20:]==initial[20:]and w(record,16)==(0x6263fc55 if registered else 0x6263578d);assert q(header,0x18)==(SOBJ if registered else 0)
 if constructed:assert w(obj,20)==name and q(obj,48)==0x100425f78 and q(obj,64)==0 and q(obj,8)&6==0
 if registered:
  assert w(obj,16)==0 and q(obj,40)==SSRC and q(source,104)==1 and q(source,112)==SOBJ and q(source,160)==0x1847e8924 and q(source,168)==0x184784050 and q(source,96)==SBAG and q(source,8)&8
  state=returned['model_state'];assert state['dictionary'][hex(name)]==hex(SSRC)and hex(SSRC)in state['collections'][hex(SET1)];assert([hex(0x507),hex(name)]in state['members'])==(c.get('service_insert_status',0)==0)
  count['original_service_object_source_dictionary_identity_oracles']+=1
 contexts=[f for f in r['service_frames']if'public_context40_hex'in f];assert len(contexts)==int(not c.get('bootstrap_status'));assert all(f['public_context40_hex']=='00'*40 for f in contexts)
 source_contexts=[f for f in r['service_frames']if'source1_input_context72_hex'in f];assert len(source_contexts)==int(constructed)
 expected_context=struct.pack('<9Q',1,SOBJ,0x1846db030,0x1846e1278,0x18481206c,0x1847791a0,0x18472e5f0,0x1847e8924,0x184784050)
 for f in source_contexts:assert bytes.fromhex(f['source1_input_context72_hex'])==expected_context
 count['complete_public_and_source1_context_oracles']+=len(contexts)+len(source_contexts)
 callbacks=r['original_daemon_callbacks'];assert len(callbacks)==len(r['service_before_original_callbacks'])==len(r['service_original_callback_returns'])==1;assert callbacks[0]['patches']==[]and callbacks[0]['return_pc']=='0x1847b7e04';assert r['service_original_callback_returns'][0]['pc']=='0x1847b7e04';before=r['service_before_original_callbacks'][0];assert q(bytes.fromhex(before['header96_hex']),24)==(SOBJ if registered else 0)
 for f in(callbacks[0]['entry_before'],callbacks[0]['entry_after']):assert int(f['registers31'][0],16)==FDO and q(bytes.fromhex(f['header96_hex']),80)==FDO
 count['original_descriptor_callback_with_stored_service_and_CF_return_oracles']+=1
 final=r['final_service'];obj=bytes.fromhex(final['object128_hex']);source=bytes.fromhex(final['service_source184_hex']);header=bytes.fromhex(final['header96_hex']);state=final['model_state'];assert q(header,24)==(SOBJ if registered else 0);assert w(obj,16)==(2 if constructed and(stop or not registered)else 0);assert q(obj,8)&6==0 and q(obj,40)==(SSRC if registered and not stop else 0)
 assert final['registry']==([hex(SOBJ)]if constructed and not stop else[])
 if registered:
  assert bool(q(source,8)&8)==(not stop)and q(source,104)==1 and q(source,112)==SOBJ;assert q(source,96)==(SBAG if not stop else 0)
 assert state['dictionary']==({hex(name):hex(SSRC)}if registered and not stop else{});assert state['collections'][hex(SET1)]==([hex(SSRC)]if registered and not stop else[]);assert state['collections'][hex(SET0)]==([]if stop else[hex(SRC)])
 members={(int(a,16),int(b,16))for a,b in state['members']};expected={(0x507,a)for a in(0x607,0x707,0x807)}
 if registered and not c.get('service_insert_status')and(not stop or c.get('service_extract_status')):expected.add((0x507,name))
 assert members==expected;count['final_service_source0_source1_registry_dictionary_membership_oracles']+=1
 mutations=r['service_state_mutations'];insert=[x for x in mutations if x['kind']=='insert_member'];extract=[x for x in mutations if x['kind']=='extract_member'];assert len(insert)==int(registered)and len(extract)==int(registered and stop)
 for m in insert+extract:assert m['name']==hex(name)and m['facility']=='0x507'
 if registered and stop:
  kinds=[x['kind']for x in mutations];assert kinds==['insert_member','hash_remove','extract_member','hash_remove','hash_remove'];assert mutations[1]['container']==hex(DICT)and mutations[1]['key']==hex(name)and mutations[1]['removed']is True;assert mutations[3]['container']==hex(SET0)and mutations[3]['removed']is False;assert mutations[4]['container']==hex(SET1)and mutations[4]['removed']is True
 count['ordered_service_registration_and_removal_oracles']+=1
 for ev in r['service_lower_models']:
  label=ev['name'];args=[int(v,16)for v in ev['arguments8']];bf=ev['service_before'];expected=copy.deepcopy(bf['model_state']);registry=list(bf['registry']);patch=[];result=0
  if label=='declared_bootstrap_check_in_return':
   assert args[:2]==[BOOTSTRAP,SNAME];result=c.get('bootstrap_status',0);patch=[]if result else[(args[2],struct.pack('<I',name))]
  elif label in('declared_service_CF_runtime_type36','declared_service_source1_runtime_type46'):
   kind=36 if label.endswith('36')else 46;assert args[:4]==[0,kind,112 if kind==36 else 168,0];result=0 if c.get('service_object_null'if kind==36 else'service_source_null')else SOBJ if kind==36 else SSRC
   if result:raw=bytearray(128 if kind==36 else 184);struct.pack_into('<Q',raw,8,kind<<8);patch=[(result,bytes(raw))]
  elif label=='declared_service_CF_info_or_type':result=(36 if args[0]==SOBJ else 46)if ev['pc']=='0x184833694'else 0
  elif label=='declared_service_non_ObjC':assert args[:2]in([36,SOBJ],[46,SSRC])
  elif label=='declared_service_registry_count':assert args[0]==ARRAY;result=len(registry)
  elif label=='declared_service_registry_value':assert args[0]==ARRAY;result=int(registry[args[1]],16)
  elif label=='declared_service_registry_append':assert args[:2]==[ARRAY,SOBJ];registry.append(hex(SOBJ))
  elif label=='declared_service_registry_remove':assert args[0]==ARRAY;registry.pop(args[1])
  elif label=='declared_service_source_bag_storage':result=SBAG
  elif label=='declared_service_source1_hash_add':
   assert args[0]in(SET1,SBAG)and args[1]==args[2];values={int(v,16)for v in expected['collections'][hex(args[0])]};values.add(args[1]);expected['collections'][hex(args[0])]=[hex(v)for v in sorted(values)];patch=[(args[0]+20,struct.pack('<I',len(values))),(args[0]+26,b'\x01')]
  elif label=='declared_service_port_dictionary_set':assert args[:3]==[DICT,name,SSRC];expected['dictionary'][hex(name)]=hex(SSRC);patch=[(DICT+20,struct.pack('<I',len(expected['dictionary'])))]
  elif label=='declared_service_bag_type4':assert args[:2]==[SBAG,4]
  elif label=='declared_service_bag_bucket':assert args[:2]==[SBAG,0];patch=[(int(ev['service_before']['registers31'][8],16),struct.pack('<4Q',0,RL,RL,1))]
  elif label=='declared_service_hash_remove':
   if args[0]==DICT:result=int(hex(args[1])in expected['dictionary']);expected['dictionary'].pop(hex(args[1]),None);n=len(expected['dictionary'])
   else:values={int(v,16)for v in expected['collections'][hex(args[0])]};result=int(args[1]in values);values.discard(args[1]);expected['collections'][hex(args[0])]=[hex(v)for v in sorted(values)];n=len(values)
   patch=[(args[0]+20,struct.pack('<I',n))]
  elif label=='declared_service_name_receive_type':assert args[:2]==[0x103,name];patch=[(args[2],struct.pack('<I',0x20000))]
  elif label in('declared_service_insert_member','declared_service_extract_member'):
   assert args[:3]==[0x103,name,0x507];insert_op=label.endswith('insert_member');result=c.get('service_insert_status'if insert_op else'service_extract_status',0);values={(int(a,16),int(b,16))for a,b in expected['members']}
   if not result:
    if insert_op:values.add((0x507,name))
    else:values.discard((0x507,name))
   expected['members']=[[hex(a),hex(b)]for a,b in sorted(values)]
  elif label=='declared_service_log_object':result=ARRAY+0x100
  elif label=='declared_service_log_disabled':pass
  else:raise AssertionError(label)
  assert int(ev['result'],16)==result and [(int(p['address'],16),bytes.fromhex(p['after_hex']))for p in ev['patches']]==patch
  if label!='declared_bootstrap_check_in_return':
   af=ev['service_after'];assert ev['model_state_before']==bf['model_state'];assert af['model_state']==ev['model_state_after']==expected;assert af['registry']==registry
  else:af=ev['after']
  before_regs=[int(v,16)for v in bf['registers31']];after_regs=[int(v,16)for v in af['registers31']];assert after_regs==[result]+[(((j+1)*0x123456789abcdef)^0x8b3dc651)&0xffffffffffffffff for j in range(1,18)]+before_regs[18:]
  assert bf['SP']==af['SP']and bf['Q_registers32']==af['Q_registers32']and int(af['NZCV'],16)==0xf0000000 and int(af.get('pc',ev['return_pc']),16)==before_regs[30];count['service_lower_state_CPU_and_patch_contracts_recomputed']+=1
 regions=[r['final_private_RAM'],r['final_lower_stack']]+r['final_daemon_regions'];ram={int(e['address'],16):decode(e)for e in regions};private=ram[B]
 for at,n,key in((SOBJ,128,'object128_hex'),(SSRC,184,'service_source184_hex'),(SBAG,64,'service_bag64_hex')):assert private[at-B:at-B+n].hex()==final[key]
 for at,n in((SOBJ,128),(SSRC,184),(SBAG,64),(ARRAY,64),(SARG,40),(SNAME,18)):assert private[at-B+n]==0xa5
 assert private[SARG-B:SARG-B+40].hex()==final['record40_hex'];assert ram[HEAP][:89600]==(bytes(876)+struct.pack('<I',0x4577df49)+bytes(16))*100 and ram[HEAP][89600]==0xa5
 assert q(header,0)==HEAP and w(header,8)==100;assert len(r['SVC_return_contracts'])==int(stop);assert r['declared_callback_effects']==[]and r['daemon_callback_return_calls']==[];count['original_context_arena_and_service_guards_checked']+=1;count['complete_final_private_RAM_bytes_checked']+=sum(len(b)for b in ram.values());return dict(count)
def cpu_frames(v):
 if isinstance(v,list):return sum(cpu_frames(e)for e in v)
 if not isinstance(v,dict):return 0
 found=0
 if'registers31'in v and'Q_registers32'in v:
  assert len(v['registers31'])==31 and len(v['Q_registers32'])==32
  for x in v['registers31']+v['Q_registers32']+[v['SP'],v['NZCV']]:int(x,16)
  found=1
 return found+sum(cpu_frames(e)for e in v.values()if isinstance(e,(dict,list)))
def replay(s,p,k):
 expected=list(configs());assert len(p['cases'])==len(expected)
 for e,c in zip(p['cases'],expected,strict=True):assert all(e['configuration'][a]==v for a,v in c.items())
 cs={**s['CF_source'],'root_caller_options':s['root_caller_options'],'bridge_bindings':[{'slot':e['binding']['slot'],'target':hex(e['captured_CF_export']['address'])}for e in s['daemon_to_CF_bindings']]};totals=Counter()
 for row in p['cases']:
  fresh=Probe(copy.deepcopy(row['configuration']),k,cs).run();assert fresh==row,row['configuration']['label'];totals.update(semantic(row));totals['cases_reexecuted']+=1;totals['original_instruction_visits_repeated']+=len(row['source_visits']);totals['ordered_reads_repeated']+=len(row['source_reads']);totals['ordered_writes_and_after_images_repeated']+=len(row['source_writes']);totals['stored_tracked_CPU_frame_records_repeated']+=cpu_frames(row);totals['original_daemon_callback_returns_to_CF_checked']+=len(row['service_original_callback_returns']);totals['intercepted_original_wake_SVC_visits_checked']+=len(row['SVC_return_contracts'])
 return{**dict(totals),'shared_engine_and_lower_models':True,'independent_service_contract_oracles':True}
