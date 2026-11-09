#!/usr/bin/env python3
"""Source-bounded SP audit of frozen authenticated-control event sequences."""
import json,re,capstone
from collections import defaultdict
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,TABLE,CS,sha,h,FLAGS
from daemon_receive_tools import verify_original_fixups
P='daemon_reader_stack_epoch'
SCOPE='Conditional shared-core F=E-0x10dd0 through keyed-reader entry and builder finish on12 frozen paths;source-only no-SP-write extension and scratch bounds. No fresh runtime replay,native mapping/initialization/PAC/callee/endpoint proof.'
CONTROL={'b','bl','br','blr','braa','brab','braaz','brabz','blraa','blrab','blraaz','blrabz','ret','retab','retaa','eret','svc','hvc','smc','brk','drps'}
def sp_effect(i):
 if 'sp'not in {i.reg_name(r)for r in i.regs_access()[1]}:return None
 if i.mnemonic in('sub','add'):
  m=re.fullmatch(r'sp, sp, #(0x[0-9a-f]+|[0-9]+)(?:, lsl #(0x[0-9a-f]+|[0-9]+))?',i.op_str);assert m,(hex(i.address),i.op_str);amount=int(m[1],0)<<(int(m[2],0)if m[2]else 0);delta=-amount if i.mnemonic=='sub'else amount
 elif i.mnemonic=='stp':
  m=re.search(r'\[sp, #(-0x[0-9a-f]+)\]!',i.op_str);assert m and i.writeback;delta=int(m[1],0)
 else:raise AssertionError((hex(i.address),i.mnemonic,i.op_str))
 return {'site':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str,'delta_bytes':delta}
def capture(a,z):
 b=IMAGE.read(a,z-a);dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True;ii=list(dc.disasm(b,a));assert 4*len(ii)==len(b)
 sp=[e for i in ii if(e:=sp_effect(i))is not None];ctrl=[{'site':hex(i.address),'mnemonic':i.mnemonic}for i in ii if i.mnemonic in CONTROL or i.mnemonic.startswith(('b.','cb','tb'))]
 return {'start':hex(a),'end':hex(z),'bytes':b.hex(),'sha256':h(b),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii],'SP_writes':sp,'controls':ctrl}
def build():
 assert sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 prefix=capture(0x10061a2d0,0x10061a318);assert [r['delta_bytes']for r in prefix['SP_writes']]==[-128,-65536,-3408]
 ps=json.loads((ROOT/'arcade_subscription_profiles.json').read_text())['profiles'];cache={};profiles=[];import_counts=defaultdict(int)
 for p in ps:
  if p['stop_reason']!='outgoing_arcade_xpc_message_boundary':continue
  assert p['source_sha256']==sha(SOURCE)and p['generator_sha256']==sha(ROOT/'probe_arcade_subscription.py')and p['base_probe_sha256']==sha(ROOT/'daemon_rpc502_probe.py')and not p['native_target_executed']and not p['target_host_operations_executed']
  ev=p['pac_bypasses'];core=next(j for j,e in enumerate(ev)if e.get('target')=='0x10061a2d0');probe=core+2;assert ev[core+1]['site']=='0x10061a2d0'and ev[probe]['site']=='0x10061a30c';start=probe+1;getter=next(j for j in range(start,len(ev))if ev[j].get('target')=='0x100847998');end=next(j for j in range(getter+1,len(ev))if ev[j].get('target')=='0x10090a400');visited={int(v,16)for v in p['visited_instruction_addresses']}
  records=defaultdict(list)
  for r in p['records']:
   if r.get('kind')in('import','private_import')and 'return_pc'in r:records[r['return_pc']].append(r)
  probe_record=records['0x10061a310'][0];assert probe_record['name']=='libSystem/___chkstk_darwin'
  a=0x10061a310;stack=[];rows=[];calls=[];counts=defaultdict(int);delta=-128;low=delta;helper_calls=0;instances=0
  for j in range(start,end+1):
   e=ev[j];site=int(e['site'],16);z=site+4;assert a<=site and z-a<0x10000,(p['label'],j,hex(a),e);key=hex(a)+':'+hex(z)
   if key not in cache:cache[key]=capture(a,z)
   f=cache[key];assert f['instructions'][-1]['mnemonic']==e['instruction'];assert all(int(i['ea'],16)in visited for i in f['instructions']);instances+=len(f['instructions'])
   if e['instruction']=='pacibsp':assert a==site and not f['controls']
   else:assert f['controls']==[{'site':e['site'],'mnemonic':e['instruction']}]
   before=delta
   for r in f['SP_writes']:delta+=r['delta_bytes'];low=min(low,delta)
   rows.append({'event_index':j,'interval':key,'call_depth':len(stack),'SP_delta_before':before,'SP_delta_after':delta,'event':e})
   if e['instruction']=='braa':a=int(e['target'],16)
   elif e['instruction']=='blraa':
    target=int(e['target'],16)
    if 0x100000000<=target<0x102000000:
     assert target==0x100444dfc;stack.append({'return_address':z,'parent_delta':delta});helper_calls+=1;a=target
    else:
     pc=hex(z);ordinal=counts[pc];counts[pc]+=1;r=records[pc][ordinal];calls.append({'event_index':j,'event':e,'record':r,'SP_delta_assumed_preserved':delta});import_counts[r['name']]+=1;a=z
   elif e['instruction']=='pacibsp':a=z
   elif e['instruction']=='retab':
    saved=stack.pop();assert delta==saved['parent_delta'];a=saved['return_address']
   else:raise AssertionError(e)
  assert not stack and a==0x10090a400 and delta==-0x10dd0 and helper_calls==9 and low==-0x10e90
  assert next(r['SP_delta_after']for r in rows if r['event_index']==getter)==-0x10dd0
  profiles.append({'label':p['label'],'first_event':start,'reader_entry_event':getter,'last_event':end,'intervals':rows,'import_calls':calls,'stack_probe_record':probe_record,'helper_calls':helper_calls,'instruction_instances':instances,'final_SP_delta':delta,'minimum_SP_delta':low,'reader_entry_SP_delta':next(r['SP_delta_after']for r in rows if r['event_index']==getter),'final_target':hex(a),'native_evidence':False,'scope':'Frozen events plus structural source audit; imports and internal return targets use explicit normal-return premises. Not a fresh execution or full data/control semantics proof.'})
 assert len(profiles)==12
 extension=[]
 specs=[('daemon_constructor_lookup_source.json',['entry','nonnull','next','candidate','prepare_decoder','decode','compare','advance','publish','mediator']),('daemon_existing_scalar_reader_source.json',None),('daemon_scalar_field_population_source.json',['entry','lookup_call','lookup_status','return','found_node','found_extent','found_header'])]
 for file,names in specs:
  obj=json.loads((ROOT/file).read_text());names=names or list(obj['fragments'])
  for n in names:
   old=obj['fragments'][n];a=int(old['start'],16);z=a+len(bytes.fromhex(old['bytes']));f=capture(a,z);assert f['bytes']==old['bytes']and not f['SP_writes']and all(r['mnemonic']=='braa'for r in f['controls']);extension.append({'file':file,'fragment':n,**f})
 assert len(extension)==36
 slot=0x1010b1e28;fix=FIXUPS[slot];assert fix['target']=='libSystem/___chkstk_darwin'and fix['kind']=='auth-bind'and fix['annotation']=='(div=0x0000 ad=1 key=IA)'
 cache_sites={i['ea']for f in cache.values()for i in f['instructions']};all_sites=cache_sites|{i['ea']for i in prefix['instructions']};ext_sites={i['ea']for f in extension for i in f['instructions']}
 deps=['arcade_subscription_profiles.json','probe_arcade_subscription.py','daemon_rpc502_probe.py','daemon_reader_context_footprint_source.json','daemon_reader_context_footprint_checks.json','daemon_existing_scalar_reader_source.json','daemon_existing_scalar_reader_checks.json','daemon_constructor_lookup_source.json','daemon_scalar_field_population_source.json','daemon_shared_roots_source.json','daemon_shared_roots_proofs.json','daemon_receive_fixups.txt']
 counts={'profiles':12,'unique_path_intervals':len(cache),'unique_path_instruction_sites':len(cache_sites),'prefix_instructions':len(prefix['instructions']),'path_plus_prefix_unique_sites':len(all_sites),'profile_interval_instances':sum(len(p['intervals'])for p in profiles),'profile_instruction_instances':sum(p['instruction_instances']for p in profiles),'internal_helper_calls':sum(p['helper_calls']for p in profiles),'import_calls':sum(len(p['import_calls'])for p in profiles),'extension_ranges':36,'extension_instruction_instances':sum(len(f['instructions'])for f in extension),'extension_unique_instruction_sites':len(ext_sites),'extension_SP_writes':0,'core_saved_bytes':128,'core_local_bytes':68944,'core_total_reservation_bytes':69072,'helper_local_bytes':192,'minimum_SP_below_entry_bytes':69264,'reader_frame_read_bound_bytes':44616,'reader_frame_bound_headroom_bytes':24328}
 return {'generator_sha256':sha(__file__),'static_scope':SCOPE,'daemon_path':str(SOURCE),'daemon_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in deps},'prefix':prefix,'path_intervals':cache,'profiles':profiles,'extension_ranges':extension,'import_call_counts':dict(sorted(import_counts.items())),'stack_probe_binding':{'slot':hex(slot),'raw_bytes':IMAGE.read(slot,8).hex(),'fixup':fix},'original_probe_fixup_check':verify_original_fixups({slot}),'verified_source_counts':counts,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
