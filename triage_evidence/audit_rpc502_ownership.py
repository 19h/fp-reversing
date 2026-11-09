#!/usr/bin/env python3
"""Independent resource ledger and composed RPC502 error-reply verification.

Re-audits frozen retained/fresh worker journals; does not reexecute workers.
Reexecutes eight short original callbacks with an abstract error return.
No native target, file API, Mach, IOKit, synchronization or IDB operation.
O(B+F+C*(V+E+S)) time, O(B+F+largest case/journal) working space.
"""
import base64,bisect,collections,hashlib,json,struct,zlib
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS,verify_original_fixups
from daemon_import_bindings import binding
from rpc502_startup_tools import unpack,journals,visits
from probe_rpc502_error_delivery import ErrorDelivery,REQUEST,REPLY,ERROR

RESOURCE={'libSystem/_malloc','libSystem/_malloc_type_malloc','libSystem/_free','libSystem/_mmap','libSystem/_munmap','libSystem/_open','libSystem/_close'}
SPECIAL={'private_open_result_model':'libSystem/_open','private_mmap_result_model':'libSystem/_mmap','private_malloc_result_model':'libSystem/_malloc'}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def normalized(e,phase):
 name=e.get('name',SPECIAL.get(e.get('kind')))
 if name not in RESOURCE:return None
 site=int(e.get('site',hex(int(e['return_pc'],16)-4)),16);args=e.get('args_x0_x7',e.get('args',[]));out={'name':name,'site':hex(site),'phase':phase,'args':args,'observer_kind':e['kind']}
 if name in['libSystem/_malloc','libSystem/_malloc_type_malloc']:
  out.update(pointer=e.get('result',e.get('return_bits',e.get('private_address'))),extent_bytes=e.get('requested_size_bytes',e.get('requested_extent_bytes',int(args[0],16)if args else None)))
 elif name=='libSystem/_mmap':out.update(pointer=e.get('result',e.get('return_bits')),extent_bytes=e.get('logical_extent_bytes',e.get('logical_file_extent_bytes')))
 elif name=='libSystem/_open':out.update(descriptor=e.get('result_signed32',e.get('signed_32_result')),path_hex=e['path_hex'])
 elif name=='libSystem/_free':out.update(pointer=e['retired_pointer'])
 elif name=='libSystem/_munmap':out.update(pointer=args[0],extent_bytes=int(args[1],16),result=e['result_signed32'])
 elif name=='libSystem/_close':out.update(descriptor=e['declared_FD'],result=e['result_signed32'])
 return out

def main():
 counts=collections.Counter();summaries=[];fixups=set();used=set();p=json.loads((ROOT/'rpc502_padding_profiles.json').read_text());f=json.loads((ROOT/'rpc502_padding_replays.json').read_text());delivery=json.loads((ROOT/'rpc502_error_delivery_profiles.json').read_text());deps={'rpc502_padding_profiles.json','rpc502_padding_replays.json','rpc502_padding_checks.json','rpc502_error_delivery_profiles.json','probe_rpc502_error_delivery.py','rpc502_startup_tools.py','daemon_receive_tools.py','daemon_import_bindings.py','daemon_receive_fixups.txt'}
 assert p['source_sha256']==f['source_sha256']==delivery['source_sha256']==sha(SOURCE)
 for obj,producer in[(p,'probe_rpc502_padding_cases.py'),(f,'probe_rpc502_padding_replay.py'),(delivery,'probe_rpc502_error_delivery.py')]:
  assert obj['generator_sha256']==sha(ROOT/producer)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h;deps.add(n)
 pool={}
 for e in p['original_instruction_pool']+delivery['source_instructions']:
  a=int(e['ea'],16);b=IMAGE.read(a,4);i=next(CS.disasm(b,a));assert b.hex()==e['bytes']and i.mnemonic==e['mnemonic']and i.op_str==e['operands'];pool[a]=struct.pack('<Q',a)+b
 assert p['original_instruction_pool']==f['original_instruction_pool']
 symbolic={}
 for v in FIXUPS.values():
  name=v['target']
  if isinstance(name,str)and name not in symbolic:symbolic[name]=0x6000000000+16*len(symbolic)
 reverse={v:k for k,v in symbolic.items()}
 for old,fresh in zip(p['cases'],f['cases']):
  assert old['case']==fresh['case'];r=unpack(old);fr=unpack(fresh);assert r==fr;del fr
  assert r['startup_returned']and r['stop_reason']=='returned_to_fixture'and r['records'][-1]['result']==hex(ERROR)
  assert not r['native_target_executed']and not r['target_host_ipc_files_or_system_calls_executed']and not r['idb_mutated']
  events=[];positions=collections.defaultdict(list);offset=0;image_pointer_stores=[];stack_pointer_stores=[]
  api_sites={int(e['allocation_pc'],16)for e in r['private_heap_allocations']}|{0x10095b5c8,0x100d94494,0x100c85e40,0x1003aaef4,0x1001f19c4,0x100023a94,0x100023a9c,0x100023aa8,0x100023ab0,0x100023ad4}
  for e in r['explicit_parser_models']:api_sites.add(int(e['site'],16))
  for d in journals(r):
   seq=visits(d);assert len(seq)==d['source_visit_count'];h=hashlib.sha256()
   for j,a in enumerate(seq):
    h.update(pool[a])
    if a in api_sites:positions[a].append(offset+j)
   assert h.hexdigest()==d['ordered_source_bytes_sha256'];offset+=len(seq)
   for e in d['records']:
    n=normalized(e,d['phase'])
    if n:events.append(n)
   for e in d.get('original_fixup_reads',[]):fixups.add(int(e.get('address',e.get('slot','0')),16))
   for e in d.get('image_writes',[]):
    if e['size']==8 and int(e['value'],16)==0x5300000000:image_pointer_stores.append(e)
   for e in d.get('stack_stores',[]):
    if e['size_bytes']==8 and e.get('actual_after_hex')==struct.pack('<Q',0x5300000000).hex():stack_pointer_stores.append(e)
  counts['reused_retained_source_visits']+=offset;counts['reused_fresh_source_visits']+=offset;counts['retained_fresh_worker_pairs']+=1
  last=-1;heap={};maps={};fds={};sequence=[]
  for e in events:
   a=int(e['site'],16);choices=positions[a];j=bisect.bisect_right(choices,last);assert j<len(choices),(e,last);last=choices[j];e['source_visit_index']=last;used.add(a);ins=next(CS.disasm(IMAGE.read(a,4),a));assert ins.mnemonic in['bl','blr','blraa','blrab','blraaz'];name=e['name'];sequence.append(e)
   if name in['libSystem/_malloc','libSystem/_malloc_type_malloc']:
    ptr=e['pointer'];assert ptr and ptr not in heap;heap[ptr]={'pointer':ptr,'extent_bytes':e['extent_bytes'],'allocation_site':e['site'],'phase':e['phase'],'retired':False};counts['allocations']+=1
   elif name=='libSystem/_free':
    ptr=e['pointer'];assert ptr in heap and not heap[ptr]['retired'];heap[ptr].update(retired=True,free_site=e['site']);counts['frees']+=1
   elif name=='libSystem/_mmap':
    ptr=e['pointer'];assert ptr not in maps;maps[ptr]={'pointer':ptr,'extent_bytes':e['extent_bytes'],'retired':False,'unmap_requests':[]};counts['mappings']+=1
   elif name=='libSystem/_munmap':
    owner=maps[e['pointer']];assert not owner['retired']and owner['extent_bytes']==e['extent_bytes'];owner['unmap_requests'].append(e['result']);owner['retired']=e['result']==0;counts['unmap_requests']+=1
   elif name=='libSystem/_open':
    fd=e['descriptor'];assert fd>=0 and fd not in fds;fds[fd]={'path_hex':e['path_hex'],'closed':False,'close_requests':[]};counts['open_requests']+=1
   elif name=='libSystem/_close':
    owner=fds[e['descriptor']];assert not owner['closed'];owner['close_requests'].append(e['result']);owner['closed']=e['result']==0;counts['close_requests']+=1
  imported=[(e['site'],reverse[int(e['target'],16)])for e in r['pac_bypasses']if'target'in e and reverse.get(int(e['target'],16))in RESOURCE];assert imported==[(e['site'],e['name'])for e in sequence];counts['resource_import_edges']+=len(imported)
  snapshots={e['address']:e for e in r['owner_snapshots']};allocations={e['address']:e for e in r['private_heap_allocations']}
  assert len(heap)==16 and len(maps)==len(fds)==2
  for ptr,e in heap.items():
   assert snapshots[ptr]['size_bytes']==e['extent_bytes']and snapshots[ptr]['retired']==e['retired']
   if ptr in allocations:assert allocations[ptr]['size_bytes']==e['extent_bytes']and allocations[ptr]['allocation_pc']==e['allocation_site']
  for ptr,e in maps.items():
   v=r['declared_mapping_owners'][ptr];assert v['size_bytes']==e['extent_bytes']and v['retired']==e['retired']and v['unmap_requests']==e['unmap_requests']
  for fd,e in fds.items():
   v=r['declared_FD_owners'][str(fd)];assert v['close_requests']==e['close_requests']and v['declared_closed']==e['closed']
  startup={e['address']for e in r['startup_snapshot']['heap_owners']};assert len(startup)==8 and startup=={k for k,v in heap.items()if v['phase']=='startup'}
  live=[v for v in heap.values()if not v['retired']];assert len(live)==10 and sum(e['extent_bytes']for e in live)==92319
  freed=[v for v in heap.values()if v['retired']];assert len(freed)==6 and sum(e['extent_bytes']for e in freed)==2272
  assert maps['0x5100000000']['retired']and not maps['0x5300000000']['retired']and all(v['closed']for v in fds.values())
  records=[e for e in r['supplemental_points']if e['pc']=='0x1008b5170'];assert len(records)==1;mr=bytes.fromhex(records[0]['mapping_record_hex']);assert struct.unpack_from('<I',mr)[0]==8 and struct.unpack_from('<Q',mr,8)[0]==0x5300000000
  output_order=[positions[a]for a in[0x100023a94,0x100023a9c,0x100023aa8,0x100023ab0,0x100023ad4]];assert all(len(v)==1 for v in output_order)and [v[0]for v in output_order]==sorted(v[0]for v in output_order)
  summaries.append({'case_label':old['case']['label'],'source_visits':offset,'worker_status_u32':hex(ERROR),'events':sequence,'heap':list(heap.values()),'maps':maps,'descriptors':fds,'supplemental_mapping_record_hex':mr.hex(),'direct_image_pointer_stores':image_pointer_stores,'direct_stack_pointer_stores':stack_pointer_stores,'output_store_and_status_visit_indices':[v[0]for v in output_order],'ownership_escape_analysis_complete':False})
  print('LEDGER',old['case']['label'],len(sequence),offset,flush=True)
 replay=[]
 for case in delivery['cases']:
  v=case['fixture'];q=ErrorDelivery(v['disposition'],v['remote'],int(v['send_result_u32'],16));fresh=q.execute();assert fresh==case;replay.append(fresh);counts['fresh_callback_runs']+=1;counts['callback_source_visits']+=len(case['source_visits']);ev=case['events'];kinds=[e['kind']for e in ev]
  expected=['reply_allocate','abstract_application_return','destroy_request']
  if v['remote']:
   expected+=['send_request']
   if int(v['send_result_u32'],16)in[0x10000003,0x10000004]:expected+=['destroy_reply']
  expected+=['reply_free'];assert kinds==expected
  destroy=next(e for e in ev if e['kind']=='destroy_request');raw=bytes.fromhex(destroy['buffer_hex']);initial=bytearray.fromhex(case['initial_request_hex']);struct.pack_into('<I',initial,8,0);assert raw==initial==bytes.fromhex(case['final_request_hex'])
  assert destroy['source_site']=='0x10006ce90'and ev[-1]['source_site']=='0x1000bcb58'
  sent=[e for e in ev if e['kind']=='send_request'];counts['send_requests']+=len(sent);counts['request_destroy_requests']+=1;counts['reply_destroy_requests']+=kinds.count('destroy_reply')
  for e in sent:
   expected=struct.pack('<6I',v['disposition'],36,v['remote'],0,0,602)+bytes.fromhex('0000000001000000')+struct.pack('<I',ERROR);assert bytes.fromhex(e['wire_hex'])==expected and e['size_bytes']==36;assert e['args'][1]==hex(0x11 if v['disposition']==18 else 1)and e['args'][2]=='0x24'and all(x=='0x0'for x in e['args'][3:7]);assert e['source_site']=='0x100035184'
  for a in case['source_visits']:assert int(a,16)in pool
  for e in case['source_fixups']:
   a=int(e['address'],16);assert IMAGE.read(a,8).hex()==e['word_hex'];fixups.add(a)
 fixups.discard(0);original=[binding(a)if FIXUPS[a]['kind'].endswith('bind')else verify_original_fixups([a])['records'][0]for a in sorted(fixups)];counts['original_fixup_records']=len(original);counts['source_instructions']=len(pool);counts['resource_call_sites']=len(used)
 (ROOT/'rpc502_error_delivery_replays.json').write_text(json.dumps({'scope':'Eight distinct fresh guarded callback runs;application remains abstract.','generator_sha256':sha(Path(__file__)),'cases':replay,'native_target_executed':False},indent=2)+'\n')
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in sorted(deps)},'verified_counts':dict(counts),'case_summaries':summaries,'original_fixup_records':original,'resource_call_site_bytes':[{'address':hex(a),'bytes':IMAGE.read(a,4).hex()}for a in sorted(used)],'fresh_callback_replays_sha256':sha(ROOT/'rpc502_error_delivery_replays.json'),'new_worker_executions':0,'native_target_executed':False,'native_leak_established':False,'all_checks_pass':True,'full_goal_complete':False}
 (ROOT/'rpc502_ownership_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(dict(counts)),flush=True)
if __name__=='__main__':main()
