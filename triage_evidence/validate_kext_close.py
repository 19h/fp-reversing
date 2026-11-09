#!/usr/bin/env python3
"""Fresh close-prefix replay, source epochs, record codecs and IDB readback.

O(B+V+E+S) source/journal work plus five timeout-bounded local proofs.
No native target/API, IDB mutation or successful finalization is established.
"""
import collections,hashlib,json,struct,subprocess
from pathlib import Path
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,bank,qword,TABLE
from probe_kext_close import Close,STACK,WARM
from verify_interface_contracts import Image
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def tool_json(obj):
 text='\n'.join(e.get('text','')for e in obj['content']);return json.loads(text.split('[assist:tool-output]\n',1)[1].split('\n[/assist:tool-output]',1)[0])
def main():
 counts=collections.Counter();p=json.loads((ROOT/'kext_close_profiles.json').read_text());c=json.loads((ROOT/'kext_close_contracts.json').read_text());deps={'probe_kext_close.py','recover_kext_close.py','kext_close_profiles.json','kext_close_contracts.json','kext_close_ida_availability.json','kext_close_daemon_readback.json','kext_port_tools.py'}
 for obj,producer in[(p,'probe_kext_close.py'),(c,'recover_kext_close.py')]:
  assert obj['generator_sha256']==sha(ROOT/producer)and obj['source_sha256']==sha(SOURCE)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h;deps.add(n)
 for e in c['source_ranges']:
  a=int(e['start'],16);z=int(e['end'],16);raw=IMAGE.read(a,z-a);assert raw.hex()==e['bytes']and hashlib.sha256(raw).hexdigest()==e['sha256'];assert e['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(raw,a)];counts['source_ranges']+=1
 for e in c['banks']:
  l=int(e['left'],16);r=int(e['right'],16);assert IMAGE.read(l,256).hex()==e['left256_hex']and IMAGE.read(r,256).hex()==e['right256_hex'];assert bank(l,r,int(e['key'],16))==int(e['constant'],16);slot=int(e['slot'],16);assert IMAGE.read(slot,8).hex()==e['original_slot_word_hex'];assert(qword(slot)+int(e['bias'],16))&((1<<64)-1)==int(e['target'],16);counts['banks_256']+=1
 assert qword(TABLE+0xc18*8)==int(c['null_registry_target'],16)==0xfffffe000a5b0ad0
 for e in c['proofs']:
  path=ROOT/e['path'];assert sha(path)==e['sha256'];r=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);assert r.stdout.strip()=='unsat'and not r.stderr;counts['proofs_unsat']+=1;deps.add(path.name)
 pool={}
 for e in p['source_instructions']:
  a=int(e['ea'],16);b=IMAGE.read(a,4);i=next(CS.disasm(b,a));assert b.hex()==e['bytes']and i.mnemonic==e['mnemonic']and i.op_str==e['operands'];pool[a]=b
 fresh=[];summaries=[]
 for r in p['cases']:
  q=Close(int(r['token_input_u64'],16),r['warm_flag']);actual=q.run();assert actual==r;fresh.append(actual);counts['fresh_runs']+=1;counts['fresh_source_visits']+=len(r['source_visits']);assert not r['native_target_executed']and not r['native_API_executed']and not r['idb_mutated'];assert all(int(a,16)in pool for a in r['source_visits'])
  if r['warm_flag']==0:
   assert r['stop_reason']=='external_call_boundary'and len(r['calls'])==1;event=r['events'][-1];assert event['target']=='0xfffffe000c4ba154'and event['arguments'][0]=='0xfffffe000847b460'and event['symbols'][0]['name']=='_IOMallocTypeImpl';counts['allocator_boundaries']+=1;continue
  assert r['stop_reason']=='wrapper_return'and r['events'][-1]['X0_return_u64']=='0xffff5b36'and not r['incomplete_call_indices'];assert '0xfffffe000a5c16d4'in r['source_visits'];assert '0xfffffe000a606728'not in r['source_visits'];counts['completed_flag1_prefixes']+=1
  assert len(r['calls'])==5 and all('return_source_visit_index'in e for e in r['calls']);counts['actual_call_return_pairs']+=5
  call=next(e for e in r['calls']if e['pc']=='0xfffffe000a5c0a48');assert call['target']=='0xfffffe000a5b07f4';ptr=int(call['registers31'][0],16);sp=int(call['SP'],16);assert ptr==sp+0xa8;raw=bytes.fromhex(call['X0_prefix32_hex']);K=((ptr&0xffffffff)^0x280834b2)*0xf87ec353&0xffffffff;t=int(r['token_input_u64'],16)&0xffffffff
  assert struct.unpack_from('<Q',raw)[0]==sp+0x70;assert(struct.unpack_from('<I',raw,8)[0]-K)&0xffffffff==0xc18;assert struct.unpack_from('<I',raw,16)[0]^K==(t+0x7a2abb13)&0xffffffff
  # Reconstruct only the source-defined input fields; observer padding excluded.
  selected=list(range(0,12))+list(range(16,20));epoch={}
  for e in r['source_writes']:
   if e['source_visit_index']>=call['source_visit_index']:continue
   a=int(e['address'],16);b=bytes.fromhex(e['after_hex']);assert len(b)==e['size_bytes']
   for j,v in enumerate(b):
    if ptr<=a+j<ptr+20:epoch[a+j-ptr]=(v,e['pc'])
  for off in selected:assert off in epoch and epoch[off][0]==raw[off];counts['source_defined_record_bytes']+=1
  during=[e for e in r['stack_reads']if call['source_visit_index']<e['source_visit_index']<call['return_source_visit_index']and ptr<=int(e['address'],16)<ptr+20];assert[(e['pc'],int(e['address'],16)-ptr,e['size_bytes'])for e in during]==[('0xfffffe000a5b08e0',8,4)];counts['record_operation_reads']+=1
  assert '0xfffffe000a5b09a8'not in r['source_visits'];after=bytes.fromhex(call['returned_prefix32_hex']);assert after[:12]==raw[:12]and after[13:]==raw[13:]and after[12]==0x22;writes=[e for e in r['source_writes']if call['source_visit_index']<e['source_visit_index']<call['return_source_visit_index']and int(e['address'],16)==ptr+12];assert len(writes)==1 and writes[0]['pc']=='0xfffffe000a5b0ad4'and writes[0]['after_hex']=='22';counts['defined_output_bytes']+=1
  registry=[e for e in r['declared_input_reads']if e['address']=='0xfffffe000cccca58'];assert len(registry)==1 and registry[0]['bytes_hex']=='0000000000000000';counts['null_registry_reads']+=1
  summaries.append({'token_input_u64':r['token_input_u64'],'record_pointer':hex(ptr),'input_field_offsets':selected,'decoded_dispatch_index':'0xc18','decoded_biased_token':hex((t+0x7a2abb13)&0xffffffff),'registry_pointer_model':'0x0','record_output_byte_at12':'0x22','wrapper_return_u64':'0xffff5b36','successful_token_processing':False})
 availability=json.loads((ROOT/'kext_close_ida_availability.json').read_text());facts=tool_json(availability['daemon_facts']);assert any(e['key']=='input_sha256'and e['value']=='4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7'for e in facts['rows']);assert availability['kext_facts_attempt']['status']=='fulfilled'and availability['kext_facts_attempt']['value']['isError']
 daemon=Image('/Users/___/Downloads/zut/fairplayd.arm64e');live=tool_json(json.loads((ROOT/'kext_close_daemon_readback.json').read_text()));assert live['count']==4
 for e in live['results']:assert e['size_read']==e['size_requested']==64 and daemon.read(int(e['address'],16),64).hex()==e['bytes'];counts['fresh_daemon_IDB_ranges']+=1;counts['fresh_daemon_IDB_bytes']+=64
 counts['source_instructions']=len(pool);(ROOT/'kext_close_replays.json').write_text(json.dumps({'scope':'Five distinct fresh private executions;no native API or complete initialized-world claim.','generator_sha256':sha(Path(__file__)),'cases':fresh,'native_target_executed':False},indent=2)+'\n')
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in sorted(deps)},'verified_counts':dict(counts),'case_summaries':summaries,'fresh_replays_sha256':sha(ROOT/'kext_close_replays.json'),'flag1_plus_null_registry_native_reachability':'unknown','tag85150332_wrapper_association':'unknown','native_target_executed':False,'complete_finalization_proved':False,'all_checks_pass':True,'full_goal_complete':False};(ROOT/'kext_close_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(dict(counts)),flush=True)
if __name__=='__main__':main()
