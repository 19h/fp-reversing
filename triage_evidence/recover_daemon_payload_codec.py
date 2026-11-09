#!/usr/bin/env python3
"""Original producer/consumer byte-codec and frozen-buffer evidence.
Static extraction only; no legacy probes, target execution or host IPC.
"""
import json,re,subprocess,capstone
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,CS,TABLE,block,binding,sha,h,FLAGS
P='daemon_payload_codec'
SCOPE='Conditional address-indexed record-payload byte encoding/decoding, seven common rotate/add/XOR rounds, source node layout/list append and retained private Arcade encoded-buffer-to-XPC comparison. No native pairing, PAC, ownership, phase-production or full constructor proof.'
BLOCKS={'key_setup':0x1008ecb78,'header_u32':0x100546c90,'after_header':0x100617400,'header_tag':0x1007b28a4,
 'after_tag':0x1005979d4,'header_return':0x100615004,'after_payload_header':0x10047cd38,'constructor_return':0x1004f4bc4,
 'span_class':0x1005e72c4,'span_header':0x10058ac54,'count_gate':0x1004c1dd4,'payload_setup':0x1005e58cc,
 'payload':0x100614278,'node_alloc':0x1006958b0,'record_alloc':0x100948a8c,'append':0x10069a4a0,'append_gate':0x1006f0208,'append_empty':0x1004def68,'serializer_byte':0x1009c3d34}
CHAIN=['key_setup','header_u32','after_header','header_tag','after_tag','header_return','header_u32','after_payload_header','constructor_return','span_class','span_header','count_gate','payload_setup']
KEYS=[0x324a764c67af2e0e,0xe70987b7a1f527b0,0x9032dc5079388982,0x144db9b1af6b5721,0xeb8e58819a88bf30,0x7faaf81a732f68b4,0x4f99108510ad96e0]
MASK=(1<<64)-1
def ror(x,n):return((x>>n)|(x<<(64-n)))&MASK
def byte_mask(a):
 """Recovered scalar formula, not a CPU/guest runner. All word ops modulo64."""
 a&=MASK;r=ror(a&~7,8);q=(r-(((2*r+0x4458ba66c9cbab3e)&MASK)&0x64b05f970e467982)+0x98848cfeec091260)&MASK
 x=q^0x91e690049073ef48;y=q^0x8084799fb75d43b3
 for k in KEYS:x=((ror(x,8)+y)&MASK)^k;y=ror(y,61)^x
 return(x>>(8*(a&7)))&255
def profile_summaries():
 old=json.loads((ROOT/'arcade_subscription_profiles.json').read_text());rows=[]
 for p in old['profiles']:
  if p['stop_reason']!='outgoing_arcade_xpc_message_boundary':continue
  assert p['source_sha256']==sha(SOURCE)and not p['native_target_executed']and not p['target_host_operations_executed']
  packet=bytes.fromhex(next(c['value']['bytes']for c in p['calls']if c['return_pc']=='0x10077e5c8'))
  records=p['records'];final_buffer=[c['result']for c in p['calls']if c['return_pc']=='0x1006c3190'][-1]
  output_writes=[j for j,r in enumerate(records)if r['kind']=='native_heap_write'and r['allocation']==final_buffer];assert output_writes
  frees=[c for c in p['calls']if c['return_pc']=='0x1007cf704'];assert len(frees)==2;decoded=[]
  for c in frees:
   ptr=int(c['args'][0],16);b=bytes.fromhex(c['allocation_bytes_at_free']);known=bytes.fromhex(c['known_byte_mask'])
   assert len(b)==c['extent_bytes']==len(known) and set(known)=={1}
   clear=bytes(v^byte_mask(ptr+i)for i,v in enumerate(b))
   ww=[j for j,r in enumerate(records)if r['kind']=='native_heap_write'and r['allocation']==hex(ptr)]
   ff=[j for j,r in enumerate(records)if r.get('return_pc')==c['return_pc']and r.get('args',[None])[0]==hex(ptr)]
   assert len(ff)==1 and max(ww)<min(output_writes)<=max(output_writes)<ff[0]
   decoded.append({'pointer':hex(ptr),'extent_bytes':len(b),'encoded_hex':b.hex(),'encoded_sha256':h(b),'known_byte_mask':known.hex(),'decoded_hex':clear.hex(),'decoded_sha256':h(clear),'free_return_pc':c['return_pc'],'first_write_record_index':min(ww),'last_write_record_index':max(ww),'final_output_first_write_record_index':min(output_writes),'final_output_last_write_record_index':max(output_writes),'retirement_record_index':ff[0]})
  assert decoded[0]['extent_bytes']==14 and bytes.fromhex(decoded[0]['decoded_hex'])==packet[:14]
  body=bytes.fromhex(decoded[0]['decoded_hex']+decoded[1]['decoded_hex']);assert packet==body+bytes.fromhex('0000000050db0000000e')+bytes(14)
  indices={id(r):j for j,r in enumerate(p['records'])}
  writes=[r for r in p['records']if r['kind']=='native_heap_write'and r['pc']=='0x1006143d8']
  by={}
  for w in writes:by.setdefault(w['allocation'],[]).append(w)
  assert len(by)==2
  spans=[]
  for ptr,ww in by.items():
   n=len(ww);assert all(w['size_bytes']==1 for w in ww)and[w['offset_bytes']for w in ww]==list(range(n+9,9,-1))
   alloc=next(a for a in p['private_allocations']if a['address']==ptr);assert alloc['extent_bytes']==n+10
   spans.append({'buffer':ptr,'payload_extent_bytes':n,'allocation_extent_bytes':n+10,'store_count':n,'first_offset_bytes':n+9,'last_offset_bytes':10,'record_indices':[indices[id(w)]for w in ww]})
  events=p['pac_bypasses'];episodes=[]
  for j,e in enumerate(events):
   if e['site']!='0x1005e5a2c':continue
   assert e['target']=='0x100614278'and e['modifier']=='0x990a'
   k=max(k for k in range(j)if events[k].get('target')=='0x1008ecb78');seq=events[k:j+1]
   assert[ev['target']for ev in seq]==[hex(BLOCKS[n])for n in CHAIN]+['0x100614278']
   assert all(ev['authentication']=='bypassed in private synthetic model'and ev['instruction']=='braa'for ev in seq)
   episodes.append({'first_event_index':k,'entry_event_index':j,'events':seq})
  assert len(episodes)==2
  appends=[e for e in events if e['site']=='0x1006f0248'];assert [e['target']for e in appends].count('0x1004def68')==2 and[e['target']for e in appends].count('0x10069a4a0')==3
  node_allocs=[c for c in p['calls']if c['return_pc']=='0x10069592c'];buffer_allocs=[c for c in p['calls']if c['return_pc']=='0x100948bfc']
  assert len(node_allocs)==len(buffer_allocs)==5 and all(c['name']=='libSystem/_malloc'and int(c['args'][0],16)==32 for c in node_allocs)
  pairs=[]
  for node,buf in zip(node_allocs,buffer_allocs):
   effects=[r for r in records if r['kind']=='native_heap_write'and r['pc']=='0x100948bfc'and r['allocation']==node['result']]
   assert len(effects)==1 and effects[0]['offset_bytes']==24 and effects[0]['size_bytes']==8
   pairs.append({'node':node['result'],'buffer':buf['result'],'extent_bytes':int(buf['args'][0],16),'source_store_pc':'0x100948bfc','node_field_offset_bytes':24,'field_width_bytes':8,'basis':'modeled malloc X0 result and immediate return-PC STR X0; recorded destination address'})
  rows.append({'label':p['label'],'packet_sha256':h(packet),'packet_size_bytes':len(packet),'decoded_body_hex':body.hex(),'encoded_buffers_at_retirement':decoded,
   'producer_payload_write_spans':spans,'key_to_payload_episodes':episodes,'node_allocations':[{'pointer':c['result'],'size_bytes':int(c['args'][0],16)}for c in node_allocs],
   'record_allocations':[{'pointer':c['result'],'size_bytes':int(c['args'][0],16)}for c in buffer_allocs],'node_buffer_pairs':pairs,'append_events':appends,'native_evidence':False})
 assert len(rows)==12;return rows
def build():
 fragments={}
 for n,a in BLOCKS.items():
  f=block(a,0x4000);assert f['instructions'][-1]['mnemonic']=='braa';f['sha256']=h(bytes.fromhex(f['bytes']));fragments[n]=f
 dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True
 preservation=[]
 for n in set(CHAIN)-{'key_setup'}:
  f=fragments[n];ii=list(dc.disasm(bytes.fromhex(f['bytes']),int(f['start'],16)));writes=set();calls=[]
  for i in ii:
   writes.update(i.reg_name(r)for r in i.regs_access()[1])
   if i.mnemonic in('bl','blr','blraa','blrab'):calls.append(hex(i.address))
  assert not({'x8','w8','x10','w10'}&writes) and not calls,(n,writes,calls)
  preservation.append({'fragment':n,'written_registers':sorted(writes),'calls':calls,'preserves_X8_X10':True})
 preservation.sort(key=lambda r:r['fragment'])
 loop_writes=set()
 for i in dc.disasm(bytes.fromhex(fragments['payload']['bytes']),BLOCKS['payload']):loop_writes.update(i.reg_name(r)for r in i.regs_access()[1])
 loop_fixed=[4,5,6,7,8,9,10,11,12,13,19,20,21,22,23,24,25,26,27,28,30]
 assert not {p+str(r)for r in loop_fixed for p in('x','w')}&loop_writes
 targets={0x100614278,0x1005e58cc,0x1004c1dd4,0x10069a4a0,0x1004def68};pointers=[]
 for at,r in sorted(FIXUPS.items()):
  if r['target']in targets:pointers.append({'slot':hex(at),'index':hex((at-TABLE)//8),'raw_bytes':IMAGE.read(at,8).hex(),'fixup':r})
 assert len(pointers)==5
 for ix in[0xb16e]:
  at=TABLE+8*ix;pointers.append({'slot':hex(at),'index':hex(ix),'raw_bytes':IMAGE.read(at,8).hex(),'fixup':FIXUPS[at]})
 call_bind=binding(0x10109ff58);assert call_bind['symbol']=='_malloc'
 rec=[]
 for fn in ['daemon_list_output_source.json','daemon_record_stream_source.json']:
  for n,f in json.loads((ROOT/fn).read_text())['fragments'].items():
   b=bytes.fromhex(f['bytes']);assert IMAGE.read(int(f['start'],16),len(b))==b;rec.append({'file':fn,'fragment':n,'bytes_checked':len(b),'sha256':h(b)})
 cmd=['/usr/bin/dyld_info','-fixups',str(SOURCE)];out=subprocess.run(cmd,capture_output=True,text=True);assert out.returncode==0 and not out.stderr
 fresh={}
 for line in out.stdout.splitlines():
  m=re.match(r'\s+\S+\s+\S+\s+(0x[0-9a-fA-F]+)\s+(\S+)\s+(\S+)(.*)',line)
  if m:fresh[int(m[1],16)]=line.strip()
 assert set(fresh)==set(FIXUPS)
 for row in pointers:assert fresh[int(row['slot'],16)]==row['fixup']['line']
 assert fresh[0x10109ff58]==FIXUPS[0x10109ff58]['line']
 profiles=profile_summaries()
 deps=['daemon_list_output_source.json','daemon_record_stream_source.json','daemon_record_stream_checks.json','arcade_subscription_profiles.json','validate_daemon_list_output.py','recover_daemon_xpc_core_bridge.py','daemon_receive_fixups.txt','daemon_import_bindings.py']
 return {'generator_sha256':sha(__file__),'static_scope':SCOPE,'daemon_path':str(SOURCE),'daemon_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in deps},
  'fragments':fragments,'key_preservation':preservation,'producer_loop_preservation':{'unchanged_register_numbers':loop_fixed,'written_registers':sorted(loop_writes)},'selected_pointer_records':pointers,'malloc_binding':call_bind,'prior_recaptures':rec,'retained_profile_summaries':profiles,
  'round_keys':[hex(k)for k in KEYS],'fixup_reference':{'command':cmd,'tool_sha256':sha(cmd[0]),'stdout_sha256':h(out.stdout.encode()),'catalog_memberships_compared':len(fresh)},
  'verified_source_counts':{'fragments':len(fragments),'instructions':sum(len(f['instructions'])for f in fragments.values()),'fragment_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fragments.values()),'preserved_key_fragments':len(preservation),'pointer_records':len(pointers),'prior_ranges':len(rec),'prior_bytes':sum(r['bytes_checked']for r in rec),'retained_profiles':12,'key_to_payload_episodes':24,'decoded_retired_buffers':24,'payload_write_spans':24,'payload_stores':sum(s['store_count']for p in profiles for s in p['producer_payload_write_spans'])},**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
