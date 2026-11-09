#!/usr/bin/env python3
"""Typed descriptor-array ABI, constructor roots and return-state source capture."""
import json,re,struct,subprocess
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,CS,TABLE,block,sha,h,FLAGS
from resolve_kernel_collection_interfaces import commands
from daemon_receive_tools import verify_original_fixups
P='daemon_constructor_callers'
SCOPE='Conditional 40 B descriptor-array entry/filter/type/value/counter/return contracts, u32/span/u64 and generic constructor roots, bounded modifier census and frozen private occurrence separation. Native owners, phases, endpoint identity/PAC and public status meanings remain unproved.'
BLOCKS={'entry':0x1008cadf0,'filter':0x100864934,'record':0x1009c4088,'kind_partition':0x100708898,'scalar_class':0x10089e028,'u32_kind':0x1009e175c,'u64_gate':0x100941ef4,'span_kind':0x10068fb08,'span_guard':0x1009123b4,'u32_params':0x1009d452c,'span_params':0x1009312bc,'u32_adapter':0x100752360,'span_adapter':0x100894dac,'u32_root':0x100828290,'span_root':0x10069d718,'u64_root':0x1006b74e8,'generic_root':0x10097b9b0,'u32_return':0x100781e0c,'span_return':0x1006d8264,'u32_status':0x10072d2cc,'span_status':0x100882c94,'u64_status':0x100712d84,'advance':0x10084dce0,'next':0x10082e028,'complete':0x100757d2c,'relay':0x100692834,'generic_status':0x10084d5d0,'generic_error':0x1008f045c,'caller_first':0x100703a30,'caller_second':0x1008f05f0,'outer_first':0x1009a9e00,'outer_second':0x10088f390}
INDICES=[0x25eb,0x845e,0xba95,0x5524,0x2c7c,0x2c4e,0xa2a0,0x316a,0x3428,0x3435,0x824e,0x825d,0x9750,0x556c,0x5570,0xa56e,0x9fdc,0x9fee,0x1be,0x148c,0x2a01,0x47f4,0x482e,0xa337,0xa34b,0x5eb2,0x222,0x1ee,0x22e,0x228,0x7c6a,0x2f82,0x1a25,0x8784,0x99,0x8b,0x8314,0x1c9,0x58aa,0x3ad1,0x18a5]

EDGES={'entry':[0xba95,0x845e],'filter':[0xa2a0,0x2c4e],'record':[0x316a],'kind_partition':[0x3428,0x3435],'scalar_class':[0x824e,0x825d],'u32_kind':[0x9750,0x556c],'u64_gate':[0x556c,0x5570],'span_kind':[0xa56e,0x2c7c],'span_guard':[0x9fee,0x9fdc],'u32_params':[0x18a5],'span_params':[0x2a01],'u32_adapter':[0x47f4,0x482e],'span_adapter':[0xa337,0xa34b],'u32_root':[0x5eb2],'span_root':[0x5eb2],'u64_root':[0x5eb2],'generic_root':[0x5eb2],'u32_return':[0x1be],'span_return':[0x148c],'u32_status':[0x2c4e,0x2c7c],'span_status':[0x2c4e,0x2c7c],'u64_status':[0x7c6a,0x556c],'advance':[0x845e],'next':[0x5524,0x2c7c],'complete':[0x2f82],'relay':[0x99,0x8b],'generic_status':[0x8784,0x1a25],'generic_error':[0x3ad1],'caller_first':[0x25eb],'caller_second':[0x25eb],'outer_first':[0x8314,0x1c9],'outer_second':[0x58aa,0x1c9]}

def census():
 for at,cmd,n in commands(IMAGE.data,0):
  if cmd!=0x19:continue
  for j in range(struct.unpack_from('<I',IMAGE.data,at+64)[0]):
   p=at+72+80*j
   if IMAGE.data[p:p+16].split(b'\0')[0]==b'__text':a,n=struct.unpack_from('<QQ',IMAGE.data,p+32);break
  else:continue
  break
 raw=IMAGE.read(a,n);pat=IMAGE.read(0x1008282c8,4);pos=0;rows=[]
 while True:
  pos=raw.find(pat,pos)
  if pos<0:break
  if pos%4==0:
   pc=a+pos;ii=list(CS.disasm(IMAGE.read(pc,8),pc))
   if len(ii)==2 and ii[1].mnemonic in('braa','blraa'):
    bb=IMAGE.read(pc-0x40,0x48);rows.append({'modifier_PC':hex(pc),'branch_PC':hex(pc+4),'start':hex(pc-0x40),'bytes':bb.hex(),'sha256':h(bb),'branch':{'ea':hex(pc+4),'mnemonic':ii[1].mnemonic,'operands':ii[1].op_str},'target_proved_by_modifier_alone':False})
  pos+=1
 assert len(rows)==8
 collisions=[{'slot':hex(a),'raw_bytes':IMAGE.read(a,8).hex(),'fixup':r}for a,r in FIXUPS.items()if'div=0x2C67 'in r['annotation']];assert len(collisions)==8
 return{'text_start':hex(a),'text_bytes':n,'text_sha256':h(raw),'pattern_hex':pat.hex(),'scope':'Aligned literal MOV X17,#2c67 immediately followed by BRAA/BLRAA in original __text only; computed modifiers/other forms and semantic caller completeness excluded.','candidates':rows,'original_modifier_collisions':collisions}

def retained():
 out=[];names=['entry','filter','record','kind_partition','scalar_class','u32_kind','u64_gate','span_kind','span_guard','u32_params','span_params','u32_adapter','span_adapter','u32_root','span_root','u64_root','generic_root','u32_return','span_return','u32_status','span_status','u64_status','advance','next','complete','relay']
 expected=[2,4,2,2,1,1,0,1,1,1,1,3,2,3,2,0,0,3,2,1,1,0,4,6,2,2]
 for p in json.loads((ROOT/'arcade_subscription_profiles.json').read_text())['profiles']:
  if p['stop_reason']!='outgoing_arcade_xpc_message_boundary':continue
  assert p['source_sha256']==sha(SOURCE)and not p['native_target_executed']and not p['target_host_operations_executed'];ev=p['pac_bypasses'];counts={n:sum(e.get('target')==hex(BLOCKS[n])for e in ev)for n in names};assert counts==dict(zip(names,expected)),(p['label'],counts)
  assert sum(e.get('target')=='0x100700d80'for e in ev)==5
  starts=[j for j,e in enumerate(ev)if e.get('target')==hex(BLOCKS['entry'])];episodes=[]
  for j in starts:
   z=next(k for k in range(j+1,len(ev))if ev[k]['site']=='0x100692838');seq=ev[j:z+1];assert all(e['authentication']=='bypassed in private synthetic model'for e in seq);episodes.append({'first_event_index':j,'last_event_index':z,'events':seq,'filters':sum(e.get('target')==hex(BLOCKS['filter'])for e in seq),'selected_record_dispatches':sum(e.get('target')==hex(BLOCKS['record'])for e in seq),'constructor_entries':sum(e.get('target')=='0x100700d80'for e in seq),'outer_return_target':seq[-1]['target']})
  assert len(episodes)==2 and[e['filters']for e in episodes]==[2,2]and[e['selected_record_dispatches']for e in episodes]==[2,0]and[e['constructor_entries']for e in episodes]==[2,0]
  assert[e['outer_return_target']for e in episodes]==['0x1009a9e00','0x10088f390']
  out.append({'label':p['label'],'counts':counts,'array_episodes':episodes,'total_constructor_entries':5,'array_constructor_entries':2,'other_constructor_entries':3,'native_evidence':False})
 assert len(out)==12;return out

def build():
 fs={}
 for n,a in BLOCKS.items():
  f=block(a,0x4000);assert f['instructions'][-1]['mnemonic']=='braa';f['sha256']=h(bytes.fromhex(f['bytes']));fs[n]=f
 edges=[]
 for n,indices in EDGES.items():
  ii=fs[n]['instructions'];assert ii[-2]['mnemonic']=='mov'and ii[-2]['operands'].startswith('x17, #');mod=int(ii[-2]['operands'].split('#')[1],0);targets=[]
  for ix in indices:
   at=TABLE+8*ix;word=int.from_bytes(IMAGE.read(at,8),'little');assert word>>63 and((word>>32)&65535)==mod and not((word>>48)&7);targets.append({'index':hex(ix),'slot':hex(at),'target':hex(FIXUPS[at]['target'])})
  edges.append({'fragment':n,'branch_site':ii[-1]['ea'],'source_modifier_u16':mod,'selected_slots':targets,'scope':'Selected source-phase cases; return relay entries are specific array caller examples, not all possible caller continuations.'})
 cc=census();slots={TABLE+8*ix for ix in INDICES}|{int(r['slot'],16)for r in cc['original_modifier_collisions']};ptr=[{'slot':hex(a),'index':hex((a-TABLE)//8),'raw_bytes':IMAGE.read(a,8).hex(),'fixup':FIXUPS[a]}for a in sorted(slots)]
 rec=[]
 for fn in ['daemon_constructor_inputs_source.json','daemon_typed_scalar_source.json','daemon_constructor_failure_source.json']:
  for n,f in json.loads((ROOT/fn).read_text())['fragments'].items():
   bb=bytes.fromhex(f['bytes']);assert IMAGE.read(int(f['start'],16),len(bb))==bb;rec.append({'file':fn,'fragment':n,'bytes_checked':len(bb),'sha256':h(bb)})
 profiles=retained();cmd=['/usr/bin/dyld_info','-fixups',str(SOURCE)];r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0 and not r.stderr;fresh={}
 for line in r.stdout.splitlines():
  m=re.match(r'\s+\S+\s+\S+\s+(0x[0-9a-fA-F]+)\s+(\S+)\s+(\S+)(.*)',line)
  if m:fresh[int(m[1],16)]=line.strip()
 assert set(fresh)==set(FIXUPS)
 for row in ptr:assert fresh[int(row['slot'],16)]==row['fixup']['line']
 deps=['daemon_constructor_inputs_source.json','daemon_constructor_inputs_checks.json','daemon_typed_scalar_source.json','daemon_typed_scalar_checks.json','daemon_constructor_failure_source.json','daemon_constructor_failure_checks.json','arcade_subscription_profiles.json','daemon_rpc502_probe.py','probe_arcade_subscription.py','recover_daemon_xpc_core_bridge.py','daemon_receive_fixups.txt']
 return{'generator_sha256':sha(__file__),'static_scope':SCOPE,'daemon_path':str(SOURCE),'daemon_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in deps},'fragments':fs,'branch_edges':edges,'original_fixup_checks':verify_original_fixups(slots),'pointer_records':ptr,'modifier_census':cc,'prior_recaptures':rec,'retained_profiles':profiles,'fixup_reference':{'command':cmd,'tool_sha256':sha(cmd[0]),'stdout_sha256':h(r.stdout.encode()),'catalog_memberships_compared':len(fresh)},'verified_source_counts':{'fragments':len(fs),'instructions':sum(len(f['instructions'])for f in fs.values()),'fragment_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'pointer_records':len(ptr),'branch_edges':len(edges),'branch_slot_modifiers_checked':sum(len(e['selected_slots'])for e in edges),'modifier_candidates':8,'modifier_collision_targets':8,'retained_profiles':12,'array_episodes':24,'array_record_filters':48,'array_selected_constructors':24,'other_constructor_entries':36,'u64_root_observations':0,'generic_root_observations':0,'prior_ranges':len(rec),'prior_bytes':sum(r['bytes_checked']for r in rec)},**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
