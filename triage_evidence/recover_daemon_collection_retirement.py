#!/usr/bin/env python3
"""Static collection retirement, caller status/output joins and frozen lifetimes."""
import json,re,subprocess,capstone
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,CS,TABLE,block,selected,binding,sha,h,FLAGS
from daemon_receive_tools import verify_original_fixups
P='daemon_collection_retirement'
SCOPE='Conditional collection/node/buffer retirement, two-child wrapper disposal and nil-output/u32-status joins, with separate frozen successful-finish and temporary-collection drain evidence. Native owner graphs, allocator/PAC behavior and daemon-kext endpoint pairing remain unknown.'
BLOCKS={'outer_finish':0x10090a400,'outer_dispose':0x10097a0c4,'outer_cell':0x1007322cc,'outer_value':0x1007778f4,'nested_entry':0x10083dd58,'nested_return':0x1004c61ec,'second_entry':0x10058bca4,'outer_free':0x10058081c,'outer_clear':0x100543b94,'outer_marker':0x1004ee734,'outer_class':0x100708ef8,'outer_low':0x10075a47c,'outer_exact':0x100706894,'outer_nil':0x10078cd00,'outer_output':0x100966d9c,'outer_return':0x100755bc0,'drain_setup':0x1006e3d4c,'drain_entry':0x1005134ec,'drain_container':0x1005b611c,'drain_head':0x1005cbf14,'drain_node':0x1005250f4,'drain_buffer':0x1007cf698,'drain_free_node':0x1005faf58,'drain_free_container':0x1004d7534,'drain_return':0x1004bd39c,'generic_error':0x1008f045c,'generic_after':0x1005271b0,'generic_output':0x100758ae8,'generic_return':0x1008c8b80,'observed_caller':0x100902518,'observed_after':0x10081bf90}
EDGES={'outer_finish':[0x7863,0x785b],'outer_dispose':[0x1fbb],'outer_cell':[0x5086,0x5096],'outer_value':[0x6e4a,0x6e42],'nested_entry':[0x3ad1],'nested_return':[0x614b],'second_entry':[0x8f82],'outer_free':[0x7b04,0x7b10],'outer_clear':[0x310f],'outer_marker':[0xaee2],'outer_class':[0x542a,0x5452],'outer_low':[0x48bf,0x486e],'outer_exact':[0x8693,0x6924],'outer_nil':[0x61be],'outer_output':[0x6f33],'outer_return':[],'drain_setup':[0x8f82],'drain_entry':[0xbdb4,0xbdb7],'drain_container':[0xb545,0xb57d],'drain_head':[0x645c,0x6452],'drain_node':[0x6e20,0x6e13],'drain_buffer':[0x6e13],'drain_free_node':[0x645c,0x6452],'drain_free_container':[0xb57d],'drain_return':[0xb9e,0xb68,0xb9f,0xb70],'generic_error':[0x3ad1],'generic_after':[0x3b30],'generic_output':[0x188e],'generic_return':[],'observed_caller':[0x3ad1],'observed_after':[0xc701,0xc74e]}
CALLS=[('buffer',0x1007cf700,0x100fc4230,0x101031fa0,0xe4,0xcbab,0x9b0,0x9a8),('node',0x1005fafc4,0x101031da0,0x100e99900,0x9a,0xcb23,0x5f0,0x5e0),('container',0x1004d7588,0x100fc4230,0x101031fa0,0xf3,0xcbc5,0x9b0,0x9a8),('outer_object',0x100580884,0x100fc4130,0x101031ea0,0xbb,0xcb4d,0x968,0x960)]

def retained():
 out=[]
 for p in json.loads((ROOT/'arcade_subscription_profiles.json').read_text())['profiles']:
  if p['stop_reason']!='outgoing_arcade_xpc_message_boundary':continue
  assert p['source_sha256']==sha(SOURCE)and not p['native_target_executed']and not p['target_host_operations_executed'];ev=p['pac_bypasses'];counts={n:sum(e.get('target')==hex(a)for e in ev)for n,a in BLOCKS.items()}
  j=next(j for j,e in enumerate(ev)if e.get('target')==hex(BLOCKS['drain_setup']));z=next(k for k in range(j+1,len(ev))if ev[k]['site']=='0x1004bd3a0');seq=ev[j:z+1]
  assert seq[0]['site']=='0x100902548'and seq[-1]['target']=='0x10081bf90'and all(e['authentication']=='bypassed in private synthetic model'for e in seq)
  fs=[c for c in p['calls']if c.get('name')=='libSystem/_free'and c.get('return_pc')in[hex(t[1]+4)for t in CALLS]]
  assert[c['return_pc']for c in fs]==['0x1007cf704','0x1005fafc8','0x1007cf704','0x1005fafc8','0x1004d758c']
  alloc={c['result']:c for c in p['calls']if c.get('name')=='libSystem/_malloc'};rows=[];ordinals={c['result']:j+1 for ret in ['0x10069592c','0x100948bfc']for j,c in enumerate(c for c in p['calls']if c.get('return_pc')==ret)}
  for f in fs:
   a=alloc[f['args'][0]];assert f['extent_bytes']==a['extent_bytes'];rows.append({'pointer':f['args'][0],'free_return_pc':f['return_pc'],'allocator_return_pc':a['return_pc'],'constructor_allocation_ordinal':ordinals.get(f['args'][0]),'extent_bytes':f['extent_bytes'],'known_byte_mask':f['known_byte_mask'],'bytes_at_free':f['allocation_bytes_at_free'],'model':f['model']})
  assert[rows[k]['extent_bytes']for k in [0,1,3,4]]==[14,32,32,16]and rows[2]['extent_bytes']>=10
  assert[r['constructor_allocation_ordinal']for r in rows]==[4,4,5,5,None]and rows[4]['allocator_return_pc']=='0x10069985c'
  nodes=[rows[1],rows[3]];container=rows[4]
  for k,n in enumerate(nodes):
   b=bytes.fromhex(n['bytes_at_free']);mask=bytes.fromhex(n['known_byte_mask']);assert mask[:20]==b'\1'*20 and mask[20:24]==b'\0'*4 and mask[24:32]==b'\1'*8
   assert int.from_bytes(b[:8],'little')==(int(nodes[1]['pointer'],16)if k==0 else 0)and int.from_bytes(b[8:16],'little')==(0 if k==0 else int(nodes[0]['pointer'],16))and b[24:32]==b'\0'*8
  b=bytes.fromhex(container['bytes_at_free']);assert bytes.fromhex(container['known_byte_mask'])==b'\1'*16 and int.from_bytes(b[:8],'little')==int(nodes[0]['pointer'],16)and int.from_bytes(b[8:16],'little')==int(nodes[1]['pointer'],16)
  assert counts['outer_finish']==counts['outer_output']==counts['outer_return']==1 and counts['outer_dispose']==counts['generic_error']==counts['generic_after']==counts['outer_free']==0
  fin=next(e for e in ev if e['site']=='0x10090a464');assert fin['target']=='0x100966d9c'
  out.append({'label':p['label'],'counts':counts,'drain_episode':{'first_event_index':j,'last_event_index':z,'events':seq,'caller':'0x100902518','return':'0x10081bf90'},'private_free_calls':rows,'private_retired_bytes':sum(r['extent_bytes']for r in rows),'outer_finish_success_target':fin['target'],'native_evidence':False})
 assert len(out)==12;return out

def build():
 fs={}
 for n,a in BLOCKS.items():
  f=block(a,0x4000);assert f['instructions'][-1]['mnemonic']=='braa';f['sha256']=h(bytes.fromhex(f['bytes']));fs[n]=f
 edges=[];indices={0xcc08}
 for n,ixs in EDGES.items():
  ii=fs[n]['instructions'];assert ii[-2]['mnemonic']=='mov'and ii[-2]['operands'].startswith('x17, #');mod=int(ii[-2]['operands'].split('#')[1],0);slots=[]
  for ix in ixs:
   a=TABLE+8*ix;w=int.from_bytes(IMAGE.read(a,8),'little');assert w>>63 and((w>>32)&65535)==mod and not((w>>48)&7),(n,hex(ix),hex(w),hex(mod));slots.append({'index':hex(ix),'slot':hex(a),'target':hex(FIXUPS[a]['target'])});indices.add(ix)
  edges.append({'fragment':n,'branch_site':ii[-1]['ea'],'modifier_u16':mod,'selected_slots':slots,'scope':'Selected compatible source phases and four drain return examples; symbolic saved outer returns are not assigned fixed destinations.'})
 banks=[]
 for role,pc,l,r,key,add,lf,rf in CALLS:
  b=selected(l,r,key,add,TABLE,0);lb,rb=IMAGE.read(l,256),IMAGE.read(r,256);vv=[i^rb[lb[i]^key]for i in range(256)];assert len(set(vv))==1 and b['target']=='libSystem/_free'and b['slot']=='0x10109ff30'
  ins=list(CS.disasm(IMAGE.read(pc-4,8),pc-4));assert ins[0].op_str=='x17, #0x46a2'and ins[1].mnemonic=='blraa'
  b.update(role=role,call_site=hex(pc),left_bytes=lb.hex(),right_bytes=rb.hex(),key_u8=key,additive_u32=add,results_256=vv,left_frame_slot=hex(lf),right_frame_slot=hex(rf),modifier_u16=0x46a2);banks.append(b)
 ptr=[{'index':hex(ix),'slot':hex(TABLE+8*ix),'raw_bytes':IMAGE.read(TABLE+8*ix,8).hex(),'fixup':FIXUPS[TABLE+8*ix]}for ix in sorted(indices)]
 rec=[]
 for fn in ['daemon_constructor_callers_source.json','daemon_constructor_failure_source.json']:
  for n,f in json.loads((ROOT/fn).read_text())['fragments'].items():
   bb=bytes.fromhex(f['bytes']);assert IMAGE.read(int(f['start'],16),len(bb))==bb;rec.append({'file':fn,'fragment':n,'bytes_checked':len(bb),'sha256':h(bb)})
 dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True;live=[]
 for n,a,z,regs in [('drain_buffer',0x1007cf698,0x1007cf700,[19,20,21,22,25,26,27]),('drain_free_node',0x1005faf58,0x1005fafc4,[19,20,21,22,25,27,28]),('drain_free_container',0x1004d7534,0x1004d7588,[19,20,22,24,27])]:
  rr=set()
  for i in dc.disasm(IMAGE.read(a,z-a),a):rr.update(i.reg_name(r)for r in i.regs_access()[1])
  assert not{p+str(j)for j in regs for p in('x','w')}&rr;live.append({'fragment':n,'start':hex(a),'end':hex(z),'preserved_registers':regs,'written_registers':sorted(rr)})
 pp=retained();cmd=['/usr/bin/dyld_info','-fixups',str(SOURCE)];r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0 and not r.stderr;fresh={}
 for line in r.stdout.splitlines():
  m=re.match(r'\s+\S+\s+\S+\s+(0x[0-9a-fA-F]+)\s+(\S+)\s+(\S+)(.*)',line)
  if m:fresh[int(m[1],16)]=line.strip()
 assert set(fresh)==set(FIXUPS)
 for row in ptr:assert fresh[int(row['slot'],16)]==row['fixup']['line']
 deps=['daemon_constructor_callers_source.json','daemon_constructor_callers_checks.json','daemon_constructor_failure_source.json','daemon_constructor_failure_checks.json','daemon_constructor_bank_origins_source.json','arcade_subscription_profiles.json','recover_daemon_xpc_core_bridge.py','daemon_receive_fixups.txt']
 return{'generator_sha256':sha(__file__),'static_scope':SCOPE,'daemon_path':str(SOURCE),'daemon_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in deps},'fragments':fs,'branch_edges':edges,'pointer_records':ptr,'original_fixup_checks':verify_original_fixups({int(r['slot'],16)for r in ptr}),'retirement_banks':banks,'free_binding':binding(0x10109ff30),'liveness_intervals':live,'retained_profiles':pp,'prior_recaptures':rec,'fixup_reference':{'command':cmd,'tool_sha256':sha(cmd[0]),'stdout_sha256':h(r.stdout.encode()),'catalog_memberships_compared':len(fresh)},'verified_source_counts':{'fragments':len(fs),'instructions':sum(len(f['instructions'])for f in fs.values()),'fragment_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'pointer_records':len(ptr),'branch_edges':len(edges),'branch_slot_modifiers_checked':sum(len(e['selected_slots'])for e in edges),'bank_inputs_checked':1024,'liveness_intervals':len(live),'retained_profiles':len(pp),'frozen_drain_episodes':12,'frozen_retired_nodes':24,'frozen_retired_buffers':24,'frozen_retired_containers':12,'frozen_private_retired_bytes':sum(p['private_retired_bytes']for p in pp),'frozen_outer_cleanup_entries':0,'frozen_generic_error_entries':0,'prior_ranges':len(rec),'prior_bytes':sum(r['bytes_checked']for r in rec)},**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
