#!/usr/bin/env python3
"""Static constructor input/frame/control capture plus retained occurrences."""
import json,re,subprocess,capstone
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,CS,TABLE,block,selected,binding,sha,h,FLAGS
P='daemon_constructor_inputs'
SCOPE='Conditional constructor input snapshot, selected-phase extent guard, allocation/header-length join and span count/source provenance. Retained private occurrence supports source linkage; native phase, API/owner/admission/transport and full constructor return remain unproved.'
BLOCKS={'u32_root':0x100828290,'span_root':0x10069d718,'entry':0x100700d80,'guard':0x10083c564,
 'node_alloc':0x1006958b0,'record_alloc':0x100948a8c,'prepare':0x1008314ec,'key_setup':0x1008ecb78,
 'count_gate':0x1004c1dd4,'after_header':0x1004f4bc4,'span_class':0x1005e72c4,'span_header':0x10058ac54,'payload_setup':0x1005e58cc,
 'payload':0x100614278,'common_finish':0x1005ae7a0,'early_return':0x10076de60}
INDICES=[0x1ee,0x222,0x5eb2,0xabaa,0xab69,0xc1cd,0x79f1,0xa1cb,0xa1c8,0xc714,0xc766,0x54e5,0x6f0f,0x24aa,0x64ae,0x4cf4,0x4d18,0xb1df,0xb16e,0x18e2,0xcc0d]
def retained():
 out=[]
 for p in json.loads((ROOT/'arcade_subscription_profiles.json').read_text())['profiles']:
  if p['stop_reason']!='outgoing_arcade_xpc_message_boundary':continue
  assert p['source_sha256']==sha(SOURCE)and not p['native_target_executed']and not p['target_host_operations_executed']
  ev=p['pac_bypasses'];episodes=[]
  for j,e in enumerate(ev):
   if e.get('target')!='0x100700d80':continue
   seq=ev[j:j+8];assert len(seq)==8
   assert[(q['site'],q.get('target'))for q in seq if q['instruction']=='braa']==[(e['site'],'0x100700d80'),('0x100700dec','0x10083c564'),('0x10083c600','0x1006958b0'),('0x10069595c','0x100948a8c'),('0x100948c24','0x1008314ec'),('0x100831524','0x1008ecb78')]
   assert all(q['authentication']=='bypassed in private synthetic model'for q in seq)
   assert [q['site']for q in seq if q['instruction']=='blraa']==['0x100695928','0x100948bf8']
   episodes.append({'first_event_index':j,'events':seq})
  assert len(episodes)==5 and sum(e['events'][0]['site']=='0x1008282cc'for e in episodes)==3 and sum(e['events'][0]['site']=='0x10069d74c'for e in episodes)==2
  calls=[c for c in p['calls']if c['return_pc']in('0x10069592c','0x100948bfc')]
  assert [c['return_pc']for c in calls]==['0x10069592c','0x100948bfc']*5
  assert all(c['name']=='libSystem/_malloc'for c in calls)
  pairs=[]
  for a,b in zip(calls[::2],calls[1::2]):
   assert int(a['args'][0],16)==32;extent=int(b['args'][0],16)
   pairs.append({'node':a['result'],'node_extent_bytes':32,'record_buffer':b['result'],'record_extent_bytes':extent,'derived_payload_extent_bytes':extent-10,'payload_extent_is_derived_not_register_snapshot':True})
  out.append({'label':p['label'],'constructor_episodes':episodes,'allocation_pairs':pairs,'native_evidence':False})
 assert len(out)==12;return out
def build():
 fs={}
 for n,a in BLOCKS.items():
  f=block(a,0x4000);assert f['instructions'][-1]['mnemonic']=='braa';f['sha256']=h(bytes.fromhex(f['bytes']));fs[n]=f
 dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True;writes={}
 for n,f in fs.items():
  rr=set()
  for i in dc.disasm(bytes.fromhex(f['bytes']),int(f['start'],16)):rr.update(i.reg_name(r)for r in i.regs_access()[1])
  writes[n]=sorted(rr)
 assert not {'w21','x21','w19','x19'}&set(writes['entry'])and not {'w21','x21','w19','x19'}&set(writes['guard'])and not {'w21','x21','w19','x19'}&set(writes['node_alloc'])
 live=[]
 for a,z,regs,role in[(0x100948ba0,0x100948bdc,[8],'saved_count'),(0x100948ba0,0x100948bf8,[0],'buffer_allocation_argument')]:
  rr=set()
  for i in dc.disasm(IMAGE.read(a,z-a),a):rr.update(i.reg_name(r)for r in i.regs_access()[1])
  assert not {p+str(r)for r in regs for p in('x','w')}&rr
  live.append({'role':role,'start':hex(a),'end':hex(z),'preserved_register_numbers':regs,'written_registers':sorted(rr)})
 ptr=[]
 for ix in INDICES:
  a=TABLE+8*ix;ptr.append({'index':hex(ix),'slot':hex(a),'raw_bytes':IMAGE.read(a,8).hex(),'fixup':FIXUPS[a]})
 banks=[]
 for role,left,right,key,add,pc,slots in[('node',0x100fc4230,0x101031fa0,0xf3,0xcbca,0x100695928,['0x9b0','0x9a8']),('record',0x100fc4130,0x101031ea0,0xa3,0xcb9b,0x100948bf8,['0x5f0','0x960'])]:
  b=selected(left,right,key,add,TABLE,0);l,r=IMAGE.read(left,256),IMAGE.read(right,256);v=[i^r[l[i]^key]for i in range(256)]
  assert len(set(v))==1 and b['target']=='libSystem/_malloc'and b['slot']=='0x10109ff58'
  ii=list(CS.disasm(IMAGE.read(pc-4,8),pc-4));assert ii[0].op_str=='x17, #0x6aa4'and ii[1].mnemonic=='blraa'
  b.update(role=role,site=hex(pc),left_bytes=l.hex(),right_bytes=r.hex(),key_u8=key,additive_u32=add,results_256=v,frame_bank_pointer_slots=slots,modifier_u16=0x6aa4);banks.append(b)
 rec=[]
 for fn in['daemon_header_codec_source.json','daemon_payload_codec_source.json']:
  for n,f in json.loads((ROOT/fn).read_text())['fragments'].items():
   bb=bytes.fromhex(f['bytes']);assert IMAGE.read(int(f['start'],16),len(bb))==bb;rec.append({'file':fn,'fragment':n,'bytes_checked':len(bb),'sha256':h(bb)})
 cmd=['/usr/bin/dyld_info','-fixups',str(SOURCE)];r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0 and not r.stderr;fresh={}
 for line in r.stdout.splitlines():
  m=re.match(r'\s+\S+\s+\S+\s+(0x[0-9a-fA-F]+)\s+(\S+)\s+(\S+)(.*)',line)
  if m:fresh[int(m[1],16)]=line.strip()
 assert set(fresh)==set(FIXUPS)
 for row in ptr:assert fresh[int(row['slot'],16)]==row['fixup']['line']
 profiles=retained();deps=['daemon_header_codec_source.json','daemon_header_codec_checks.json','daemon_payload_codec_source.json','daemon_payload_codec_checks.json','arcade_subscription_profiles.json','validate_daemon_header_codec.py','validate_daemon_payload_codec.py','recover_daemon_xpc_core_bridge.py','daemon_receive_fixups.txt']
 return{'generator_sha256':sha(__file__),'static_scope':SCOPE,'daemon_path':str(SOURCE),'daemon_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in deps},'fragments':fs,'register_write_sets':writes,'liveness_intervals':live,'pointer_records':ptr,'allocation_banks':banks,'malloc_binding':binding(0x10109ff58),'prior_recaptures':rec,'retained_profiles':profiles,
  'fixup_reference':{'command':cmd,'tool_sha256':sha(cmd[0]),'stdout_sha256':h(r.stdout.encode()),'catalog_memberships_compared':len(fresh)},
  'verified_source_counts':{'fragments':len(fs),'instructions':sum(len(f['instructions'])for f in fs.values()),'fragment_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'pointer_records':len(ptr),'bank_inputs_checked':512,'prior_ranges':len(rec),'prior_bytes':sum(r['bytes_checked']for r in rec),'retained_profiles':12,'constructor_episodes':60,'allocation_pairs':60,'u32_root_occurrences':36,'span_root_occurrences':24},**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
