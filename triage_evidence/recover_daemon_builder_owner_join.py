#!/usr/bin/env python3
"""Static builder allocation/child ownership, pointer-epoch join and prose erratum."""
import json,re,struct,subprocess
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,CS,TABLE,block,selected,binding,sha,h,FLAGS
from daemon_receive_tools import verify_original_fixups
from resolve_kernel_collection_interfaces import commands
P='daemon_builder_owner_join'
SCOPE='Selected 128 B builder and two16 B collection producers, descriptor qualifier/owner joins, actual X8 pointer-cell epoch across cleanup, and explicit prior prose-composition erratum. Frozen allocation/liveness evidence is separate; native owners/PAC/IPC pairing and opaque preparation remain unknown.'
BLOCKS={'descriptor_caller':0x1007ccfd4,'builder':0x100766c18,'child1_alloc':0x100863000,'child0_alloc':0x10072cf4c,'children_ready':0x100857c94,'apply1':0x100703a30,'apply0':0x1008f05f0,'array_entry':0x1008cadf0,'finish':0x10090a400,'cleanup_save':0x10097a0c4,'cleanup_cell':0x1007322cc,'cleanup_object':0x1007778f4,'cleanup_child1':0x10083dd58,'cleanup_next':0x1004c61ec,'cleanup_child0':0x10058bca4,'cleanup_free':0x10058081c,'cleanup_clear':0x100543b94}
EDGES={'descriptor_caller':[0xae67],'builder':[0x6f21,0x6f33],'child1_alloc':[0xca90,0xca94],'child0_alloc':[0x8cd0,0x8cdc],'children_ready':[0xc03b,0xc03f],'apply1':[0x25eb],'apply0':[0x25eb],'array_entry':[0xba95,0x845e],'finish':[0x785b,0x7863],'cleanup_save':[0x1fbb],'cleanup_cell':[0x5086,0x5096],'cleanup_object':[0x6e42,0x6e4a],'cleanup_child1':[0x3ad1],'cleanup_next':[0x614b],'cleanup_child0':[0x8f82],'cleanup_free':[0x7b04,0x7b10],'cleanup_clear':[0x310f]}
CALLS=[('bounded_length',0x1007cd098,0x100fc4230,0x101031fa0,0xf3,0xcc4d,'libSystem/_strnlen',0x682),('builder',0x100766ca8,0x101031da0,0x100e99900,0x9a,0xcb28,'libSystem/_malloc',0x6aa4),('child1',0x100863070,0x100e99a00,0x100f4e390,0x6d,0xcb3d,'libSystem/_malloc',0x6aa4),('child0',0x10072cfc0,0x100fc4230,0x101031fa0,0xf3,0xcbca,'libSystem/_malloc',0x6aa4),('builder_release',0x100580884,0x100fc4130,0x101031ea0,0xbb,0xcb4d,'libSystem/_free',0x46a2)]

def census():
 start=size=None
 for at,cmd,n in commands(IMAGE.data,0):
  if cmd!=0x19:continue
  for j in range(struct.unpack_from('<I',IMAGE.data,at+64)[0]):
   p=at+72+80*j
   if IMAGE.data[p:p+16].split(b'\0')[0]==b'__text':start,size=struct.unpack_from('<QQ',IMAGE.data,p+32);break
  if start is not None:break
 raw=IMAGE.read(start,size);pat=int.from_bytes(IMAGE.read(0x10078cd14,4),'little')&~31;hits=[start+4*j for j,(w,)in enumerate(struct.iter_unpack('<I',raw))if w&~31==pat];assert hits==[0x100766cac,0x10078cd14,0x100ace664];rows=[]
 for a in hits:
  b=IMAGE.read(a-24,52);rows.append({'store_site':hex(a),'start':hex(a-24),'bytes':b.hex(),'sha256':h(b),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(b,a-24)]})
 return{'text_start':hex(start),'text_bytes':size,'text_sha256':h(raw),'instruction_words_checked':size//4,'mask':'0xffffffe0','pattern':hex(pat),'scope':'Aligned literal STR Xn,[SP,#0x3950] only. Computed/pair/other-width stores and frame equivalence excluded; alternative source0x100ace664 is unjoined.','windows':rows}

def root_fields():
 s=json.loads((ROOT/'daemon_shared_roots_profiles.json').read_text());assert s['source_sha256']==sha(SOURCE);rows=[]
 for q in s['cases']:
  assert not q['native_target_executed']
  F=int(q['frame_base'],16)
  for off,expected in [(0x600,0x100e99a00),(0x5f8,0x100f4e390)]:
   ww=[w for w in q['source_writes']if int(w['address'],16)==F+off];assert len(ww)==1;w=ww[0];assert w['size_bytes']==8 and int.from_bytes(bytes.fromhex(w['after_hex']),'little')==expected;pc=int(w['pc'],16);op=next(CS.disasm(IMAGE.read(pc,4),pc));assert op.mnemonic=='str'and op.op_str.endswith('[sp, #'+hex(off)+']');rows.append({'configuration':q['configuration'],'field_offset':hex(off),'value':hex(expected),'writer':w,'original_instruction':{'ea':hex(pc),'bytes':IMAGE.read(pc,4).hex(),'mnemonic':op.mnemonic,'operands':op.op_str},'native_evidence':False,'same_frame_reaching_definition_proved':False})
 assert len(rows)==16;return rows

def retained():
 out=[]
 for p in json.loads((ROOT/'arcade_subscription_profiles.json').read_text())['profiles']:
  if p['stop_reason']!='outgoing_arcade_xpc_message_boundary':continue
  assert p['source_sha256']==sha(SOURCE)and not p['native_target_executed']and not p['target_host_operations_executed'];ev=p['pac_bypasses'];alloc=[]
  for ret,extent,role in [('0x100766cac',128,'builder'),('0x100863074',16,'child1'),('0x10072cfc4',16,'child0')]:
   cc=[c for c in p['calls']if c.get('return_pc')==ret];assert len(cc)==1 and cc[0]['name']=='libSystem/_malloc'and cc[0]['extent_bytes']==extent;c=cc[0];a=next(a for a in p['private_allocations']if a['address']==c['result']);assert not a['freed']and a['extent_bytes']==extent;alloc.append({'role':role,'recorded_allocation':c,'private_owner_at_stop':a})
  counts={n:sum(e.get('target')==hex(a)for e in ev)for n,a in BLOCKS.items()};assert all(counts[n]==1 for n in ['descriptor_caller','builder','child1_alloc','child0_alloc','children_ready','apply1','apply0','finish'])and counts['array_entry']==2 and all(counts[n]==0 for n in ['cleanup_save','cleanup_cell','cleanup_object','cleanup_child1','cleanup_next','cleanup_child0','cleanup_free','cleanup_clear'])
  n=next(c for c in p['calls']if c.get('return_pc')=='0x1007cd09c');assert n['name']=='libSystem/_strnlen'and n['args'][1]=='0x400'and isinstance(n['result'],int)and 0<=n['result']<=1024
  out.append({'label':p['label'],'allocations':alloc,'bounded_length_call':n,'counts':counts,'source_implied_child_cells':{'child1':'builder+8','child0':'builder+0'},'mapping_is_source_composition_not_heap_cell_snapshot':True,'native_evidence':False})
 assert len(out)==12;return out

def build():
 fs={}
 for n,a in BLOCKS.items():
  f=block(a,0x4000);assert f['instructions'][-1]['mnemonic']=='braa';f['sha256']=h(bytes.fromhex(f['bytes']));fs[n]=f
 edges=[];indices={0xc7b}
 for n,ixs in EDGES.items():
  ii=fs[n]['instructions'];mod=int(ii[-2]['operands'].split('#')[1],0);slots=[]
  for ix in ixs:
   a=TABLE+8*ix;w=int.from_bytes(IMAGE.read(a,8),'little');assert w>>63 and((w>>32)&65535)==mod and not((w>>48)&7),(n,hex(ix));slots.append({'index':hex(ix),'slot':hex(a),'target':hex(FIXUPS[a]['target'])});indices.add(ix)
  edges.append({'fragment':n,'branch_site':ii[-1]['ea'],'modifier_u16':mod,'selected_slots':slots})
 banks=[]
 for role,pc,l,r,key,add,target,mod in CALLS:
  b=selected(l,r,key,add,TABLE,0);lb,rb=IMAGE.read(l,256),IMAGE.read(r,256);vv=[i^rb[lb[i]^key]for i in range(256)];assert len(set(vv))==1 and b['target']==target;indices.add(int(b['index'],16));ins=list(CS.disasm(IMAGE.read(pc-4,8),pc-4));assert ins[0].op_str=='x17, #'+hex(mod)and ins[1].mnemonic=='blraa';b.update(role=role,call_site=hex(pc),left_bytes=lb.hex(),right_bytes=rb.hex(),key_u8=key,additive_u32=add,results_256=vv,modifier_u16=mod);banks.append(b)
 ptr=[{'index':hex(ix),'slot':hex(TABLE+8*ix),'raw_bytes':IMAGE.read(TABLE+8*ix,8).hex(),'fixup':FIXUPS[TABLE+8*ix]}for ix in sorted(indices)]
 old=json.loads((ROOT/(P+'_prior_manifest.json')).read_text());historical=next(r for r in old['files']if r['path']=='daemon_collection_retirement_report.md')
 err={'historical_report':'daemon_collection_retirement_report.md','historical_report_sha256':historical['sha256'],'historical_checks_preserved':'daemon_collection_retirement_checks.json','incorrect_composition':'Heap value loaded from frame+3950 was treated as the pointer-cell address forwarded unchanged to cleanup_cell.','correct_composition':'cleanup_save stores the heap builder pointer at frame+6520, changes X8 to frame+6520, saves that address at frame+4a68 and forwards it to cleanup_cell; the object loaded through it is the original builder.','source_sites':['0x10097a0d8','0x10097a0dc','0x10097a0e0','0x10097a0e4'],'scope':'Earlier local source queries remain historical. They did not assert the final X8 output across this inter-block join; the human prose composition was wrong and is corrected explicitly.'}
 cc=census();pp=retained();rr=root_fields();rec=[]
 for fn in ['daemon_collection_retirement_source.json','daemon_constructor_callers_source.json']:
  for n,f in json.loads((ROOT/fn).read_text())['fragments'].items():
   bb=bytes.fromhex(f['bytes']);assert IMAGE.read(int(f['start'],16),len(bb))==bb;rec.append({'file':fn,'fragment':n,'bytes_checked':len(bb),'sha256':h(bb)})
 cmd=['/usr/bin/dyld_info','-fixups',str(SOURCE)];r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0 and not r.stderr;fresh={}
 for line in r.stdout.splitlines():
  m=re.match(r'\s+\S+\s+\S+\s+(0x[0-9a-fA-F]+)\s+(\S+)\s+(\S+)(.*)',line)
  if m:fresh[int(m[1],16)]=line.strip()
 assert set(fresh)==set(FIXUPS)
 for row in ptr:assert fresh[int(row['slot'],16)]==row['fixup']['line']
 deps=['daemon_collection_retirement_source.json','daemon_collection_retirement_checks.json','daemon_constructor_callers_source.json','daemon_constructor_callers_checks.json','daemon_constructor_bank_origins_source.json','daemon_shared_roots_profiles.json','arcade_subscription_profiles.json','recover_daemon_xpc_core_bridge.py','daemon_receive_fixups.txt']
 return{'generator_sha256':sha(__file__),'static_scope':SCOPE,'daemon_path':str(SOURCE),'daemon_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in deps},'fragments':fs,'branch_edges':edges,'pointer_records':ptr,'original_fixup_checks':verify_original_fixups({int(r['slot'],16)for r in ptr}),'call_banks':banks,'bindings':{b['target']:binding(int(b['slot'],16))for b in banks},'literal_saved_pointer_store_census':cc,'child1_bank_root_fields':rr,'retained_profiles':pp,'composition_erratum':err,'prior_recaptures':rec,'fixup_reference':{'command':cmd,'tool_sha256':sha(cmd[0]),'stdout_sha256':h(r.stdout.encode()),'catalog_memberships_compared':len(fresh)},'verified_source_counts':{'fragments':len(fs),'instructions':sum(len(f['instructions'])for f in fs.values()),'fragment_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'pointer_records':len(ptr),'branch_edges':len(edges),'branch_slot_modifiers_checked':sum(len(e['selected_slots'])for e in edges),'call_sites':len(banks),'bank_inputs_checked':1280,'literal_pointer_store_candidates':3,'literal_census_window_bytes':156,'retained_profiles':len(pp),'recorded_builder_allocations':12,'recorded_child_allocations':24,'recorded_child1_root_field_instances':16,'native_graphs_observed':0,'outer_cleanup_entries_observed':0,'prior_ranges':len(rec),'prior_bytes':sum(r['bytes_checked']for r in rec),'prose_compositions_corrected':1},**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
