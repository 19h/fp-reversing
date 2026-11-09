#!/usr/bin/env python3
"""Missing-key scalar population, opaque stateful output ABI and frozen wire field."""
import json,re,struct,subprocess,capstone
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,CS,TABLE,block,selected,sha,h,FLAGS
from daemon_receive_tools import verify_original_fixups
from resolve_kernel_collection_interfaces import commands
P='daemon_scalar_field_population'
SCOPE='Selected C1 keyed lookup/miss-to-generated-u32 insertion, found-header reader frontier, full5497-instruction helper structural/argument/counter ABI and frozen field lineage. Helper value algorithm,complete found-value interpretation,native state/owners/PAC and daemon-kext pairing remain unknown.'
KNOWLEDGE=json.loads("{\"observed_UTC_date\":\"2026-11-06\",\"database_label\":\"fairplayd\",\"database_id\":\"6b117c693e3b\",\"queries\":[{\"arguments\":{\"target\":\"6b117c693e3b\",\"scope\":\"all\",\"query\":\"collection serialize builder\",\"limit\":6},\"result\":{\"count\":0,\"facts\":[],\"notes\":[],\"pending_peer_memories\":0,\"pending_peer_memory_text\":\"0 pending memories\",\"schema_version\":2,\"truncated\":false}},{\"arguments\":{\"target\":\"6b117c693e3b\",\"scope\":\"all\",\"address\":\"0x100847998\",\"limit\":6},\"result\":{\"count\":4,\"facts\":[{\"anchor\":\"\",\"author_id\":\"external:mesh:369959ffb028891cccb605e6792456bf\",\"category\":\"protocol\",\"confidence\":0.949999988079071,\"fact\":\"[foreign: peer external:mesh:369959ffb028891cccb605e6792456bf ] ARM64e fairplayd MIG table map verified by targeted relocated IDB byte parsing and lookup/stub decompilation: subsystem header32bytes;descriptor40bytes,stub pointer at descriptor+8,maximum_reply_size at+32. Header includes lookup pointer+0,start ID+8,end-exclusive ID+12,maxreply+16. Five tables,eleven non-null stubs:1200..1204 header0x101038040,descriptors0x101038060,lookup0x1000044FC,maxreply212bytes;1000..1002 header0x101038128,descriptors0x101038148,lookup0x100004C10,maxreply200bytes;500..502 header0x1010381C0,descriptors0x1010381E0,lookup0x100005094,maxreply384bytes;41471(0xA1FF) header0x101038258,descriptors0x101038278,lookup0x100005304,maxreply36bytes;61471(0xF01F) header0x1010382A0,descriptors0x1010382C0,lookup0x1000054B8,maxreply40bytes. IDs500,501 have NULL stub entries. These lookup functions return matching stub pointers or NULL,not Boolean demux results. Single-ID lookups PAC-sign their function pointers. Table presence and stub mappings are verified; full routing from callback0x100425F78 to all five tables is NOT established. Tables/functions are specific to ARM64e peer7da84cef0261;never transplant addresses from ARM64 fairplayd.H2.\",\"fact_id\":7,\"metadata\":{\"anchor_unresolved\":false,\"portable_anchors\":{},\"verification\":\"unverified\"},\"origin_member\":\"external:mesh:369959ffb028891cccb605e6792456bf\",\"provenance\":\"inbound\",\"provenance_token\":\"FOREIGN peer external:mesh:369959ffb028891cccb605e6792456bf binary 4c91eccb\",\"revision\":2,\"scope\":\"global\",\"source\":\"ai\",\"state\":\"accepted\",\"verification\":\"unverified\"},{\"anchor\":\"\",\"author_id\":\"local:ai\",\"category\":\"memory_offset\",\"confidence\":0.949999988079071,\"fact\":\"Opaque helper calls use mov reg, sign-extended imm32; add reg, [off_100321B60+idx*8+disp]; call/jmp reg. At 0x10005D180 the immediate is 0xFFFFFFFFD51649B6 and the slot is 0x100321B08+al*8. qword 0x100322000 (index 0x9F, file value 0x000000012B1C55DA) plus that immediate is 0x100329F90, which is UNDEF and filled with 0xFF, not 0x1000329F90. Across 0x100321B60..0x100322F80 that same immediate puts only slot 0x100322998 into __text (0x100082A89). Immediate 0xFFFFFFFF92B14D72 puts 0x100321C50->0x100242DA8 and 0x1003225E8->0x10000E5A9 into __text; 0xFFFFFFFFC50F5C05 and 0xFFFFFFFFF50DF94A put none of that range into __text.\",\"fact_id\":3,\"metadata\":{\"anchor_unresolved\":false,\"checkpoint_batch\":\"062cffe2-a9f7-4a1f-bd24-cefba97e279f:532265438245375\",\"portable_anchors\":{},\"tags\":[\"encoded_pointer\",\"dispatch\"],\"verification\":\"unverified\"},\"provenance_token\":\"NATIVE\",\"revision\":3,\"scope\":\"global\",\"source\":\"ai\",\"state\":\"accepted\",\"verification\":\"unverified\"},{\"anchor\":\"\",\"author_id\":\"local:ai\",\"category\":\"memory_offset\",\"confidence\":0.949999988079071,\"fact\":\"File image of _main's once/success globals: unk_100328968 (0x100328968) is 0x30B1BCBA followed by zeros, Darwin PTHREAD_ONCE_INIT, so pthread_once of sub_10010A0B0 has not run in the file. unk_100328D64 low dword is 0x1BB85F56, the constant _main compares against, so that branch matches the static image. __data ends at 0x100328ED0; __bss is 0x100328ED0–0x1003290F0; __common is 0x1003290F0–0x100329B68 (unk_1003290F0, 0x100329B08, unk_100329B18, dword_100329B4C int[5] have no file bytes). ___stack_chk_guard is an UNDEF import at 0x100329EE0; GOT slot ___stack_chk_guard_ptr at 0x1003239E0 holds that address. _ptrace is 0x10032A038 and _pthread_once is 0x10032A008, both libSystem UNDEF.\",\"fact_id\":4,\"metadata\":{\"anchor_unresolved\":false,\"checkpoint_batch\":\"062cffe2-a9f7-4a1f-bd24-cefba97e279f:532265438245375\",\"portable_anchors\":{},\"tags\":[\"globals\",\"bss\"],\"verification\":\"unverified\"},\"provenance_token\":\"NATIVE\",\"revision\":2,\"scope\":\"global\",\"source\":\"ai\",\"state\":\"accepted\",\"verification\":\"unverified\"},{\"anchor\":\"\",\"author_id\":\"local:ai\",\"category\":\"protocol\",\"confidence\":0.949999988079071,\"fact\":\"jpt_100012B21 is at 0x1002E9900 (next label jpt_100010F74 at 0x1002E9920). Dispatch adds a signed rel32 from that table to a per-site base. Verified static sums: index 7 rel32 0xFFFDEADA + base 0x10007E63E = 0x10005D118; index 4 rel32 0xFFFF6AD9 + base 0x1000AF140 = 0x1000A5C19; index 5 rel32 0xFFFD2869 + base 0x1000AF140 = 0x1000819A9. Index 6 rel32 0x00030B02 + 0x10007E63E = 0x1000A9140, but the 1091-byte chunk still mutates the pointer (xor edx,34h and a byte xor) before jmp rsi at 0x10007EA7E, so 0x1000AF140 is not that raw sum. Entries at 0x1002E9964 are rel32 0x00052028 and 0xFFFC2D44 (index 25 and 26 if the table starts at 0x1002E9900); those two deltas do not share one base that lands on both 0x100074659 and 0x1000BA189. Landed arms are instruction-misaligned: 0x10005D118 is +3 from 0x10005D115; 0x1000A5C19 is +2 from sub_1000A5C17; 0x1000819A9 is inside a 336-byte undefined item at 0x100081878.\",\"fact_id\":2,\"metadata\":{\"anchor_unresolved\":false,\"checkpoint_batch\":\"062cffe2-a9f7-4a1f-bd24-cefba97e279f:532265438245375\",\"portable_anchors\":{},\"tags\":[\"jump_table\",\"dispatch\"],\"verification\":\"unverified\"},\"provenance_token\":\"NATIVE\",\"revision\":2,\"scope\":\"global\",\"source\":\"ai\",\"state\":\"accepted\",\"verification\":\"unverified\"}],\"notes\":[],\"pending_peer_memories\":0,\"pending_peer_memory_text\":\"0 pending memories\",\"schema_version\":2,\"truncated\":false}},{\"arguments\":{\"target\":\"6b117c693e3b\",\"scope\":\"all\",\"query\":\"0x100939f64 112\",\"limit\":6},\"result\":{\"count\":0,\"facts\":[],\"notes\":[],\"pending_peer_memories\":0,\"pending_peer_memory_text\":\"0 pending memories\",\"schema_version\":2,\"truncated\":false}}],\"knowledge_stats_summary\":{\"total_facts\":9,\"global\":4,\"local\":5},\"source_semantic_claims_taken_from_knowledge\":false,\"scope\":\"Read-only stored-knowledge lookup only; no current IDB byte comparison, input-file hash attestation, rename, save or memory write. No relevant checked serializer/tail fact was returned; unverified global notes are excluded from semantic evidence.\"}")
BLOCKS={'caller':0x1009ab118,'entry':0x100847998,'lookup_call':0x10074ab80,'lookup_status':0x1004e9b70,'return':0x1006f76a8,'caller_status':0x1006985d4,'populate':0x1006f0a84,'adapter':0x100752360,'root':0x100828290,'typed_return':0x100781e0c,'finish':0x10090a400,'found_node':0x1009238d8,'found_extent':0x1005dd9c8,'found_header':0x10074add4}
EDGES={'caller':[0x3b01],'entry':[0x3cc0,0x3d4f],'lookup_call':[0x18e2],'lookup_status':[0x3cc0,0x9aa9],'return':[0x922],'caller_status':[0x1c9,0x89ec],'populate':[0x18a5],'adapter':[0x47f4,0x482e],'root':[0x5eb2],'typed_return':[0x1c9],'finish':[0x785b,0x7863],'found_node':[0x7023,0x7067],'found_extent':[0x7067,0xc217],'found_header':[0x2520]}
PROJECTIONS={'helper_stack':(0x100444e00,0x100444e20),'helper_context':(0x100447970,0x100447978),'helper_counter_read':(0x1004486a0,0x1004486a4),'helper_output':(0x10044a394,0x10044a3c0)}

def norm(n):return'x'+n[1:]if n.startswith('w')and n[1:].isdigit()else'x29'if n=='fp'else'x30'if n=='lr'else n

def helper_summary():
 a,z=0x100444dfc,0x10044a3e0;bb=IMAGE.read(a,z-a);dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True;ii=list(dc.disasm(bb,a));assert len(ii)==5497 and len(bb)==len(ii)*4
 ctrls=[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii if i.mnemonic.startswith(('b.','cb','tb'))or i.mnemonic in('b','bl','blr','br','braa','brab','blraa','blrab','svc','hvc','smc','retab','retaa','ret')];assert ctrls==[{'ea':'0x10044a3dc','mnemonic':'retab','operands':''}]
 spw=[];access=[];known=set();uninit=[];needs=[];seen={'sp'};arguses=[];initial_arg=True;w30=[];x20=[]
 for i in ii:
  rr,ww=i.regs_access();rr={norm(i.reg_name(r))for r in rr};ww={norm(i.reg_name(r))for r in ww}
  if 'sp'in ww:spw.append({'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str})
  if initial_arg and 'x0'in rr:arguses.append({'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str})
  if 'x0'in ww:initial_arg=False
  if i.address>0x100444e1c and i.address<0x10044a3c0:
   for r in rr-seen-{'xzr','wzr'}:needs.append({'site':hex(i.address),'register':r})
   seen|=ww
  if 'x30'in ww and 0x1004486a4<=i.address<0x10044a39c:w30.append(hex(i.address))
  if 'x20'in ww and 0x100447978<=i.address<0x1004486a4:x20.append(hex(i.address))
  if '[sp'not in i.op_str:continue
  m=re.search(r'\[sp(?:, #(0x[0-9a-f]+|[0-9]+))?\]',i.op_str);assert m,i.op_str;off=int(m[1],0)if m[1]else 0;rd=i.op_str.split(',')[0];width=1 if i.mnemonic.endswith('b')else 2 if i.mnemonic.endswith('h')else 4 if rd.startswith('w')else 8;width*=2 if i.mnemonic in('stp','ldp')else 1
  row={'site':hex(i.address),'offset_bytes':off,'width_bytes':width,'mnemonic':i.mnemonic,'operands':i.op_str,'kind':'write'if i.mnemonic.startswith('st')else'read'};access.append(row)
  if row['kind']=='write':known.update(range(off,off+width))
  elif not set(range(off,off+width))<=known:uninit.append(row)
 assert spw==[{'ea':'0x100444e00','mnemonic':'sub','operands':'sp, sp, #0xc0'},{'ea':'0x10044a3d8','mnemonic':'add','operands':'sp, sp, #0xc0'}]and not needs and not uninit and not w30 and not x20
 assert arguses==[{'ea':'0x100444e1c','mnemonic':'str','operands':'x0, [sp, #0x48]'}]
 argaccess=[x for x in access if x['offset_bytes']<0x50 and 0x48<x['offset_bytes']+x['width_bytes']];assert[x['site']for x in argaccess]==['0x100444e1c','0x10044a3b8']
 saved_early=[x for x in access if x['kind']=='read'and int(x['site'],16)<0x10044a3c0 and x['offset_bytes']<0xc0 and 0x60<x['offset_bytes']+x['width_bytes']];assert not saved_early
 starts=[]
 for at,cmd,n in commands(IMAGE.data,0):
  if cmd!=0x26:continue
  off,n=struct.unpack_from('<II',IMAGE.data,at+8);raw=IMAGE.data[off:off+n];p=0;cur=0x100000000
  while p<len(raw):
   val=shift=0
   while True:
    b=raw[p];p+=1;val|=(b&127)<<shift;shift+=7
    if not b&128:break
   if not val:break
   cur+=val;starts.append(cur)
 assert a in starts and starts[starts.index(a)+1]==z
 return{'start':hex(a),'end':hex(z),'bytes':bb.hex(),'sha256':h(bb),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii],'compiler_start':hex(a),'next_compiler_start':hex(z),'control_instructions':ctrls,'SP_writes':spw,'direct_SP_accesses':access,'direct_SP_reads_before_write':uninit,'incoming_GPR_data_reads_before_definition':needs,'initial_X0_uses':arguses,'argument_slot_accesses':argaccess,'saved_register_reads_before_epilogue':saved_early,'W30_clobbers_after_counter_read':w30,'X20_clobbers_before_counter_read':x20,'scope':'Complete source structural checks; no whole-helper value expression,computed-memory alias proof,native timing/PAC or algorithm identity is claimed. Stack/ARG/state separation and saved-slot integrity remain premises.'}

def wire_records(data,base=0,depth=0):
 if depth>4:return[]
 p=0;out=[]
 while p<len(data):
  if p+10>len(data):return[]
  key,tag,n=struct.unpack_from('>IHI',data,p)
  if tag not in(0x9777,0x8485,0x50db)or p+10+n>len(data):return[]
  payload=data[p+10:p+10+n];out.append({'offset_bytes':base+p,'identifier':hex(key),'wire_tag':hex(tag),'payload_extent_bytes':n,'payload_hex':payload.hex()})
  if tag==0x50db and payload:out.extend(wire_records(payload,base+p+10,depth+1))
  p+=10+n
 return out

def retained():
 out=[]
 for p in json.loads((ROOT/'arcade_subscription_profiles.json').read_text())['profiles']:
  if p['stop_reason']!='outgoing_arcade_xpc_message_boundary':continue
  assert p['source_sha256']==sha(SOURCE)and not p['native_target_executed']and not p['target_host_operations_executed'];ev=p['pac_bypasses'];j=next(j for j,e in enumerate(ev)if e.get('target')=='0x100847998');z=next(k for k in range(j+1,len(ev))if ev[k].get('target')=='0x10090a400');seq=ev[j:z+1]
  for pc,target in [('0x1004e9bac','0x1006f76a8'),('0x100698628','0x1006f0a84'),('0x1006f0b24','0x100444dfc'),('0x1006f0b5c','0x100752360'),('0x100781e1c','0x10090a400')]:assert sum(e.get('site')==pc and e.get('target')==target for e in seq)==1
  counts={n:sum(e.get('target')==hex(a)for e in seq)for n,a in BLOCKS.items()};assert counts['found_node']==counts['found_extent']==counts['found_header']==0 and counts['populate']==counts['root']==counts['typed_return']==1
  nodes=[c for c in p['calls']if c.get('return_pc')=='0x10069592c'];bufs=[c for c in p['calls']if c.get('return_pc')=='0x100948bfc'];assert len(nodes)==len(bufs)==5 and nodes[2]['extent_bytes']==32 and bufs[2]['extent_bytes']==14
  setter=next(c for c in p['calls']if c.get('name')=='libSystem/_xpc_dictionary_set_data');raw=bytes.fromhex(setter['value']['bytes']);rr=[r for r in wire_records(raw)if r['identifier']=='0xf6964e3e'];assert len(rr)==1 and rr[0]['wire_tag']=='0x9777'and rr[0]['payload_extent_bytes']==4 and rr[0]['payload_hex']=='04f2abb5';v=int.from_bytes(bytes.fromhex(rr[0]['payload_hex']),'big');out.append({'label':p['label'],'episode':{'first_event_index':j,'last_event_index':z,'events':seq,'counts':counts},'third_node_allocation':nodes[2],'third_buffer_allocation':bufs[2],'wire_field':rr[0],'setter_return_pc':setter['return_pc'],'packet_sha256':h(raw),'derived_encoded_value_u32':hex(v^0x8b3dc651),'derived_helper_output_low32':hex(v^0x55919137),'helper_low32_is_inferred_not_register_snapshot':True,'native_evidence':False})
 assert len(out)==12;return out

def build():
 fs={}
 for n,a in BLOCKS.items():
  f=block(a,0x4000);assert f['instructions'][-1]['mnemonic']=='braa';f['sha256']=h(bytes.fromhex(f['bytes']));fs[n]=f
 for n,(a,z)in PROJECTIONS.items():
  b=IMAGE.read(a,z-a);fs[n]={'start':hex(a),'end':hex(z),'bytes':b.hex(),'sha256':h(b),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(b,a)]}
 edges=[];indices={0x130c,0x8c3f,0x74,0x222}
 for n,ixs in EDGES.items():
  ii=fs[n]['instructions'];mod=int(ii[-2]['operands'].split('#')[1],0);slots=[]
  for ix in ixs:
   a=TABLE+8*ix;w=int.from_bytes(IMAGE.read(a,8),'little');assert w>>63 and((w>>32)&65535)==mod and not((w>>48)&7),(n,hex(ix));slots.append({'index':hex(ix),'slot':hex(a),'target':hex(FIXUPS[a]['target'])});indices.add(ix)
  edges.append({'fragment':n,'branch_site':ii[-1]['ea'],'modifier_u16':mod,'selected_slots':slots})
 bank=selected(0x100e99700,0x100f4e190,0x81,0xcc10,TABLE,0);assert bank['target']=='0x100444dfc'and bank['index']=='0xcc58';l,r=IMAGE.read(0x100e99700,256),IMAGE.read(0x100f4e190,256);vv=[i^r[l[i]^0x81]for i in range(256)];assert set(vv)=={0x48};bank.update(left_bytes=l.hex(),right_bytes=r.hex(),results_256=vv,key_u8=0x81,additive_u32=0xcc10,call_site='0x1006f0b24',modifier_u16=0x9a7c,left_frame_slot='0x870',right_frame_slot='0x868');indices.add(0xcc58)
 ptr=[{'index':hex(ix),'slot':hex(TABLE+8*ix),'raw_bytes':IMAGE.read(TABLE+8*ix,8).hex(),'fixup':FIXUPS[TABLE+8*ix]}for ix in sorted(indices)]
 helper=helper_summary();pp=retained();rec=[]
 for fn in ['daemon_builder_owner_join_source.json','daemon_constructor_lookup_source.json','daemon_constructor_callers_source.json']:
  for n,f in json.loads((ROOT/fn).read_text())['fragments'].items():
   b=bytes.fromhex(f['bytes']);assert IMAGE.read(int(f['start'],16),len(b))==b;rec.append({'file':fn,'fragment':n,'bytes_checked':len(b),'sha256':h(b)})
 old=json.loads((ROOT/'arcade_subscription_contracts.json').read_text());assert any(r.get('start')=='0x100444dfc'and r['sha256']==helper['sha256']for r in old['ranges'])
 cmd=['/usr/bin/dyld_info','-fixups',str(SOURCE)];r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0 and not r.stderr;fresh={}
 for line in r.stdout.splitlines():
  m=re.match(r'\s+\S+\s+\S+\s+(0x[0-9a-fA-F]+)\s+(\S+)\s+(\S+)(.*)',line)
  if m:fresh[int(m[1],16)]=line.strip()
 assert set(fresh)==set(FIXUPS)
 for row in ptr:assert fresh[int(row['slot'],16)]==row['fixup']['line']
 deps=['daemon_builder_owner_join_source.json','daemon_builder_owner_join_checks.json','daemon_constructor_lookup_source.json','daemon_constructor_lookup_checks.json','daemon_constructor_callers_source.json','daemon_constructor_callers_checks.json','daemon_payload_codec_source.json','daemon_payload_codec_checks.json','daemon_record_stream_source.json','arcade_subscription_contracts.json','arcade_subscription_profiles.json','recover_daemon_xpc_core_bridge.py','daemon_receive_fixups.txt']
 return{'generator_sha256':sha(__file__),'static_scope':SCOPE,'daemon_path':str(SOURCE),'daemon_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in deps},'fragments':fs,'branch_edges':edges,'pointer_records':ptr,'original_fixup_checks':verify_original_fixups({int(r['slot'],16)for r in ptr}),'helper_call_bank':bank,'helper_complete':helper,'read_only_IDA_knowledge_snapshot':KNOWLEDGE,'retained_profiles':pp,'prior_recaptures':rec,'fixup_reference':{'command':cmd,'tool_sha256':sha(cmd[0]),'stdout_sha256':h(r.stdout.encode()),'catalog_memberships_compared':len(fresh)},'verified_source_counts':{'primary_fragments':len(BLOCKS),'primary_instructions':sum(len(fs[n]['instructions'])for n in BLOCKS),'primary_bytes':sum(len(bytes.fromhex(fs[n]['bytes']))for n in BLOCKS),'helper_instructions':5497,'helper_bytes':21988,'helper_projection_ranges':len(PROJECTIONS),'helper_projection_instructions':sum(len(fs[n]['instructions'])for n in PROJECTIONS),'helper_direct_SP_accesses':len(helper['direct_SP_accesses']),'helper_semantic_incoming_GPRs':0,'helper_initial_X0_uses':1,'helper_output_width_bits':64,'pointer_records':len(ptr),'branch_slot_modifiers_checked':sum(len(e['selected_slots'])for e in edges),'bank_inputs_checked':256,'retained_profiles':len(pp),'lookup_miss_population_episodes':12,'typed_scalar_constructions':12,'found_value_entries_observed':0,'wire_field_instances':12,'IDA_knowledge_queries':3,'IDA_semantic_facts_used':0,'prior_ranges':len(rec),'prior_bytes':sum(r['bytes_checked']for r in rec)},**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
