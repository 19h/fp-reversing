#!/usr/bin/env python3
"""Original-image XPC reply emission, signed status and local cleanup lifecycle.
Static only. O(B+F+I+256K) time/space; no target execution or native request.
"""
import json,re,struct,subprocess
from recover_daemon_xpc_payload import ROOT,IMAGE,SOURCE,FIXUPS,CS,TABLE,POOL,qword,selected,block,verify_original_fixups,binding,SDK,sha,h,D,FLAGS
from recover_daemon_xpc_listener import A,B,E,F
P='daemon_xpc_reply_lifecycle'
FRAGMENTS={
 'post_core':0x100dbdd48,'create_reply':0x100a85cdc,'status_gate':0x100a7c9a0,'set_data':0x100bd69dc,'send_reply':0x100bb4bf4,
 'cleanup_output':0x100b12c30,'free_output':0x10095b834,'cleanup_input':0x100d5dd58,'free_input':0x100c3dba8,
 'collection_prepare':0x100c09f40,'collection_constants':0x100a35e0c,'collection_slot':0x100c99318,'collection_object':0x100ca32b8,
 'head':0x100c7d598,'node':0x100d25fcc,'free_node_buffer':0x100aaedd8,'free_node':0x100ade894,'free_collection':0x10094e000,
 'cleanup_return':0x100c71cec,'epilogue':0x100c577b8,'guard_stub':0x100e2aad0}
SPECS=[('create_reply',A,0x6c,0xcdae,TABLE,0),('set_data',B,0xbb,0xcc71,TABLE,0),('set_status',B,0xa3,0xceb1,TABLE,0),
 ('status_key',D,0x9c,0x265,POOL,0xffffffffb288301d),('data_key',E,0x56,0x1295,POOL,0xfffffffff279fd69),
 ('send_reply',A,0xf3,0xccf8,TABLE,0),('release_reply',D,0x54,0xcba1,TABLE,0),('free_output',B,0x4e,0xcb09,TABLE,0),
 ('free_input',B,0xbb,0xcb4d,TABLE,0),('free_node_buffer',A,0xe4,0xcbab,TABLE,0),('free_node',F,0x61,0xcbef,TABLE,0),('free_collection',D,0x6d,0xcb38,TABLE,0)]
CALLS=[('create_reply',0x100a85d44),('set_data',0x100bd6a5c),('set_status',0x100bb4cb8),('send_reply',0x100bb4d08),('release_reply',0x100bb4d50),
 ('free_output',0x10095b888),('free_input',0x100c3dc10),('free_node_buffer',0x100aaee2c),('free_node',0x100ade90c),('free_collection',0x10094e050)]
BRANCHES=[('event_peer_present','post_core',0xa236,0x100a85cdc),('event_or_peer_null','post_core',0xa25b,0x100b12c30),
 ('reply_present','create_reply',0x805c,0x100a7c9a0),('reply_null','create_reply',0x805d,0x100b12c30),
 ('status_marker','status_gate',0x9f0d,0x100bd69dc),('status_other','status_gate',0x2dfe,0x100bb4bf4),('data_done','set_data',0x2dfe,0x100bb4bf4),
 ('after_reply_release','send_reply',0x4ef0,0x100b12c30),('output_nonnull','cleanup_output',0xae34,0x10095b834),('output_null','cleanup_output',0xae30,0x100d5dd58),
 ('output_freed','free_output',0xae30,0x100d5dd58),('input_nonnull','cleanup_input',0x84e3,0x100c3dba8),('input_null','cleanup_input',0x84ea,0x100c09f40),
 ('input_freed','free_input',0x1942,0x100c09f40),('collection_cleanup','collection_prepare',0x1e83,0x100a35e0c),('collection_setup','collection_constants',0x804e,0x100c99318),
 ('slot_nonnull','collection_slot',0x3b04,0x100ca32b8),('slot_null','collection_slot',0x3b12,0x100c71cec),('Q_nonnull','collection_object',0x58e1,0x100c7d598),('Q_null','collection_object',0x5902,0x100c71cec),
 ('head_nonnull','head',0x6d3d,0x100d25fcc),('head_null','head',0x6d36,0x10094e000),('buffer_nonnull','node',0xc4c5,0x100aaedd8),('buffer_null','node',0xc492,0x100ade894),
 ('buffer_freed','free_node_buffer',0x3142,0x100ade894),('next_nonnull','free_node',0x6d3d,0x100d25fcc),('next_null','free_node',0x6d36,0x10094e000),
 ('Q_freed','free_collection',0x3b12,0x100c71cec),('saved_cleanup_return','cleanup_return',0xb66,0x100c577b8)]

def build():
 fragments={}
 for name,a in FRAGMENTS.items():
  f=block(a,0x4000);assert f['instructions'][-1]['mnemonic']in('braa','retab');f['sha256']=h(bytes.fromhex(f['bytes']));fragments[name]=f
 inherited=json.loads((ROOT/'daemon_xpc_listener_source.json').read_text())['fragments']['protected_entry']
 assert IMAGE.read(int(inherited['start'],16),len(bytes.fromhex(inherited['bytes'])))==bytes.fromhex(inherited['bytes'])
 banks={}
 for name,pair,key,add,base,bias in SPECS:
  r=selected(*pair,key,add,base,bias);l,rr=IMAGE.read(pair[0],256),IMAGE.read(pair[1],256)
  r.update(left_bytes=l.hex(),right_bytes=rr.hex(),results_256=[i^rr[l[i]^key]for i in range(256)]);banks[name]=r
 slots={int(r['slot'],16)for r in banks.values()}|{0x1010b1d00,0x1010b1e18};calls=[]
 for name,pc in CALLS:
  r=banks[name];slot=int(r['slot'],16);ii=list(CS.disasm(IMAGE.read(pc-4,8),pc-4));assert ii[0].mnemonic=='mov'and ii[1].mnemonic=='blraa'
  mod=int(ii[0].op_str.split('#')[1],0);w=struct.unpack('<Q',IMAGE.read(slot,8))[0]
  assert w>>63 and(w>>32&65535)==mod and not(w>>48&1)and not(w>>49&3)
  calls.append({'role':name,'site':hex(pc),'slot':hex(slot),'target':r['target'],'modifier_u16':mod,'bytes':IMAGE.read(pc-4,8).hex(),'pointer_word':hex(w)})
 branches=[]
 for name,source,ix,target in BRANCHES:
  ii=fragments[source]['instructions'];assert ii[-1]['mnemonic']=='braa'and ii[-2]['mnemonic']=='mov';mod=int(ii[-2]['operands'].split('#')[1],0)
  slot=TABLE+8*ix;w=struct.unpack('<Q',IMAGE.read(slot,8))[0];assert qword(slot)==target and w>>63 and(w>>32&65535)==mod and not(w>>48&1)and not(w>>49&3)
  slots.add(slot);branches.append({'role':name,'source':source,'site':ii[-1]['ea'],'index':hex(ix),'slot':hex(slot),'target':hex(target),'modifier_u16':mod,'pointer_word':hex(w)})
 cmd=['/usr/bin/dyld_info','-fixups',str(SOURCE)];r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0 and not r.stderr
 fresh={}
 for line in r.stdout.splitlines():
  m=re.match(r'\s+\S+\s+\S+\s+(0x[0-9a-fA-F]+)\s+(\S+)\s+(\S+)(.*)',line)
  if m:fresh[int(m[1],16)]=line.strip()
 assert set(fresh)==set(FIXUPS)
 for a in slots:assert fresh[a]==FIXUPS[a]['line']
 headers=[SDK/'usr/include/xpc/xpc.h',SDK/'usr/include/xpc/connection.h',SDK/'usr/include/mach/message.h',SDK/'usr/include/stdlib.h']
 deps=['recover_daemon_xpc_core_bridge.py','daemon_xpc_core_bridge_source.json','daemon_xpc_core_bridge_checks.json','daemon_xpc_listener_source.json','daemon_xpc_payload_source.json','daemon_xpc_iteration_source.json','daemon_receive_tools.py','daemon_receive_fixups.txt','daemon_import_bindings.py']
 return {'generator_sha256':sha(__file__),'daemon_path':str(SOURCE),'daemon_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in deps},
  'fragments':fragments,'key_literals':{'data':{'address':'0x100e86130','bytes':IMAGE.read(0x100e86130,5).hex()},'status':{'address':'0x100f18410','bytes':IMAGE.read(0x100f18410,7).hex()}},'guard_failure':{'call_site':'0x100c577f0','call_bytes':IMAGE.read(0x100c577f0,4).hex(),'stub':'0x100e2aad0','slot':'0x1010b1d00','target':FIXUPS[0x1010b1d00]['target'],'pointer_word':IMAGE.read(0x1010b1d00,8).hex()},'inherited_entry_match':{'start':inherited['start'],'bytes_checked':len(bytes.fromhex(inherited['bytes'])),'sha256':h(bytes.fromhex(inherited['bytes']))},'banks':banks,'calls':calls,'branches':branches,'imports':[binding(a)for a in sorted(slots)if isinstance(FIXUPS[a]['target'],str)],
  'selected_pointer_records':[{'slot':hex(a),'raw_bytes':IMAGE.read(a,8).hex(),'fixup':FIXUPS[a]}for a in sorted(slots)],'original_pointer_checks':verify_original_fixups([a for a in slots if not isinstance(FIXUPS[a]['target'],str)or FIXUPS[a]['kind'].startswith('auth-')]),
  'fixup_reference':{'command':cmd,'stdout_sha256':h(r.stdout.encode()),'catalog_memberships_compared':len(fresh),'selected_lines':{hex(a):fresh[a]for a in sorted(slots)}},
  'SDK_headers':[{'path':str(p),'size_bytes':p.stat().st_size,'sha256':sha(p)}for p in headers],'inspection_tools':[{'path':'/usr/bin/dyld_info','sha256':sha('/usr/bin/dyld_info')}],
  'verified_source_counts':{'fragments':len(fragments),'instructions':sum(len(f['instructions'])for f in fragments.values()),'fragment_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fragments.values()),'bank_cases':len(banks),'bank_inputs_checked':256*len(banks),'resolved_calls':len(calls),'branch_bindings':len(branches),'imports':len([a for a in slots if isinstance(FIXUPS[a]['target'],str)]),'conditional_guard_transfers':1,'selected_pointer_records':len(slots),'fixup_catalog_memberships_compared':len(fresh)},**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
