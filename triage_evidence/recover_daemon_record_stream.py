#!/usr/bin/env python3
"""Read-only source and frozen-profile extraction; never imports legacy probes.
O(image + fixups + retained bytes + recorded PCs), no target execution.
"""
import json,re,subprocess
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,CS,TABLE,qword,block,binding,sha,h,FLAGS
P='daemon_record_stream'
SCOPE='Original-image stop-record prefix and historical private Arcade serializer-to-XPC byte lineage. Shared grammar is not a native transport join. No new target execution/emulation, host IPC, request, PAC authentication or IDB mutation.'
BLOCKS={'loop':0x100b22fe4,'nonempty':0x100ad9f78,'minimum':0x100ba9504,'extent':0x100a6c060,
 'header':0x100cc0944,'signed_root':0x100d31e14,'signed_ge':0x100aa9478,'upper':0x100cb31bc,
 'variable':0x100a85d74,'result':0x100c8f210,'publish_result':0x100c044d4,
 'writer_trailer':0x1009178e4,'writer_padding':0x1006d6a30,'writer_publish':0x10068f630}
EDGES=[('nonempty','loop',0x6b0c,0x100ad9f78),('source_present','nonempty',0x5c7f,0x100ba9504),
 ('header_fits','minimum',0x2eba,0x100a6c060),('record_fits','extent',0x6aaa,0x100cc0944),
 ('header_decoded','header',0xcb09,0x100d31e14),('signed_ge','signed_root',0x35aa,0x100aa9478),
 ('upper','signed_ge',0x9af4,0x100cb31bc),('variable','upper',0x48b9,0x100a85d74),
 ('H_zero','variable',0x3b5c,0x100c8f210),('H_nonzero','variable',0x3b60,0x100ab3e34),
 ('publish_Q','result',0x5f5a,0x100c044d4),('outer','publish_result',0x893a,0x100c4dc4c)]
PRIOR=['daemon_list_output_source.json','daemon_xpc_records_source.json','daemon_xpc_iteration_source.json','arcade_subscription_contracts.json']
DEPS=PRIOR+['arcade_subscription_profiles.json','daemon_list_output_checks.json','daemon_xpc_records_checks.json','daemon_xpc_iteration_checks.json','validate_daemon_list_output.py','recover_daemon_xpc_core_bridge.py','daemon_receive_fixups.txt','daemon_import_bindings.py']
OCCURRENCE=['0x100847960','0x1006bc13c','0x1006c318c','0x1009178e4','0x10068f630','0x10090f880','0x10077e614']
def decode(data):
 """Structural decoder for retained bytes, depth is fixed at two by caller."""
 out=[];c=0
 while c<len(data):
  assert c+10<=len(data);H=int.from_bytes(data[c:c+4],'big');T=int.from_bytes(data[c+4:c+6],'big');n=int.from_bytes(data[c+6:c+10],'big');e=c+10+n
  assert e<=len(data) and T in (0x9777,0x8485,0x50db)
  out.append({'offset_bytes':c,'H':hex(H),'T':hex(T),'P_bytes':n,'payload_hex':data[c+10:e].hex()});c=e
 return out
def retained_profiles():
 old=json.loads((ROOT/'arcade_subscription_profiles.json').read_text());rows=[];excluded=[]
 for p in old['profiles']:
  assert p['source_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
  assert not p['native_target_executed'] and not p['target_host_operations_executed'] and not p['full_goal_complete']
  if p['stop_reason']!='outgoing_arcade_xpc_message_boundary':
   excluded.append({'label':p['label'],'stop_reason':p['stop_reason']});continue
  alloc=[c for c in p['calls'] if c['return_pc']=='0x1006c3190'];setter=[c for c in p['calls']if c['return_pc']=='0x10077e5c8'];send=[c for c in p['calls']if c['return_pc']=='0x10077e618']
  assert len(alloc)==3 and len(setter)==len(send)==1;setter,send=setter[0],send[0]
  assert alloc[-1]['name']=='libSystem/_malloc' and setter['name']=='libSystem/_xpc_dictionary_set_data' and send['name']=='libSystem/_xpc_connection_send_message_with_reply_sync'
  packet=bytes.fromhex(setter['value']['bytes']);assert setter['key']=='data' and setter['value']==send['message']['fields']['data']['value']
  assert int(alloc[-1]['result'],16)==int(setter['args'][2],16)
  assert int(alloc[-1]['args'][0],16)==int(setter['args'][3],16)==setter['value']['size_bytes']==len(packet)
  assert setter['args'][0]==send['args'][1];outer=decode(packet);assert len(outer)==3
  assert [(r['H'],r['T'])for r in outer]==[('0x7976211a','0x9777'),('0xfd2821c7','0x50db'),('0x0','0x50db')]
  inner=decode(bytes.fromhex(outer[1]['payload_hex']));assert len(inner)==4
  assert [(r['H'],r['T'])for r in inner]==[('0x7e852555','0x9777'),('0x1fe19f28','0x50db'),('0xf6964e3e','0x9777'),('0x0','0x50db')]
  path=bytes.fromhex(inner[1]['payload_hex']);assert path and path[-1]==0 and b'\0' not in path[:-1]
  n=len(path);Li=64+16*(n//16);Lo=112+16*(n//16)
  assert inner[-1]['offset_bytes']==38+n and inner[-1]['P_bytes']==16-(n&15)
  assert outer[1]['P_bytes']==Li and outer[-1]['offset_bytes']==24+Li and outer[-1]['P_bytes']==14 and len(packet)==Lo
  for r in [inner[-1],outer[-1]]:assert bytes.fromhex(r['payload_hex'])==bytes(r['P_bytes'])
  assert [int(a['args'][0],16)for a in alloc]==[16,Li,Lo]
  assert outer[0]['payload_hex']=='00000000' and inner[0]['payload_hex']=='2cfbf0b8' and inner[2]['payload_hex']=='04f2abb5'
  assert set(OCCURRENCE)<=set(p['visited_instruction_addresses'])
  events=[e for e in p['pac_bypasses']if e['site']=='0x100847994'];assert len(events)==1
  e=events[0];assert e['target']=='0x1006bc13c' and e['modifier']=='0x6e32' and e['authentication']=='bypassed in private synthetic model'
  returns=[e for e in p['pac_bypasses'] if e['site']=='0x10066efc8' and e['target']=='0x10090f880'];assert len(returns)==1 and returns[0]['modifier']=='0x5677'
  rows.append({'label':p['label'],'stop_reason':p['stop_reason'],'private_cpu_model':p['private_cpu_model'],
   'packet_sha256':h(packet),'packet_size_bytes':len(packet),'path_size_including_NUL_bytes':n,
   'allocations':[{'pointer':a['result'],'size_bytes':int(a['args'][0],16)}for a in alloc],
   'setter_buffer':setter['args'][2],'setter_extent_bytes':int(setter['args'][3],16),'dictionary':setter['args'][0],
   'send_connection':send['args'][0],'send_dictionary':send['args'][1],
   'outer_records':outer,'inner_records':inner,'source_PC_memberships':OCCURRENCE,'selected_auth_events':events+returns,
   'original_instruction_bytes_verified':p['original_instruction_bytes_verified'],'exploration_mode':p['exploration_mode'],
   'packet_equal_setter_and_send':True,'last_allocation_equals_setter':True,'native_evidence':False})
 assert len(rows)==12 and len(excluded)==4
 return {'profiles':rows,'excluded_profiles':excluded,'legacy_generators_rerun':False,'unique_PC_sets_are_not_dynamic_traces':True}
def build():
 fragments={}
 for n,a in BLOCKS.items():
  f=block(a,0x4000);assert f['instructions'][-1]['mnemonic']=='braa';f['sha256']=h(bytes.fromhex(f['bytes']));fragments[n]=f
 a,z=0x10077e48c,0x10077e61c;raw=IMAGE.read(a,z-a)
 fragments['arcade_send']={'start':hex(a),'end':hex(z),'bytes':raw.hex(),'sha256':h(raw),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(raw,a)]}
 edges=[];slots=set()
 for role,n,ix,target in EDGES:
  f=fragments[n];ii=f['instructions'];mod=int(ii[-2]['operands'].split('#')[1],0);slot=TABLE+8*ix;w=int.from_bytes(IMAGE.read(slot,8),'little')
  assert qword(slot)==target and w>>63 and (w>>32&65535)==mod and not(w>>48&1)and not(w>>49&3)
  edges.append({'role':role,'source':n,'site':ii[-1]['ea'],'index':hex(ix),'slot':hex(slot),'target':hex(target),'modifier_u16':mod});slots.add(slot)
 imports=[]
 for pc,slot,mod,symbol in [(0x10077e5c4,0x1010a0850,0x485b,'_xpc_dictionary_set_data'),(0x10077e614,0x1010a04d0,0x2e76,'_xpc_connection_send_message_with_reply_sync')]:
  i=list(CS.disasm(IMAGE.read(pc-4,8),pc-4));assert i[0].op_str==f'x17, #{hex(mod)}' and i[1].mnemonic=='blraa'
  b=binding(slot);assert b['symbol']==symbol
  w=int.from_bytes(IMAGE.read(slot,8),'little');assert w>>63 and (w>>32&65535)==mod and not(w>>48&1)and not(w>>49&3)
  imports.append({'site':hex(pc),'slot':hex(slot),'modifier_u16':mod,'symbol':symbol,'binding':b});slots.add(slot)
 recaptures=[]
 def walk(o,fn,path=''):
  if isinstance(o,dict):
   data=o.get('bytes',o.get('bytes_hex'));a=o.get('start')
   if isinstance(data,str)and isinstance(a,str)and a.startswith('0x')and 0x100000000<=int(a,16)<0x102000000:
    bb=bytes.fromhex(data);assert IMAGE.read(int(a,16),len(bb))==bb,(fn,path)
    recaptures.append({'file':fn,'path':path,'start':a,'bytes_checked':len(bb),'sha256':h(bb)})
   for k,v in o.items():walk(v,fn,path+'/'+k)
  elif isinstance(o,list):
   for j,v in enumerate(o):walk(v,fn,path+'/'+str(j))
 for fn in PRIOR:walk(json.loads((ROOT/fn).read_text()),fn)
 cmd=['/usr/bin/dyld_info','-fixups',str(SOURCE)];r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0 and not r.stderr
 fresh={}
 for line in r.stdout.splitlines():
  m=re.match(r'\s+\S+\s+\S+\s+(0x[0-9a-fA-F]+)\s+(\S+)\s+(\S+)(.*)',line)
  if m:fresh[int(m[1],16)]=line.strip()
 assert set(fresh)==set(FIXUPS)
 for a in slots:assert fresh[a]==FIXUPS[a]['line']
 retained=retained_profiles()
 return {'generator_sha256':sha(__file__),'static_scope':SCOPE,'daemon_path':str(SOURCE),'daemon_sha256':sha(SOURCE),
  'dependencies':{n:sha(ROOT/n)for n in DEPS},'fragments':fragments,'branches':edges,'imports':imports,
  'pointer_records':[{'slot':hex(a),'raw_bytes':IMAGE.read(a,8).hex(),'fixup':FIXUPS[a]}for a in sorted(slots)],
  'source_recaptures':recaptures,'retained_model_evidence':retained,
  'fixup_reference':{'command':cmd,'tool_sha256':sha(cmd[0]),'stdout_sha256':h(r.stdout.encode()),'catalog_memberships_compared':len(fresh)},
  'verified_source_counts':{'fragments':len(fragments),'instructions':sum(len(f['instructions'])for f in fragments.values()),
   'fragment_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fragments.values()),'branch_bindings':len(edges),'import_bindings':len(imports),'pointer_records':len(slots),
   'prior_source_ranges':len(recaptures),'prior_source_bytes':sum(r['bytes_checked']for r in recaptures),'historical_send_profiles':12,'excluded_profiles':4},**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
