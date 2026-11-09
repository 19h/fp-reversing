#!/usr/bin/env python3
"""Static original-image XPC data/copy/initial-record contract capture.
No recovered code execution, emulation, native request or IDB mutation.
O(B+F+I+256K) time/space; B image, F fixups, I instructions, K bank cases.
"""
import json,re,struct,subprocess
from recover_daemon_xpc_listener import ROOT,IMAGE,SOURCE,FIXUPS,CS,TABLE,POOL,qword,selected,block,verify_original_fixups,binding,SDK,sha,h,A,B,C,D,E
P='daemon_xpc_payload'
FLAGS=['target_executed','target_emulated','FairPlay_requests_sent','native_listener_identity_proved','native_peer_identity_proved','native_authorization_proved','hardware_PAC_checked','IDB_mutated','full_goal_complete']
FRAGMENTS={
 'entry':0x100b27b78,'type_gate':0x100b09274,'dictionary_gate':0x100b07a54,
 'get_data':0x100ad1240,'allocate_data':0x100ba9a14,'copy_gate':0x100a68d94,
 'copy_prepare':0x100a80f48,'copy_tail':0x100a7cedc,'copy_group_gate':0x100c3dc60,
 'copy_group':0x100a35fb8,'copy_done':0x100c09f90,'encode_length':0x100aa5588,
 'allocate_record':0x100c6f0b0,'zero_record':0x100c032dc,'record_loop_gate':0x100b22fe4,
 'record_nonempty':0x100ad9f78,'record_minimum':0x100ba9504,'record_extent':0x100a6c060,
 'record_failure':0x100bd9558,'empty_result':0x100c8f210,'cleanup':0x100b12c30}
SPECS=[('get_type',E,0x81,0xccec,TABLE,0),('error_type',D,0x54,0x4da,POOL,0),
 ('dictionary_type',D,0x78,0x1253,POOL,0),('get_data',B,0xbb,0xcbe8,TABLE,0),
 ('data_key',E,0x56,0x1295,POOL,0xfffffffff279fd69),
 ('classic_header',B,0x4e,0xa6e,POOL,0xffffffffc53e9a7d),
 ('allocate_data',A,0xf3,0xcbca,TABLE,0),('allocate_record',C,0x86,0xcbb5,TABLE,0)]
CALLS=[('get_type',0x100b092dc),('get_data',0x100ad12bc),('allocate_data',0x100ba9a70),('allocate_record',0x100c6f154)]
# role, source fragment, index, original target. Branch conditions are separately verified.
BRANCHES=[
 ('core_error','type_gate',0xcb2f,0x100a15240),('core_nonerror','type_gate',0xcb34,0x100b07a54),
 ('dictionary','dictionary_gate',0xc762,0x100ad1240),('not_dictionary','dictionary_gate',0xa25b,0x100b12c30),
 ('data_present','get_data',0xb897,0x100ba9a14),('data_null','get_data',0xb8c2,0x100b12c30),
 ('allocation_ok','allocate_data',0xb615,0x100a68d94),('allocation_null','allocate_data',0xb66d,0x100b12c30),
 ('copy_zero','copy_gate',0xbf79,0x100aa5588),('copy_nonzero','copy_gate',0xbf7c,0x100a80f48),
 ('tail_zero','copy_prepare',0x23b7,0x100c3dc60),('tail_nonzero','copy_prepare',0x23b9,0x100a7cedc),
 ('tail_repeat','copy_tail',0x23b9,0x100a7cedc),('tail_done','copy_tail',0x23b7,0x100c3dc60),
 ('groups_needed','copy_group_gate',0x19b8,0x100a35fb8),('groups_skip','copy_group_gate',0x196c,0x100c09f90),
 ('group_repeat','copy_group',0x19b8,0x100a35fb8),('group_done','copy_group',0x196c,0x100c09f90),
 ('copy_join','copy_done',0x5fcf,0x100aa5588),('length_encoded','encode_length',0x3815,0x100c6f0b0),
 ('record_allocation_ok','allocate_record',0xb21e,0x100c032dc),('record_allocation_null','allocate_record',0xb1f9,0x100c4dc4c),
 ('record_zeroed','zero_record',0x2282,0x100b22fe4),('record_empty','record_loop_gate',0x3b5c,0x100c8f210),
 ('record_nonempty','record_loop_gate',0x6b0c,0x100ad9f78),('record_source_present','record_nonempty',0x5c7f,0x100ba9504),
 ('record_source_null','record_nonempty',0x5c78,0x100bd9558),('record_has_header','record_minimum',0x2eba,0x100a6c060),
 ('record_short','record_minimum',0x2edb,0x100bd9558),('record_fits','record_extent',0x6aaa,0x100cc0944),
 ('record_exceeds','record_extent',0x6a6b,0x100bd9558)]

def build():
 prior=json.loads((ROOT/'daemon_xpc_listener_source.json').read_text())
 fragments={}
 for name,a in FRAGMENTS.items():
  f=block(a);f['sha256']=h(bytes.fromhex(f['bytes']));fragments[name]=f
 for name,old in [('entry','protected_entry'),('type_gate','protected_nonnull'),('cleanup','protected_null')]:
  assert fragments[name]['bytes']==prior['fragments'][old]['bytes']
 banks={}
 for name,pair,key,add,base,bias in SPECS:
  r=selected(*pair,key,add,base,bias);l,rr=IMAGE.read(pair[0],256),IMAGE.read(pair[1],256)
  r.update(left_bytes=l.hex(),right_bytes=rr.hex(),results_256=[i^rr[l[i]^key]for i in range(256)]);banks[name]=r
 calls=[];slots={int(r['slot'],16)for r in banks.values()}
 for name,pc in CALLS:
  r=banks[name];slot=int(r['slot'],16);ii=list(CS.disasm(IMAGE.read(pc-4,8),pc-4));assert ii[0].mnemonic=='mov'and ii[1].mnemonic=='blraa'
  mod=int(ii[0].op_str.split('#')[1],0);word=struct.unpack('<Q',IMAGE.read(slot,8))[0]
  assert word>>63 and((word>>32)&65535)==mod and not(word>>48&1)and not(word>>49&3)
  calls.append({'role':name,'site':hex(pc),'slot':hex(slot),'target':r['target'],'modifier_u16':mod,'bytes':IMAGE.read(pc-4,8).hex(),'pointer_word':hex(word)})
 branches=[]
 for name,source,ix,target in BRANCHES:
  ii=fragments[source]['instructions'];assert ii[-1]['mnemonic']=='braa'and ii[-2]['mnemonic']=='mov'
  mod=int(ii[-2]['operands'].split('#')[1],0);slot=TABLE+8*ix;word=struct.unpack('<Q',IMAGE.read(slot,8))[0]
  assert qword(slot)==target and word>>63 and((word>>32)&65535)==mod and not(word>>48&1)and not(word>>49&3)
  slots.add(slot);branches.append({'role':name,'source':source,'site':ii[-1]['ea'],'index':hex(ix),'slot':hex(slot),'target':hex(target),'modifier_u16':mod,'pointer_word':hex(word)})
 imports=[binding(a)for a in sorted(slots)if isinstance(FIXUPS[a]['target'],str)]
 pointers=verify_original_fixups([a for a in slots if not isinstance(FIXUPS[a]['target'],str)or FIXUPS[a]['kind'].startswith('auth-')])
 cmd=['/usr/bin/dyld_info','-fixups',str(SOURCE)];r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0 and not r.stderr
 fresh={}
 for line in r.stdout.splitlines():
  m=re.match(r'\s+\S+\s+\S+\s+(0x[0-9a-fA-F]+)\s+(\S+)\s+(\S+)(.*)',line)
  if m:fresh[int(m[1],16)]=line.strip()
 assert set(fresh)==set(FIXUPS)
 for a in slots:assert fresh[a]==FIXUPS[a]['line']
 headers=[SDK/'usr/include/xpc/xpc.h',SDK/'usr/include/stdlib.h',SDK/'usr/include/mach/message.h']
 deps=['daemon_receive_tools.py','daemon_import_bindings.py','daemon_receive_fixups.txt','recover_daemon_xpc_listener.py','daemon_xpc_listener_source.json','daemon_xpc_listener_checks.json','daemon_registration_contracts.json']
 return {'generator_sha256':sha(__file__),'daemon_path':str(SOURCE),'daemon_sha256':sha(SOURCE),
  'dependencies':{n:sha(ROOT/n)for n in deps},'fragments':fragments,'banks':banks,'calls':calls,'branches':branches,
  'selected_pointer_records':[{'slot':hex(a),'raw_bytes':IMAGE.read(a,8).hex(),'fixup':FIXUPS[a]}for a in sorted(slots)],'imports':imports,'original_pointer_checks':pointers,
  'data_key':{'address':'0x100e86130','bytes':IMAGE.read(0x100e86130,5).hex()},
  'fixup_reference':{'command':cmd,'stdout_sha256':h(r.stdout.encode()),'catalog_memberships_compared':len(fresh),'selected_lines':{hex(a):fresh[a]for a in sorted(slots)}},
  'SDK_headers':[{'path':str(p),'size_bytes':p.stat().st_size,'sha256':sha(p)}for p in headers],
  'inspection_tools':[{'path':'/usr/bin/dyld_info','sha256':sha('/usr/bin/dyld_info')}],
  'verified_source_counts':{'fragments':len(fragments),'instructions':sum(len(f['instructions'])for f in fragments.values()),'fragment_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fragments.values()),'bank_cases':len(banks),'bank_inputs_checked':256*len(banks),'resolved_calls':len(calls),'branch_bindings':len(branches),'imports':len(imports),'selected_pointer_records':len(slots),'fixup_catalog_memberships_compared':len(fresh)},**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
