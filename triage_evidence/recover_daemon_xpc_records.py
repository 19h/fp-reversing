#!/usr/bin/env python3
"""Original-image record discriminator, value ABI and constructor capture.
Static only. O(B+F+I+256K) time/space; no target execution or native request.
"""
import json,re,struct,subprocess
from recover_daemon_xpc_payload import ROOT,IMAGE,SOURCE,FIXUPS,CS,TABLE,POOL,qword,selected,block,verify_original_fixups,binding,SDK,sha,h,D,FLAGS
P='daemon_xpc_records'
FRAGMENTS={
 'header':0x100cc0944,'signed_root':0x100d31e14,'signed_lower':0x100ab2cfc,'signed_ge':0x100aa9478,
 'middle':0x100d431c0,'upper':0x100cb31bc,'u32_extent':0x100b09c1c,'u64_extent':0x100c2bf48,
 'u32_value':0x100a8a6b4,'u64_value':0x100a611b8,'value_join':0x100a18fcc,'variable':0x100a85d74,
 'argument_load':0x100ab3e34,'local_record':0x100a86128,'object_gate':0x100a7c454,
 'allocate_object':0x1009ba4dc,'allocate_buffer':0x100a41df0,'buffer_ready':0x100bd6680,
 'allocation_cleanup_frontier':0x100c0b788,'helper_return':0x100c29a88,'failure':0x100bd9558,
 'result':0x100c8f210,'publish_result':0x100c044d4,
 'inherited_allocate_record':0x100c6f0b0,'inherited_extent':0x100a6c060}
SPECS=[('allocate_object',D,0x6d,0xcb3d),('allocate_buffer',D,0x78,0xcb6c)]
CALLS=[('allocate_object',0x1009ba548),('allocate_buffer',0x100a41f48)]
BRANCHES=[
 ('header_decoded','header',0xcb09,0x100d31e14),('signed_lt','signed_root',0x35bf,0x100ab2cfc),('signed_ge','signed_root',0x35aa,0x100aa9478),
 ('type9777','signed_lower',0x587c,0x100b09c1c),('lower_reject','signed_lower',0x2edb,0x100bd9558),
 ('middle_range','signed_ge',0x9b15,0x100d431c0),('upper_range','signed_ge',0x9af4,0x100cb31bc),
 ('type8485','middle',0xb7ff,0x100c2bf48),('middle_reject','middle',0x6a6b,0x100bd9558),
 ('type50db','upper',0x48b9,0x100a85d74),('upper_reject','upper',0x2edb,0x100bd9558),
 ('u32_extent4','u32_extent',0x9736,0x100a8a6b4),('u32_other_extent','u32_extent',0x2edb,0x100bd9558),
 ('u64_extent8','u64_extent',0x8b4d,0x100a611b8),('u64_other_extent','u64_extent',0x5c78,0x100bd9558),
 ('u32_join','u32_value',0x43bb,0x100a18fcc),('u64_join','u64_value',0x43bb,0x100a18fcc),
 ('scalar_arguments','value_join',0x3b60,0x100ab3e34),('variable_tag_nonzero','variable',0x3b60,0x100ab3e34),('variable_tag_zero','variable',0x3b5c,0x100c8f210),
 ('arguments','argument_load',0x5d2e,0x100a86128),('object_present','local_record',0xc0f3,0x100a7c454),('object_null','local_record',0xc0e5,0x100c29a88),
 ('extent_admissible','object_gate',0xa40f,0x1009ba4dc),('extent_reject','object_gate',0x5938,0x100c29a88),
 ('object_allocated','allocate_object',0xb8e1,0x100a41df0),('object_allocation_null','allocate_object',0xb901,0x100c0b788),
 ('buffer_allocated','allocate_buffer',0xb202,0x100bd6680),('buffer_allocation_null','allocate_buffer',0xb21c,0x100c0b788),
 ('buffer_ready_frontier','buffer_ready',0x3b96,0x100b067d8),('saved_helper_continuation','helper_return',0x21f,0x1009e1230),
 ('publish_Q','result',0x5f5a,0x100c044d4),('post_result_frontier','publish_result',0x893a,0x100c4dc4c)]
def build():
 fragments={}
 for name,a in FRAGMENTS.items():
  f=block(a);f['sha256']=h(bytes.fromhex(f['bytes']));fragments[name]=f
 prior=json.loads((ROOT/'daemon_xpc_payload_source.json').read_text())
 for name,old in [('inherited_allocate_record','allocate_record'),('inherited_extent','record_extent'),('failure','record_failure'),('result','empty_result')]:assert fragments[name]['bytes']==prior['fragments'][old]['bytes']
 banks={}
 for name,pair,key,add in SPECS:
  r=selected(*pair,key,add);l,rr=IMAGE.read(pair[0],256),IMAGE.read(pair[1],256)
  r.update(left_bytes=l.hex(),right_bytes=rr.hex(),results_256=[i^rr[l[i]^key]for i in range(256)]);banks[name]=r
 slots={int(r['slot'],16)for r in banks.values()};calls=[]
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
 headers=[SDK/'usr/include/stdint.h',SDK/'usr/include/stdlib.h',SDK/'usr/include/stddef.h']
 deps=['recover_daemon_xpc_payload.py','daemon_xpc_payload_source.json','daemon_xpc_payload_checks.json','daemon_receive_tools.py','daemon_receive_fixups.txt','daemon_import_bindings.py']
 return {'generator_sha256':sha(__file__),'daemon_path':str(SOURCE),'daemon_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in deps},
  'fragments':fragments,'banks':banks,'calls':calls,'branches':branches,'imports':[binding(a)for a in sorted(slots)if isinstance(FIXUPS[a]['target'],str)],
  'selected_pointer_records':[{'slot':hex(a),'raw_bytes':IMAGE.read(a,8).hex(),'fixup':FIXUPS[a]}for a in sorted(slots)],'original_pointer_checks':verify_original_fixups(slots),
  'fixup_reference':{'command':cmd,'stdout_sha256':h(r.stdout.encode()),'catalog_memberships_compared':len(fresh),'selected_lines':{hex(a):fresh[a]for a in sorted(slots)}},
  'SDK_headers':[{'path':str(p),'size_bytes':p.stat().st_size,'sha256':sha(p)}for p in headers],'inspection_tools':[{'path':'/usr/bin/dyld_info','sha256':sha('/usr/bin/dyld_info')}],
  'verified_source_counts':{'fragments':len(fragments),'instructions':sum(len(f['instructions'])for f in fragments.values()),'fragment_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fragments.values()),'bank_cases':len(banks),'bank_inputs_checked':256*len(banks),'resolved_calls':len(calls),'branch_bindings':len(branches),'imports':1,'selected_pointer_records':len(slots),'fixup_catalog_memberships_compared':len(fresh)},**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
