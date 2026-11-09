#!/usr/bin/env python3
"""Original listener/callback/type-gate and protected-entry ABI capture.
No target execution/emulation, native XPC request or IDB mutation.
O(image bytes + fixups + selected code + 256*bank cases) time/space.
"""
import bisect,json,re,struct,subprocess
from pathlib import Path
from daemon_receive_tools import ROOT,IMAGE,SOURCE,FIXUPS,CS,TABLE,POOL,qword,selected,block,verify_original_fixups
from daemon_import_bindings import binding
from bootpolicy_cache_reader import uleb
from recover_launchd_variant_binding import SDK,sha,h
from resolve_kernel_collection_interfaces import commands
P='daemon_xpc_listener'
FLAGS=['target_executed','target_emulated','FairPlay_requests_sent','native_listener_identity_proved','native_peer_identity_proved','native_authorization_proved','hardware_PAC_checked','IDB_mutated','full_goal_complete']
A=(0x100fc4230,0x101031fa0);B=(0x100fc4130,0x101031ea0);C=(0x101031da0,0x100e99900);D=(0x100e99a00,0x100f4e390);E=(0x100e99700,0x100f4e190);F=(0x100e99800,0x100f4e290)
# label,pair,key,index addition,pointer table,post-load bias
SPECS=[
 ('listener_create',E,0x81,0xccbe,TABLE,0),('service_name',D,0x6d,0x103f,POOL,0xffffffffb9e13b49),('main_queue',B,0xbb,0x66a,POOL,0),
 ('listener_block_isa',D,0xd7,0x5ef,POOL,0),('listener_block_descriptor',C,0xa,-0xe2,POOL,0xffffffffc9ae9cf6),('listener_set_handler',C,0x86,0xccf3,TABLE,0),('listener_activate',C,0x9a,0xce3b,TABLE,0),
 ('peer_target_queue',A,0xf3,0xcd31,TABLE,0),('peer_block_isa',A,0x6c,0x5f4,POOL,0),('peer_block_descriptor',A,0xe4,0xd6f,POOL,0xffffffffc05f330a),('peer_set_handler',D,0x6d,0xcc7b,TABLE,0),('peer_resume',A,0x6c,0xcc6b,TABLE,0),
 ('event_get_type',A,0xf3,0xccf1,TABLE,0),('event_dispatch_base',E,0x56,0x906,POOL,0xffffffffd0c4d1ee),('event_error_type',C,0x9a,0x4ab,POOL,0),('event_type_recheck',E,0x81,0xccec,TABLE,0),('event_dictionary_type',F,0x61,0x12db,POOL,0),('invalid_error_object',E,0x56,0xab0,POOL,0),
 ('message_adapter',B,0x4e,0xccff,TABLE,0),('cancel_other',D,0x54,0xcbdc,TABLE,0),('cancel_invalid',A,0xe4,0xcc35,TABLE,0),('adapter_dispatch_base',C,0xa,0x830,POOL,0xffffffffd0c4d1ee),('protected_entry',D,0x54,0xcdd3,TABLE,0),
 ('caller_stack_seed',B,0xbb,0x1ac,POOL,0xffffffffc4cf3581),('adapter_stack_seed',C,0x9a,0x182,POOL,0xffffffffc4cf3581),('audit_clear',C,0x9a,0xcbb6,TABLE,0),('audit_token',B,0xbb,0xccc5,TABLE,0),('core_get_type',E,0x81,0xccec,TABLE,0),('core_dispatch_base',B,0x4e,0x81b,POOL,0xffffffffd0c4d1ee)]
CALLS=[('listener_create',0x1000935e4),('listener_set_handler',0x1000b2878),('listener_activate',0x1000b28c8),('peer_target_queue',0x100007948),('peer_set_handler',0x100007a70),('peer_resume',0x100007ab0),('event_get_type',0x10044d4f8),('event_type_recheck',0x1001c8e6c),('message_adapter',0x100288c78),('cancel_other',0x100157324),('cancel_invalid',0x1001bceb8),('protected_entry',0x100ba82e8),('audit_clear',0x100b27e3c),('audit_token',0x100b27ea8),('core_get_type',0x100b092dc)]
COMPLETE={'peer_callback':0x10000778c,'event_callback':0x10044d2fc,'message_adapter':0x100ba80a8,'audit_clear':0x10046faf8}
FRAGMENTS={'listener_create':0x100093518,'listener_install':0x1000b2748,'error_event':0x1002fa1ac,'other_event':0x1001c8e2c,'forward_record':0x100288b38,'cancel_other':0x1001572a8,'cancel_invalid':0x1001bce68,'event_return':0x10016b184,'protected_entry':0x100b27b78,'protected_nonnull':0x100b09274,'protected_null':0x100b12c30}

def unwrap(result):
 t=next(q['text']for q in result['content']if q['type']=='text'and'[assist:tool-output]\n'in q['text'])
 return json.loads(t.split('[assist:tool-output]\n',1)[1].split('\n[/assist:tool-output]',1)[0])

def build():
 starts=[]
 for at,cmd,n in commands(IMAGE.data,0):
  if cmd==0x26:
   off,z=struct.unpack_from('<II',IMAGE.data,at+8);bb=IMAGE.data[off:off+z];i=0;a=0x100000000
   while i<len(bb):
    d,i=uleb(bb,i)
    if not d:break
    a+=d;starts.append(a)
 def capture(a,z,complete=False):
  raw=IMAGE.read(a,z-a);ii=list(CS.disasm(raw,a));assert len(ii)*4==len(raw);ix=bisect.bisect_right(starts,a)-1
  return{'start':hex(a),'end':hex(z),'bytes':raw.hex(),'sha256':h(raw),'compiler_start':hex(starts[ix]),'next_compiler_start':hex(starts[ix+1]),'complete_compiler_body':complete,'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]}
 bodies={label:capture(a,starts[starts.index(a)+1],True)for label,a in COMPLETE.items()}
 fragments={label:capture(a,int(block(a)['end'],16))for label,a in FRAGMENTS.items()}
 banks={}
 for label,pair,key,add,base,bias in SPECS:
  r=selected(*pair,key,add,base,bias);l,rbytes=IMAGE.read(pair[0],256),IMAGE.read(pair[1],256);r.update(left_bytes=l.hex(),right_bytes=rbytes.hex(),results_256=[i^rbytes[l[i]^key]for i in range(256)]);banks[label]=r
 calls=[]
 for label,pc in CALLS:
  r=banks[label];slot=int(r['slot'],16);bb=IMAGE.read(pc-4,8);ii=list(CS.disasm(bb,pc-4));assert len(ii)==2 and ii[0].mnemonic=='mov'and ii[0].op_str.startswith('x17, #')and ii[1].mnemonic=='blraa'
  mod=int(ii[0].op_str.split('#')[1],0);word=struct.unpack('<Q',IMAGE.read(slot,8))[0];assert word>>63 and((word>>32)&65535)==mod and not(word>>48&1)and(word>>49&3)==0
  calls.append({'role':label,'site':hex(pc),'slot':hex(slot),'target':r['target'],'modifier_u16':mod,'bytes':bb.hex(),'pointer_word':hex(word)})
 slots={int(r['slot'],16)for r in banks.values()};imports=[binding(a)for a in sorted(slots)if isinstance(FIXUPS[a]['target'],str)]
 for a in[0x101038348+16,0x1010382e8+16]:slots.add(a)
 pointer_checks=verify_original_fixups([a for a in slots if not isinstance(FIXUPS[a]['target'],str)or FIXUPS[a]['kind'].startswith('auth-')])
 descriptors=[]
 for role in['listener_block_descriptor','peer_block_descriptor']:
  a=int(banks[role]['target'],16);sig=qword(a+16);text=IMAGE.read(sig,100).split(b'\0')[0];descriptors.append({'role':role,'address':hex(a),'prefix24_bytes':IMAGE.read(a,24).hex(),'reserved_u64':struct.unpack('<Q',IMAGE.read(a,8))[0],'block_size_bytes':struct.unpack('<Q',IMAGE.read(a+8,8))[0],'signature_pointer_record':FIXUPS[a+16],'signature_address':hex(sig),'signature_bytes':(text+b'\0').hex(),'signature':text.decode()})
 origins=[]
 for off,bias,want in[(0x60f0,0xffffffffa75b1642,A[0]),(0x2240,0xfffffffffa184636,A[1]),(0x29c8,0xffffffffaa591739,B[0]),(0x4c18,0xffffffff8af86dcd,B[1]),(0x1658,0xffffffffa6e7fab5,D[0]),(0x26a0,0xffffffff9d07c0b2,D[1]),(0x6188,0xffffffffdc8ddf91,E[0]),(0x3030,0xffffffffc6a5784a,E[1]),(0x6640,0xffffffffdaeb98b6,F[0]),(0x4048,0xffffffffb971d649,F[1])]:
  slot=POOL+off;target=(qword(slot)+bias)&((1<<64)-1);assert target==want;slots.add(slot);origins.append({'slot':hex(slot),'bias':hex(bias),'result':hex(target),'raw_bytes':IMAGE.read(slot,8).hex(),'fixup':FIXUPS[slot]})
 pointer_checks=verify_original_fixups([a for a in slots if not isinstance(FIXUPS[a]['target'],str)or FIXUPS[a]['kind'].startswith('auth-')])
 branches=[]
 for role,ix,mod in[('error_type',0xa777,0xbe0c),('not_error_type',0xa7d7,0xbe0c),('dictionary',0xab7f,0x21ae),('other_nondictionary',0xaba5,0x21ae),('error_invalid',0x68fd,0x5122),('error_other',0x68f4,0x5122),('event_return',0x3a8a,0x7732),('core_nonnull',0x77a0,0xab60),('core_null',0x77ae,0xab60)]:
  slot=TABLE+ix*8;w=struct.unpack('<Q',IMAGE.read(slot,8))[0];assert w>>63 and((w>>32)&65535)==mod;slots.add(slot);branches.append({'role':role,'index':hex(ix),'slot':hex(slot),'target':hex(qword(slot)),'modifier_u16':mod,'pointer_word':hex(w),'fixup':FIXUPS[slot]})
 cmd=['/usr/bin/dyld_info','-fixups',str(SOURCE)];result=subprocess.run(cmd,capture_output=True,text=True);assert result.returncode==0 and not result.stderr
 fresh={}
 for line in result.stdout.splitlines():
  m=re.match(r'\s+\S+\s+\S+\s+(0x[0-9a-fA-F]+)\s+(\S+)\s+(\S+)(.*)',line)
  if m:fresh[int(m[1],16)]=line.strip()
 assert set(fresh)==set(FIXUPS)
 for a in slots:assert fresh[a]==FIXUPS[a]['line']
 fixref={'command':cmd,'exit_code':result.returncode,'stdout_sha256':h(result.stdout.encode()),'catalog_memberships_compared':len(fresh),'selected_lines':{hex(a):fresh[a]for a in sorted(slots)}}
 cmd=['/usr/bin/dyld_info','-function_starts',str(SOURCE)];result=subprocess.run(cmd,capture_output=True,text=True);assert result.returncode==0 and not result.stderr
 found=[int(x,16)for x in re.findall(r'^\s+(0x[0-9a-fA-F]+)\s',result.stdout,re.M)];assert found==starts
 startref={'command':cmd,'exit_code':result.returncode,'stdout_sha256':h(result.stdout.encode()),'starts_compared':len(found)}
 ida=json.loads((ROOT/(P+'_ida.json')).read_text());facts=unwrap(ida['facts']);assert dict((r['key'],r['value'])for r in facts['rows'])['input_sha256']=='4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7'
 matched=[]
 for r in unwrap(ida['byte_readback'])['results']:
  bb=bytes.fromhex(r['bytes']);assert IMAGE.read(int(r['address'],16),len(bb))==bb;matched.append({'address':r['address'],'bytes_checked':len(bb),'sha256':h(bb),'match':True})
 sdk_headers=[SDK/'usr/include/xpc/connection.h',SDK/'usr/include/xpc/xpc.h',SDK/'usr/include/dispatch/queue.h',SDK/'usr/include/mach/message.h',SDK/'usr/include/Block.h']
 ptrs=[{'slot':hex(a),'raw_bytes':IMAGE.read(a,8).hex(),'fixup':FIXUPS[a]}for a in sorted(slots)]
 ranges=list(bodies.values())+list(fragments.values());deps=['daemon_receive_tools.py','daemon_import_bindings.py','daemon_receive_fixups.txt','resolve_kernel_collection_interfaces.py','verify_interface_contracts.py',P+'_ida.json','daemon_registration_contracts.json']
 frame={'scope':'Declared inputs for the two flattened startup fragments; original whole-main reachability, intervening aliases and native object identity remain unproved.',
  'create_listener':{'registers':{'X28':hex(TABLE),'X23':hex(POOL),'X25':hex(D[0])},'SP_pointer_slots':{'0x98':hex(E[0]),'0xf8':hex(E[1]),'0x100':hex(D[1]),'0xe0':hex(B[0]),'0xb8':hex(B[1])}},
  'install_listener_handler':{'registers':{'X28':hex(TABLE),'X23':hex(POOL),'X22':hex(D[0]),'X21':hex(D[1]),'X24':'queue object supplied by creation contract','X0':'listener object supplied by caller'},'SP_pointer_slots':{'0x170':hex(C[0]),'0x178':hex(C[1])}}}
 return{'generator_sha256':sha(__file__),'daemon_path':str(SOURCE),'daemon_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in deps},'complete_functions':bodies,'fragments':fragments,'banks':banks,'calls':calls,'branches':branches,'biased_bank_origins':origins,'selected_pointer_records':ptrs,'original_pointer_checks':pointer_checks,'imports':imports,'block_descriptors':descriptors,'service_literal':{'address':'0x100f23670','bytes':IMAGE.read(0x100f23670,24).hex(),'preceding_byte':IMAGE.read(0x100f2366f,1).hex()},'frame_contract':frame,'fixup_reference':fixref,'compiler_starts_reference':startref,'IDA_matches':matched,
  'SDK_headers':[{'path':str(p),'size_bytes':p.stat().st_size,'sha256':sha(p)}for p in sdk_headers],'inspection_tools':[{'path':p,'sha256':sha(p)}for p in['/usr/bin/dyld_info','/usr/bin/clang']],
  'verified_source_counts':{'complete_functions':len(bodies),'fragments':len(fragments),'instructions':sum(len(r['instructions'])for r in ranges),'function_and_fragment_bytes':sum(len(bytes.fromhex(r['bytes']))for r in ranges),'bank_cases':len(banks),'bank_inputs_checked':len(banks)*256,'resolved_calls':len(calls),'branch_bindings':len(branches),'biased_bank_origins':len(origins),'block_descriptors':len(descriptors),'imports':len(imports),'selected_pointer_records':len(ptrs),'compiler_starts_compared':len(starts),'fixup_catalog_memberships_compared':len(fresh),'IDA_ranges_matched':len(matched),'IDA_bytes_matched':sum(r['bytes_checked']for r in matched)},**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
