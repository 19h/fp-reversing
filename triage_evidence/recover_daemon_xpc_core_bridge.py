#!/usr/bin/env python3
"""Original-image XPC consumer fork, audit handoff and shared-core caller bridge.
Static only. O(B+F+I+256K) time/space; no target execution or native request.
"""
import json,re,struct,subprocess
from recover_daemon_xpc_payload import ROOT,IMAGE,SOURCE,FIXUPS,CS,TABLE,POOL,qword,selected,block,verify_original_fixups,binding,SDK,sha,h,D,FLAGS
from recover_daemon_xpc_listener import A,B,C,F,uleb
from resolve_kernel_collection_interfaces import commands
P='daemon_xpc_core_bridge'
FRAGMENTS={
 'consumer':0x100d281ac,'lower_test':0x100d9f5b0,'upper_test':0x100bde624,
 'fallback':0x100a86c64,'special_lower':0x100aa689c,'special_upper':0x100c54704,
 'getter_length':0x100ca22c0,'getter_firstword':0x100a61ba0,'getter_tag_call':0x100ba8c48,
 'fallback_adapter':0x10065ffd8,'getter_tag_decoder':0x1009e57e0,'getter_tag_return':0x100be4edc,'value_load':0x100c65c9c}
COMPLETE={'copy_helper':(0x10046f89c,0x10046faf8)}
SPECS=[('fallback_copy',C,0xa,0xcac9,TABLE,0),('lower_copy',F,0x61,0xcb9a,TABLE,0),
 ('fallback_adapter',A,0xe4,0xcc8c,TABLE,0),('lower_acquire',B,0x4e,0xcaf4,TABLE,0),
 ('upper_malloc',F,0x61,0xcbf4,TABLE,0),('protected_core',A,0x6c,0xce92,TABLE,0),
 ('budget_cell',D,0x6d,0xcbb,POOL,0xffffffffc7024c75)]
CALLS=[('fallback_copy',0x100a86d04),('lower_copy',0x100aa6928),('fallback_adapter',0x100a86e3c),('lower_acquire',0x100aa6a14),('upper_malloc',0x100c54774),('protected_core',0x10066022c)]
BRANCHES=[('consumer_lt','consumer',0xb4ae,0x100d9f5b0),('consumer_ge','consumer',0xb4ad,0x100bde624),
 ('lower_equal','lower_test',0xa637,0x100aa689c),('lower_other','lower_test',0x2d1d,0x100a86c64),
 ('upper_equal','upper_test',0x2d1b,0x100c54704),('upper_other','upper_test',0x2d1d,0x100a86c64),
 ('fallback_return','fallback',0x4f79,0x100000000),
 ('getter_tag_decoder','getter_tag_call',0x3221,0x1009e57e0),('getter_tag_return','getter_tag_decoder',0x96e,0x100be4edc)]
# The unknown downstream fallback target is recorded from the original table;
# no semantic name or whole return behavior is assigned to it.
BRANCHES=[(n,f,ix,qword(TABLE+ix*8)if target==0x100000000 else target)for n,f,ix,target in BRANCHES]
PRIOR_FILES=['daemon_operation_heads_source.json','daemon_rpc502_contracts.json','daemon_mig_handover_source.json','daemon_iokit_sync_contracts.json','daemon_record40_consumer_contracts.json']
PRIOR_PROOFS=['daemon_operation_heads_constructor_100a86d70_aligned_prekey_original.smt2','daemon_operation_heads_constructor_100a86d70_all_key32_codec_original.smt2','daemon_operation_heads_nested_tag6cf4_iff_phase4f79_original.smt2']

def build():
 fragments={}
 for name,a in FRAGMENTS.items():
  f=block(a,0x4000);assert f['instructions'][-1]['mnemonic']in('braa','retab');f['sha256']=h(bytes.fromhex(f['bytes']));fragments[name]=f
 functions={}
 for name,(a,z)in COMPLETE.items():
  bb=IMAGE.read(a,z-a);ii=list(CS.disasm(bb,a));assert len(bb)==4*len(ii)
  functions[name]={'start':hex(a),'end':hex(z),'bytes':bb.hex(),'sha256':h(bb),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]}
 fragments.update(functions)
 starts=[]
 for at,cmd,n in commands(IMAGE.data,0):
  if cmd==0x26:
   off,size=struct.unpack_from('<II',IMAGE.data,at+8);raw=IMAGE.data[off:off+size];i=0;a=0x100000000
   while i<len(raw):
    delta,i=uleb(raw,i)
    if not delta:break
    a+=delta;starts.append(a)
 for name,(a,z)in COMPLETE.items():assert starts[starts.index(a)+1]==z
 cmd=['/usr/bin/dyld_info','-function_starts',str(SOURCE)];sr=subprocess.run(cmd,capture_output=True,text=True);assert sr.returncode==0 and not sr.stderr
 assert [int(x,16)for x in re.findall(r'^\s+(0x[0-9a-fA-F]+)\s',sr.stdout,re.M)]==starts
 recaptures=[]
 def walk(obj,file,path=''):
  if isinstance(obj,dict):
   data=obj.get('bytes',obj.get('bytes_hex'));a=obj.get('start')
   if isinstance(data,str)and isinstance(a,str)and a.startswith('0x'):
    bb=bytes.fromhex(data);assert IMAGE.read(int(a,16),len(bb))==bb,(file,path,a)
    recaptures.append({'file':file,'path':path,'start':a,'bytes_checked':len(bb),'sha256':h(bb)})
   for k,v in obj.items():walk(v,file,path+'/'+k)
  elif isinstance(obj,list):
   for j,v in enumerate(obj):walk(v,file,path+'/'+str(j))
 for name in PRIOR_FILES:walk(json.loads((ROOT/name).read_text()),name)
 banks={}
 for name,pair,key,add,base,bias in SPECS:
  r=selected(*pair,key,add,base,bias);l,rr=IMAGE.read(pair[0],256),IMAGE.read(pair[1],256)
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
 headers=[SDK/'usr/include/stdint.h',SDK/'usr/include/stdlib.h',SDK/'usr/include/stddef.h',SDK/'usr/include/xpc/xpc.h',SDK/'usr/include/mach/message.h']
 deps=['recover_daemon_xpc_iteration.py','daemon_xpc_iteration_source.json','daemon_xpc_iteration_checks.json','daemon_xpc_listener_source.json','daemon_xpc_payload_source.json','daemon_operation_heads_proofs.json','daemon_core_dispatch_proofs.json','daemon_mig_handover_proofs.json','daemon_record40_consumer_proofs.json','daemon_receive_tools.py','daemon_receive_fixups.txt','daemon_import_bindings.py']+PRIOR_FILES+PRIOR_PROOFS
 return {'generator_sha256':sha(__file__),'daemon_path':str(SOURCE),'daemon_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in deps},
  'fragments':fragments,'complete_functions':list(COMPLETE),'prior_source_recaptures':recaptures,'prior_obligations':[{'path':n,'sha256':sha(ROOT/n)}for n in PRIOR_PROOFS],'adapter_compiler_span':{'start':'0x10065ffd8','next_start':hex(starts[starts.index(0x10065ffd8)+1]),'selected_return_end':'0x100660254'},'compiler_starts_reference':{'command':['/usr/bin/dyld_info','-function_starts',str(SOURCE)],'starts_compared':len(starts),'stdout_sha256':h(sr.stdout.encode())},'banks':banks,'calls':calls,'branches':branches,'imports':[binding(a)for a in sorted(slots)if isinstance(FIXUPS[a]['target'],str)],
  'selected_pointer_records':[{'slot':hex(a),'raw_bytes':IMAGE.read(a,8).hex(),'fixup':FIXUPS[a]}for a in sorted(slots)],'original_pointer_checks':verify_original_fixups(slots),
  'fixup_reference':{'command':cmd,'stdout_sha256':h(r.stdout.encode()),'catalog_memberships_compared':len(fresh),'selected_lines':{hex(a):fresh[a]for a in sorted(slots)}},
  'SDK_headers':[{'path':str(p),'size_bytes':p.stat().st_size,'sha256':sha(p)}for p in headers],'inspection_tools':[{'path':'/usr/bin/dyld_info','sha256':sha('/usr/bin/dyld_info')}],
  'verified_source_counts':{'fragments':len(fragments),'instructions':sum(len(f['instructions'])for f in fragments.values()),'fragment_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fragments.values()),'bank_cases':len(banks),'bank_inputs_checked':256*len(banks),'resolved_calls':len(calls),'branch_bindings':len(branches),'imports':1,'complete_compiler_functions':len(COMPLETE),'prior_source_ranges_checked':len(recaptures),'prior_source_bytes_checked':sum(x['bytes_checked']for x in recaptures),'compiler_starts_compared':len(starts),'selected_pointer_records':len(slots),'fixup_catalog_memberships_compared':len(fresh)},**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
