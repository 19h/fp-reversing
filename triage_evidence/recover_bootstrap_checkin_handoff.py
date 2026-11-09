#!/usr/bin/env python3
"""Static bootstrap/XPC check-in, launchd receive handoff and supplied-trace correlation.
O(B+F+I+T) time/space. No target execution, packet emission or service mutation.
"""
import json,re,struct
from pathlib import Path
from recover_launchd_variant_binding import variant,binary,PATH,SDK,sha,h,CS
from recover_host_special_registration import fixup_reference
from bootpolicy_cache_reader import Cache,Dylib,CACHE
from analyze_zut_trace import decode_descriptors
ROOT=Path(__file__).resolve().parent;P='bootstrap_checkin_handoff';TRACE=Path('/Users/___/Downloads/zut/annotated-strace-rax-user.txt')
FLAGS=['target_executed','target_emulated','bootstrap_check_in_called','native_receive_right_transferred','native_port_identity_proved','native_right_balance_proved','hardware_PAC_checked','native_RPC700_exchange','full_goal_complete']
def trace_messages():
 data=TRACE.read_bytes();lines=data.decode().splitlines();out=[];head=re.compile(r'\s+(send|received) bits=(0x[0-9a-f]+) size=(\d+) remote=(0x[0-9a-f]+) local=(0x[0-9a-f]+) voucher=(0x[0-9a-f]+) id=(\d+)');dump=re.compile(r'\]\s+([0-9a-f]{4,})\s+((?:[0-9a-f]{2}\s+)+)\|')
 for j,line in enumerate(lines):
  m=head.search(line)
  if not m:continue
  raw=bytearray();end=j+1
  while end<len(lines):
   d=dump.search(lines[end])
   if not d:break
   assert int(d[1],16)==len(raw);raw.extend(bytes.fromhex(d[2]));end+=1
  bits,size,remote,local,voucher,mid=struct.unpack_from('<6I',raw);assert [bits,size,remote,local,voucher,mid]==[int(m[k],0 if k in[2,4,5,6]else 10)for k in range(2,8)]and len(raw)>=size
  out.append({'line':j+1,'hex_end_line':end,'direction':m[1],'bits':bits,'size_bytes':size,'remote':hex(remote),'local':hex(local),'voucher':hex(voucher),'id':mid,'message_hex':raw[:size].hex(),'trailer_hex':raw[size:].hex(),'descriptors':decode_descriptors(raw[:size],bits),'annotation':line})
 return out
def flat_dictionary(msg):
 raw=bytes.fromhex(msg['message_hex']);assert len(raw)==msg['size_bytes'];ds=msg['descriptors'];assert len(ds)==1 and ds[0]['kind']=='port';at=40;magic,version,tag,length,count=struct.unpack_from('<5I',raw,at);assert(magic,version,tag)==(0x40585043,5,0xf000)and count in[1,5];end=at+16+length;assert end==len(raw);at+=20;entries=[];di=0
 for _ in range(count):
  begin=at;z=raw.index(0,at,end);key=raw[at:z].decode('ascii');at=(z+4)&~3;typ=struct.unpack_from('<I',raw,at)[0];at+=4
  if typ==0x4000:value=struct.unpack_from('<Q',raw,at)[0];at+=8;kind='uint64'
  elif typ==0x9000:
   n=struct.unpack_from('<I',raw,at)[0];at+=4;value=raw[at:at+n];assert len(value)==n and value[-1:]==b'\0'and b'\0'not in value[:-1];value=value[:-1].decode('ascii');at=(at+n+3)&~3;kind='string'
  elif typ in[0xd000,0x15000]:assert di<len(ds);value=ds[di];di+=1;kind='mach_send'if typ==0xd000 else'mach_receive'
  else:raise AssertionError(('unsupported trace-only tag',hex(typ)))
  assert at<=end;entries.append({'key':key,'type_tag':hex(typ),'kind':kind,'value':value,'offset_bytes':begin,'end_offset_bytes':at})
 assert at==end and di==len(ds)and len({e['key']for e in entries})==count
 return {'magic':hex(magic),'version':version,'root_tag':hex(tag),'declared_dictionary_bytes':length,'entry_count':count,'entries':entries,'scope':'Bounded flat form observed in these ten packets; no general XPC parser/serializer claim.'}
def selected_trace():
 msgs=trace_messages();out=[]
 for j,q in enumerate(msgs):
  if q['direction']!='send'or q['id']!=0x400000ce:continue
  reply=msgs[j+1];assert reply['direction']=='received'and reply['id']==0x20000000 and reply['local']==q['local'];out.append({'request':q,'reply':reply,'request_dictionary':flat_dictionary(q),'reply_dictionary':flat_dictionary(reply)})
 assert len(msgs)==44 and len(out)==5
 return {'source_path':str(TRACE),'sha256':sha(TRACE),'size_bytes':TRACE.stat().st_size,'printed_message_headers':len(msgs),'pairs':out,'scope':'Historical RAX capture only; guest names/annotations are not native kernel or sender identity proof.'}
def address(ins):return int(ins['operands'][1:],0)
def derive(n,prior):
 init=n.function(int(prior['roles']['fixed22']['start'],16));ii=init['instructions'];j=next(j for j,i in enumerate(ii)if i['mnemonic']=='mov'and i['operands']=='w0, #5');register=address(ii[j+1]);disp=int(ii[j-4]['operands'].split('#')[1],0)+int(ii[j-3]['operands'].split('#')[1],0);d=n.function(disp);ii=d['instructions'];j=next(j for j,i in enumerate(ii)if i['mnemonic']=='ldrsw'and i['operands']=='x16, [x17, x16, lsl #2]');table=int(ii[j-2]['operands'].split('#')[1],0)+int(ii[j-1]['operands'].split('#')[1],0);base=int(ii[j+1]['operands'].split('#')[1],0);jt={'address':hex(table),'relative_base':hex(base),'bytes':n.read(table,48).hex(),'targets':[hex(base+x)for x in struct.unpack('<12i',n.read(table,48))]};entry=int(jt['targets'][6],16);call=next(i for i in ii if entry<=int(i['ea'],16)<entry+24 and i['mnemonic']=='bl');handler=n.function(address(call));stubs=prior['stubs'];stub_addrs={v['address']for v in stubs.values()}
 def calls(body):return[i for i in body['instructions']if i['mnemonic']=='bl'and i['operands'][1:]not in stub_addrs]
 local=calls(handler);assert len(local)==2;core=n.function(address(local[0]));status=n.function(address(local[1]));cc=core['instructions'];pos=next(j for j,i in enumerate(cc)if i['mnemonic']=='cmp'and i['operands']=='w0, #3');activate=n.function(address(cc[pos-1]));aa=activate['instructions'];pos=next(j for j,i in enumerate(aa)if i['mnemonic']=='mov'and i['operands']=='w1, #0x45');notify=n.function(address(aa[pos+1]));gets={address(i)for j,i in enumerate(cc)if j and i['mnemonic']=='bl'and cc[j-1]['mnemonic']=='mov'and cc[j-1]['operands']=='w1, #4'};assert len(gets)==1;ctx=n.function(address(calls(d)[0]));decoder=n.function(address(calls(ctx)[0]));roles={'init':init,'register':n.function(register),'dispatcher':d,'domain_context':ctx,'domain_decode':decoder,'handler':handler,'core':core,'status_map':status,'activate':activate,'getter':n.function(gets.pop()),'notify_setup':notify,'send_object':n.function(int(prior['roles']['send_object']['start'],16)),'send_name':n.function(int(prior['roles']['send_name']['start'],16))};used={}
 by_address={r['address']:(name,r)for name,r in stubs.items()}
 for body in roles.values():
  for i in body['instructions']:
   if i['mnemonic']not in['b','bl']or not i['operands'].startswith('#'):continue
   if i['operands'][1:]in by_address:
    name,r=by_address[i['operands'][1:]];used[name]=n.stub(int(r['address'],16));assert used[name]==r
 return {'label':prior['label'],'uuid':n.inv['uuid'],'slice':n.inv['selected_slice'],'roles':roles,'stubs':used,'routine_table':jt,'routine206_handler_call':call,'LLVM':n.llvm_record,'fixup_reference':fixup_reference(n)}
def build():
 meta=binary(PATH);raw=PATH.read_bytes();old=json.loads((ROOT/'launchd_variant_binding_source.json').read_text());variants=[]
 for j,label in enumerate(['arm64e','arm64e.x1']):n=variant(meta,meta['slices'][j],raw);n.prepare(label);variants.append(derive(n,old['variants'][j]))
 c=Cache();xp='/usr/lib/system/libxpc.dylib';lib=Dylib(c,xp);functions=[]
 addrs=[0x184b7f884,0x184b82e80,0x184b7f8d8,0x184b736a0,0x184b73724,0x184b70674,0x184b6d250,0x184b706f0,0x184b8a790,0x184ba24d8,0x184b70b0c,0x184ba325c,0x184b89130,0x184b89250,0x184b73bfc,0x184b7cc3c,0x184b7ccc8,0x184b9fbf8,0x184b7cd28,0x184b7fbe4]
 for a in addrs:
  r=lib.function(a);assert len(r['instructions'])*4==len(bytes.fromhex(r['bytes']));r['original_nlist']=lib.symbols_at(a);r['exact_exports']=[name for name,row in lib.exports.items()if row['address']==a];functions.append(r)
 cache_stubs=[];libs={xp:lib}
 for a in[0x18806d230,0x18806d260,0x18806eb80,0x188087440,0x188087cc0]:
  raw_stub=c.read(a,16);ii=list(CS.disasm(raw_stub,a));assert[i.mnemonic for i in ii]==['adrp','add','ldr','braa'];slot=int(ii[0].op_str.split('#')[1],0)+int(ii[1].op_str.split('#')[1],0);p=c.pointer(slot);target=int(p['target'],16);path=max((row for row in c.images if row['address']<=target),key=lambda row:row['address'])['path'];d=libs.setdefault(path,Dylib(c,path));names=[name for name,row in d.exports.items()if row['address']==target];assert names;cache_stubs.append({'stub':hex(a),'bytes':raw_stub.hex(),'pointer':p,'target':hex(target),'library':path,'uuid':d.uuid,'exact_exports':names})
 strings=[{'address':hex(a),'text':c.read(a,128).split(b'\0')[0].decode()}for a in[0x184bba81c,0x184bb6555,0x184bba159,0x184bb659d,0x184bba2da,0x184bba2df,0x184bb6683,0x184bba27c,0x184bb3685,0x184bb368f]];constants=[{'address':hex(a),'bytes':c.read(a,8).hex()}for a in[0x184bb32b8]];ptrs=[c.pointer(a)for a in[0x1e0615388,0x1e0615350]]
 deps=['recover_launchd_variant_binding.py','recover_host_special_registration.py','recover_managed_fairplay_bridge.py','recover_rpc700_namespace.py','resolve_kernel_collection_interfaces.py','bootpolicy_cache_reader.py','analyze_zut_trace.py','launchd_variant_binding_source.json','launchd_service_endpoint_source.json','daemon_registration_contracts.json','zut_trace_decoded.json'];bodies=[r for v in variants for r in v['roles'].values()]+functions;counts={'launchd_variants':2,'launchd_functions':sum(len(v['roles'])for v in variants),'cache_functions':len(functions),'complete_functions':len(bodies),'instructions':sum(len(r['instructions'])for r in bodies),'function_bytes':sum(len(bytes.fromhex(r['bytes']))for r in bodies),'LLVM_only_launchd_words':sum(len(r['extended'])for v in variants for r in v['roles'].values()),'fixups_compared':4894,'trace_pairs':5,'trace_packets_decoded':10,'cache_stub_bindings':len(cache_stubs)}
 return {'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'launchd_source_path':str(PATH),'launchd_source_sha256':sha(PATH),'variants':variants,'cache_uuid':c.uuid,'cache_library':xp,'cache_library_uuid':lib.uuid,'cache_functions':functions,'cache_stubs':cache_stubs,'cache_type_links':ptrs,'cache_strings':strings,'cache_constants':constants,'cache_files':[{'path':p,'uuid':c.files[p]['uuid'],'size_bytes':Path(p).stat().st_size,'sha256':sha(p)}for p in sorted(c.used|{str(CACHE)})],'inspection_tools':[{'path':r['path'],'sha256':sha(r['path'])}for r in old['tools']],'SDK_headers':[{'path':str(p),'sha256':sha(p),'size_bytes':p.stat().st_size}for p in[SDK/'usr/include/mach/message.h',SDK/'usr/include/servers/bootstrap.h',SDK/'usr/include/mach/notify.h']],'trace':selected_trace(),'verified_source_counts':counts,**{f:False for f in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
