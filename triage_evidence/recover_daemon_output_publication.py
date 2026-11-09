#!/usr/bin/env python3
"""Static original-image output publisher and helper-cell interfaces.
O(image+fixups+captured source+text words) time/space. No target execution.
"""
import json,re,subprocess
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,CS,TABLE,POOL,qword,block,selected,verify_original_fixups,sha,h,FLAGS
from recover_daemon_xpc_listener import F,B
from resolve_kernel_collection_interfaces import macho
P='daemon_output_publication'
BLOCKS={'success_gate':0x10059c7d0,'publish':0x100582808,'result_stage':0x1004de1d4,
 'terminal_gate':0x1007fb760,'helper_input':0x10058d5c4,'helper_setup':0x1005db618,
 'helper_return':0x1007518a4,'nested_outputs':0x100847960,'owner_stage':0x1005aa740}
FIXED={'fill':(0x10046faf8,0x10046fc5c),'fill_banks':(0x1004c268c,0x1004c26cc)}
EDGES=[('inner_marker','success_gate',0xc268,0x100582808),('inner_other','success_gate',0x4146,0x1004de1d4),
 ('published','publish',0x48cd,0x1004de1d4),('staged','result_stage',0x39b4,0x1005aa740),
 ('helper_component','helper_input',0x1997,0x1005db618)]
SPECS=[('zero16',F,0x61,0xcc82),('zero32',B,0xbb,0xcbe0)]
PRIOR=['daemon_xpc_error_outputs_source.json','daemon_xpc_reply_lifecycle_source.json','daemon_frame_entry_contracts.json']
SCOPE='Conditional A70 output publication, exact u32-XOR-to-u64 extent codec, success/error shared result staging, helper output-cell transfers and bounded literal-opcode locator census. Full allocation/serialization and logical helper-return continuity, budget/delta stability, native admission/return/PAC/heap ownership/port identity/delivery and daemon-kext exchange remain unproved.'

def capture(a,z):
 bb=IMAGE.read(a,z-a);ii=list(CS.disasm(bb,a));assert len(bb)==4*len(ii)
 return {'start':hex(a),'end':hex(z),'bytes':bb.hex(),'sha256':h(bb),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]}

def build():
 fragments={n:capture(a,z)for n,(a,z)in FIXED.items()}
 for n,a in BLOCKS.items():
  f=block(a,0x4000);assert f['instructions'][-1]['mnemonic']in('braa','retab');f['sha256']=h(bytes.fromhex(f['bytes']));fragments[n]=f
 edges=[];slots={POOL+0x4048,POOL+0x6640}
 for name,source,ix,target in EDGES:
  slot=TABLE+8*ix;w=int.from_bytes(IMAGE.read(slot,8),'little');ii=fragments[source]['instructions'];mod=int(ii[-2]['operands'].split('#')[1],0)
  assert qword(slot)==target and w>>63 and(w>>32&65535)==mod and not(w>>48&1)and not(w>>49&3)
  slots.add(slot);edges.append({'role':name,'source':source,'site':ii[-1]['ea'],'index':hex(ix),'slot':hex(slot),'target':hex(target),'modifier_u16':mod,'pointer_word':hex(w)})
 banks={};calls=[]
 for name,pair,key,add in SPECS:
  r=selected(*pair,key,add,TABLE,0);l,rr=IMAGE.read(pair[0],256),IMAGE.read(pair[1],256)
  r.update(left_bytes=l.hex(),right_bytes=rr.hex(),results_256=[i^rr[l[i]^key]for i in range(256)]);banks[name]=r;slot=int(r['slot'],16);slots.add(slot)
  assert r['target']=='0x10046faf8'
  pc=0x1005db6e8 if name=='zero16'else 0x1005db73c;w=int.from_bytes(IMAGE.read(slot,8),'little')
  assert w>>63 and(w>>32&65535)==0xac7d and not(w>>48&1)and not(w>>49&3)
  calls.append({'role':name,'site':hex(pc),'slot':hex(slot),'target':r['target'],'modifier_u16':0xac7d,'pointer_word':hex(w),'bytes':IMAGE.read(pc-4,8).hex()})
 biases=[('right_F',POOL+0x4048,0xffffffffb971d649,0x100f4e290),('left_F',POOL+0x6640,0xffffffffdaeb98b6,0x100e99800)]
 decoded=[]
 for name,slot,bias,target in biases:
  assert(qword(slot)+bias)&((1<<64)-1)==target
  decoded.append({'role':name,'slot':hex(slot),'biased_base':hex(qword(slot)),'bias':hex(bias),'target':hex(target)})
 recaptures=[]
 def walk(o,fn,path=''):
  if isinstance(o,dict):
   data=o.get('bytes',o.get('bytes_hex'));a=o.get('start')
   if isinstance(data,str)and isinstance(a,str)and a.startswith('0x'):
    bb=bytes.fromhex(data);assert IMAGE.read(int(a,16),len(bb))==bb
    recaptures.append({'file':fn,'path':path,'start':a,'bytes_checked':len(bb),'sha256':h(bb)})
   for k,v in o.items():walk(v,fn,path+'/'+k)
  elif isinstance(o,list):
   for j,v in enumerate(o):walk(v,fn,path+'/'+str(j))
 for fn in PRIOR:walk(json.loads((ROOT/fn).read_text()),fn)
 sec=next(x for x in macho(IMAGE.data,0,'daemon')['sections']if x['section']=='__text');a=sec['address'];bb=IMAGE.read(a,sec['size'])
 census=[]
 for off,width,mode in [(0x1a30,8,'ldr'),(0x7098,8,'ldr'),(0x70c8,8,'str'),(0x3928,4,'str')]:
  opcode=(0xf94003e0 if mode=='ldr'else 0xf90003e0 if width==8 else 0xb90003e0)|((off//width)<<10);hits=[]
  for j in range(0,len(bb)-3,4):
   if int.from_bytes(bb[j:j+4],'little')&0xffffffe0==opcode:hits.append(capture(a+j,a+j+32))
  census.append({'mode':mode,'width_bytes':width,'SP_offset':hex(off),'mask':'0xffffffe0','opcode':hex(opcode),'hits':hits})
 assert[len(r['hits'])for r in census]==[10,2,1,0]
 cmd=['/usr/bin/dyld_info','-fixups',str(SOURCE)];r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0 and not r.stderr
 fresh={}
 for line in r.stdout.splitlines():
  m=re.match(r'\s+\S+\s+\S+\s+(0x[0-9a-fA-F]+)\s+(\S+)\s+(\S+)(.*)',line)
  if m:fresh[int(m[1],16)]=line.strip()
 assert set(fresh)==set(FIXUPS)
 for slot in slots:assert fresh[slot]==FIXUPS[slot]['line']
 deps=PRIOR+['daemon_xpc_error_outputs_checks.json','daemon_xpc_reply_lifecycle_checks.json','daemon_client_object_contracts.json','daemon_vm_cleanup_contracts.json','daemon_receive_tools.py','daemon_receive_fixups.txt','recover_daemon_xpc_core_bridge.py','resolve_kernel_collection_interfaces.py']
 return {'generator_sha256':sha(__file__),'daemon_path':str(SOURCE),'daemon_sha256':sha(SOURCE),'static_scope':SCOPE,
  'dependencies':{n:sha(ROOT/n)for n in deps},'fragments':fragments,'branches':edges,'banks':banks,'calls':calls,'bank_frame_producers':decoded,
  'prior_source_recaptures':recaptures,'literal_census':{'section':sec,'sha256':h(bb),'words_scanned_per_pattern':len(bb)//4,'patterns':census,'scope':'Only aligned literal unsigned-immediate opcodes with SP base, ignoring Rt. Equal offsets do not establish a frame epoch. Aliases, pair/vector/register-offset stores, escaped pointers and other encodings are outside this census.'},
  'selected_pointer_records':[{'slot':hex(slot),'raw_bytes':IMAGE.read(slot,8).hex(),'fixup':FIXUPS[slot]}for slot in sorted(slots)],'original_pointer_checks':verify_original_fixups(slots),
  'fixup_reference':{'command':cmd,'stdout_sha256':h(r.stdout.encode()),'catalog_memberships_compared':len(fresh),'selected_lines':{hex(slot):fresh[slot]for slot in sorted(slots)}},
  'inspection_tools':[{'path':'/usr/bin/dyld_info','sha256':sha('/usr/bin/dyld_info')}],
  'verified_source_counts':{'fragments':len(fragments),'instructions':sum(len(f['instructions'])for f in fragments.values()),'fragment_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fragments.values()),'branch_bindings':len(edges),'resolved_fill_calls':len(calls),'bank_cases':len(banks),'bank_inputs_checked':256*len(banks),'selected_pointer_records':len(slots),'fixup_catalog_memberships_compared':len(fresh),'prior_source_ranges_checked':len(recaptures),'prior_source_bytes_checked':sum(x['bytes_checked']for x in recaptures),'literal_census_patterns':len(census),'literal_census_hits':sum(len(x['hits'])for x in census),'text_words_per_pattern':len(bb)//4},**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
