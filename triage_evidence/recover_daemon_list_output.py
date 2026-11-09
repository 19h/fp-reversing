#!/usr/bin/env python3
"""Original list-sized output allocation, trailing-record and output interfaces.
Static only; O(image+fixups+captured/prior bytes) time/space. No target execution.
"""
import json,re,subprocess
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,CS,TABLE,POOL,qword,block,selected,verify_original_fixups,binding,sha,h,FLAGS
from recover_daemon_xpc_listener import C
from recover_daemon_output_publication import capture
P='daemon_list_output'
BLOCKS={'caller':0x100847960,'entry':0x1006bc13c,'head':0x10075b804,'sum_guard':0x1006875c8,'sum_step':0x1008fdae0,
 'size':0x10082d364,'allocate':0x1006c3080,'copy_init':0x100708918,'node_gate':0x100756764,'copy_setup':0x10087bbbc,
 'byte_body':0x1009c3d34,'copy_done':0x1006f8aa4,'next_node':0x1009019f8,'trailing_record':0x1009178e4,
 'padding':0x1006d6a30,'publish':0x10068f630,'return':0x10066efc4,'continuation':0x10090f880,'parent_publish':0x1007518a4}
EDGES=[('nested_entry','caller',0x8194,0x1006bc13c),('container_null','entry',0x486d,0x10066efc4),('container_present','entry',0x484f,0x10075b804),
 ('head_null','head',0xabd6,0x10082d364),('head_present','head',0xab7e,0x1006875c8),('sum_overflow','sum_guard',0x6ef2,0x10066efc4),('sum_fits','sum_guard',0x6f62,0x1008fdae0),
 ('sum_next','sum_step',0xab7e,0x1006875c8),('sum_end','sum_step',0xabd6,0x10082d364),('size_rejected','size',0x6ef2,0x10066efc4),('size_admitted','size',0x9cb5,0x1006c3080),
 ('malloc_null','allocate',0x8435,0x10066efc4),('malloc_present','allocate',0x8462,0x100708918),('copy_head_null','copy_init',0x4383,0x1009178e4),('copy_head_present','copy_init',0x4396,0x100756764),
 ('zero_node','node_gate',0x72ea,0x1009019f8),('nonzero_node','node_gate',0x7309,0x10087bbbc),('byte_entry','copy_setup',0x56af,0x1009c3d34),
 ('byte_repeat','byte_body',0x56af,0x1009c3d34),('byte_done','byte_body',0xbbe0,0x1006f8aa4),('pad_present','trailing_record',0x6e3b,0x1006d6a30),('pad_absent_component','trailing_record',0x6dca,0x10068f630),
 ('pad_repeat','padding',0x6e3b,0x1006d6a30),('pad_done','padding',0x6dca,0x10068f630),('published_return','publish',0x486d,0x10066efc4),
 ('parent_success','continuation',0x344d,0x1007518a4),('parent_failure','continuation',0x1a56,0x100902518),('copied_node','copy_done',0x567c,0x1009019f8),('copy_next','next_node',0x4396,0x100756764),('copy_end','next_node',0x4383,0x1009178e4)]
SCOPE='Conditional phase1593 list-sized output allocator, checked u32 sum, per-node byte-XOR transfer/loop interfaces, padding/size arithmetic, trailing record and output publication/parent continuation. Full buffer coverage assumes a stable finite acyclic list and valid disjoint owners. Actual incoming phase production, producer-side encoding inverse, heap/list ownership, adapter delta and native return/PAC/port identity/delivery/daemon-kext exchange remain unproved. IDA is read only and corroborates two byte ranges; its fragment bounds are not whole semantic-function bounds.'
PRIOR=['daemon_output_publication_source.json','daemon_xpc_error_outputs_source.json','daemon_xpc_reply_lifecycle_source.json']

def build():
 fragments={}
 for n,a in BLOCKS.items():
  f=block(a,0x4000);assert f['instructions'][-1]['mnemonic']=='braa';f['sha256']=h(bytes.fromhex(f['bytes']));fragments[n]=f
 slots={TABLE+8*0x1593};edges=[]
 for name,source,ix,target in EDGES:
  slot=TABLE+8*ix;w=int.from_bytes(IMAGE.read(slot,8),'little');ii=fragments[source]['instructions'];mod=int(ii[-2]['operands'].split('#')[1],0)
  assert qword(slot)==target and w>>63 and(w>>32&65535)==mod and not(w>>48&1)and not(w>>49&3)
  slots.add(slot);edges.append({'role':name,'source':source,'site':ii[-1]['ea'],'index':hex(ix),'slot':hex(slot),'target':hex(target),'modifier_u16':mod,'pointer_word':hex(w)})
 r=selected(*C,0xa,0xcb23,TABLE,0);l,rr=IMAGE.read(C[0],256),IMAGE.read(C[1],256)
 r.update(left_bytes=l.hex(),right_bytes=rr.hex(),results_256=[i^rr[l[i]^0xa]for i in range(256)]);assert r['target']=='libSystem/_malloc';slot=int(r['slot'],16);slots.add(slot)
 alloc={'site':'0x1006c318c','slot':hex(slot),'target':r['target'],'modifier_u16':0x6aa4,'bytes':IMAGE.read(0x1006c3188,8).hex(),'pointer_word':hex(int.from_bytes(IMAGE.read(slot,8),'little'))}
 # Exhaust all original IA/5677/ad0 continuation fixups, not guessed phases.
 candidates=[]
 def compatible(ix,div):
  si=ix-(1<<32)if ix>>31 else ix;row=FIXUPS.get((TABLE+8*si)&((1<<64)-1))
  return bool(row and row['kind']=='auth-rebase'and f'div=0x{div:04X} ad=0 key=IA'in row['annotation'])
 for at,row in sorted(FIXUPS.items()):
  if row['kind']!='auth-rebase'or 'div=0x5677 ad=0 key=IA'not in row['annotation']:continue
  assert(at-TABLE)%8==0;c=(at-TABLE)//8;assert -(1<<31)<=c<(1<<31);w=c&0xffffffff
  i=((w^0x5ddc)+(w+0x23b2))&0xffffffff;rn=(TABLE+8*(i-(1<<32)if i>>31 else i))&((1<<64)-1)
  callee=FIXUPS.get(rn);w9=w^0x5ddc;null=((((w9^0x4df3)*19-0x6cd2)&0xffffffff)^w9)
  ok=bool(callee and callee['target']==0x1006bc13c and compatible(i,0x6e32)and compatible(w9,0x374b)and compatible(null,0x374b))
  slots.add(at);candidates.append({'phase_u32':hex(w),'continuation_slot':hex(at),'continuation_target':hex(row['target']),'call_index':hex(i),'present_index':hex(w9),'null_index':hex(null),'all_selected_pointer_constraints_match':ok})
 assert len(candidates)==23 and [x['phase_u32']for x in candidates if x['all_selected_pointer_constraints_match']]==['0x1593']
 recaptures=[]
 def walk(o,fn,path=''):
  if isinstance(o,dict):
   data=o.get('bytes',o.get('bytes_hex'));a=o.get('start')
   if isinstance(data,str)and isinstance(a,str)and a.startswith('0x'):
    bb=bytes.fromhex(data);assert IMAGE.read(int(a,16),len(bb))==bb;recaptures.append({'file':fn,'path':path,'start':a,'bytes_checked':len(bb),'sha256':h(bb)})
   for k,v in o.items():walk(v,fn,path+'/'+k)
  elif isinstance(o,list):
   for j,v in enumerate(o):walk(v,fn,path+'/'+str(j))
 for fn in PRIOR:walk(json.loads((ROOT/fn).read_text()),fn)
 ida=json.loads((ROOT/(P+'_ida.json')).read_text());assert ida['target']=='6b117c693e3b'and not ida['idb_mutated'];raw=ida['calls'][1]['result'];assert raw['status']=='fulfilled'
 txt=raw['value']['content'][0]['text'];j=json.loads(txt.split('[assist:tool-output]\n')[1].split('\n[/assist:tool-output]')[0]);readback=[]
 for row in j['results']:
  bb=bytes.fromhex(row['bytes']);assert len(bb)==row['size_read']==row['size_requested']and IMAGE.read(int(row['address'],16),len(bb))==bb
  readback.append({'address':row['address'],'size_bytes':len(bb),'sha256':h(bb)})
 cmd=['/usr/bin/dyld_info','-fixups',str(SOURCE)];out=subprocess.run(cmd,capture_output=True,text=True);assert out.returncode==0 and not out.stderr
 fresh={}
 for line in out.stdout.splitlines():
  m=re.match(r'\s+\S+\s+\S+\s+(0x[0-9a-fA-F]+)\s+(\S+)\s+(\S+)(.*)',line)
  if m:fresh[int(m[1],16)]=line.strip()
 assert set(fresh)==set(FIXUPS)
 for a in slots:assert fresh[a]==FIXUPS[a]['line']
 deps=PRIOR+[P+'_ida.json','daemon_output_publication_checks.json','daemon_receive_tools.py','daemon_receive_fixups.txt','daemon_import_bindings.py','recover_daemon_output_publication.py','recover_daemon_xpc_core_bridge.py']
 return {'generator_sha256':sha(__file__),'daemon_path':str(SOURCE),'daemon_sha256':sha(SOURCE),'static_scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in deps},'fragments':fragments,'branches':edges,'malloc_bank':r,'malloc_call':alloc,'malloc_import':binding(slot),'phase_constraints':candidates,'IDA_readback':readback,'prior_source_recaptures':recaptures,
  'selected_pointer_records':[{'slot':hex(a),'raw_bytes':IMAGE.read(a,8).hex(),'fixup':FIXUPS[a]}for a in sorted(slots)],'original_pointer_checks':verify_original_fixups(slots),'fixup_reference':{'command':cmd,'stdout_sha256':h(out.stdout.encode()),'catalog_memberships_compared':len(fresh),'selected_lines':{hex(a):fresh[a]for a in sorted(slots)}},'inspection_tools':[{'path':'/usr/bin/dyld_info','sha256':sha('/usr/bin/dyld_info')}],
  'verified_source_counts':{'fragments':len(fragments),'instructions':sum(len(f['instructions'])for f in fragments.values()),'fragment_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fragments.values()),'branch_bindings':len(edges),'bank_inputs_checked':256,'selected_pointer_records':len(slots),'phase_continuation_candidates':len(candidates),'matching_phase_candidates':1,'fixup_catalog_memberships_compared':len(fresh),'prior_source_ranges_checked':len(recaptures),'prior_source_bytes_checked':sum(x['bytes_checked']for x in recaptures),'IDA_ranges_compared':len(readback),'IDA_bytes_compared':sum(x['size_bytes']for x in readback)},**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
