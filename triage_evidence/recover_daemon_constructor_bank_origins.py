#!/usr/bin/env python3
"""Static setup origin projections, frozen field ledgers and constructor consumer compatibility."""
import json,re,struct,subprocess,capstone
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,CS,TABLE,POOL,sha,h,FLAGS
from resolve_kernel_collection_interfaces import commands
P='daemon_constructor_bank_origins'
SCOPE='Fourteen shared-frame initializer field origins, all-state local register projections, eight frozen setup epochs and26 constructor consumer loads. Four bank fields extend prior ten-field tracking. Compatibility of offsets/values does not prove later reaching definitions, native phase/loader/owners/PAC or daemon-kext transport.'
EXPECTED={0x9b0:0x100fc4230,0x9a8:0x101031fa0,0x968:0x100fc4130,0x960:0x101031ea0,0x5f0:0x101031da0,0x5e0:0x100e99900,0x870:0x100e99700,0x868:0x100f4e190,0x5d0:0x100e99800,0x5d8:0x100f4e290,0x9c0:0x1010c4670,0x9c8:0x1010b8dc8,0x9d0:0x6cf4,0x9d8:TABLE}
SPAN_SPECS={'prefix':(0x10061a328,0x10061a990),'setup':(0x1004c24a4,0x1004c3638)}
CONSUMERS=[(0x9b0,0x1006958e8,'node allocation left'),(0x9a8,0x100695900,'node allocation right'),(0x968,0x100948bbc,'record allocation left'),(0x960,0x100948bd0,'record allocation right'),(0x5f0,0x1008c3584,'candidate cleanup left'),(0x5e0,0x1008c3580,'candidate cleanup right'),(0x870,0x1006c1064,'old-buffer retirement left'),(0x868,0x1006c1080,'old-buffer retirement right'),(0x5d0,0x100747e50,'old-node retirement left'),(0x5d8,0x100747e64,'old-node retirement right'),(0x9c8,0x1006958c0,'node controller0'),(0x9c8,0x10078c38c,'candidate buffer controller0'),(0x9c8,0x1006c103c,'old buffer controller0'),(0x9c8,0x100747e28,'old node controller0'),(0x9c0,0x1006958c8,'node controller1'),(0x9c0,0x10078c394,'candidate buffer controller1'),(0x9c0,0x1006c1044,'old buffer controller1'),(0x9c0,0x100747e30,'old node controller1'),(0x9d8,0x100695918,'node allocation table'),(0x9d8,0x100948bec,'record allocation table'),(0x9d8,0x10078c3e4,'candidate buffer table'),(0x9d8,0x1006c109c,'old buffer table'),(0x9d8,0x100747e78,'old node table'),(0x9d0,0x1008ecc70,'constructor key setup phase'),(0x9d0,0x1005a37c4,'u64 writer return phase'),(0x9d0,0x100615a20,'identifier compare phase')]
DC=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);DC.detail=True

def norm(x):return'x'+x[1:]if x.startswith('w')and x[1:].isdigit()else'x29'if x=='fp'else'x30'if x=='lr'else x

def project(q,off):
 F=int(q['frame_base'],16);ww=[x for x in q['source_writes']if int(x['address'],16)<F+off+8 and F+off<int(x['address'],16)+x['size_bytes']];assert len(ww)==1;w=ww[0];assert int(w['address'],16)==F+off and w['size_bytes']==8 and int.from_bytes(bytes.fromhex(w['after_hex']),'little')==EXPECTED[off]
 pc=int(w['pc'],16);i=next(DC.disasm(IMAGE.read(pc,4),pc));assert i.mnemonic=='str';live={norm(i.op_str.split(',')[0])};out=[]
 for j in range(w['source_visit_index']-1,-1,-1):
  st=q['source_visits'][j];a=int(st['pc'],16);ins=next(DC.disasm(bytes.fromhex(st['bytes_hex']),a));r,wr=ins.regs_access();writes={norm(ins.reg_name(v))for v in wr};reads={norm(ins.reg_name(v))for v in r}
  if live&writes:
   assert st['image']=='daemon';out.append((j,st,ins));live-=writes;live|=reads;live.discard('sp')
 out.reverse();assert live==({'x0'}if off==0x9d0 else set());by={x['source_visit_index']:x for x in q['source_reads']};loads=[];ii=[]
 for j,st,ins in out:
  ii.append({'ea':hex(ins.address),'mnemonic':ins.mnemonic,'operands':ins.op_str})
  if ins.mnemonic.startswith('ldr'):
   r=by[j];a=int(r['address'],16);kind='pool_fixup'if a in FIXUPS else'runtime_controller'if a in[0x1010b8dc8,0x1010c4670]else'bank_byte'if r['size_bytes']==1 else'protected_tag'if a==int(q['record_address'],16)+8 else'unknown';assert kind!='unknown';row={'site':hex(ins.address),'kind':kind,'nominal_address':hex(a),'width_bits':r['size_bytes']*8}
   if kind=='pool_fixup':assert isinstance(FIXUPS[a]['target'],int);row['fixup']=FIXUPS[a]
   loads.append(row)
 ii.append({'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str})
 return{'field_offset':hex(off),'expected_value':hex(EXPECTED[off]),'writer':w['pc'],'stored_register':i.op_str.split(',')[0],'live_register_inputs':sorted(live),'instructions':ii,'loads':loads}

def structure(p):
 return{**p,'loads':[{k:v for k,v in r.items()if k!='nominal_address'or r['kind']not in('bank_byte','protected_tag')}for r in p['loads']]}

def census():
 for at,cmd,n in commands(IMAGE.data,0):
  if cmd!=0x19:continue
  for j in range(struct.unpack_from('<I',IMAGE.data,at+64)[0]):
   p=at+72+80*j
   if IMAGE.data[p:p+16].split(b'\0')[0]==b'__text':a,n=struct.unpack_from('<QQ',IMAGE.data,p+32);break
  else:continue
  break
 raw=IMAGE.read(a,n);pat={0xf90003e0|((off//8)<<10):off for off in EXPECTED};rows={off:[]for off in EXPECTED}
 for j,(w,)in enumerate(struct.iter_unpack('<I',raw)):
  off=pat.get(w&0xffffffe0)
  if off is not None:rows[off].append(hex(a+j*4))
 return{'text_start':hex(a),'text_bytes':n,'text_sha256':h(raw),'instruction_words_checked':n//4,'scope':'Aligned literal unsigned-immediate STR Xn,[SP,#offset] only; aliases, pairs, other widths/forms and frame equivalence are not established.','fields':[{'offset':hex(off),'candidate_PCs':rows[off]}for off in EXPECTED]}

def build():
 raw=json.loads((ROOT/'daemon_shared_roots_profiles.json').read_text());assert raw['source_sha256']==sha(SOURCE);cases=raw['cases'];assert len(cases)==8;projs={hex(o):project(cases[0],o)for o in EXPECTED};ledgers=[];checked=reads_checked=0
 for q in cases:
  assert not q['native_target_executed']and q['fixture_PC_transitions']==0 and q['boundary']['kind']=='before_shared_setup_branch';F=int(q['frame_base'],16);assert F==int(q['entry_SP'],16)-0x10dd0;fields=[]
  for st in q['source_visits']:
   if st['image']=='daemon':assert IMAGE.read(int(st['pc'],16),4).hex()==st['bytes_hex'];checked+=1
  for off,value in EXPECTED.items():
   p=project(q,off);assert structure(p)==structure(projs[hex(off)]);ww=[w for w in q['source_writes']if int(w['address'],16)<F+off+8 and F+off<int(w['address'],16)+w['size_bytes']];assert len(ww)==1;w=ww[0];rr=[]
   for r in q['source_reads']:
    a=int(r['address'],16);z=a+r['size_bytes']
    if r['source_visit_index']<=w['source_visit_index']or a>=F+off+8 or F+off>=z:continue
    lo,hi=max(a,F+off),min(z,F+off+8);bb=bytes.fromhex(r['bytes_hex']);assert bb[lo-a:hi-a]==value.to_bytes(8,'little')[lo-F-off:hi-F-off];rr.append(r);reads_checked+=1
   fields.append({'offset':hex(off),'expected_value':hex(value),'writer':w,'reads_before_boundary':rr,'overlapping_writes_total':1})
  ledgers.append({'configuration':q['configuration'],'frame_base':q['frame_base'],'boundary':q['boundary']['kind'],'next_target':q['boundary']['registers31'][8],'fields':fields,'native_evidence':False})
 fs={}
 for n,(a,z)in SPAN_SPECS.items():
  bb=IMAGE.read(a,z-a);ii=list(CS.disasm(bb,a));assert len(ii)*4==len(bb);fs[n]={'start':hex(a),'end':hex(z),'bytes':bb.hex(),'sha256':h(bb),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]}
 footprint={'stores':[],'SP_write_sites':[],'call_sites':[],'branch_sites':[]}
 for i in DC.disasm(bytes.fromhex(fs['setup']['bytes']),int(fs['setup']['start'],16)):
  if i.mnemonic.startswith('str'):
   assert i.mnemonic=='str';m=re.fullmatch(r'([xw][0-9]+), \[sp, #(0x[0-9a-f]+)\]',i.op_str);assert m,i.op_str;footprint['stores'].append({'site':hex(i.address),'offset_bytes':int(m[2],16),'width_bytes':8 if m[1][0]=='x'else 4,'instruction':{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}})
  if any(i.reg_name(r)=='sp'for r in i.regs_access()[1]):footprint['SP_write_sites'].append(hex(i.address))
  if i.mnemonic.startswith(('bl','blr')):footprint['call_sites'].append(hex(i.address))
  if i.mnemonic.startswith(('b','cb','tb')):footprint['branch_sites'].append(hex(i.address))
 assert len(footprint['stores'])==129 and not footprint['SP_write_sites']and not footprint['call_sites']and footprint['branch_sites']==['0x1004c3634']
 for off,p in projs.items():
  a=int(off,16);over=[r for r in footprint['stores']if r['offset_bytes']<a+8 and a<r['offset_bytes']+r['width_bytes']];assert [r['site']for r in over]==([p['writer']]if 0x1004c24a4<=int(p['writer'],16)<0x1004c3634 else[])
 consumers=[]
 for off,pc,role in CONSUMERS:
  bb=IMAGE.read(pc,4);i=next(CS.disasm(bb,pc));assert i.mnemonic=='ldr'and i.op_str.split(',')[0].startswith('x');consumers.append({'field_offset':hex(off),'site':hex(pc),'role':role,'bytes':bb.hex(),'instruction':{'ea':hex(pc),'mnemonic':i.mnemonic,'operands':i.op_str},'initializer_value':hex(EXPECTED[off]),'same_frame_reaching_definition_proved':False})
 cc=census()
 for off,p in projs.items():assert p['writer']in next(r['candidate_PCs']for r in cc['fields']if r['offset']==off)
 banks=[]
 for role,l,r,key,add in [('controller0',0x100fc4230,0x101031fa0,0xf3,0xac7),('controller1',0x100e99700,0x100f4e190,0x56,0x80),('dispatch_table',0x100fc4230,0x101031fa0,0x6c,0x893)]:
  lb,rb=IMAGE.read(l,256),IMAGE.read(r,256);vv=[i^rb[lb[i]^key]for i in range(256)];assert len(set(vv))==1;slot=POOL+8*(add+vv[0]);assert slot in FIXUPS;banks.append({'role':role,'left':hex(l),'right':hex(r),'key_u8':key,'additive_index':hex(add),'collapsed_byte':hex(vv[0]),'left_bytes':lb.hex(),'right_bytes':rb.hex(),'results_256':vv,'pool_slot':hex(slot),'fixup':FIXUPS[slot]})
 slots=sorted({int(r['nominal_address'],16)for p in projs.values()for r in p['loads']if r['kind']=='pool_fixup'});ptr=[{'slot':hex(a),'raw_bytes':IMAGE.read(a,8).hex(),'fixup':FIXUPS[a]}for a in slots]
 rec=[]
 for fn in ['daemon_constructor_inputs_source.json','daemon_constructor_lookup_source.json','daemon_constructor_failure_source.json']:
  for n,f in json.loads((ROOT/fn).read_text())['fragments'].items():
   bb=bytes.fromhex(f['bytes']);assert IMAGE.read(int(f['start'],16),len(bb))==bb;rec.append({'file':fn,'fragment':n,'bytes_checked':len(bb),'sha256':h(bb)})
 cmd=['/usr/bin/dyld_info','-fixups',str(SOURCE)];r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0 and not r.stderr;fresh={}
 for line in r.stdout.splitlines():
  m=re.match(r'\s+\S+\s+\S+\s+(0x[0-9a-fA-F]+)\s+(\S+)\s+(\S+)(.*)',line)
  if m:fresh[int(m[1],16)]=line.strip()
 assert set(fresh)==set(FIXUPS)
 for row in ptr:assert fresh[int(row['slot'],16)]==row['fixup']['line']
 deps=['daemon_shared_roots_profiles.json','daemon_shared_roots_source.json','daemon_shared_roots_checks.json','daemon_shared_roots_proofs.json','daemon_constructor_inputs_source.json','daemon_constructor_inputs_checks.json','daemon_constructor_lookup_source.json','daemon_constructor_lookup_checks.json','daemon_constructor_failure_source.json','daemon_constructor_failure_checks.json','recover_daemon_xpc_core_bridge.py','daemon_receive_fixups.txt']
 return{'generator_sha256':sha(__file__),'static_scope':SCOPE,'daemon_path':str(SOURCE),'daemon_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in deps},'fragments':fs,'field_projections':projs,'frozen_field_ledgers':ledgers,'constructor_consumers':consumers,'setup_store_footprint':footprint,'bank_lemmas':banks,'pointer_records':ptr,'literal_store_census':cc,'prior_recaptures':rec,'fixup_reference':{'command':cmd,'tool_sha256':sha(cmd[0]),'stdout_sha256':h(r.stdout.encode()),'catalog_memberships_compared':len(fresh)},'verified_source_counts':{'fragments':len(fs),'instructions':sum(len(f['instructions'])for f in fs.values()),'fragment_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'fields':14,'newly_tracked_fields':4,'projection_instruction_instances':sum(len(p['instructions'])for p in projs.values()),'pointer_records':len(ptr),'bank_inputs_checked':768,'retained_setup_profiles':8,'field_instances':112,'field_reads_checked':reads_checked,'frozen_daemon_instruction_instances_checked':checked,'constructor_consumer_loads':len(consumers),'setup_store_instructions':len(footprint['stores']),'literal_store_candidates':sum(len(r['candidate_PCs'])for r in cc['fields']),'prior_ranges':len(rec),'prior_bytes':sum(r['bytes_checked']for r in rec)},**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
