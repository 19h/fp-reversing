#!/usr/bin/env python3
"""Independent serialized-tree/option/copy contracts and fresh source replay.
O(visits+journals+mapped bytes) space; timeline sorting O(J log J). No executor.
"""
import json
from hashlib import sha256
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read
from unicorn import arm64_const as ar
from probe_rpc502_vm_handoff import decode as uncompress
from replay_kernel_vm_mig import Replay as Core
from replay_kernel_boot_environment_publication import oracle as prefix_oracle
from replay_kernel_secure_dt_execution import decode as decode_tree,API_oracle as tree_contracts
from replay_kernel_boot_option_execution import option_oracle,parse
from replay_kernel_boot_cpu_identity import pages,get,put
import recover_kernel_platform_environment_execution as R
E=R.E;O=R.O;P=0x6500000000;SIZE=0x100000;SP=P+0xf0000;TREE=P+0x10000
TREE_APIS=[O.B.B.LOOKUP,O.B.B.PROPERTY,O.B.B.ITERATE,O.B.B.FIND,O.B.SKIP,O.B.STRCMP]
OPTION_APIS=[O.PARSE,O.NUMBER,O.FLAG,O.SPACE,O.STRLEN]
TRACKED=[*TREE_APIS,*OPTION_APIS,E.STRLCPY,E.COPY,E.PLATFORM,R.CLOCK,R.ANCHOR,R.FLAGS,R.TIMER]
LEAVES={0xfffffe000c621194:'declared_vector_registration_no_RAM_effect',0xfffffe000c47cce0:'declared_early_registration_no_RAM_effect'}

def legacy(row):
 raw=uncompress(row['initial_private_RAM']);initial=[{'address':hex(P+j),'bytes_hex':raw[j:j+4096].hex()} for j in range(0,SIZE,4096)]+row['initial_image_pages']
 out={**row,'initial_pages':initial,'writes':[{**w,'visit':w['source_visit_index']} for w in row['source_writes']],
  'declared_models':[{'PC':m['pc'],'name':m['symbol'],'before_visit':m['before_source_visit_index'],'api_writes':[]} for m in row['API_models']]}
 for targets,prefix in [(TREE_APIS,'tree'),(OPTION_APIS,'option')]:
  indices={j:n for n,(j,_) in enumerate((j,e) for j,e in enumerate(row['original_API_entries']) if int(e['PC'],16) in targets)}
  out['original_'+prefix+'_API_entries']=[e for j,e in enumerate(row['original_API_entries']) if j in indices]
  out['original_'+prefix+'_call_returns']=[{**e,'entry_index':indices[e['entry_index']]} for e in row['original_API_returns'] if e['entry_index'] in indices]
 return out

def copy_contracts(row,old):
 memory=pages(old['initial_pages']);events=[];pending={};checks=[];calls=0;copied=0
 for j,w in enumerate(row['source_writes']):events.append((w['source_visit_index'],2,j,'write',w))
 for j,e in enumerate(row['original_API_entries']):
  if int(e['PC'],16) in [E.COPY,E.STRLCPY]:events.append((e['before_visit'],1,j,'entry',e))
 for j,e in enumerate(row['original_API_returns']):
  if int(row['original_API_entries'][e['entry_index']]['PC'],16) in [E.COPY,E.STRLCPY]:events.append((e['before_visit'],0,j,'return',e))
 def ok(name,p):assert p,('copy_contract',name);checks.append(name)
 for _,_,index,kind,e in sorted(events,key=lambda x:x[:3]):
  if kind=='write':raw=bytes.fromhex(e['after_hex']);put(memory,int(e['address'],16),len(raw),raw);continue
  if kind=='entry':
   a,b,n=map(lambda x:int(x,16),e['arguments6'][:3]);assert 0<=n<=1152;calls+=1
   if int(e['PC'],16)==E.COPY:expected=get(memory,b,n);status=a
   else:
    raw=bytearray()
    for j in range(512):
     ch=get(memory,b+j,1)
     if ch==b'\0':break
     raw+=ch
    else:raise AssertionError('unterminated_private_string')
    status=len(raw);expected=bytes(raw[:max(0,n-1)])+b'\0' if n else b''
   pending[index]=(a,expected,status);continue
  a,raw,status=pending.pop(e['entry_index']);ok('return_'+str(e['entry_index']),int(e['return_value'],16)==status);ok('output_'+str(e['entry_index']),get(memory,a,len(raw))==raw);copied+=len(raw)
 ok('all_copy_and_strlcpy_calls_returned',not pending)
 return {'checks':checks,'calls':calls,'destination_bytes_checked':copied}

def oracle(row,e):
 old=legacy(row);parsed=decode_tree(old);apis=tree_contracts(old,parsed);options=option_oracle(old);copies=copy_contracts(row,old);checks=[];checkpoint=row['prefix_checkpoint']
 prefix={**row,'source_visits':row['source_visits'][:checkpoint['before_visit']],'final_private_RAM':checkpoint['private_RAM'],'final_image_globals':checkpoint['image_globals'],'original_call_entries':checkpoint['original_call_entries'],'API_models':checkpoint['API_models'],
  'boundary':{'pc':checkpoint['PC'],'kind':'before_later_helper','registers31':checkpoint['registers31'],'SP':checkpoint['SP'],'NZCV':checkpoint['NZCV']}}
 initial=prefix_oracle(prefix,json.loads(read(ROOT/(E.P+'_checks.json'))));wanted={}
 for r in checkpoint['image_globals']:
  a=int(r['address'],16)
  for j,b in enumerate(bytes.fromhex(r['bytes_hex'])):wanted[a+j]=b
 def getw(a,n):return bytes(wanted[a+j] for j in range(n))
 def value(a,n):return int.from_bytes(getw(a,n),'little')
 def putw(a,b):
  assert all(a+j in wanted for j in range(len(b)))
  for j,x in enumerate(b):wanted[a+j]=x
 def store(a,n,v):putw(a,(v&((1<<(8*n))-1)).to_bytes(n,'little'))
 def ok(name,p):assert p,('platform_contract',name,row['configuration']['label']);checks.append(name)
 def prop(n,key):return next((p for p in n['properties'] if p['key']==key),None) if n else None
 def pbytes(n,key):p=prop(n,key);return p['value'] if p else None
 def strcopy(a,data,cap):
  assert data is not None and b'\0' in data
  data=data.split(b'\0')[0];putw(a,data[:cap-1]+b'\0')
 def capped(a,data,cap,terminate):
  if data is None:return
  n=min(len(data),cap)
  if n:putw(a,data[:n]);store(a+n-1,1,0) if terminate else None
 nodes=parsed['nodes'];arm=nodes.get('/bridge/arm-io');anchor=0
 if arm:
  anchor=value(0xfffffe000cba4120,8)
  if value(0xfffffe000cba40f8,8)==0:
   data=pbytes(arm,'device_type');strcopy(0xfffffe000cba4100,data,32);store(0xfffffe000cba40f8,8,0xfffffe000cba4100)
   ranges=pbytes(arm,'ranges');assert ranges is not None and len(ranges)>=16;anchor=int.from_bytes(ranges[8:16],'little');store(0xfffffe000cba4120,8,anchor)
 anchor_returns=[r for r in row['original_API_returns'] if row['original_API_entries'][r['entry_index']]['PC']==hex(R.ANCHOR)]
 ok('original_anchor_return_matches_named_node_cache_and_second_range_word',len(anchor_returns)==1 and int(anchor_returns[0]['return_value'],16)==anchor)
 C=0xfffffe000cb5c5b0;running_count=0
 if anchor:
  putw(C+0x20,bytes(0xa8));store(C+0x48,8,24000000)
  putw(C,bytes.fromhex(next(d['bytes_hex'] for d in e['literal_data'] if d['address']=='0xfffffe0007010930'))+bytes(16))
  for cpu in nodes['/cpus']['children']:
   state=pbytes(cpu,'state');reference=b'running\0';equal=state is not None
   if state is not None:
    for left,right in zip(state,reference):
     if left!=right:equal=False;break
     if left==0:break
   if not equal:continue
   running_count+=1
   for key,raw_offset,replicas,clamp in [('timebase-frequency',0x48,[0x10],None),('bus-frequency',0x60,[0x68,0x70],0),('memory-frequency',0xa8,[0xb0,0xb8],None),('peripheral-frequency',0x90,[0x98,0xa0],None),('fixed-frequency',0xc0,[],None),('clock-frequency',0x78,[0x80,0x88],8)]:
    raw=pbytes(cpu,key)
    if raw is not None:assert len(raw) in [4,8];store(C+raw_offset,8,int.from_bytes(raw,'little'))
    n=value(C+raw_offset,8)
    for off in replicas:store(C+off,8,n)
    if clamp is not None:store(C+clamp,8,min(n,0xffffffff))
  bus,cpu=value(C,8),value(C+8,8);store(C+0x18,8,bus);store(C+0x20,8,1);store(C+0x28,8,((cpu*2)&0xffffffffffffffff)//bus if bus else 0)
  putw(C+0x30,bytes.fromhex(next(d['bytes_hex'] for d in e['literal_data'] if d['address']=='0xfffffe0007010940')));tb=value(C+0x10,8);store(C+0x40,8,bus//tb if tb else 0)
 root=nodes['/'];store(0xfffffe000cb5c404,1,0);capped(0xfffffe000cb5c404,pbytes(root,'target-type'),16,True)
 product=nodes.get('/product')
 if product:
  store(0xfffffe000cb5c414,1,0);capped(0xfffffe000cb5c414,pbytes(product,'unique-model'),16,True);store(0xfffffe000cb5c424,1,0);capped(0xfffffe000cb5c424,pbytes(product,'sub-product-type'),32,True)
 chosen=nodes.get('/chosen')
 for key,a,cap,terminate in [('debug-enabled',0xfffffe0007f8b5c8,4,False),('system-firmware-version',0xfffffe000cb5c300,128,True),('firmware-version',0xfffffe000cb5c380,128,True),('unique-chip-id',0xfffffe000cb5c444,8,False),('dram-vendor-id',0xfffffe000cb5c44c,4,False)]:capped(a,pbytes(chosen,key),cap,terminate)
 cursor=prop(product,'name')['next'] if product else TREE+row['fixture_extent_bytes'];store(O.B.CURSOR,8,cursor)
 raw=getw(E.ARGS+0x6c,256)
 def opt(key,width,before=None):return parse(raw,key.encode(),width,0,bytes(width) if before is None else before)
 flags=0
 for key,bit in [('assertions',1),('statistics',2)]:
  present,b=opt(key,4)
  if present and int.from_bytes(b,'little'):flags|=bit
 if value(0xfffffe0007f8b5c8,4):
  present,b=opt('diagnostic_api',4)
  if not present or int.from_bytes(b,'little'):flags|=4
 store(0xfffffe0007f8b524,4,flags);present,b=opt('cpu-factor',4,(1).to_bytes(4,'little'))
 if present:putw(0xfffffe000caac7d0,b)
 elif prop(root,'target-is-fpga') is not None:store(0xfffffe000caac7d0,4,10)
 def compare_globals(snapshot,label):
  for r in snapshot:
   a=int(r['address'],16);ok(label+'_'+r['address'],getw(a,len(bytes.fromhex(r['bytes_hex'])))==bytes.fromhex(r['bytes_hex']))
 compare_globals(row['original_platform_return']['image_globals'],'whole_platform_return_region')
 ok('original_platform_return_restores_actual_main_frame',row['original_platform_return']['SP']==hex(SP-0xc0) and row['original_platform_return']['PC']=='0xfffffe000c639b9c')
 system=dict(row['initial_system']);timer=None;divisor=None;quotient=None
 if not row['configuration'].get('platform_only'):
  store(0xfffffe0007ef8228,8,value(E.ARGS+0x18,8));system['s3_1_c15_c1_5']=0;system['s3_4_c15_c14_6']=3
  present,b=opt('wfe_events_sec',8);requested=int.from_bytes(b,'little');divisor=max(1,min(requested,1000000)) if present else 1000000;frequency=value(C+0x48,8);quotient=frequency//divisor;assert 1<=quotient<=1<<32
  timer=max(0,(quotient-1).bit_length()-1);store(0xfffffe0007ef8c60,4,timer)
  system['s3_4_c15_c9_6']|=(timer<<4)|15;system['cntkctl_el1']|=3;system['actlr_el1']&=0xfffffffffffff1ff
  for key,a,n in [('icdsb',0xfffffe0007ef9164,4),('diversify_user_jop',0xfffffe0007e6d154,4),('sptm_stability_hacks',0xfffffe0007e6d159,1)]:
   present,b=opt(key,n,getw(a,n))
   if present:putw(a,b)
  _,b=opt('user_ts_jop',4,(1).to_bytes(4,'little'))
  if int.from_bytes(b,'little')==0:store(0xfffffe0007e6d650,8,value(0xfffffe0007e6d650,8)|(1<<61))
  store(0xfffffe0007e6d9c0,4,14);store(0xfffffe000cb502c0,4,14)
 compare_globals(row['final_image_globals'],'whole_final_region');ok('logical_system_values_follow_original_main',row['final_system']==system)
 before=uncompress(row['initial_private_RAM']);after=uncompress(row['final_private_RAM']);ok('all_nonstack_private_bytes_preserved',before[:SP-P-0x1000]==after[:SP-P-0x1000] and before[SP-P+0x100:]==after[SP-P+0x100:])
 ok('no_generic_initializer_or_call_frame_epoch',not any(v['pc']==hex(E.GENERIC) for v in row['source_visits']) and 'epochs' not in row)
 return {'checks':checks,'prefix_contracts':initial,'tree_API_contracts':apis,'option_API_contracts':options,'copy_contracts':copies,'decoded_tree':{k:parsed[k] for k in ['serialized_bytes','node_count','property_count']},'range_anchor':hex(anchor),'clock_running_CPUs':running_count,'diagnostic_mask':flags,'timer_divisor':divisor,'timer_quotient':quotient,'timer_parameter':timer,'whole_mutable_bytes_per_checkpoint':len(wanted),'private_nonstack_bytes_checked':SIZE-0x1100}

class Replay(Core):
 def __init__(self,image,row):
  super().__init__(image,row);self.entries=[];self.returns=[];self.active=[];self.logical=[];self.system=dict(row['initial_system']);self.checkpoints=0
  for j in range(32):self.u.reg_write(getattr(ar,'UC_ARM64_REG_Q'+str(j)),0)
 def checkpoint(self,wanted):
  assert wanted['before_visit']==self.seq and wanted['registers31']==[hex(self.reg(j)) for j in range(31)] and wanted['SP']==hex(self.u.reg_read(ar.UC_ARM64_REG_SP)) and wanted['NZCV']==hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV)) and wanted['system']==self.system
  assert bytes(self.u.mem_read(P,SIZE))==uncompress(wanted['private_RAM'])
  for r in wanted['image_globals']:assert bytes(self.u.mem_read(int(r['address'],16),len(bytes.fromhex(r['bytes_hex'])))).hex()==r['bytes_hex']
  self.counts['whole_checkpoint_private_bytes_checked']+=SIZE;self.counts['whole_checkpoint_image_bytes_checked']+=sum(len(bytes.fromhex(r['bytes_hex'])) for r in wanted['image_globals']);self.checkpoints+=1
 def code(self,u,a,n,d):
  self.finish()
  while self.active and self.entries[self.active[-1]]['return_PC']==hex(a) and self.entries[self.active[-1]]['entry_SP']==hex(u.reg_read(ar.UC_ARM64_REG_SP)):
   self.returns.append({'entry_index':self.active.pop(),'before_visit':self.seq,'return_value':hex(self.reg(0))})
  if a==E.NEXT_TREE:self.checkpoint(self.p['prefix_checkpoint'])
  if a==0xfffffe000c639b9c:self.checkpoint(self.p['original_platform_return'])
  if a in TRACKED:
   self.active.append(len(self.entries));self.entries.append({'PC':hex(a),'entry_SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'arguments6':[hex(self.reg(j)) for j in range(6)],'return_PC':hex(self.reg(30)),'before_visit':self.seq})
  if self.mi<len(self.models) and a==int(self.models[self.mi]['pc'],16):
   m=self.models[self.mi];assert a in LEAVES and m['symbol']==LEAVES[a] and m['return_value']=='0x0'
   for j in range(18):assert int(m['after_registers31'][j],16)==(0 if j==0 else (((j+1)*0x123456789abcdef)^((self.mi+1)*0x8b3dc651))&0xffffffffffffffff)
   assert int(m['after_NZCV'],16)==(0xf0000000 if (self.mi+1)&1 else 0)
  if len(self.logical)<len(self.p['logical_effects']):
   expected=self.p['logical_effects'][len(self.logical)]
   if expected['before_visit']==self.seq and expected['PC']==hex(a):
    raw=bytes(u.mem_read(a,4));assert raw==self.image.k.read(a,4) and self.p['source_visits'][self.seq]=={'pc':hex(a),'bytes_hex':raw.hex()};i=next(self.image.k.cs.disasm(raw,a));event={'PC':hex(a),'kind':i.mnemonic,'operands':i.op_str,'before_visit':self.seq,'system_before':dict(self.system)};target=a+4
    if i.mnemonic in ['mrs','msr']:
     left,right=i.op_str.split(', ')
     if i.mnemonic=='mrs':assert right in self.system;u.reg_write(getattr(ar,'UC_ARM64_REG_'+left.upper()),self.system[right])
     else:self.system[left]=0 if right=='xzr' else self.reg(int(right[1:]))
    elif i.mnemonic=='blraa':
     assert self.reg(19)==O.SPACE and self.reg(17)==0xba5;target=self.reg(19);u.reg_write(ar.UC_ARM64_REG_X30,a+4);event['target']=hex(target);event['modifier_X17']=hex(self.reg(17))
    else:assert i.mnemonic in ['paciza','xpaci','pacia','isb']
    event['system_after']=dict(self.system);assert event==expected;self.logical.append(event);self.current=self.seq;self.seq+=1;self.rc=self.wc=0;self.counts['source_visits_checked']+=1;self.counts['logical_effects_checked']+=1;u.reg_write(ar.UC_ARM64_REG_PC,target);return
  return super().code(u,a,n,d)
 def run(self):
  entry=int(self.p['entry_PC'],16);self.ensure(entry);self.u.emu_start(entry,0,count=len(self.p['source_visits'])+len(self.models)+10);self.finish()
  assert self.seq==len(self.p['source_visits']) and self.mi==len(self.models) and self.counts['final_boundaries_checked']==1
  assert self.entries==self.p['original_API_entries'] and self.returns==self.p['original_API_returns'] and not self.active and self.checkpoints==2
  assert self.logical==self.p['logical_effects'] and self.system==self.p['final_system']
  assert bytes(self.u.mem_read(P,SIZE))==uncompress(self.p['final_private_RAM']);self.counts['whole_private_bytes_checked']+=SIZE
  assert {hex(pg):sha256(bytes(self.u.mem_read(pg,4096))).hexdigest() for pg in sorted(self.pages)}==self.p['final_page_sha256'];self.counts['whole_image_page_bytes_checked']+=len(self.pages)*4096
  for j,x in enumerate(self.p['final_vectors']):assert hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))))==x;self.counts['vector_registers_checked']+=1
  self.counts['original_API_entries_and_returns_checked']+=len(self.entries);return dict(self.counts)
