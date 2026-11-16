#!/usr/bin/env python3
"""Independent option grammar/arithmetic, per-call contracts and fresh replay.
No executor import. O(journals + visits + mapped bytes + fixtures) space;
sorted phase materialization adds O(journals log journals) time.
"""
from unicorn import arm64_const as ar
from replay_kernel_boot_cpu_identity import pages,get,put,P,SP,HALT,MASK,regno
from replay_kernel_secure_dt_execution import Replay as Parent,oracle as tree_oracle,state_at,decode as decode_tree,API_oracle as tree_API_contracts
from replay_kernel_cpu_topology_handoff import Replay as Core
import recover_kernel_boot_option_execution as R
K=R.B.B.B;WORK=P+0x6000;LIMIT=100000;DELIMITERS={0,9,32}
def number(raw,mode=0):
 """Selected original numeric grammar; u64 accumulation, signed-u32 scale."""
 if not mode and not raw.startswith(b'='):return 0,1
 text=raw[1:] if raw.startswith(b'=') else raw;sign=-1 if text.startswith(b'-') else 1
 if sign<0:text=text[1:]
 assert text
 if not 48<=text[0]<=57:return 1,None
 radix=10;at=1;value=text[0]-48
 if text[0]==48:
  nxt=text[1] if len(text)>1 else 0
  if 48<=nxt<56:radix=8;at=2;value=nxt-48
  elif nxt==120:radix=16;at=2;value=0
  elif nxt==98:radix=2;at=2;value=0
  elif nxt not in DELIMITERS:return 1,None
 while at<len(text):
  ch=text[at]
  if ch in DELIMITERS:return 0,(value*sign)&MASK
  digit=ch-48 if 48<=ch<=57 else ch-87 if 97<=ch<=102 else ch-55 if 65<=ch<=70 else None
  if digit is not None:
   if digit>=radix:return 1,None
   value=(value*radix+digit)&MASK;at+=1;continue
  scale={107:10,109:20,103:30}.get(ch|32)
  if scale is None or at+1<len(text) and text[at+1] not in DELIMITERS:return 1,None
  signed=(sign<<scale)&0xffffffff;signed=signed if signed<0x80000000 else signed-(1<<32)
  return 0,(value*signed)&MASK
 return 0,(value*sign)&MASK
def write_number(before,width,value):
 out=bytearray(before)
 if width==0:return bytes(out)
 n=width if width in [1,2,3,8] else 4;out[:n]=(value&((1<<(n*8))-1)).to_bytes(n,'little');return bytes(out)
def parse(raw,key,width,string_mode,before):
 """Independent scanner for bounded selected ASCII buffers and normal widths."""
 data=raw.split(bytes(1))[0];requested=key;result=0;out=bytes(before);pos=0
 while pos<len(data):
  while pos<len(data) and data[pos] in [9,32]:pos+=1
  if pos==len(data):break
  end=pos
  while end<len(data) and data[end] not in [9,32,61]:end+=1
  name=data[pos:end];cursor=end
  while cursor<len(data) and data[cursor] in [9,32]:cursor+=1
  match=name==requested
  if match and name.startswith(b'-'):
   if width:
    if string_mode:out=bytes(b'1'+bytes(1)+out[2:])
    else:out=write_number(out,width,1)
   return 1,out
  if match and end<len(data) and data[end]!=61 and cursor<len(data) and data[cursor]==61:
   match=False;pos=cursor+1
  if match:
   suffix=data[cursor:]+bytes(1);status,value=(1,None) if string_mode else number(suffix)
   if not status:out=write_number(out,width,value)
   elif width:
    value=suffix[1:] if suffix.startswith(b'=') else b'1'+bytes(1);value=value.split(bytes(1))[0].split(b' ')[0].split(b'\t')[0];value=value[:max(width-1,0)];out=value+bytes(1)+out[len(value)+1:]
   result=1
  while pos<len(data) and data[pos] not in [9,32]:pos+=1
 return result,out

def option_oracle(row):
 memory=pages(row['initial_pages']);events=[];pending={};checks=[];hist={};outputs=[]
 def ok(label,p):assert p,('semantic_oracle',label);checks.append(label)
 def u(a,n):return int.from_bytes(get(memory,a,n),'little')
 def string(a):
  out=bytearray()
  for j in range(512):
   x=u(a+j,1)
   if x==0:return bytes(out)
   out.append(x)
  raise AssertionError('fixture_option_string_not_terminated')
 for j,w in enumerate(row['writes']):events.append((w['visit'],2,j,'write',w))
 for j,m in enumerate(row['declared_models']):
  for n,w in enumerate(m['api_writes']):events.append((m['before_visit'],2,j*4+n,'write',w))
 for j,e in enumerate(row['original_option_API_entries']):events.append((e['before_visit'],1,j,'entry',e))
 for j,e in enumerate(row['original_option_call_returns']):events.append((e['before_visit'],0,j,'return',e))
 for _,_,index,kind,e in sorted(events,key=lambda x:x[:3]):
  if kind=='write':raw=bytes.fromhex(e['after_hex']);put(memory,int(e['address'],16),len(raw),raw);continue
  if kind=='return':
   status,out=pending.pop(e['entry_index']);ok('option_status_'+str(e['entry_index']),int(e['return_value'],16)==status)
   for j,(at,raw) in enumerate(out):ok('option_output_'+str(e['entry_index'])+'_'+str(j),get(memory,at,len(raw))==raw)
   continue
  a=int(e['PC'],16);v=list(map(lambda x:int(x,16),e['arguments6']));out=[];hist[hex(a)]=hist.get(hex(a),0)+1
  if a==R.PARSE:
   width=v[3]&0xffffffff;mode=v[4]&0xffffffff;assert width in [0,1,2,3,4,8,16,32] and mode in [0,1]
   n=4 if width==3 else width;before=get(memory,v[2],n);raw=string(v[0]);key=string(v[1]) if raw.strip(b' \t') else None
   status,after=parse(raw+bytes(1),key or b'',width,mode,before);out=[(v[2],after)] if n else []
   outputs.append({'entry_index':index,'key':key.decode('ascii') if key is not None else None,'width':width,'string_mode':mode,'status':status,'expected_output_hex':after.hex()})
  elif a==R.NUMBER:
   status,value=number(string(v[0])+bytes(1),v[3]&0xffffffff);out=[(v[1],value.to_bytes(8,'little') if status==0 else get(memory,v[1],8))]
  elif a==R.SPACE:status=int(v[0]&0xffffffff in DELIMITERS)
  elif a==R.STRLEN:status=len(string(v[0]))
  elif a==R.FLAG:
   width=v[1]&0xffffffff;n=4 if width==3 else width if width in [1,2,8] else 4;status=v[0];out=[(v[0],write_number(get(memory,v[0],n),width,1))]
  else:raise AssertionError(hex(a))
  pending[index]=(status,out)
 ok('all_original_option_API_calls_returned',not pending and len(row['original_option_API_entries'])==len(row['original_option_call_returns']))
 ok('no_declared_option_outputs',not any(m['name']=='declared_boot_option_output' for m in row['declared_models']))
 return {'checks':checks,'API_calls':len(row['original_option_API_entries']),'entry_histogram':hist,'parser_results':outputs}

def oracle(row):
 options=option_oracle(row);checks=[]
 def ok(label,p):assert p,('semantic_oracle',label);checks.append(label)
 c=row['configuration'];original=pages(row['initial_pages'])
 if not c.get('operations'):
  synthetic=dict(row);configuration=dict(c);configuration['options']={}
  for key,width in [('cpus',4),('cpumask',8),('enable_skstb',0),('enable_skstsct',0),('cluster_power',4),('siq_realtime_thread_mode',4)]:
   found,out=parse(c.get('boot_text','').encode()+bytes(1),key.encode(),width,0,bytes(width))
   if found:configuration['options'][key]=int.from_bytes(out,'little') if width else 1
  synthetic['configuration']=configuration;topology=tree_oracle(synthetic)
  return {'checks':checks,'option_contracts':options,'tree_and_topology':topology,'derived_options':configuration['options']}
 expected=pages(row['initial_pages']);tree_size=row['fixture_extent_bytes'];base=P+0x10000
 for at,n,v in [(R.B.GLOBALS,8,base),(R.B.GLOBALS+8,8,tree_size),(R.B.GLOBALS+16,8,base+tree_size),(R.B.GLOBALS+24,4,1)]:put(expected,at,n,v)
 returns=row['dedicated_option_API_returns'];ok('all_dedicated_option_calls_return',len(returns)==len(c['operations']));byte_count=0
 for j,(op,result) in enumerate(zip(c['operations'],returns)):
  at=WORK+j*64;width=op['width'];span=4 if width==3 else width;old=get(expected,at,64);status,out=parse(op['text'].encode()+bytes(1),op['key'].encode(),width,op.get('string_mode',0),old)
  put(expected,at,64,out);ok('dedicated_option_status_'+str(j),int(result['registers'][0],16)==status);ok('dedicated_option_workspace_'+str(j),result['workspace_hex']==get(expected,WORK,512).hex())
  actual=state_at(row,result['before_visit'])
  for pg in expected:
   if pg==P+0xe000:continue
   ok('dedicated_option_nonstack_'+str(j)+'_'+hex(pg),actual[pg]==expected[pg]);byte_count+=4096
 ok('dedicated_option_final_boundary',int(row['boundary']['PC'],16)==HALT and row['final_system']==row['initial_system'])
 return {'checks':checks,'option_contracts':options,'tree_and_topology':None,'initializer_contracts':tree_API_contracts(row,decode_tree(row)),'independent_API_nonstack_bytes_checked':byte_count}
class Replay(Parent):
 def __init__(self,image,row):
  super().__init__(image,row);self.option_entries=[];self.option_returns=[];self.option_stack=[]
  assert row['initial_vectors']==['0x0']*32
  for j in range(32):self.u.reg_write(getattr(ar,'UC_ARM64_REG_Q'+str(j)),0)
 def code(self,u,a,n,d):
  self.finish()
  while self.active_calls and a==int(self.native_entries[self.active_calls[-1]]['return_PC'],16) and u.reg_read(ar.UC_ARM64_REG_SP)==int(self.native_entries[self.active_calls[-1]]['entry_SP'],16):
   self.tree_call_returns.append({'entry_index':self.active_calls.pop(),'before_visit':self.seq,'return_value':hex(self.regs()[0])})
  while self.option_stack and a==int(self.option_entries[self.option_stack[-1]]['return_PC'],16) and u.reg_read(ar.UC_ARM64_REG_SP)==int(self.option_entries[self.option_stack[-1]]['entry_SP'],16):
   self.option_returns.append({'entry_index':self.option_stack.pop(),'before_visit':self.seq,'return_value':hex(self.regs()[0])})
  if a in [R.PARSE,R.NUMBER,R.FLAG,R.SPACE,R.STRLEN]:
   self.option_stack.append(len(self.option_entries));self.option_entries.append({'PC':hex(a),'entry_SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'arguments6':list(map(hex,self.regs()[:6])),'return_PC':hex(self.regs()[30]),'before_visit':self.seq})
  if a==HALT:
   if self.init_checkpoint is None:
    self.init_checkpoint={'PC':hex(a),'before_visit':self.seq,'global_bytes_hex':bytes(u.mem_read(R.B.GLOBALS,32)).hex(),'registers':list(map(hex,self.regs()))};self.stage='API' if self.row['configuration'].get('operations') else 'enumeration'
   elif self.stage=='API':self.api_returns.append({'operation':len(self.api_returns),'PC':hex(a),'before_visit':self.seq,'registers':list(map(hex,self.regs())),'workspace_hex':bytes(u.mem_read(WORK,0x200)).hex()})
  if self.epoch<len(self.row['epochs']):
   e=self.row['epochs'][self.epoch]
   if a==int(e['PC'],16) and self.seq==e['before_visit']:
    assert e['writes_completed']==self.wi and e['system']==self.system and e['registers']==list(map(hex,self.regs()))
    assert e['kind'] in ['explicit_boot_option_API_call','tree_initializer_to_main_cut','bootstrap_to_CPU_caller_cut']
    self.epoch+=1;u.reg_write(ar.UC_ARM64_REG_SP,SP);u.reg_write(regno(30),HALT)
    for j,v in enumerate(e['arguments']):u.reg_write(regno(j),int(v,16))
    u.reg_write(ar.UC_ARM64_REG_PC,int(e['next_PC'],16));return
  if a in [R.B.INIT,R.B.B.LOOKUP,R.B.B.PROPERTY,R.B.B.ITERATE,R.B.B.FIND,R.B.SKIP,R.B.STRCMP]:
   self.active_calls.append(len(self.native_entries));self.native_entries.append({'PC':hex(a),'entry_SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'arguments6':list(map(hex,self.regs()[:6])),'return_PC':hex(self.regs()[30]),'before_visit':self.seq})
  raw=bytes(u.mem_read(a,4))
  if self.seq<len(self.row['source_visits']):
   i=next(self.image.k.cs.disasm(raw,a))
   if i.mnemonic in ['pacia','blraa']:
    assert raw==self.image.k.read(a,4) and self.row['source_visits'][self.seq]=={'PC':hex(a),'bytes_hex':raw.hex()};index=self.seq;self.seq+=1
    if i.mnemonic=='pacia':
     assert self.row['logical_effects'][self.ei]=={'visit':index,'PC':hex(a),'kind':'logical_PAC','mnemonic':i.mnemonic,'operands':i.op_str};self.ei+=1;u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
    regs=self.regs();assert regs[19]==R.SPACE and regs[17]==0xba5
    assert self.row['logical_effects'][self.ei]=={'visit':index,'PC':hex(a),'kind':'logical_authenticated_call','target':hex(regs[19]),'discriminator':hex(regs[17]),'return_PC':hex(a+4)};self.ei+=1;u.reg_write(regno(30),a+4);u.reg_write(ar.UC_ARM64_REG_PC,regs[19]);return
  return Core.code(self,u,a,n,d)
 def run(self):
  self.u.emu_start(int(self.row['start'],16),0,count=LIMIT);self.finish();assert self.stopped
  assert (self.ri,self.wi,self.mi,self.ei,self.epoch)==tuple(len(self.row[k]) for k in ['reads','writes','declared_models','logical_effects','epochs'])
  assert self.system==self.row['final_system'] and self.copy_entries==self.row['original_copy_entries']
  assert self.comparisons==self.row['original_comparison_entries'] and self.wrapper_calls==self.row['declared_selector0e_calls'] and self.boot_snapshots==self.row['source_boot_record_snapshots'] and self.main_snapshots==self.row['source_main_continuation_checkpoints']
  assert self.option_entries==self.row['original_option_API_entries'] and self.option_returns==self.row['original_option_call_returns'] and not self.option_stack
  assert [hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j)))) for j in range(32)]==self.row['final_vectors']
  assert hex(self.u.reg_read(ar.UC_ARM64_REG_SP))==self.row['final_SP'] and hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))==self.row['final_NZCV']
  assert self.tree_call_returns==self.row['original_tree_call_returns'] and not self.active_calls
  assert self.native_entries==self.row['original_tree_API_entries'] and self.api_returns==self.row['dedicated_option_API_returns'] and self.init_checkpoint==self.row['tree_initializer_return']
  for pg,raw in pages(self.row['final_pages']).items():assert bytes(self.u.mem_read(pg,4096))==raw
  return {'source_visits_checked':self.seq,'reads_checked':self.ri,'writes_checked':self.wi,'declared_models_checked':self.mi,'logical_effects_checked':self.ei,'same_RAM_epochs_checked':self.epoch,'whole_mapped_bytes_checked':len(self.row['final_pages'])*4096,'original_tree_API_entries_checked':len(self.native_entries),'original_tree_call_returns_checked':len(self.tree_call_returns),'dedicated_option_API_returns_checked':len(self.api_returns),'tree_initializer_returns_checked':1,'original_option_API_calls_and_returns_checked':len(self.option_entries),'vector_registers_checked':32}
