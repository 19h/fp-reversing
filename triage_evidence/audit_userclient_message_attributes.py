#!/usr/bin/env python3
"""Source-state composition through FPMessageAttr construction and overlay.
O(I+64I+C*I+1024+query DAG) construction/space; SMT search separately bounded.
External allocation/random returns preserve declared caller storage by premise.
"""
import copy,json
import z3
from kext_port_tools import ROOT,IMAGE,TABLE,qword
from lskd_values_symbolic import mem,resize,Lift
from verify_daemon_reader_record_payloads_publication import read,sha
import audit_userclient_schema_lookup_result as Parent
import recover_userclient_message_attributes as R
H=Parent.H;DEC=Parent.DEC;Publication=Parent.Publication;SUCCESS=Parent.SUCCESS;TOKEN=Parent.TOKEN;PHASE=Parent.PHASE;pc=R.pc
Search=Parent.Parent.Parent.Parent
PROFILES=['mode_zero','mode_nonzero','allocation_null']
ATTR_STORE_PCS={pc(a)for a in [0xa652f30,0xa652f34,0xa652f38,0xa652f40,0xa652fe4,0xa653080,0xa6530b8,0xa6530bc,0xa653108,0xa636a8c,0xa636a98,0xa636b58,0xa636b90,0xa636d04]}|{pc(a)for a in range(0xa6530c4,0xa653104,4)}|{pc(a)for a in range(0xa636aa0,0xa636b1c,8)}|{pc(a)for a in range(0xa636b98,0xa636c94,8)}
CONTEXT_STORES={pc(a):(root,off,n)for a,root,off,n in [(0xa636984,'C',0x100,8),(0xa636988,'S',0xb60,4),(0xa63698c,'S',0xf4,4),(0xa636990,'C',0x360,8),(0xa636994,'C',0x1b0,8),(0xa636998,'C',0x700,8),(0xa6369b0,'F',0x9e0,8),(0xa652e18,'C',0x480,8),(0xa652f1c,'F',0x9d0,4),(0xa653110,'C',0x1b0,8),(0xa6369dc,'S',0xd0c,4),(0xa636b1c,'C',0x4a8,8),(0xa641b1c,'S',0xab8,4)]}
def parent_input(e):
 p=copy.deepcopy(e);p['source']=copy.deepcopy(e['lookup_result_source']);return p
class Model(Parent.Model):
 def __init__(self,e,frontier=False):
  # Adopt the complete actual source state; no returned business field is seeded.
  prior=Parent.consumed(parent_input(e),'hit_nonnull')if frontier else Parent.Model(parent_input(e));self.__dict__.update(prior.__dict__);self.e=copy.deepcopy(self.e);self.e['source']['spans']+=copy.deepcopy(e['source']['spans']);self.attribute_receipt=e;self.attribute=z3.BitVec('MA_attribute64',64);self.original_input=z3.BitVec('MA_original_input64',64);self.old_workspace=z3.BitVec('MA_initial_workspace_d0c32',32);self.payload_bytes=[z3.BitVec('MA_payload_byte_'+str(j),8)for j in range(56)];self.raw_random=[z3.BitVec('MA_provider_word_'+str(j),32)for j in range(64)];self.attribute_bytes={};self.attribute_stores=[];self.attribute_bank_reads=[];self.attribute_controller_reads=[];self.attribute_payload_reads=[];self.attribute_API_returns=[];self.attribute_owned=False;self.payload_owned=False;self.new_store_start=len(self.stores);self.new_source_start_count=self.count;self.imported_root_equalities=[];self.initial_unknown_reads=[];self.profile=None;c=self.common
  for off,n,kind,value in R.ROOTS:
   want=c['C']+value if kind=='C'else c['N']^SUCCESS if kind=='encoded_extent'else self.original_input if kind=='original_input'else resize(value,n*8);key=(z3.simplify(c['F']+off).sexpr(),n)
   if key in self.memory:self.imported_root_equalities.append(self.memory[key]==resize(want,n*8))
   else:mem(self,c['F']+off,n,want)
 def owned(self):
  out=super().owned();c=self.common;ranges=[(c['F']-0x70,resize(0x1160,64)),(c['C'],resize(0x1000,64)),(c['S'],resize(0x4000,64)),(c['H'],resize(16,64)),(c['J'],resize(32,64)),(c['Z'],z3.ZeroExt(32,c['L'])+10)]
  if self.header_owned:ranges.append((self.holder,resize(16,64)))
  if self.result_array_owned:ranges.append((self.entries,24*z3.ZeroExt(32,self.capacity)))
  new=[]
  if self.attribute_owned:new.append((self.attribute,resize(112,64)))
  if self.payload_owned:new.append((self.payload,resize(56,64)))
  for j,(a,n)in enumerate(new):
   out.extend([a!=0,z3.ULE(a,resize((1<<64)-1,64)-n)])
   for b,m in ranges+new[j+1:]:out.append(z3.Or(z3.ULE(a+n,b),z3.ULE(b+m,a)))
   for b,off,m in IMAGE.segments:out.append(z3.Or(z3.ULE(a+n,resize(b,64)),z3.ULE(resize(b+m,64),a)))
  return out
 def load(self,a,n):
  if self.pc==pc(0xa652e1c):
   assert n==4;self.address_checks.append(a==self.common['S']+0xd0c);self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});self.initial_unknown_reads.append({'source_PC':hex(self.pc),'root':'S','offset':'0xd0c','width_bits':32,'initial_value_defined_by_original_prefix':False,'concrete_value_supplied':False});return self.old_workspace
  if self.pc in [pc(v)for v in [0xa652e40,0xa652e48,0xa652f74,0xa652f78,0xa653014,0xa653018]]:
   assert n==4;expected=pc(0xccc30d0)if self.pc in [pc(0xa652e40),pc(0xa652f74),pc(0xa653014)]else pc(0xccc32f8);self.address_checks.append(a==expected);self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});self.attribute_controller_reads.append(hex(self.pc));return z3.BitVec('MA_controller_'+str(len(self.attribute_controller_reads)),32)
  for name,(lp,rp,pp)in R.BANK_PCS.items():
   rule=next(q for q in self.attribute_receipt['attribute_bank_rules']if q['name']==name);left,right=int(rule['left'],16),int(rule['right'],16)
   if self.pc==lp:
    assert n==1;self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});self.attr_bank_input=z3.Extract(7,0,a-left);self.attr_bank_byte=z3.BitVec('MA_bank_'+str(len(self.attribute_bank_reads)),8);self.address_checks.append(a==left+z3.ZeroExt(56,self.attr_bank_input));return self.attr_bank_byte
   if self.pc==rp:
    assert n==1;self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});self.address_checks.append(a==right+z3.ZeroExt(56,self.attr_bank_byte^int(rule['key'],16)));self.attribute_bank_reads.append({'source_PC':hex(self.pc),'rule':name,'certified_inputs':256});return self.attr_bank_input^int(rule['constant'],16)
   if self.pc==pp:
    assert n==8;self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});self.address_checks.append(a==int(rule['slot'],16));return resize(int(rule['original_pointer']['target'],16),64)
  if self.pc in [pc(v)for v in list(range(0xa636a9c,0xa636b1c,8))+[0xa636b20]+list(range(0xa636b94,0xa636c94,8))+[0xa636d00]]:
   off=0 if self.pc==pc(0xa636d00)else 4 if self.pc==pc(0xa636b20)else 0x17-(self.pc-pc(0xa636a9c))//8 if self.pc<pc(0xa636b1c)else 0x37-(self.pc-pc(0xa636b94))//8;assert n==(4 if off==0 else 1);self.address_checks.append(a==self.payload+off);self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});self.attribute_payload_reads.append({'pc':self.pc,'offset':off,'size_bytes':n});return z3.Concat(*reversed(self.payload_bytes[off:off+n]))if n>1 else self.payload_bytes[off]
  if self.pc in R.BRANCHES:
   assert n==8;self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});js=R.BRANCHES[self.pc];self.address_checks.append(z3.Or(*[a==TABLE+8*j for j in js]));value=resize(0,64)
   for j in js:value=z3.If(a==TABLE+8*j,resize(qword(TABLE+8*j),64),value)
   return value
  return super().load(a,n)
 def store(self,a,n,value,source_pc):
  if source_pc in ATTR_STORE_PCS:
   off=z3.simplify(a-self.attribute);assert z3.is_bv_value(off)and off.as_long()+n<=112,(hex(source_pc),off,n);off=off.as_long();value=resize(value,8*n)
   for j in range(n):self.attribute_bytes[off+j]=z3.Extract(8*j+7,8*j,value)
   self.attribute_stores.append({'pc':source_pc,'offset':off,'size_bytes':n})
  super().store(a,n,value,source_pc)
 def external_return(self,kind,expected_return,random_index=None):
  edge=self.edges[-1];target=pc(0xc4ba154)if kind=='allocate'else pc(0xbf09e30);modifier=0xd0c8 if kind=='allocate'else 0xc350;self.address_checks.extend([edge['target']==target,edge['modifier']==modifier,self.read('sp')==self.common['F'],self.read('x30')==expected_return,resize(edge['pc']+4,64)==expected_return]);j=len(self.attribute_API_returns)
  self.attribute_API_returns.append({'kind':kind,'source_PC':hex(edge['pc']),'nominal_return_PC':hex(expected_return),'callee_saved_registers_preserved':True,'declared_caller_storage_preserved':True,'native_target_executed':False,'random_index':random_index})
  for reg in list(range(19))+[30]:self.seed('x'+str(reg),z3.BitVec('MA_API_'+str(j)+'_X'+str(reg),64))
  self.seed('x0',self.attribute if kind=='allocate'else z3.ZeroExt(32,self.raw_random[random_index]&0x7fffffff));return self
 def attribute_cell(self,off,n):return z3.Concat(*reversed([self.attribute_bytes[off+j]for j in range(n)]))if n>1 else self.attribute_bytes[off]

def follow(v,label,modifier):
 v.address_checks.append(z3.Not(Publication.edge(v,R.SPANS[label][0],modifier)));return v.run(label)
def prepared(e):
 v=Model(e,True);v.run('attr_begin');follow(v,'attr_bridge',0x1408);return follow(v,'attr_allocate',0xa848)
def finished(e,profile):
 assert profile in PROFILES;v=prepared(e);v.profile=profile;c=v.common
 if profile=='allocation_null':v.extra.append(v.attribute==0)
 else:v.attribute_owned=True;v.payload_owned=True;v.extra.append(v.payload_bytes[4]==0 if profile=='mode_zero'else v.payload_bytes[4]!=0)
 v.external_return('allocate',pc(0xa652ed0)).run('attr_allocate_return')
 if profile!='allocation_null':
  follow(v,'attr_initial_header',0x7757)
  for j in range(32):
   follow(v,'attr_first_random_request',0x29d9);v.external_return('random',pc(0xa652fc0),j).run('attr_first_random_return');v.address_checks.append(v.read('x26')==j+1)
  for j in range(32):
   follow(v,'attr_second_random_request',0x29d9);v.external_return('random',pc(0xa653060),j+32).run('attr_second_random_return');v.address_checks.append(v.read('x23')==j+1)
  follow(v,'attr_constructor_finish',0x29d9)
 follow(v,'attr_constructor_return',0x7757);follow(v,'attr_caller_return',0xf596)
 if profile=='allocation_null':return follow(v,'attr_error',0x7ad9)
 follow(v,'attr_caller_nonnull',0x7ad9);follow(v,'attr_copy16_mode',0xc4ed)
 if profile=='mode_zero':follow(v,'attr_copy32',0xa9fd);follow(v,'attr_reload_payload',0x5271)
 else:follow(v,'attr_nonzero_mode',0xa9fd)
 return follow(v,'attr_copy_header',0x44c9)

def expected_attribute(v):
 out={};put=lambda off,raw:out.update({off+j:resize(b,8)for j,b in enumerate(raw)})
 def word(off,value,n):put(off,[z3.Extract(8*j+7,8*j,resize(value,8*n))for j in range(n)])
 word(0,0x3908f615,4);word(4,0,4)
 for j in range(64):out[8+j]=z3.Extract(7,0,v.raw_random[j])^0xc7
 word(0x48,0,8);out[0x50]=resize(int(v.profile=='mode_nonzero'),8);out[0x51]=resize(0x1a,8);put(0x54,v.payload_bytes[:4]);put(0x58,v.payload_bytes[8:24]);word(0x68,16,4);out[0x6c]=resize(3,8)
 if v.profile=='mode_zero':put(8,v.payload_bytes[24:56]);word(0x48,32,4)
 return out
def output_bad(v):
 c=v.common;bad=[*[z3.Not(q)for q in v.imported_root_equalities],H.cell(v,c['C']+0x100,8)!=c['C']+0x90,H.cell(v,c['C']+0x360,8)!=0,H.cell(v,c['C']+0x700,8)!=v.payload,H.cell(v,c['S']+0xb60,4)!=SUCCESS,H.cell(v,c['S']+0xf4,4)!=SUCCESS,H.cell(v,c['S']+0xd0c,4)!=v.old_workspace]
 for q in v.stores[v.new_store_start:]:
  if q['pc']in ATTR_STORE_PCS:
   off=z3.simplify(q['address']-v.attribute);assert z3.is_bv_value(off)and off.as_long()+q['size_bytes']<=112
  else:
   root,off,n=CONTEXT_STORES[q['pc']];assert q['size_bytes']==n;bad.append(q['address']!=c[root]+off)
 if v.profile=='allocation_null':
  assert not v.attribute_bytes and not v.attribute_payload_reads;bad.extend([H.cell(v,c['C']+0x1b0,8)!=0,H.cell(v,c['S']+0xab8,4)!=0xce515bb2,Publication.edge(v,pc(0xa6621e4),0x682a)]);assert len(v.attribute_API_returns)==1
 else:
  want=expected_attribute(v);assert set(want)==set(v.attribute_bytes)==set(range(112))-{0x52,0x53,0x6d,0x6e,0x6f};bad.extend(v.attribute_bytes[j]!=value for j,value in sorted(want.items()));bad.extend([H.cell(v,c['C']+0x1b0,8)!=v.attribute,H.cell(v,c['C']+0x4a8,8)!=v.payload,v.read('w22')!=(c['N']^SUCCESS),v.read('x8')!=c['C']+0x360,v.read('x20')!=v.original_input,Publication.edge(v,pc(0xa6575b0),0x2854)]);assert len(v.attribute_API_returns)==65 and [q['random_index']for q in v.attribute_API_returns[1:]]==list(range(64))
 return z3.Or(*bad)

class RandomCut(Lift):
 def __init__(self,e):
  super().__init__({'spans':e['source']['spans']});self.e=e;self.count=0;self.visited=set();self.edges=[];self.guards=[];self.extra=[];self.address_checks=[];self.raw=z3.BitVec('MA_random_provider_output32',32);self.thread=z3.BitVec('MA_random_TPIDR64',64);self.frame=z3.BitVec('MA_random_frame64',64);self.state=z3.BitVec('MA_random_state64',64);self.providers=[z3.BitVec('MA_random_provider_'+str(j),64)for j in range(2)];self.field=z3.BitVec('MA_random_thread_field16',16)
 def owned(self):return[]
 def run(self,label):
  row=next(s for s in self.e['source']['spans']if s['label']==label)
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   self.pc=i.address;self.visited.add(i.address)
   if i.mnemonic=='mrs':assert i.op_str=='x8, tpidr_el1';self.write('x8',self.thread);self.count+=1
   elif i.mnemonic=='blraa':self.edges.append({'pc':i.address,'target':self.read(i.reg_name(i.operands[0].reg)),'modifier':self.read(i.reg_name(i.operands[1].reg))});self.count+=1
   elif i.mnemonic=='adrp':self.write(i.reg_name(i.operands[0].reg),resize(i.operands[1].imm,64));self.count+=1
   else:
    self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run('one')
  return self
 def address(self,i,o):
  if i.writeback:
   assert i.address==pc(0xbf09e6c);a=z3.simplify(self.read(i.reg_name(o.mem.base))+o.mem.disp);self.write(i.reg_name(o.mem.base),a);return a
  return super().address(i,o)

def source_obligations(e):
 out=[];visited=set()
 def prove(name,v,bad):
  premises=v.owned()+v.guards+v.extra;p=z3.SolverFor('QF_BV');p.set(timeout=60000);p.add(*premises);r=p.check();assert r==z3.sat,(name,'premises',str(r),p.reason_unknown());obligation=z3.simplify(z3.Or(bad,*[z3.Not(q)for q in v.address_checks]));terms=list(obligation.children())if z3.is_or(obligation)else[obligation];parts=[terms[j:j+2]for j in range(0,len(terms),2)]
  for j,terms in enumerate(parts):
   label=name if len(parts)==1 else name+'_part_'+str(j+1);s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*premises,z3.Or(*terms));query=s.to_smt2();r=s.check();assert r==z3.unsat,(label,str(r),s.reason_unknown(),s.model()if r==z3.sat else'');out.append({'name':label,'semantic_contract':name,'counterexample_partition':j+1,'counterexample_partitions':len(parts),'result':'unsat','premises_nonvacuous':True,'query':query,'lifted_instruction_instances':v.count,'modeled_external_returns':len(getattr(v,'attribute_API_returns',[])),'new_certified_bank_applications':len(getattr(v,'attribute_bank_reads',[]))});print('proved '+label,flush=True)
  visited.update(v.visited)
 for label in ['random_enter_provider','random_generate_provider','random_mask_return']:
  v=RandomCut(e);v.seed('sp',v.frame);v.seed('x19',pc(0x7e6c9a0));v.seed('x20',pc(0xcb88000));mem(v,pc(0x7e6c9a0),8,v.providers[0]);mem(v,pc(0x7e6c9a8),8,v.providers[1]);mem(v,pc(0xcb88f48),8,v.state);mem(v,v.thread+0x1b8,2,v.field);mem(v,v.frame+0xc,4,v.raw);v.run(label)
  if label=='random_enter_provider':bad=z3.Or(v.read('x0')!=v.state,v.edges[-1]['target']!=v.providers[0],v.edges[-1]['modifier']!=((pc(0x7e6c9a0)&0xffffffffffff)|(0x4d5f<<48)))
  elif label=='random_generate_provider':bad=z3.Or(v.read('x0')!=v.state,v.read('w1')!=z3.ZeroExt(16,v.field),v.read('w2')!=4,v.read('x3')!=v.frame+0xc,v.edges[-1]['target']!=v.providers[1],v.edges[-1]['modifier']!=((pc(0x7e6c9a8)&0xffffffffffff)|(0xedeb<<48)))
  else:bad=z3.Or(v.read('w0')!=(v.raw&0x7fffffff),z3.Extract(31,31,v.read('w0'))!=0)
  prove(label+'_original_kernel_contract',v,bad)
 v=prepared(e);prove('actual_hit_requests_original_FPMessageAttr_and_preserves_unknown_word',v,z3.Or(v.read('x0')!=pc(0x847b1e0),v.read('w19')!=v.old_workspace,H.cell(v,v.common['C']+0x480,8)!=pc(0xa6369c8),Publication.edge(v,pc(0xc4ba154),0xd0c8)))
 # Source byte codec over every u32 return, including the -1 special case.
 v=Model(e);raw=z3.BitVec('MA_any_random_return32',32);v.seed('w0',raw);v.seed('x22',v.attribute);v.seed('x26',0);v.seed('x20',0x430);v.seed('w25',0x3fc);v.run('attr_first_random_return');prove('all_return32_source_random_byte_codec',v,v.attribute_bytes[8]!=z3.If(raw==0xffffffff,resize(0xc7,8),z3.Extract(7,0,raw)^0xc7))
 models={}
 for profile in PROFILES:
  v=finished(e,profile);prove('complete_attribute_'+profile,v,output_bad(v));models[profile]=v
 captured={int(i['pc'],16)for s in e['source']['spans']for i in s['instructions']};assert captured<=visited,captured-visited
 return out,models,len(captured&visited)

def evaluations(e,models):
 rows=[];certs=[];predecessors=[r for r in e['predecessor_states']if Search.values_for(r)[0]=='u32']
 for source,adid in [(r,False)for r in predecessors]+[(predecessors[0],True)]:
  _,values=Search.values_for(source);old=values['D'];values['D']=Search.KEY
  if adid:values.update(U=0x9777,L=4,V=0,N=14)
  for profile,v in models.items():
   b=Search.bindings(v,values)+[(v.capacity,resize(128,32)),(v.original_input,resize(int(source['original_input64'],16),64))];premises=[z3.simplify(z3.substitute(q,*b))for q in v.owned()+v.guards+v.extra+v.address_checks];p=z3.SolverFor('QF_BV');p.set(timeout=60000);p.add(*premises);assert p.check()==z3.sat,(profile,adid,p.reason_unknown());s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*premises,z3.simplify(z3.substitute(output_bad(v),*b)));assert s.check()==z3.unsat,(profile,adid,s.reason_unknown());row={'source_predecessor_case_index':source['predecessor_case_index'],'profile':profile,'evaluation_kind':'derived_tag_and_declared_table_payload_profile','original_raw_tag32':hex(old),'raw_tag32':hex(values['D']),'raw_scalar32':hex(values['V']),'capacity_profile32':128,'environment_premises_sat':True,'conditional_output_query_unsat':True,'attribute_bytes_checked':len(v.attribute_bytes),'symbolic_random_output_bytes_checked':0 if profile=='allocation_null'else 32 if profile=='mode_zero'else 64,'payload_bytes_copied':0 if profile=='allocation_null'else 52 if profile=='mode_zero'else 20,'modeled_allocator_returns':1,'modeled_random_returns':0 if profile=='allocation_null'else 64,'final_target':'0xfffffe000a6621e4'if profile=='allocation_null'else'0xfffffe000a6575b0','native_target_executed':False,'native_entropy_supplied':False,'native_payload_bytes_supplied':0,'native_pointer_values_supplied':0,'initial_undefined_workspace_word_remains_symbolic':True,'continuous_guest_extended':False,'all_checks_pass':True}
   if adid:
    raw=e['adid_evidence']['packets'][0]['field_record_hex'];actual=bytes(H.numeric(H.cell(v,v.common['Z']+j,1),b)for j in range(14));assert raw=='fa83411297770000000400000000'and actual==bytes(x^H.py_mask(values['Z']+j)for j,x in enumerate(bytes.fromhex(raw)));certs.append({**row,'raw_record_hex':raw,'protected_record_hex':actual.hex(),'protected_bytes_checked':14,'whole_ADID_packet_parsed_by_kext':False,'native_transport_identity_established':False})
   else:rows.append(row)
 return rows,certs

def negative_controls(e):
 rows=[]
 for addr,profile in [(pc(0xa636aa0),'mode_zero'),(pc(0xa636b58),'mode_nonzero'),(pc(0xa652fdc),'mode_nonzero')]:
  changed=copy.deepcopy(e);row=next(s for s in changed['source']['spans']if int(s['start'],16)<=addr<int(s['end_exclusive'],16));off=addr-int(row['start'],16);raw=bytearray.fromhex(row['bytes_hex']);original=bytes(raw[off:off+4]);word=int.from_bytes(original,'little');word=(word&~(0xfff<<10))|(0x66<<10)if addr==pc(0xa636aa0)else(word&~31)|31 if addr==pc(0xa636b58)else word^(1<<10);replacement=word.to_bytes(4,'little');raw[off:off+4]=replacement;row['bytes_hex']=raw.hex()
  if addr==pc(0xa652fdc):
   v=prepared(changed);v.attribute_owned=True;v.extra.append(v.attribute!=0);v.external_return('allocate',pc(0xa652ed0)).run('attr_allocate_return');follow(v,'attr_initial_header',0x7757);follow(v,'attr_first_random_request',0x29d9);v.external_return('random',pc(0xa652fc0),0).run('attr_first_random_return');bad=resize(v.stores[-1]['value'],8)!=(z3.Extract(7,0,v.raw_random[0])^0xc7);stop='after_first_mutated_random_byte_store'
  else:
   v=finished(changed,profile);bad=v.attribute_bytes[0x67]!=v.payload_bytes[0x17]if addr==pc(0xa636aa0)else v.attribute_bytes[0x50]!=1;stop='at_next_private_facility_request'
  p=v.owned()+v.guards+v.extra+v.address_checks;s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*p);assert s.check()==z3.sat;s.add(bad);assert s.check()==z3.sat
  rows.append({'mutated_PC':hex(addr),'original_word_hex':original.hex(),'replacement_word_hex':replacement.hex(),'normal_oracle_rejected':True,'satisfiable_violation_query':s.to_smt2(),'stop_boundary':stop,'native_target_executed':False})
 return rows

def audit(e=None):
 e=e if e is not None else json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();proofs,models,covered=source_obligations(e);cases,certs=evaluations(e,models);controls=negative_controls(e);prior=[]
 old=json.loads(read(ROOT/'userclient_schema_lookup_result_audit.json'));names={'actual_packet_helper_and_caller_hit_nonnull','all_payload64_outer_caller_NULL_gate'}
 for q in old['source_proofs']:
  if q['semantic_contract']not in names:continue
  ctx=z3.Context();s=z3.SolverFor('QF_BV',ctx=ctx);s.set(timeout=120000);s.add(*z3.parse_smt2_string(q['query'],ctx=ctx));assert s.check()==z3.unsat,(q['name'],s.reason_unknown());prior.append({'name':q['name'],'result':'unsat','source_audit':'userclient_schema_lookup_result_audit.json','source_audit_sha256':sha(ROOT/'userclient_schema_lookup_result_audit.json')})
 totals={'new_source_queries_unsat':len(proofs),'new_semantic_contracts':len({q['semantic_contract']for q in proofs}),'prior_source_queries_unsat':len(prior),'lifted_instruction_instances':sum(q['lifted_instruction_instances']for q in proofs),'new_source_words_covered':covered,'derived_predecessor_profile_projections':len(cases),'ADID_profile_projections':len(certs),'conditional_environment_sat_unsat_pairs':len(cases)+len(certs),'attribute_byte_values_checked':sum(q['attribute_bytes_checked']for q in cases+certs),'symbolic_random_byte_values_checked':sum(q['symbolic_random_output_bytes_checked']for q in cases+certs),'payload_byte_copies_checked':sum(q['payload_bytes_copied']for q in cases+certs),'additional_prefix_cells_reconstructed':sum(len(p['attribute_additional_source_cells'])for p in e['predecessor_states']),'additional_prefix_bytes_reconstructed':sum(sum(q['size_bytes']for q in p['attribute_additional_source_cells'])for p in e['predecessor_states']),'negative_source_controls':len(controls),'constructor_random_calls':64,'new_controller_reads_success':130,'new_controller_reads_allocation_null':2,'new_bank_applications_success':66,'new_bank_applications_allocation_null':2,'native_target_calls':0,'concrete_unknown_workspace_values_supplied':0,'concrete_random_values_supplied':0,'concrete_payload_bytes_supplied':0}
 return {'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],'kernel_collection_sha256':e['kernel_collection_sha256'],'scope':e['scope'],'dependencies':e['dependencies'],'verified_counts':e['verified_counts'],'source_proofs':proofs,'rechecked_prior_source_proofs':prior,'partial_state_evaluations':cases,'ADID_field_certificates':certs,'negative_source_controls':controls,'independent_totals':totals,'conditional_message_attribute_contract_established':True,'all_checks_pass':True,**{n:False for n in R.FALSE}}
if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
