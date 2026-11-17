#!/usr/bin/env python3
"""Prove selected FPMessage formation and exact common-parser handoff.
O(I+16I+8I+C*I+1536+query DAG) construction/space; SMT separately bounded.
The local zero-fill summary is rebuilt from original source for all alignments.
"""
import copy,json
import z3
from kext_port_tools import ROOT,IMAGE,TABLE,qword
from lskd_values_symbolic import Lift,mem,resize
from verify_daemon_reader_record_payloads_publication import read,sha
import audit_userclient_message_attributes as Parent
import recover_userclient_message_initialization as R
H=Parent.H;DEC=Parent.DEC;Publication=Parent.Publication;SUCCESS=Parent.SUCCESS;TOKEN=Parent.TOKEN;PHASE=Parent.PHASE;Search=Parent.Search;pc=R.pc
PROFILES=['mode_zero_success','mode_nonzero_success','mode_zero_null','mode_nonzero_null']
CONTEXT_STORES={pc(a):(root,off,n)for a,root,off,n in [(0xa6575c4,'C',0x5d0,8),(0xa6575c8,'C',0x430,8),(0xa6575cc,'S',0x150,4),(0xa6575d4,'C',0x498,8),(0xa6575d8,'C',0xa8,8),(0xa6575dc,'C',0x620,8),(0xa6575e0,'C',0x6b0,8),(0xa6575e4,'S',0x18,4),(0xa6575e8,'S',0xa60,4),(0xa6575ec,'C',0x380,8),(0xa657794,'C',0x788,8),(0xa653898,'C',0x448,8),(0xa6538a8,'F',0x9e0,4),(0xa6538dc,'F',0x480,4),(0xa6538ec,'F',0x9d0,8),(0xa656b98,'C',0x718,8),(0xa656b9c,'C',0x18,8),(0xa656bcc,'S',0xc8,4),(0xa656bd0,'S',0x1e0,4),(0xa641b1c,'S',0xab8,4)]}
def parent_input(e):
 p=copy.deepcopy(e);p['source']=copy.deepcopy(e['attribute_source']);return p
class Zero(Lift):
 def __init__(self,e,align):
  super().__init__({'spans':[]});self.instructions={i.address:i for i in DEC.disasm(bytes.fromhex(e['zero_helper_envelope']['bytes_hex']),int(e['zero_helper_envelope']['start'],16))};self.dest=z3.BitVec('MI_zero_destination64',64);self.align=align;self.extra=[(self.dest&7)==align];self.guards=[];self.address_checks=[];self.visited=set();self.bytes={};self.initial={}
  for reg in ['sp']+['x'+str(j)for j in range(19,31)]:self.initial[reg]=z3.BitVec('MI_zero_initial_'+reg,64);self.seed(reg,self.initial[reg])
  self.seed('x0',self.dest);self.seed('x1',0);self.seed('x2',32)
 def owned(self):return[z3.ULE(self.dest,resize((1<<64)-33,64))]
 def address(self,i,o):
  if i.writeback:
   assert i.mnemonic in ['str','strb']and i.operands[2].type==2;reg=i.reg_name(o.mem.base);a=self.read(reg)+o.mem.disp;self.write(reg,self.read(reg)+i.operands[2].imm);return z3.simplify(a)
  return super().address(i,o)
 def store(self,a,n,value,source_pc):
  off=z3.simplify(a-self.dest);assert z3.is_bv_value(off)and off.as_long()+n<=32
  for j in range(n):assert off.as_long()+j not in self.bytes;self.bytes[off.as_long()+j]=z3.Extract(8*j+7,8*j,resize(value,8*n))
  super().store(a,n,value,source_pc)
 def cond(self,name):return self.equal if name=='eq'else z3.Not(self.equal)if name=='ne'else self.cmp_left>self.cmp_right if name=='gt'else z3.ULT(self.cmp_left,self.cmp_right)if name=='lo'else None
 def run_body(self):
  at=pc(0xa687d64)
  for step in range(150):
   i=self.instructions[at];self.pc=at;self.visited.add(at);m=i.mnemonic;o=i.operands;nextpc=at+4
   if m=='bti':self.count+=1
   elif m=='b':nextpc=o[0].imm&((1<<64)-1);self.count+=1
   elif m.startswith('b.')or m in ['cbz','cbnz']:
    condition=self.cond(m[2:])if m.startswith('b.')else self.read(i.reg_name(o[0].reg))==0 if m=='cbz'else self.read(i.reg_name(o[0].reg))!=0;assert condition is not None;take=z3.simplify(z3.substitute(condition,(self.dest,resize(0x7800000000+self.align,64))));assert z3.is_true(take)or z3.is_false(take);yes=z3.is_true(take);self.address_checks.append(condition if yes else z3.Not(condition));nextpc=(o[0].imm if m.startswith('b.')else o[1].imm)&((1<<64)-1)if yes else at+4;self.count+=1
   elif m=='csel':
    assert i.op_str.endswith(', lo');self.write(i.reg_name(o[0].reg),z3.If(z3.ULT(self.cmp_left,self.cmp_right),self.read(i.reg_name(o[1].reg)),self.read(i.reg_name(o[2].reg))));self.count+=1
   elif m=='ubfx':self.write(i.reg_name(o[0].reg),z3.Extract(o[2].imm+o[3].imm-1,o[2].imm,self.read(i.reg_name(o[1].reg))));self.count+=1
   elif m=='subs':
    value=self.read(i.reg_name(o[1].reg))-o[2].imm;self.write(i.reg_name(o[0].reg),value);self.cmp_left=value;self.cmp_right=resize(0,value.size());self.equal=value==0;self.count+=1
   elif m=='ret':self.count+=1;self.return_target=self.read('x30');return self
   else:self.c={'spans':[{'label':'one','start':hex(at),'bytes_hex':bytes(i.bytes).hex()}]};super().run('one')
   at=nextpc
  raise AssertionError('zero helper bound exceeded')
def zero_bad(v):
 assert set(v.bytes)==set(range(32));return z3.Or(*[b!=0 for b in v.bytes.values()],*[v.read(r)!=x for r,x in v.initial.items()],v.return_target!=v.initial['x30'],v.read('x0')!=v.dest+(32 if v.align==0 else 31))
class Model(Parent.Model):
 def __init__(self,e,mode='mode_zero',frontier=True):
  prior=Parent.finished(parent_input(e),mode)if frontier else Parent.Model(parent_input(e));self.__dict__.update(prior.__dict__);self.e=copy.deepcopy(self.e);self.e['source']['spans']+=copy.deepcopy(e['source']['spans']);self.message_receipt=e;self.message=z3.BitVec('MI_message64',64);self.message_owned=False;self.message_bytes={};self.message_reads=[];self.message_bank_inputs={};self.message_bank_bytes={};self.message_bank_reads=[];self.message_controller_reads=[];self.message_profile=None;self.zero_summaries=[];self.message_API_returns=[];self.message_store_start=len(self.stores);self.message_new_count=self.count;self.message_root_equalities=[];self.message_store_PCs={int(i['pc'],16)for s in e['source']['spans']for i in s['instructions']if i['mnemonic'].startswith('str')and'[x0'in i['operands']}|{pc(0xa653c6c)}
  for off,root,value in R.ROOTS:
   want=self.common[root]+value if root in ['C','S']else resize(value,64);key=(z3.simplify(self.common['F']+off).sexpr(),8)
   if key in self.memory:self.message_root_equalities.append(self.memory[key]==want)
   else:mem(self,self.common['F']+off,8,want)
 def owned(self):
  out=super().owned()
  if self.message_owned:
   c=self.common;a=self.message;n=resize(128,64);out.extend([a!=0,z3.ULE(a,resize((1<<64)-129,64))]);ranges=[(c['F']-0x70,resize(0x1160,64)),(c['C'],resize(0x1000,64)),(c['S'],resize(0x4000,64)),(c['H'],resize(16,64)),(c['J'],resize(32,64)),(c['Z'],z3.ZeroExt(32,c['L'])+10),(self.holder,resize(16,64)),(self.entries,24*z3.ZeroExt(32,self.capacity)),(self.attribute,resize(112,64)),(self.payload,resize(56,64))]+[(resize(b,64),resize(m,64))for b,off,m in IMAGE.segments]
   out.extend(z3.Or(z3.ULE(a+n,b),z3.ULE(b+m,a))for b,m in ranges)
  return out
 def address(self,i,o):
  if i.address==pc(0xa6538e8):
   assert i.writeback and i.operands[2].imm==0x67;a=self.read('x8');self.write('x8',a+0x67);return a
  return super().address(i,o)
 def load(self,a,n):
  controllers={pc(a):pc(b)for a,b in [(0xa6575f0,0xccc30d0),(0xa6575f8,0xccc32f8),(0xa6576c4,0xccc30d0),(0xa6576cc,0xccc32f8),(0xa653ba0,0xccc30d0),(0xa653ba4,0xccc32f8)]}
  if self.pc in controllers:
   assert n==4;self.address_checks.append(a==controllers[self.pc]);self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});self.message_controller_reads.append(hex(self.pc));return z3.BitVec('MI_controller_'+str(len(self.message_controller_reads)),32)
  for rule in self.message_receipt['message_bank_rules']:
   name=rule['name'];L,Rr=int(rule['left'],16),int(rule['right'],16)
   if self.pc==int(rule['left_PC'],16):
    assert n==1;self.message_bank_inputs[name]=z3.Extract(7,0,a-L);b=z3.BitVec('MI_bank_'+str(len(self.message_bank_reads)),8);self.message_bank_bytes[name]=b;self.address_checks.append(a==L+z3.ZeroExt(56,self.message_bank_inputs[name]));self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});return b
   if self.pc==int(rule['right_PC'],16):
    assert n==1;self.address_checks.append(a==Rr+z3.ZeroExt(56,self.message_bank_bytes[name]^int(rule['key'],16)));self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});self.message_bank_reads.append({'rule':name,'source_PC':hex(self.pc),'certified_inputs':256});return self.message_bank_inputs[name]^int(rule['constant'],16)
   if self.pc==int(rule['pointer_PC'],16):assert n==8;self.address_checks.append(a==int(rule['slot'],16));self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});return resize(int(rule['original_pointer']['target'],16),64)
  if pc(0xa6538e8)<=self.pc<=pc(0xa653d24):
   off=z3.simplify(a-self.attribute)
   if z3.is_bv_value(off)and off.as_long()<112:
    off=off.as_long();assert all(off+j in self.attribute_bytes for j in range(n));self.address_checks.append(a==self.attribute+off);self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});self.message_reads.append({'source_PC':hex(self.pc),'offset':off,'size_bytes':n});return z3.Concat(*reversed([self.attribute_bytes[off+j]for j in range(n)]))if n>1 else self.attribute_bytes[off]
  if self.pc in [pc(v)for v in [0xa653c00,0xa653c20,0xa653c4c]]:
   name={pc(0xa653c00):'mask1',pc(0xa653c20):'mask2',pc(0xa653c4c):'mask3'}[self.pc];q=next(q for q in self.message_receipt['message_mask_arrays']if q['name']==name);off=z3.simplify(a-int(q['start'],16));assert n==1 and z3.is_bv_value(off)and off.as_long()<16;self.address_checks.append(a==int(q['start'],16)+off.as_long());self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});return resize(bytes.fromhex(q['bytes_hex'])[off.as_long()],8)
  if self.pc in R.BRANCHES:
   assert n==8;self.address_checks.append(z3.Or(*[a==TABLE+8*j for j in R.BRANCHES[self.pc]]));self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});value=resize(0,64)
   for j in R.BRANCHES[self.pc]:value=z3.If(a==TABLE+8*j,resize(qword(TABLE+8*j),64),value)
   return value
  return super().load(a,n)
 def store(self,a,n,value,source_pc):
  if source_pc in self.message_store_PCs:
   off=z3.simplify(a-self.message);assert z3.is_bv_value(off)and off.as_long()+n<=128
   for j in range(n):self.message_bytes[off.as_long()+j]=z3.Extract(8*j+7,8*j,resize(value,8*n))
  return super().store(a,n,value,source_pc)
 def zero_summary(self):
  c=self.common;self.address_checks.extend([z3.Not(Publication.edge(self,pc(0xa687d64),0x46ae)),self.read('x0')==c['S']+0xcc8,self.read('w1')==0,self.read('x2')==32,self.read('x30')==pc(0xa65764c)]);self.zero_summaries.append({'source_PC':hex(pc(0xa657648)),'target':hex(pc(0xa687d64)),'source_sha256':self.message_receipt['zero_helper_envelope']['sha256'],'all_alignment_source_proofs_required':8,'zeroed_bytes':32,'native_target_executed':False})
  # Apply only the independently proved memory effect; volatile registers are
  # conservatively forgotten, not substituted with guessed helper internals.
  for n in [1,4,8]:
   for j in range(33-n):mem(self,c['S']+0xcc8+j,n,0)
  for reg in list(range(19))+[30]:self.seed('x'+str(reg),z3.BitVec('MI_zero_volatile_'+str(reg),64))
  return self
 def allocated_return(self):
  self.address_checks.extend([z3.Not(Publication.edge(self,pc(0xc4ba154),0xd0c8)),self.read('x0')==pc(0x847b560),self.read('sp')==self.common['F'],self.read('x30')==pc(0xa65775c)]);self.message_API_returns.append({'source_PC':hex(pc(0xa657758)),'nominal_return_PC':hex(pc(0xa65775c)),'callee_saved_registers_preserved':True,'caller_storage_preserved_by_premise':True,'native_target_executed':False})
  for reg in list(range(19))+[30]:self.seed('x'+str(reg),z3.BitVec('MI_allocator_volatile_'+str(reg),64))
  self.seed('x0',self.message);return self
def follow(v,label,modifier):v.address_checks.append(z3.Not(Publication.edge(v,R.SPANS[label][0],modifier)));return v.run(label)
def requested(e,mode):
 v=Model(e,mode);follow(v,'message_entry',0x2854);v.zero_summary().run('message_after_clear');return follow(v,'message_allocate',0x7fe0)
def finished(e,profile):
 assert profile in PROFILES;mode='mode_zero'if profile.startswith('mode_zero_')else'mode_nonzero';v=requested(e,mode);v.message_profile=profile
 if profile.endswith('_null'):v.extra.append(v.message==0)
 else:v.message_owned=True
 v.allocated_return().run('message_after_allocate')
 if profile.endswith('_null'):
  follow(v,'message_early_return',0x3262);follow(v,'message_outer_return',0xbe01);return follow(v,'message_error',0x5ab2)
 for name,modifier in [('message_gate',0x3262),('message_zero0',0x3417),('message_gate8',0xdfdd),('message_zero8',0x540e),('message_attr_gate',0xab82),('message_attr_entry',0x9fef),('message_copy_entry',0x2ee0),('message_copy_fields',0xbadf)]:follow(v,name,modifier)
 for j in range(16):follow(v,'message_copy16',0x7aa9);v.address_checks.append(v.read('x10')==resize(-j-1,64))
 follow(v,'message_flags',0x7aa9);follow(v,'message_flags_length',0xbadf)
 if mode=='mode_zero':follow(v,'message_flag_one',0xbadf)
 for name,modifier in [('message_copy_return',0xbadf),('message_bridge',0x7fb0),('message_parser_prepare',0xcb79),('message_parser_extent',0xf77b),('message_parser_request',0x1420)]:follow(v,name,modifier)
 return v
def expected_message(v):
 out={j:resize(0,8)for j in range(16)};a=Parent.expected_attribute(v)
 for src,dst,n in [(0,0x10,4),(8,0x18,64),(0x48,0x58,8),(0x50,0x60,2),(0x54,0x64,4),(0x68,0x78,4)]:
  for j in range(n):out[dst+j]=a[src+j]
 for j in range(4):out[0x14+j]=resize(int(v.profile=='mode_zero')if j==0 else 0,8)
 for j,b in enumerate(bytes.fromhex(v.message_receipt['message_mask16_hex'])):out[0x68+j]=a[0x58+j]^b
 out[0x7c]=resize(0xcb,8);return out
def output_bad(v):
 c=v.common;bad=[*[z3.Not(q)for q in v.message_root_equalities],*[H.cell(v,c['S']+0xcc8+j,1)!=0 for j in range(32)],H.cell(v,c['C']+0x5d0,8)!=pc(0xa636d34),H.cell(v,c['C']+0x430,8)!=c['C']+0x360,H.cell(v,c['C']+0x498,8)!=v.original_input,H.cell(v,c['S']+0x150,4)!=(c['N']^SUCCESS),H.cell(v,c['S']+0xd0c,4)!=v.old_workspace,*[v.attribute_bytes[j]!=b for j,b in Parent.expected_attribute(v).items()]]
 for q in v.stores[v.message_store_start:]:
  if q['pc']in v.message_store_PCs:
   off=z3.simplify(q['address']-v.message);assert z3.is_bv_value(off)and off.as_long()+q['size_bytes']<=128
  else:root,off,n=CONTEXT_STORES[q['pc']];assert q['size_bytes']==n;bad.append(q['address']!=c[root]+off)
 assert len(v.message_API_returns)==len(v.zero_summaries)==1
 assert len(v.message_controller_reads)==(4 if v.message_profile.endswith('_null')else 36)
 assert len(v.message_bank_reads)==(3 if v.message_profile.endswith('_null')else 51)
 bad.append(H.cell(v,c['C']+0x788,8)!=v.message)
 if v.message_profile.endswith('_null'):
  assert not v.message_bytes and not v.message_reads;bad.extend([H.cell(v,c['S']+0xab8,4)!=0xce515bb2,Publication.edge(v,pc(0xa6621e4),0x682a)])
 else:
  want=expected_message(v);assert set(want)==set(v.message_bytes)==set(range(128))-{0x62,0x63,0x7d,0x7e,0x7f};assert {q['offset']+j for q in v.message_reads for j in range(q['size_bytes'])}==set(v.attribute_bytes);bad.extend(v.message_bytes[j]!=b for j,b in want.items());bad.extend([H.cell(v,c['C']+0x718,8)!=v.message,H.cell(v,c['C']+0x18,8)!=v.original_input,H.cell(v,c['S']+0xc8,4)!=(c['N']^SUCCESS),H.cell(v,c['S']+0x1e0,4)!=0xfbb3f478,Publication.edge(v,pc(0xa636338),0xb40b)])
 return z3.Or(*bad)
def source_obligations(e):
 out=[];visited=set();zero_visited=set()
 def prove(name,v,bad):
  premises=v.owned()+v.guards+v.extra;s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*premises);r=s.check();assert r==z3.sat,(name,'premises',str(r),s.reason_unknown());bad=z3.simplify(z3.Or(bad,*[z3.Not(q)for q in v.address_checks]));terms=list(bad.children())if z3.is_or(bad)else[bad];parts=[terms[j:j+2]for j in range(0,len(terms),2)]
  for j,terms in enumerate(parts):
   s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*premises,z3.Or(*terms));query=s.to_smt2();r=s.check();assert r==z3.unsat,(name,j,str(r),s.reason_unknown(),s.model()if r==z3.sat else'');out.append({'name':name+'_part_'+str(j+1),'semantic_contract':name,'counterexample_partition':j+1,'counterexample_partitions':len(parts),'result':'unsat','premises_nonvacuous':True,'query':query,'lifted_instruction_instances':v.count});print('proved '+name+' '+str(j+1)+'/'+str(len(parts)),flush=True)
  visited.update(v.visited)
 for align in range(8):
  v=Zero(e,align).run_body();prove('source_zero32_alignment_'+str(align),v,zero_bad(v));zero_visited.update(v.visited)
 models={}
 for profile in PROFILES:
  v=finished(e,profile);prove('actual_attribute_to_message_'+profile,v,output_bad(v));models[profile]=v
 v=Model(e,frontier=False);extent=z3.BitVec('MI_cut_extent32',32)
 for reg,value in [('x7',TABLE),('w1',PHASE),('w3',TOKEN),('w30',SUCCESS),('w25',0x9c9),('w20',0xaed),('w22',extent^SUCCESS)]:v.seed(reg,value)
 v.run('message_after_clear');prove('independent_all_extent32_gate',v,Publication.edge(v,z3.If(extent==0,resize(pc(0xa665154),64),resize(pc(0xa6576b8),64)),0x7fe0))
 captured={int(i['pc'],16)for s in e['source']['spans']for i in s['instructions']};assert captured<=visited,captured-visited
 return out,models,len(captured&visited),len(zero_visited)
def evaluations(e,models):
 cases=[];certs=[];predecessors=[r for r in e['predecessor_states']if Search.values_for(r)[0]=='u32']
 for source,adid in [(r,False)for r in predecessors]+[(predecessors[0],True)]:
  _,values=Search.values_for(source);old=values['D'];values['D']=Search.KEY
  if adid:values.update(U=0x9777,L=4,V=0,N=14)
  for profile,v in models.items():
   bindings=Search.bindings(v,values)+[(v.capacity,resize(128,32)),(v.original_input,resize(int(source['original_input64'],16),64))];premises=[z3.simplify(z3.substitute(q,*bindings))for q in v.owned()+v.guards+v.extra+v.address_checks];s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*premises);assert s.check()==z3.sat,(profile,adid,s.reason_unknown());s.add(z3.simplify(z3.substitute(output_bad(v),*bindings)));assert s.check()==z3.unsat,(profile,adid,s.reason_unknown());row={'source_predecessor_case_index':source['predecessor_case_index'],'profile':profile,'evaluation_kind':'derived_tag_and_declared_message_allocation_profile','original_raw_tag32':hex(old),'raw_tag32':hex(values['D']),'raw_scalar32':hex(values['V']),'capacity_profile32':128,'environment_premises_sat':True,'conditional_output_query_unsat':True,'message_bytes_checked':len(v.message_bytes),'attribute_bytes_preserved':107,'zero_summary_bytes_checked':32,'transformed_field_bytes_checked':16 if v.message_bytes else 0,'final_target':hex(pc(0xa636338)if v.message_bytes else pc(0xa6621e4)),'native_target_executed':False,'native_message_values_supplied':0,'native_payload_values_supplied':0,'continuous_guest_extended':False,'all_checks_pass':True}
   if adid:
    raw=e['adid_evidence']['packets'][0]['field_record_hex'];actual=bytes(H.numeric(H.cell(v,v.common['Z']+j,1),bindings)for j in range(14));assert raw=='fa83411297770000000400000000'and actual==bytes(b^H.py_mask(values['Z']+j)for j,b in enumerate(bytes.fromhex(raw)));certs.append({**row,'raw_record_hex':raw,'protected_record_hex':actual.hex(),'protected_bytes_checked':14,'whole_ADID_packet_parsed_by_kext':False,'native_transport_identity_established':False})
   else:cases.append(row)
 return cases,certs
def negative_controls(e):
 out=[]
 for addr,kind in [(pc(0xa653938),'copy32_destination'),(pc(0xa653c50),'copy16_transform'),(pc(0xa653d50),'length_flag')]:
  changed=copy.deepcopy(e);row=next(s for s in changed['source']['spans']if int(s['start'],16)<=addr<int(s['end_exclusive'],16));off=addr-int(row['start'],16);raw=bytearray.fromhex(row['bytes_hex']);old=bytes(raw[off:off+4]);word=int.from_bytes(old,'little');word=(word&~(0xfff<<10))|(0x36<<10)if kind=='copy32_destination'else(word&~(31<<10))|(31<<10)if kind=='copy16_transform'else word^(1<<5);new=word.to_bytes(4,'little');raw[off:off+4]=new;row['bytes_hex']=raw.hex();v=finished(changed,'mode_zero_success');want=expected_message(v);bad=next(q['address']for q in v.stores[v.message_store_start:]if q['pc']==addr)!=v.message+0x37 if kind=='copy32_destination'else v.message_bytes[0x77]!=want[0x77]if kind=='copy16_transform'else v.message_bytes[0x14]!=1;s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*(v.owned()+v.guards+v.extra+v.address_checks));assert s.check()==z3.sat;s.add(bad);assert s.check()==z3.sat;out.append({'mutated_PC':hex(addr),'kind':kind,'original_word_hex':old.hex(),'replacement_word_hex':new.hex(),'normal_oracle_rejected':True,'satisfiable_violation_query':s.to_smt2(),'stop_boundary':'pending_common_parser_reentry','native_target_executed':False})
 return out
def audit(e=None):
 e=e if e is not None else json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();proofs,models,covered,zero_words=source_obligations(e);cases,certs=evaluations(e,models);controls=negative_controls(e);prior=[];old=json.loads(read(ROOT/'userclient_message_attributes_audit.json'))
 for q in old['source_proofs']:
  if q['semantic_contract']not in ['complete_attribute_mode_zero','complete_attribute_mode_nonzero']:continue
  ctx=z3.Context();s=z3.SolverFor('QF_BV',ctx=ctx);s.set(timeout=120000);s.add(*z3.parse_smt2_string(q['query'],ctx=ctx));assert s.check()==z3.unsat,(q['name'],s.reason_unknown());prior.append({'name':q['name'],'result':'unsat','source_audit':'userclient_message_attributes_audit.json','source_audit_sha256':sha(ROOT/'userclient_message_attributes_audit.json')})
 totals={'new_source_queries_unsat':len(proofs),'new_semantic_contracts':len({q['semantic_contract']for q in proofs}),'prior_source_queries_unsat':len(prior),'lifted_instruction_instances':sum(q['lifted_instruction_instances']for q in proofs),'new_source_words_covered':covered,'zero_helper_source_words_covered':zero_words,'zero_helper_alignment_contracts':8,'derived_predecessor_profile_projections':len(cases),'ADID_profile_projections':len(certs),'conditional_environment_sat_unsat_pairs':len(cases)+len(certs),'message_byte_values_checked':sum(q['message_bytes_checked']for q in cases+certs),'attribute_bytes_preserved_checked':sum(q['attribute_bytes_preserved']for q in cases+certs),'zero_summary_bytes_checked':sum(q['zero_summary_bytes_checked']for q in cases+certs),'transformed_field_bytes_checked':sum(q['transformed_field_bytes_checked']for q in cases+certs),'additional_prefix_cells_reconstructed':sum(len(p['message_additional_source_cells'])for p in e['predecessor_states']),'additional_prefix_bytes_reconstructed':sum(sum(q['size_bytes']for q in p['message_additional_source_cells'])for p in e['predecessor_states']),'negative_source_controls':len(controls),'new_controller_reads_success':36,'new_controller_reads_null':4,'new_bank_applications_success':51,'new_bank_applications_null':3,'native_target_calls':0,'concrete_unknown_workspace_values_supplied':0,'concrete_message_payload_values_supplied':0}
 return {'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],'kernel_collection_sha256':e['kernel_collection_sha256'],'scope':e['scope'],'dependencies':e['dependencies'],'verified_counts':e['verified_counts'],'source_proofs':proofs,'rechecked_prior_source_proofs':prior,'partial_state_evaluations':cases,'ADID_field_certificates':certs,'negative_source_controls':controls,'independent_totals':totals,'conditional_message_initialization_contract_established':True,'all_checks_pass':True,**{n:False for n in R.FALSE}}
if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
