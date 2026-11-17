#!/usr/bin/env python3
"""Check second-parser source composition and separately qualified completion cuts.
O(I+256R+C*I+query DAG) construction/space; SMT separately bounded.
"""
import copy,json
import z3
from kext_port_tools import ROOT,TABLE,qword
from lskd_values_symbolic import resize,mem
from verify_daemon_reader_record_payloads_publication import read,sha
import audit_userclient_message_initialization as Parent
import recover_userclient_message_parser as R
H=Parent.H;DEC=Parent.DEC;Publication=Parent.Publication;SUCCESS=Parent.SUCCESS;TOKEN=Parent.TOKEN;PHASE=Parent.PHASE;pc=R.pc
MODES=['mode_zero','mode_nonzero']
class Model(Parent.Model):
 def __init__(self,e,mode='mode_zero'):
  prior=Parent.finished(json.loads(read(ROOT/'userclient_message_initialization_checks.json')),mode+'_success');self.__dict__.update(prior.__dict__);self.e=copy.deepcopy(self.e);self.e['source']['spans']+=copy.deepcopy(e['source']['spans']);self.parser_receipt=e;self.parser_container=z3.BitVec('MP_container64',64);self.parser_owned=False;self.parser_store_start=len(self.stores);self.parser_count_start=self.count;self.parser_visited_start=set(self.visited);self.parser_left={};self.parser_left_bytes={};self.parser_bank_reads=[];self.parser_controllers=[];self.parser_API_returns=[];self.parser_bytes={};self.parser_profile=None;self.parser_new_visited=set();self.parser_check_start=len(self.address_checks)
 def owned(self):
  out=super().owned()
  if self.parser_owned:
   c=self.common;a=self.parser_container;n=resize(16,64);out.extend([a!=0,z3.ULE(a,resize((1<<64)-17,64))]);ranges=[(c['F']-0x70,resize(0x1160,64)),(c['C'],resize(0x1000,64)),(c['S'],resize(0x4000,64)),(c['H'],resize(16,64)),(c['J'],resize(32,64)),(c['Z'],z3.ZeroExt(32,c['L'])+10),(self.holder,resize(16,64)),(self.entries,24*z3.ZeroExt(32,self.capacity)),(self.attribute,resize(112,64)),(self.payload,resize(56,64)),(self.message,resize(128,64))]+[(resize(b,64),resize(m,64))for b,off,m in Parent.IMAGE.segments];out.extend(z3.Or(z3.ULE(a+n,b),z3.ULE(b+m,a))for b,m in ranges)
  return out
 def load(self,a,n):
  if self.pc in [pc(p)for p in [0xa63637c,0xa636384,0xa63644c,0xa636450]]:
   at=pc(0xccc30d0 if self.pc in [pc(0xa63637c),pc(0xa63644c)]else 0xccc32f8);assert n==4;self.address_checks.append(a==at);self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});self.parser_controllers.append(hex(self.pc));return z3.BitVec('MP_controller_'+str(len(self.parser_controllers)),32)
  left=[r for r in self.parser_receipt['bank_rules']if self.pc==int(r['left_PC'],16)]
  if left:
   assert n==1;key=left[0]['left_PC'];L=int(left[0]['left'],16);self.parser_left[key]=z3.Extract(7,0,a-L);self.parser_left_bytes[key]=z3.BitVec('MP_left_'+str(len(self.parser_left_bytes)),8);self.address_checks.append(a==L+z3.ZeroExt(56,self.parser_left[key]));self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});return self.parser_left_bytes[key]
  right=[r for r in self.parser_receipt['bank_rules']if self.pc==int(r['right_PC'],16)]
  if right:
   r=right[0];key=r['left_PC'];assert n==1;self.address_checks.append(a==int(r['right'],16)+z3.ZeroExt(56,self.parser_left_bytes[key]^int(r['key'],16)));self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});self.parser_bank_reads.append(hex(self.pc));return self.parser_left[key]^int(r['constant'],16)
  if self.pc in R.LITERALS:
   at=R.LITERALS[self.pc];assert n==8;self.address_checks.append(a==at);self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});return resize(qword(at),64)
  if self.pc in R.BRANCHES:
   js=R.BRANCHES[self.pc];assert n==8;self.address_checks.append(z3.Or(*[a==TABLE+8*j for j in js]));self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});value=resize(0,64)
   for j in js:value=z3.If(a==TABLE+8*j,resize(qword(TABLE+8*j),64),value)
   return value
  if self.pc==pc(0xa6611a0):
   assert n==1;self.address_checks.append(a==self.message+0x60);self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});return self.message_bytes[0x60]
  return super().load(a,n)
 def store(self,a,n,value,source_pc):
  if hasattr(self,'parser_receipt'):
   row=next((s for s in self.parser_receipt['source']['spans']if int(s['start'],16)<=source_pc<int(s['end_exclusive'],16)),None)
   if row is not None:
    raw=bytes.fromhex(row['bytes_hex']);off=source_pc-int(row['start'],16);i=next(DEC.disasm(raw[off:off+4],source_pc));o=i.operands[-1];base=i.reg_name(o.mem.base);root={'x2':self.common['C'],'x4':self.common['S'],'sp':self.common['F'],'x0':self.parser_container,'x10':self.message}[base];offset=o.mem.disp
    if i.mnemonic=='stp':self.address_checks.append(z3.Or(a==root+offset,a==root+offset+n))
    else:self.address_checks.append(a==root+offset)
  if source_pc==pc(0xa6366c8):
   off=z3.simplify(a-self.parser_container);assert z3.is_bv_value(off)and off.as_long()+n<=16
   for j in range(n):self.parser_bytes[off.as_long()+j]=z3.Extract(8*j+7,8*j,resize(value,8*n))
  return super().store(a,n,value,source_pc)
 def run(self,label,take=None):
  original=self.e;row=next(s for s in original['source']['spans']if s['label']==label)
  if label in R.SPANS:self.parser_new_visited.update(range(*R.SPANS[label],4))
  if not label.startswith('completion_tag'):return super().run(label,take)
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   self.pc=i.address;self.visited.add(i.address)
   if i.address in R.DIRECT:
    m,t=R.DIRECT[i.address];assert i.mnemonic==m and i.operands[0].imm&((1<<64)-1)==t;cond=self.condition(m[2:]);self.direct.append({'pc':i.address,'condition':cond,'next_PC':z3.If(cond,resize(t,64),resize(i.address+4,64))});self.count+=1
    if take is not None:self.guards.append(cond if take else z3.Not(cond))
   else:self.e={'source':{'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]}};super().run('one');self.e=original
  return self
 def allocator_return(self):
  self.address_checks.extend([z3.Not(Publication.edge(self,pc(0xc4ba154),0xd0c8)),self.read('x0')==pc(0x847bb60),self.read('sp')==self.common['F'],self.read('x30')==pc(0xa636408)]);self.parser_API_returns.append({'source_PC':hex(pc(0xa636404)),'nominal_return_PC':hex(pc(0xa636408)),'native_target_executed':False,'caller_storage_preserved_by_premise':True})
  for j in list(range(19))+[30]:self.seed('x'+str(j),z3.BitVec('MP_allocator_volatile_'+str(j),64))
  self.seed('x0',self.parser_container);return self
def follow(v,label,modifier):v.address_checks.append(z3.Not(Publication.edge(v,R.SPANS[label][0],modifier)));return v.run(label)
def requested(e,mode):return follow(Model(e,mode),'parser_entry',0xb40b)
def returned(e,mode,nonnull=True):
 v=requested(e,mode);v.parser_owned=nonnull
 if not nonnull:v.extra.append(v.parser_container==0)
 v.allocator_return().run('parser_result');return v
def header(e,mode,input_nonnull=True):
 v=returned(e,mode);v.parser_profile='header_nonnull'if input_nonnull else'header_null';follow(v,'parser_zero',0x1fcb);follow(v,'parser_cursor',0xc9dc);follow(v,'parser_next',0x2f10);v.extra.append(v.original_input!=0 if input_nonnull else v.original_input==0)
 if input_nonnull:
  follow(v,'parser_header',0x5e1c);follow(v,'parser_header_address',0x5e1c)
 return v
def completion(e,mode,status,publish=False):
 # Separate interface cut: no cursor exhaustion, record contents or parser
 # completion is assumed to have been executed. C+170 and caller tag are actual.
 v=returned(e,mode)
 for reg,value in [('x2',v.common['C']),('x4',v.common['S']),('x7',TABLE),('w1',PHASE),('w3',TOKEN),('w22',0x7795e3ce),('w23',status),('x28',pc(0x7949dd0))]:v.seed(reg,value)
 if publish:
  v.seed('w12',0x69c);v.seed('w30',SUCCESS);v.run('completion_exhaustion');follow(v,'completion_publish',0x8ef5)
 v.run('completion_tag1',False).run('completion_tag2',True).run('completion_status');return v
def entry_bad(v):
 c=v.common;return z3.Or(H.cell(v,c['C']+0x170,8)!=v.message,H.cell(v,c['C']+0x98,8)!=v.original_input,H.cell(v,c['S']+0xb5c,4)!=(c['N']^SUCCESS),H.cell(v,c['S']+0xa10,8)!=0,H.cell(v,c['S']+4,4)!=SUCCESS,H.cell(v,c['S']+0xc60,8)!=0x8f98c6acce5848ca,H.cell(v,c['C']+0x690,8)!=0,v.read('w19')!=0x4a2,v.read('w20')!=0x68e,v.read('x0')!=pc(0x847bb60),Publication.edge(v,pc(0xc4ba154),0xd0c8))
def result_bad(v):
 c=v.common;return z3.Or(H.cell(v,c['C']+0xb0,8)!=v.parser_container,H.cell(v,c['C']+0x170,8)!=v.message,H.cell(v,c['S']+0x1e0,4)!=0xfbb3f478,v.read('w23')!=0xce515bb2,Publication.edge(v,pc(0xa6366ac)if v.parser_owned else pc(0xa660b88),0x1fcb))
def header_bad(v):
 c=v.common;bad=[H.cell(v,v.parser_container,8)!=0,H.cell(v,v.parser_container+8,8)!=0,H.cell(v,c['S']+0xa10,8)!=0,H.cell(v,c['C']+0x670,8)!=v.original_input,H.cell(v,c['C']+0x170,8)!=v.message,*[v.message_bytes[j]!=b for j,b in Parent.expected_message(v).items()]]
 if v.parser_profile=='header_nonnull':bad.extend([v.read('x9')!=6,v.read('x10')!=v.original_input,v.read('x8')!=0,v.read('w23')!=0xce515bb8])
 else:bad.append(Publication.edge(v,pc(0xa661bfc),0x5e1c))
 return z3.Or(*bad)
def source_obligations(e):
 proofs=[];visited=set();models={}
 def prove(name,v,bad):
  premises=v.owned()+v.guards+v.extra;s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*premises);assert s.check()==z3.sat,(name,s.reason_unknown());bad=z3.simplify(z3.Or(bad,*[z3.Not(q)for q in v.address_checks[v.parser_check_start:]]));terms=list(bad.children())if z3.is_or(bad)else[bad];parts=[terms[j:j+2]for j in range(0,len(terms),2)]
  for j,terms in enumerate(parts):
   s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*premises,z3.Or(*terms));query=s.to_smt2();r=s.check();assert r==z3.unsat,(name,j,str(r),s.reason_unknown(),s.model()if r==z3.sat else'');proofs.append({'name':name+'_part_'+str(j+1),'semantic_contract':name,'counterexample_partition':j+1,'counterexample_partitions':len(parts),'result':'unsat','premises_nonvacuous':True,'query':query,'lifted_instruction_instances':v.count});print('proved '+name+' '+str(j+1)+'/'+str(len(parts)),flush=True)
  visited.update(v.parser_new_visited)
 for mode in MODES:
  v=requested(e,mode);prove(mode+'_actual_parser_entry_and_typed_request',v,entry_bad(v))
  for nonnull in [True,False]:
   v=returned(e,mode,nonnull);prove(mode+('_nonnull'if nonnull else'_null')+'_actual_allocation_result_routing',v,result_bad(v))
  for yes in [True,False]:
   v=header(e,mode,yes);prove(mode+('_nonnull'if yes else'_null')+'_original_input_pointer_to_header_frontier',v,header_bad(v));models[mode+'_'+v.parser_profile]=v
  v=returned(e,mode,False);v.run('completion_tag1',False).run('completion_tag2',True).run('completion_status');prove(mode+'_actual_null_allocation_to_caller_failure',v,Publication.edge(v,pc(0xa6650a4),0xcb79))
  status=z3.BitVec('MP_completion_status32',32);v=completion(e,mode,status);want=z3.If(status==SUCCESS,resize(pc(0xa661180),64),resize(pc(0xa6650a4),64));prove(mode+'_independent_completion_all_status_routing',v,Publication.edge(v,want,0xcb79))
  v=completion(e,mode,resize(SUCCESS,32),True);follow(v,'completion_flag',0xcb79);target=pc(0xa6611e4)if mode=='mode_zero'else pc(0xa663c9c);prove(mode+'_independent_exhaustion_publication_and_actual_message_flag',v,z3.Or(H.cell(v,v.message,8)!=v.parser_container,H.cell(v,v.common['S']+0xc94,4)!=SUCCESS,Publication.edge(v,target,0xeeda)))
 # Third tag remains a distinct interface. This cut covers all discriminator32,
 # independent of the composed caller, and proves exact ordered recognition.
 v=Model(e);tag=z3.BitVec('MP_cut_discriminator32',32);mem(v,v.common['S']+0x1e0,4,tag);v.seed('x4',v.common['S']);v.run('completion_tag1').run('completion_tag2').run('completion_tag3');d=v.direct[-3:];prove('independent_all_tag32_ordered_dispatch',v,z3.Or(d[0]['condition']!=(tag==0x89f25623),d[1]['condition']!=(tag==0xfbb3f478),d[2]['condition']!=(tag!=0x1830b7ce)))
 captured={int(i['pc'],16)for s in e['source']['spans']for i in s['instructions']};assert captured<=visited,captured-visited
 return proofs,models,len(captured&visited)
def audit(e=None):
 e=e if e is not None else json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();proofs,models,covered=source_obligations(e)
 controls=negative_controls(e);rechecked=[];prior=json.loads(read(ROOT/'userclient_message_initialization_audit.json'))
 for q in prior['source_proofs']:
  if q['semantic_contract']not in ['actual_attribute_to_message_mode_zero_success','actual_attribute_to_message_mode_nonzero_success']:continue
  ctx=z3.Context();s=z3.SolverFor('QF_BV',ctx=ctx);s.set(timeout=120000);s.add(*z3.parse_smt2_string(q['query'],ctx=ctx));assert s.check()==z3.unsat,(q['name'],s.reason_unknown());rechecked.append({'name':q['name'],'result':'unsat','source_audit_sha256':sha(ROOT/'userclient_message_initialization_audit.json')})
 totals={'new_source_queries_unsat':len(proofs),'new_semantic_contracts':len({p['semantic_contract']for p in proofs}),'prior_source_queries_unsat':len(rechecked),'new_source_words_covered':covered,'lifted_instruction_instances':sum(p['lifted_instruction_instances']for p in proofs),'composed_header_profiles':len(models),'negative_source_controls':len(controls),'new_controller_reads_per_request':2,'new_controller_reads_per_return':4,'new_certified_bank_applications_per_return':11,'native_target_calls':0,'input_content_bytes_supplied':0}
 return {'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],'kernel_collection_sha256':e['kernel_collection_sha256'],'scope':e['scope'],'dependencies':e['dependencies'],'verified_counts':e['verified_counts'],'source_proofs':proofs,'rechecked_prior_source_proofs':rechecked,'negative_source_controls':controls,'independent_totals':totals,'conditional_message_parser_interfaces_established':True,'all_checks_pass':True,**{n:False for n in R.FALSE}}
def negative_controls(e):
 out=[]
 for at,kind in [(pc(0xa636348),'output_alias'),(pc(0xa660b70),'published_pointer'),(pc(0xa661160),'raw_status_comparison')]:
  changed=copy.deepcopy(e);row=next(s for s in changed['source']['spans']if int(s['start'],16)<=at<int(s['end_exclusive'],16));offset=at-int(row['start'],16);raw=bytearray.fromhex(row['bytes_hex']);old=bytes(raw[offset:offset+4]);word=int.from_bytes(old,'little');new=bytes.fromhex('1f2003d5')if kind=='output_alias'else((word&~31)|31).to_bytes(4,'little')if kind=='published_pointer'else((word&~(31<<16))|(31<<16)).to_bytes(4,'little');raw[offset:offset+4]=new;row['bytes_hex']=raw.hex()
  if kind=='output_alias':v=requested(changed,'mode_zero');bad=entry_bad(v)
  else:
   v=completion(changed,'mode_zero',resize(SUCCESS,32),True);bad=H.cell(v,v.message,8)!=v.parser_container if kind=='published_pointer'else Publication.edge(v,pc(0xa661180),0xcb79)
  s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*v.owned(),*v.guards,*v.extra,*v.address_checks[v.parser_check_start:]);assert s.check()==z3.sat,(kind,'premises');s.add(bad);query=s.to_smt2();assert s.check()==z3.sat,kind;out.append({'mutated_PC':hex(at),'kind':kind,'original_word_hex':old.hex(),'replacement_word_hex':new.hex(),'normal_oracle_rejected':True,'satisfiable_violation_query':query,'native_target_executed':False,'stop_boundary':'before_following_next_target'})
 return out
if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
