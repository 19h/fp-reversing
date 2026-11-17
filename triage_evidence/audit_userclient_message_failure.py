#!/usr/bin/env python3
"""Compose actual allocation failure with two qualified retirement returns.
O(I+256R+C*I+query DAG) construction/space; SMT separately bounded.
"""
import copy,json
import z3
from kext_port_tools import ROOT,TABLE,qword
from lskd_values_symbolic import resize,mem
from verify_daemon_reader_record_payloads_publication import read,sha
import audit_userclient_message_parser as Parent
import recover_userclient_message_failure as R
H=Parent.H;DEC=Parent.DEC;Publication=Parent.Publication;SUCCESS=Parent.SUCCESS;TOKEN=Parent.TOKEN;PHASE=Parent.PHASE;pc=R.pc
ERROR=0xce515bb2
class Model(Parent.Model):
 def __init__(self,e,mode='mode_zero'):
  prior=Parent.returned(json.loads(read(ROOT/'userclient_message_parser_checks.json')),mode,False);prior.run('completion_tag1',False).run('completion_tag2',True).run('completion_status');self.__dict__.update(prior.__dict__);self.e=copy.deepcopy(self.e);self.e['source']['spans']+=copy.deepcopy(e['source']['spans']);self.failure_receipt=e;self.failure_check_start=len(self.address_checks);self.failure_store_start=len(self.stores);self.failure_visited=set();self.failure_left={};self.failure_bank_bytes={};self.failure_bank_reads=[];self.failure_controllers=[];self.failure_returns=[];self.retired=[];self.failure_loads=[];self.failure_root_equalities=[]
  for off,n,root,value in R.ROOTS:
   want=self.common[root]+value if root in ['C','S']else resize(value,8*n);key=(z3.simplify(self.common['F']+off).sexpr(),n)
   if key in self.memory:self.failure_root_equalities.append(self.memory[key]==want)
   else:mem(self,self.common['F']+off,n,want)
 def load(self,a,n):
  if hasattr(self,'failure_receipt'):
   self.failure_loads.append({'pc':self.pc,'address':a,'size_bytes':n})
   for base,extent in self.retired:self.address_checks.append(z3.Or(z3.ULE(a+n,base),z3.ULE(base+extent,a)))
   if self.pc in [pc(p)for p in [0xa660990,0xa660998,0xa656aa4,0xa656aac]]:
    at=pc(0xccc30d0 if self.pc in [pc(0xa660990),pc(0xa656aa4)]else 0xccc32f8);assert n==4;self.address_checks.append(a==at);self.failure_controllers.append(hex(self.pc));self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});return z3.BitVec('MF_controller_'+str(len(self.failure_controllers)),32)
   for r in self.failure_receipt['bank_rules']:
    key=r['left_PC']
    if self.pc==int(key,16):
     assert n==1;L=int(r['left'],16);self.failure_left[key]=z3.Extract(7,0,a-L);self.failure_bank_bytes[key]=z3.BitVec('MF_bank_'+str(len(self.failure_bank_reads)),8);self.address_checks.append(a==L+z3.ZeroExt(56,self.failure_left[key]));self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});return self.failure_bank_bytes[key]
    if self.pc==int(r['right_PC'],16):
     assert n==1;self.address_checks.append(a==int(r['right'],16)+z3.ZeroExt(56,self.failure_bank_bytes[key]^int(r['key'],16)));self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});self.failure_bank_reads.append(hex(self.pc));return self.failure_left[key]^int(r['constant'],16)
   if self.pc in R.LITERALS:
    at=R.LITERALS[self.pc];assert n==8;self.address_checks.append(a==at);self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});return resize(qword(at),64)
   if self.pc in R.BRANCHES:
    js=R.BRANCHES[self.pc];assert n==8;self.address_checks.append(z3.Or(*[a==TABLE+8*j for j in js]));self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});value=resize(0,64)
    for j in js:value=z3.If(a==TABLE+8*j,resize(qword(TABLE+8*j),64),value)
    return value
  return super().load(a,n)
 def store(self,a,n,value,source_pc):
  if hasattr(self,'failure_receipt'):
   row=next((s for s in self.failure_receipt['source']['spans']if int(s['start'],16)<=source_pc<int(s['end_exclusive'],16)),None)
   if row is not None:
    raw=bytes.fromhex(row['bytes_hex']);offset=source_pc-int(row['start'],16);i=next(DEC.disasm(raw[offset:offset+4],source_pc));base=i.reg_name(i.operands[-1].mem.base);off=i.operands[-1].mem.disp
    roots={'x2':self.common['C'],'x4':self.common['S'],'x8':self.common['C']+0x1d0,'x10':self.common['C']+0x360,'x19':self.common['C']+0x1b0};self.address_checks.append(a==roots[base]+off)
   for base,extent in self.retired:self.address_checks.append(z3.Or(z3.ULE(a+n,base),z3.ULE(base+extent,a)))
  return super().store(a,n,value,source_pc)
 def run(self,label,take=None):
  if label in R.SPANS:self.failure_visited.update(range(*R.SPANS[label],4))
  return super().run(label,take)
 def retirement_return(self,kind):
  message=kind=='message';call=pc(0xa660a20 if message else 0xa656b24);ret=call+4;obj=self.message if message else self.attribute;descriptor=pc(0x847b360 if message else 0x847b920);extent=128 if message else 112
  self.address_checks.extend([z3.Not(Publication.edge(self,pc(0xc4ba368),0x4d6a)),self.edges[-1]['pc']==call,self.read('x0')==descriptor,self.read('x1')==obj,self.read('x30')==ret,self.read('sp')==self.common['F']]);self.failure_returns.append({'kind':kind,'source_PC':hex(call),'descriptor':hex(descriptor),'nominal_return_PC':hex(ret),'native_target_executed':False,'caller_storage_preserved_by_premise':True,'retired_object_storage_preservation_assumed':False});self.retired.append((obj,extent))
  for j in list(range(19))+[30]:self.seed('x'+str(j),z3.BitVec('MF_'+kind+'_free_volatile_'+str(j),64))
  return self
def follow(v,label,modifier):v.address_checks.append(z3.Not(Publication.edge(v,R.SPANS[label][0],modifier)));return v.run(label)
def requested(e,mode):
 v=Model(e,mode)
 for label,mod in [('failure_save',0xcb79),('failure_stage',0x53f6),('failure_destroy_entry',0x682a),('failure_message_children',0xb75d),('failure_container_bridge',0xb23e),('failure_container_entry',0x189),('failure_container_object',0xb775),('failure_container_return',0x53f6),('failure_second_child',0x4ed7),('failure_container_entry',0x189),('failure_container_object',0xb775),('failure_container_return',0x53f6),('failure_message_free',0x4ed7)]:follow(v,label,mod)
 return v
def through_message(e,mode,stop=None):
 v=requested(e,mode);v.retirement_return('message').run('failure_message_freed')
 for label,mod in [('failure_clear_alias',0x5426),('failure_saved_callback',0xb75d),('failure_restore',0x9ca),('failure_output',0x53f6),('failure_outer',0xd098),('failure_outer_status',0xbe01),('failure_outer_prepare',0x5ab2),('failure_destroy_entry',0x682a),('failure_saved_callback',0xb75d),('failure_attribute_prepare',0x9ca),('failure_attribute_entry',0x123b),('failure_attribute_free',0xf244)]:
  follow(v,label,mod)
  if label==stop:break
 return v
def finished(e,mode):
 v=through_message(e,mode);v.retirement_return('attribute').run('failure_attribute_freed')
 for label,mod in [('failure_attribute_return',0xf244),('failure_final_status',0xb745),('failure_original_container',0x64d8)]:follow(v,label,mod)
 return v
def request_bad(v):
 c=v.common;return z3.Or(*[z3.Not(q)for q in v.failure_root_equalities],H.cell(v,c['S']+0xd98,4)!=ERROR,H.cell(v,c['C']+0x1d0,8)!=v.message,H.cell(v,c['C']+0x78,8)!=v.message,H.cell(v,v.message,8)!=0,H.cell(v,v.message+8,8)!=0,v.read('x0')!=pc(0x847b360),v.read('x1')!=v.message,Publication.edge(v,pc(0xc4ba368),0x4d6a))
def attribute_bad(v):
 c=v.common;return z3.Or(H.cell(v,c['S']+0xd98,4)!=ERROR,H.cell(v,c['S']+0xab8,4)!=ERROR,H.cell(v,c['C']+0x1d0,8)!=0,H.cell(v,c['C']+0x788,8)!=0,H.cell(v,c['C']+0x360,8)!=0,H.cell(v,c['C']+0x78,8)!=0,H.cell(v,c['C']+0x1b0,8)!=v.attribute,v.read('x0')!=pc(0x847b920),v.read('x1')!=v.attribute,Publication.edge(v,pc(0xc4ba368),0x4d6a))
def final_bad(v):
 c=v.common;return z3.Or(H.cell(v,c['S']+0xd98,4)!=ERROR,H.cell(v,c['S']+0xab8,4)!=ERROR,H.cell(v,c['S']+0x1c,4)!=ERROR,*[H.cell(v,c['C']+off,8)!=0 for off in [0x1d0,0x788,0x360,0x78,0x1b0]],H.cell(v,c['C']+0x418,8)!=c['H'],H.cell(v,c['H'],8)!=c['J'],H.cell(v,c['H']+8,8)!=c['J'],H.cell(v,c['J']+0x18,8)!=c['Z'],v.read('w23')!=ERROR,v.read('x19')!=c['C']+0x418,Publication.edge(v,pc(0xa66229c),0xb23e))
def source_obligations(e):
 out=[];visited=set();models={}
 def prove(name,v,bad):
  premises=v.owned()+v.guards+v.extra;s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*premises);assert s.check()==z3.sat,(name,s.reason_unknown());bad=z3.simplify(z3.Or(bad,*[z3.Not(q)for q in v.address_checks[v.failure_check_start:]]));terms=list(bad.children())if z3.is_or(bad)else[bad];parts=[terms[j:j+2]for j in range(0,len(terms),2)]
  for j,terms in enumerate(parts):
   s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*premises,z3.Or(*terms));query=s.to_smt2();r=s.check();assert r==z3.unsat,(name,j,str(r),s.reason_unknown(),s.model()if r==z3.sat else'');out.append({'name':name+'_part_'+str(j+1),'semantic_contract':name,'counterexample_partition':j+1,'counterexample_partitions':len(parts),'result':'unsat','premises_nonvacuous':True,'query':query,'lifted_instruction_instances':v.count});print('proved '+name+' '+str(j+1)+'/'+str(len(parts)),flush=True)
  visited.update(v.failure_visited)
 for mode in Parent.MODES:
  v=requested(e,mode);prove(mode+'_actual_null_parser_to_message_retirement',v,request_bad(v))
  v=through_message(e,mode);prove(mode+'_retired_message_cleared_output_and_attribute_retirement',v,attribute_bad(v))
  v=finished(e,mode);prove(mode+'_both_retirements_raw_error_and_original_container_request',v,final_bad(v));models[mode]=v
 captured={int(i['pc'],16)for s in e['source']['spans']for i in s['instructions']};assert captured<=visited,captured-visited
 return out,models,len(captured&visited)
def audit(e=None):
 e=e if e is not None else json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();proofs,models,covered=source_obligations(e)
 controls=negative_controls(e);prior=[];old=json.loads(read(ROOT/'userclient_message_parser_audit.json'))
 for q in old['source_proofs']:
  if q['semantic_contract']not in [mode+'_actual_null_allocation_to_caller_failure'for mode in Parent.MODES]:continue
  ctx=z3.Context();s=z3.SolverFor('QF_BV',ctx=ctx);s.set(timeout=120000);s.add(*z3.parse_smt2_string(q['query'],ctx=ctx));assert s.check()==z3.unsat,(q['name'],s.reason_unknown());prior.append({'name':q['name'],'result':'unsat','source_audit_sha256':sha(ROOT/'userclient_message_parser_audit.json')})
 totals={'new_source_queries_unsat':len(proofs),'new_semantic_contracts':len({p['semantic_contract']for p in proofs}),'prior_source_queries_unsat':len(prior),'new_source_words_covered':covered,'lifted_instruction_instances':sum(p['lifted_instruction_instances']for p in proofs),'composed_modes':len(models),'retirement_calls_per_mode':2,'additional_prefix_cells_reconstructed':sum(len(p['source_defined_cells'])for p in e['prefix_cells']),'additional_prefix_bytes_reconstructed':sum(sum(c['size_bytes']for c in p['source_defined_cells'])for p in e['prefix_cells']),'negative_source_controls':len(controls),'new_controller_reads_per_mode':4,'new_bank_applications_per_mode':4,'input_content_bytes_supplied':0,'native_target_calls':0}
 return {'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],'kernel_collection_sha256':e['kernel_collection_sha256'],'scope':e['scope'],'dependencies':e['dependencies'],'verified_counts':e['verified_counts'],'source_proofs':proofs,'rechecked_prior_source_proofs':prior,'negative_source_controls':controls,'retirement_interfaces':{mode:v.failure_returns for mode,v in models.items()},'independent_totals':totals,'conditional_message_failure_unwind_established':True,'all_checks_pass':True,**{n:False for n in R.FALSE}}
def negative_controls(e):
 out=[]
 for at,kind in [(pc(0xa6650c4),'saved_error'),(pc(0xa660a84),'message_alias_clear'),(pc(0xa656b58),'attribute_alias_clear')]:
  changed=copy.deepcopy(e);row=next(s for s in changed['source']['spans']if int(s['start'],16)<=at<int(s['end_exclusive'],16));offset=at-int(row['start'],16);raw=bytearray.fromhex(row['bytes_hex']);old=bytes(raw[offset:offset+4]);word=int.from_bytes(old,'little');new=((word&~31)|31).to_bytes(4,'little')if kind=='saved_error'else bytes.fromhex('1f2003d5');raw[offset:offset+4]=new;row['bytes_hex']=raw.hex()
  if kind=='saved_error':v=through_message(changed,'mode_zero','failure_restore');bad=v.read('w23')!=ERROR
  else:v=finished(changed,'mode_zero');bad=H.cell(v,v.common['C']+(0x1d0 if kind=='message_alias_clear'else 0x1b0),8)!=0
  s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*v.owned(),*v.guards,*v.extra,*v.address_checks[v.failure_check_start:]);assert s.check()==z3.sat,(kind,'premises');s.add(bad);query=s.to_smt2();assert s.check()==z3.sat,kind;out.append({'mutated_PC':hex(at),'kind':kind,'original_word_hex':old.hex(),'replacement_word_hex':new.hex(),'normal_oracle_rejected':True,'satisfiable_violation_query':query,'stop_boundary':'before_next_control_transfer_is_followed','native_target_executed':False})
 return out
if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
