#!/usr/bin/env python3
"""Compose original-object retirement with two failure fallback outcomes.
O(I+256R+C*I+query DAG) construction/space; SMT search bounded separately.
"""
import copy,json
import z3
from kext_port_tools import ROOT,IMAGE,qword
from lskd_values_symbolic import resize,mem
from verify_daemon_reader_record_payloads_publication import read,sha
import audit_userclient_message_failure as Parent
import recover_userclient_failure_fallback as R
H=Parent.H;DEC=Parent.DEC;Publication=Parent.Publication;SUCCESS=Parent.SUCCESS;pc=R.pc
ERROR=0xce515bb2
MODES=['mode_zero','mode_nonzero']
def label(a):return 'ff_'+format(a,'x')
def mask(a):return z3.Extract(7,0,z3.LShR((z3.RotateRight(a&resize(-8,64),8)+0x02e859d27e491464)^0x4dae26df20976138,(a&7)<<3))

class Model(Parent.Model):
 def __init__(self,e,mode='mode_zero'):
  prior=Parent.finished(json.loads(read(ROOT/'userclient_message_failure_checks.json')),mode);self.__dict__.update(prior.__dict__);self.e=copy.deepcopy(self.e);self.e['source']['spans']+=copy.deepcopy(e['source']['spans']);self.fallback_receipt=e;self.fallback_check_start=len(self.address_checks);self.fallback_visited=set();self.fallback_left={};self.fallback_bank_bytes={};self.fallback_bank_reads=[];self.fallback_controllers=[];self.fallback_returns=[];self.fallback_input_reads=[];self.fallback_copy_stores=[];self.fallback_root_equalities=[];self.static_reads=[];self.buffer=z3.BitVec('FF_buffer64',64);self.buffer_owned=False;self.input_bytes=[z3.BitVec('FF_input_'+str(j),8)for j in range(14)]
  for off,n,role,value in R.ROOTS:
   c=self.common;want=c[role]+value if role in ['C','S']else self.original_input if role=='I'else z3.ZeroExt(32,c['N'])+value if role=='N_add'else z3.ZeroExt(32,c['N']^value)if role=='N_xor'else resize(value,8*n);key=(z3.simplify(c['F']+off).sexpr(),n)
   if key in self.memory:
    if off==0x9ec:self.extra.append(self.memory[key]==want)
    else:self.fallback_root_equalities.append(self.memory[key]==want)
   else:mem(self,c['F']+off,n,want)
 def owned(self):
  out=super().owned()
  if not self.buffer_owned:return out
  c=self.common;I=self.original_input;B=self.buffer;live=[(c['F']-0x70,resize(0x1160,64)),(c['C'],resize(4096,64)),(c['S'],resize(16384,64)),(self.holder,resize(16,64)),(self.entries,24*z3.ZeroExt(32,self.capacity)),(self.payload,resize(56,64))]+[(resize(a,64),resize(n,64))for a,off,n in IMAGE.segments]
  for a in [I,B]:
   out.extend([a!=0,z3.ULE(a,resize((1<<64)-15,64))]);out.extend(z3.Or(z3.ULE(a+14,b),z3.ULE(b+n,a))for b,n in live)
  out.append(z3.Or(z3.ULE(I+14,B),z3.ULE(B+14,I)))
  # The input stays live. The new allocation may reuse retired object addresses.
  out.extend(z3.Or(z3.ULE(I+14,b),z3.ULE(b+n,I))for b,n in self.retired)
  return out
 def static_read(self,a,n,lo,extent):
  segment=next((b,m)for b,off,m in IMAGE.segments if b<=lo and lo+extent<=b+m);b,m=segment
  self.address_checks.extend([z3.UGE(a,lo),z3.ULE(a+n,lo+extent)]);self.static_reads.append({'source_PC':hex(self.pc),'size_bytes':n,'admitted_range_start':hex(lo),'admitted_range_bytes':extent,'image_segment_start':hex(b),'image_segment_bytes':m,'retired_extent_separation_lemma_applied':True})
 def load(self,a,n):
  if hasattr(self,'fallback_receipt'):
   if self.pc in R.CONTROLLERS:
    assert n==4;self.address_checks.append(a==R.CONTROLLERS[self.pc]);self.static_read(a,n,R.CONTROLLERS[self.pc],4);self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});self.fallback_controllers.append(hex(self.pc));return z3.BitVec('FF_controller_'+str(len(self.fallback_controllers)),32)
   for r in self.fallback_receipt['bank_rules']:
    key=r['left_PC']
    if self.pc==int(key,16):
     assert n==1;L=int(r['left'],16);self.fallback_left[key]=z3.Extract(7,0,a-L);self.fallback_bank_bytes[key]=z3.BitVec('FF_bank_'+str(len(self.fallback_bank_reads)),8);self.address_checks.append(a==L+z3.ZeroExt(56,self.fallback_left[key]));self.static_read(a,n,L,256);self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});return self.fallback_bank_bytes[key]
    if self.pc==int(r['right_PC'],16):
     assert n==1;self.address_checks.append(a==int(r['right'],16)+z3.ZeroExt(56,self.fallback_bank_bytes[key]^int(r['key'],16)));self.static_read(a,n,int(r['right'],16),256);self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});self.fallback_bank_reads.append(hex(self.pc));return self.fallback_left[key]^int(r['constant'],16)
   if self.pc in R.POINTERS:
    aa=R.POINTERS[self.pc];assert n==8;self.address_checks.append(z3.Or(*[a==at for at in aa]));self.static_read(a,n,min(aa),max(aa)-min(aa)+8);self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});value=resize(0,64)
    for at in aa:value=z3.If(a==at,resize(qword(at),64),value)
    return value
   if self.pc==pc(0xa641e10):
    index=13-len(self.fallback_input_reads);assert n==1 and 0<=index<14;self.address_checks.append(a==self.original_input+index);self.address_checks.extend(z3.Or(z3.ULE(a+n,b),z3.ULE(b+m,a))for b,m in self.retired);self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});self.fallback_input_reads.append(index);return self.input_bytes[index]
  return super().load(a,n)
 def store(self,a,n,value,source_pc):
  if hasattr(self,'fallback_receipt'):
   row=next((s for s in self.fallback_receipt['source']['spans']if int(s['start'],16)<=source_pc<int(s['end_exclusive'],16)),None)
   if row is not None:
    off=source_pc-int(row['start'],16);i=next(DEC.disasm(bytes.fromhex(row['bytes_hex'])[off:off+4],source_pc));base=i.reg_name(i.operands[-1].mem.base);disp=i.operands[-1].mem.disp;c=self.common
    roots={'x2':c['C'],'x4':c['S'],'sp':c['F'],'x19':c['C']+0x418,'x23':c['J'],'x9':c['C']+0x90,'x13':c['S']+0xbe4}
    if source_pc==pc(0xa641e48):
     index=13-len(self.fallback_copy_stores);self.address_checks.append(a==self.buffer+index);self.fallback_copy_stores.append({'index':index,'address':a,'value':resize(value,8)})
     retired=self.retired;self.retired=[]
     try:return super().store(a,n,value,source_pc)
     finally:self.retired=retired
    self.address_checks.append(a==roots[base]+disp)
   for b,m in self.retired:self.address_checks.append(z3.Or(z3.ULE(a+n,b),z3.ULE(b+m,a)))
  return super().store(a,n,value,source_pc)
 def run(self,name,take=None):
  if not name.startswith('ff_'):return super().run(name,take)
  original=self.e;row=next(s for s in original['source']['spans']if s['label']==name);skip=None
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if i.address==skip:continue
   self.pc=i.address;self.fallback_visited.add(i.address)
   if i.mnemonic.startswith('b.'):
    assert i.address in [pc(0xa641c6c),pc(0xa641c7c),pc(0xa641e20)];cond=self.condition(i.mnemonic[2:]);yes=i.address==pc(0xa641e20);self.guards.append(cond if yes else z3.Not(cond));self.count+=1
    if yes:assert i.operands[0].imm&((1<<64)-1)==i.address+8;skip=i.address+4
   else:
    self.e={'source':{'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]}};super().run('one');self.e=original
  return self
 def api_return(self,kind):
  c=self.common
  info={'record':(0xa6607e8,0xc4ba84c,0x85d,c['Z'],resize(14,64),c['Z'],14),
   'node':(0xa660708,0xc4ba368,0x4d6a,resize(pc(0x847be20),64),c['J'],c['J'],32),
   'container':(0xa6605c4,0xc4ba368,0x4d6a,resize(pc(0x847bde0),64),c['H'],c['H'],16),
   'allocate':(0xa641cf8,0xc4ba60c,0xca0c,z3.ZeroExt(32,c['N']),None,None,None),
   'context':(0xa666260,0xc4ba368,0x4d6a,resize(pc(0x847ba60),64),c['C'],c['C'],4096)}[kind]
  at,target,mod,arg0,arg1,obj,extent=info;self.address_checks.extend([z3.Not(Publication.edge(self,pc(target),mod)),self.edges[-1]['pc']==pc(at),self.read('x0')==arg0,self.read('sp')==c['F'],self.read('x30')==pc(at+4)])
  if arg1 is not None:self.address_checks.append(self.read('x1')==arg1)
  if obj is not None:self.retired.append((obj,extent))
  self.fallback_returns.append({'kind':kind,'source_PC':hex(pc(at)),'nominal_return_PC':hex(pc(at+4)),'native_target_executed':False,'surviving_caller_storage_preserved_by_premise':True,'retired_object_storage_preservation_assumed':False})
  for j in list(range(19))+[30]:self.seed('x'+str(j),z3.BitVec('FF_'+kind+'_volatile_'+str(j),64))
  if kind=='allocate':self.seed('x0',self.buffer)
  return self

def follow(v,a,mod):v.address_checks.append(z3.Not(Publication.edge(v,pc(a),mod)));return v.run(label(a))
def record_request(e,mode):
 v=Model(e,mode)
 for a,mod in [(0xa66229c,0xb23e),(0xa660468,0x189),(0xa6604a4,0xb775),(0xa6604fc,0x53f6),(0xa660750,0xad37),(0xa660790,0x776f)]:follow(v,a,mod)
 return v
def node_request(e,mode):
 v=record_request(e,mode);v.api_return('record').run(label(0xa6607ec));follow(v,0xa66066c,0x776f);return v
def container_request(e,mode):
 v=node_request(e,mode);v.api_return('node').run(label(0xa66070c));follow(v,0xa660534,0xad37);return v
def allocation_request(e,mode):
 v=container_request(e,mode);v.api_return('container').run(label(0xa6605c8));follow(v,0xa660614,0x1fb3);follow(v,0xa641c60,0x4ed7);return v
def allocated(e,mode,nonnull):
 v=allocation_request(e,mode);v.buffer_owned=nonnull
 if not nonnull:v.extra.append(v.buffer==0)
 v.api_return('allocate').run(label(0xa641cfc));return v
def context_request(e,mode):return follow(allocated(e,mode,False),0xa6661bc,0x3ad3)
def workspace_request(e,mode):
 v=context_request(e,mode);return v.api_return('context').run(label(0xa666264))
def parser_request(e,mode):
 v=allocated(e,mode,True);follow(v,0xa641d54,0x3ad3)
 for j in range(14):follow(v,0xa641e08,0xf01)
 for a,mod in [(0xa641e68,0xf01),(0xa641ee0,0x1aac),(0xa641fb4,0x2824)]:follow(v,a,mod)
 return v

def copy_bad(v):return z3.Or(*[q['value']!=(v.input_bytes[q['index']]^mask(v.buffer+q['index']))for q in v.fallback_copy_stores])
def request_bad(v,kind):
 c=v.common
 if kind=='record':return z3.Or(*[z3.Not(q)for q in v.fallback_root_equalities],v.read('x0')!=c['Z'],v.read('x1')!=14,v.read('x25')!=0,Publication.edge(v,pc(0xc4ba84c),0x85d))
 if kind=='node':return z3.Or(H.cell(v,c['J']+0x18,8)!=0,v.read('x0')!=pc(0x847be20),v.read('x1')!=c['J'],v.read('x25')!=0,Publication.edge(v,pc(0xc4ba368),0x4d6a))
 if kind=='container':return z3.Or(v.read('x0')!=pc(0x847bde0),v.read('x1')!=c['H'],Publication.edge(v,pc(0xc4ba368),0x4d6a))
 if kind=='allocate':return z3.Or(H.cell(v,c['C']+0x418,8)!=0,H.cell(v,c['S']+0x1c,4)!=ERROR,H.cell(v,c['S']+0xe10,8)!=z3.ZeroExt(32,c['N'])+0x621745fcc03f95d4,v.read('x0')!=z3.ZeroExt(32,c['N']),Publication.edge(v,pc(0xc4ba60c),0xca0c))
 if kind=='context':return z3.Or(H.cell(v,c['C']+0x90,8)!=0,v.read('w26')!=ERROR,v.read('w23')!=SUCCESS,v.read('x0')!=pc(0x847ba60),v.read('x1')!=c['C'],Publication.edge(v,pc(0xc4ba368),0x4d6a))
 if kind=='workspace':return z3.Or(v.read('w26')!=ERROR,v.read('w23')!=SUCCESS,v.read('x0')!=c['S'],v.read('w1')!=16384,Publication.edge(v,pc(0xc4b9a24),0x84ff))
 if kind=='parser':return z3.Or(copy_bad(v),H.cell(v,c['C']+0x418,8)!=0,H.cell(v,c['C']+0x90,8)!=v.buffer,H.cell(v,c['C']+0x358,8)!=v.buffer,H.cell(v,c['C']+0x600,8)!=0,H.cell(v,c['C']+0x3c0,8)!=0,H.cell(v,c['C']+0x618,8)!=v.buffer,H.cell(v,c['C']+0x188,8)!=c['C']+0x600,H.cell(v,c['C']+0x5c8,8)!=pc(0xa656c08),H.cell(v,c['S']+0xbe4,4)!=SUCCESS,H.cell(v,c['S']+0xc8c,4)!=(c['N']^SUCCESS),H.cell(v,c['F']+0xa80,8)!=0,v.read('x0')!=pc(0x847b620),Publication.edge(v,pc(0xc4ba154),0xd0c8))
 raise AssertionError(kind)

def source_obligations(e):
 out=[];domains=[];ownership=[];visited=set();models={}
 def prove(name,v,bad):
  s=z3.SolverFor('QF_BV');s.set(timeout=60000);premises=v.owned()+v.guards+v.extra;s.add(*premises);assert s.check()==z3.sat,(name,s.reason_unknown());s.push();s.add(z3.Or(v.common['N']!=14,v.common['L']!=4));domain_query=s.to_smt2();assert s.check()==z3.unsat,(name,'selected extent domain',s.reason_unknown());s.pop();domains.append({'semantic_contract':name,'premises_nonvacuous':True,'result':'unsat','query':domain_query,'source_entailed_bindings':{str(v.common['N']):14,str(v.common['L']):4}})
  invalid=[]
  for base,extent in v.retired:
   invalid.append(z3.UGT(base,resize((1<<64)-1-extent,64)))
   for b,off,n in IMAGE.segments:invalid.append(z3.Not(z3.Or(z3.ULE(base+extent,b),z3.ULE(b+n,base))))
  os=z3.SolverFor('QF_BV');os.set(timeout=60000);os.add(*v.owned(),*v.extra,z3.simplify(z3.substitute(z3.Or(*invalid),(v.common['L'],resize(4,32)))));oq=os.to_smt2();assert os.check()==z3.unsat,(name,'retired image ownership',os.reason_unknown());ownership.append({'semantic_contract':name,'premises_nonvacuous':True,'result':'unsat','query':oq,'retired_extents_checked':len(v.retired)})
  bad=z3.simplify(z3.substitute(z3.Or(bad,*[z3.Not(q)for q in v.address_checks[v.fallback_check_start:]]),(v.common['N'],resize(14,32)),(v.common['L'],resize(4,32))));terms=list(bad.children())if z3.is_or(bad)else[bad];parts=[terms[j:j+2]for j in range(0,len(terms),2)]
  for j,terms in enumerate(parts):
   s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*premises,z3.Or(*terms));query=s.to_smt2();r=s.check();assert r==z3.unsat,(name,j,str(r),s.reason_unknown(),s.model()if r==z3.sat else'');out.append({'name':name+'_part_'+str(j+1),'semantic_contract':name,'counterexample_partition':j+1,'counterexample_partitions':len(parts),'premises_nonvacuous':True,'result':'unsat','query':query,'lifted_instruction_instances':v.count});print('proved '+name+' '+str(j+1)+'/'+str(len(parts)),flush=True)
  visited.update(v.fallback_visited)
 for mode in MODES:
  for kind,factory in [('record',record_request),('node',node_request),('container',container_request),('allocate',allocation_request),('context',context_request),('workspace',workspace_request),('parser',parser_request)]:
   v=factory(e,mode);prove(mode+'_'+kind+'_request',v,request_bad(v,kind));models[mode+'_'+kind]=v
 captured={int(i['pc'],16)for s in e['source']['spans']for i in s['instructions']};assert captured-visited=={pc(0xa641e24)},captured-visited
 return out,models,len(visited&captured),domains,ownership

def prefix_obligations(e):
 from audit_userclient_early_node import Lift
 from audit_userclient_entry_execution import proof
 out=[]
 for name in ['prefix_length_channels','prefix_saved_error','qualified_return_decode']:
  row=next(s for s in e['prefix_source']if s['label']==name);v=Lift({'spans':[row]});F=z3.BitVec('FF_prefix_F64',64);N=z3.BitVec('FF_prefix_N32',32)
  for j in range(31):v.seed('x'+str(j),z3.BitVec('FF_prefix_'+name+'_X'+str(j),64))
  v.seed('sp',F);v.seed('w19',N)
  if name=='qualified_return_decode':v.seed('w26',ERROR);v.seed('w23',SUCCESS)
  v.run(name)
  if name=='prefix_length_channels':bad=z3.Or(H.cell(v,F+0x4d8,8)!=z3.ZeroExt(32,N)+0xe33fe5fefaffb7f5,H.cell(v,F+0x4d0,8)!=z3.ZeroExt(32,N)+0x621745fcc03f95d4)
  elif name=='prefix_saved_error':bad=H.cell(v,F+0x9ec,4)!=ERROR
  else:bad=v.read('w0')!=(ERROR^SUCCESS)
  out.append(proof(name,v,bad))
 return out

def static_separation_obligations():
 out=[]
 for start,off,extent in IMAGE.segments:
  B,L,A,W=z3.BitVecs('FF_retired_base64 FF_retired_extent64 FF_image_read64 FF_image_width64',64);end=start+extent;maximum=resize((1<<64)-1,64)
  premises=[L!=0,W!=0,z3.ULE(B,maximum-L),z3.ULE(A,maximum-W),z3.Or(z3.ULE(B+L,start),z3.ULE(end,B)),z3.UGE(A,start),z3.ULE(A+W,end)]
  s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*premises);assert s.check()==z3.sat;s.add(z3.Not(z3.Or(z3.ULE(A+W,B),z3.ULE(B+L,A))));query=s.to_smt2();assert s.check()==z3.unsat
  out.append({'image_segment_start':hex(start),'image_segment_bytes':extent,'premises_nonvacuous':True,'result':'unsat','query':query})
 return out

def negative_controls(e):
 out=[]
 for at,kind in [(pc(0xa6605e0),'container_owner_clear'),(pc(0xa641ce8),'fallback_allocation_size'),(pc(0xa641e44),'protected_copy_xor')]:
  changed=copy.deepcopy(e);row=next(s for s in changed['source']['spans']if int(s['start'],16)<=at<int(s['end_exclusive'],16));off=at-int(row['start'],16);raw=bytearray.fromhex(row['bytes_hex']);old=bytes(raw[off:off+4]);new=((int.from_bytes(old,'little')&~31)|31).to_bytes(4,'little')if kind=='fallback_allocation_size'else bytes.fromhex('1f2003d5');raw[off:off+4]=new;row['bytes_hex']=raw.hex()
  if kind=='protected_copy_xor':v=parser_request(changed,'mode_zero');bad=copy_bad(v)
  else:v=allocation_request(changed,'mode_zero');bad=H.cell(v,v.common['C']+0x418,8)!=0 if kind=='container_owner_clear'else v.read('x0')!=z3.ZeroExt(32,v.common['N'])
  s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*v.owned(),*v.guards,*v.extra,*v.address_checks[v.fallback_check_start:]);assert s.check()==z3.sat,(kind,'premises');s.add(bad);query=s.to_smt2();assert s.check()==z3.sat,kind;out.append({'mutated_PC':hex(at),'kind':kind,'original_word_hex':old.hex(),'replacement_word_hex':new.hex(),'normal_oracle_rejected':True,'satisfiable_violation_query':query,'native_target_executed':False})
 return out

def audit(e=None):
 e=e if e is not None else json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();prefix=prefix_obligations(e);separation=static_separation_obligations();proofs,models,covered,domains,ownership=source_obligations(e);controls=negative_controls(e);prior=[]
 wanted={'userclient_message_failure_audit.json':lambda p:p.get('semantic_contract','').endswith('_both_retirements_raw_error_and_original_container_request'),'userclient_container_staging_audit.json':lambda p:p.get('label')in ['all_argument64_low32_size_three_exact_codecs','every_valid_reverse_counter_one_protected_byte_exact_destination_and_backedge','shared_parser_entry_retains_output_continuation_input_and_encoded_extent','alternate_staging_pointer_MOVK_bit_transform_only']}
 for f,choose in wanted.items():
  for p in json.loads(read(ROOT/f))['source_proofs']:
   if not choose(p):continue
   ctx=z3.Context();s=z3.SolverFor('QF_BV',ctx=ctx);s.set(timeout=120000);s.add(*z3.parse_smt2_string(p['query'],ctx=ctx));assert s.check()==z3.unsat,(f,p.get('name',p.get('label')),s.reason_unknown());prior.append({'name':p.get('name',p.get('label')),'source_audit_sha256':sha(ROOT/f),'result':'unsat'})
 reuse=[]
 for mode in MODES:
  v=models[mode+'_parser']
  for name,base in [('message',v.message),('attribute',v.attribute),('container',v.common['H']),('node',v.common['J']),('record',v.common['Z'])]:
   s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*v.owned(),*v.guards,*v.extra,v.buffer==base);assert s.check()==z3.sat,(mode,name,s.reason_unknown());reuse.append({'mode':mode,'retired_address_reused':name,'new_epoch_premises_satisfiable':True,'native_reuse_observed':False})
 totals={'new_source_queries_unsat':len(proofs),'new_semantic_contracts':len({p['semantic_contract']for p in proofs}),'prefix_and_qualified_cut_queries_unsat':len(prefix),'prior_source_queries_unsat':len(prior),'new_source_words_covered':covered,'alternate_retag_word_covered_by_prior_proof':1,'lifted_instruction_instances':sum(p['lifted_instruction_instances']for p in proofs),'composed_modes':2,'new_retirement_returns_before_fallback_per_mode':3,'new_retirement_requests_NULL_fallback_per_mode':5,'additional_prefix_cells_reconstructed':sum(len(p['source_defined_cells'])for p in e['prefix_cells']),'additional_prefix_bytes_reconstructed':sum(sum(c['size_bytes']for c in p['source_defined_cells'])for p in e['prefix_cells']),'protected_copy_bytes_per_nonnull_mode':14,'new_controller_reads_NULL_mode':len(models['mode_zero_workspace'].fallback_controllers),'new_controller_reads_nonnull_mode':len(models['mode_zero_parser'].fallback_controllers),'new_bank_applications_NULL_mode':len(models['mode_zero_workspace'].fallback_bank_reads),'new_bank_applications_nonnull_mode':len(models['mode_zero_parser'].fallback_bank_reads),'negative_source_controls':len(controls),'retired_address_reuse_SAT_checks':len(reuse),'input_content_bytes_supplied':0,'native_target_calls':0}
 totals['static_image_separation_queries_unsat']=len(separation);totals['source_entailed_extent_domain_queries_unsat']=len(domains);totals['retired_image_ownership_queries_unsat']=len(ownership)
 return {'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],'kernel_collection_sha256':e['kernel_collection_sha256'],'scope':e['scope'],'dependencies':e['dependencies'],'verified_counts':e['verified_counts'],'source_proofs':proofs,'source_entailed_extent_domain_proofs':domains,'retired_image_ownership_proofs':ownership,'prefix_and_qualified_cut_proofs':prefix,'static_image_separation_proofs':separation,'static_image_reads':{name:v.static_reads for name,v in models.items()if name.endswith(('_workspace','_parser'))},'rechecked_prior_source_proofs':prior,'negative_source_controls':controls,'retired_address_reuse_checks':reuse,'API_returns':{name:v.fallback_returns for name,v in models.items()if name.endswith(('_workspace','_parser'))},'copied_input_indices':{name:v.fallback_input_reads for name,v in models.items()if name.endswith('_parser')},'independent_totals':totals,'conditional_failure_fallback_established':True,'all_checks_pass':True,**{n:False for n in R.FALSE}}
if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
