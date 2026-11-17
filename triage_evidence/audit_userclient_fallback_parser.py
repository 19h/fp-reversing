#!/usr/bin/env python3
"""Compose source allocation outcomes and protected-byte round trips.
O(I+256R+C*W+query DAG) construction/space; SMT cost bounded separately.
"""
import copy,json
import z3
from kext_port_tools import ROOT,IMAGE,qword
from lskd_values_symbolic import resize,mem
from verify_daemon_reader_record_payloads_publication import read,sha
import audit_userclient_failure_fallback as Parent
import recover_userclient_fallback_parser as R
H=Parent.H;DEC=Parent.DEC;Publication=Parent.Publication;SUCCESS=Parent.SUCCESS;ERROR=Parent.ERROR;pc=R.pc
MODES=Parent.MODES
class Model(Parent.Model):
 def __init__(self,e,mode,nonnull):
  v=Parent.parser_request(json.loads(read(ROOT/'userclient_failure_fallback_checks.json')),mode);self.__dict__.update(v.__dict__);self.e=copy.deepcopy(self.e);self.e['source']['spans']+=copy.deepcopy(e['source']['spans']);self.new_receipt=e;self.new_check_start=len(self.address_checks);self.new_visited=set();self.new_reads=[];self.restore_stores=[];self.new_controllers=[];self.new_bank_reads=[];self.new_left={};self.new_left_bytes={};self.typed=z3.BitVec('FP_typed64',64);self.typed_owned=nonnull;self.new_root_equalities=[];self.new_static_start=len(self.static_reads)
  at=self.common['F']+0x728;want=self.common['C']+0x3c0;key=(z3.simplify(at).sexpr(),8)
  if key in self.memory:self.new_root_equalities.append(self.memory[key]==want)
  else:mem(self,at,8,want)
  if not nonnull:self.extra.append(self.typed==0)
  self.address_checks.extend([z3.Not(Publication.edge(self,pc(0xc4ba154),0xd0c8)),self.read('x0')==pc(0x847b620),self.edges[-1]['pc']==pc(0xa642098),self.read('x30')==pc(0xa64209c),self.read('sp')==self.common['F']])
  for j in list(range(19))+[30]:self.seed('x'+str(j),z3.BitVec('FP_alloc_volatile_'+str(j),64))
  self.seed('x0',self.typed)
 def owned(self):
  out=super().owned()
  if not self.typed_owned:return out
  c=self.common;T=self.typed;n=resize(16,64);out.extend([T!=0,z3.ULE(T,resize((1<<64)-17,64))]);live=[(c['F']-0x70,resize(0x1160,64)),(c['C'],resize(4096,64)),(c['S'],resize(16384,64)),(self.holder,resize(16,64)),(self.entries,24*z3.ZeroExt(32,self.capacity)),(self.payload,resize(56,64)),(self.original_input,resize(14,64)),(self.buffer,resize(14,64))]+[(resize(a,64),resize(m,64))for a,off,m in IMAGE.segments]
  out.extend(z3.Or(z3.ULE(T+n,b),z3.ULE(b+m,T))for b,m in live);return out
 def load(self,a,n):
  if hasattr(self,'new_receipt'):
   if self.pc in R.CONTROLLERS:
    at=R.CONTROLLERS[self.pc];assert n==4;self.address_checks.append(a==at);self.static_read(a,n,at,4);self.new_controllers.append(hex(self.pc));return z3.BitVec('FP_controller_'+str(len(self.new_controllers)),32)
   for r in self.new_receipt['bank_rules']:
    key=r['left_PC']
    if self.pc==int(key,16):
     assert n==1;L=int(r['left'],16);self.new_left[key]=z3.Extract(7,0,a-L);self.new_left_bytes[key]=z3.BitVec('FP_bank_'+str(len(self.new_bank_reads)),8);self.address_checks.append(a==L+z3.ZeroExt(56,self.new_left[key]));self.static_read(a,n,L,256);return self.new_left_bytes[key]
    if self.pc==int(r['right_PC'],16):
     assert n==1;L=int(r['right'],16);self.address_checks.append(a==L+z3.ZeroExt(56,self.new_left_bytes[key]^int(r['key'],16)));self.static_read(a,n,L,256);self.new_bank_reads.append(hex(self.pc));return self.new_left[key]^int(r['constant'],16)
   if self.pc in R.POINTERS:
    aa=R.POINTERS[self.pc];assert n==8;self.address_checks.append(z3.Or(*[a==at for at in aa]));self.static_read(a,n,min(aa),max(aa)-min(aa)+8);value=resize(0,64)
    for at in aa:value=z3.If(a==at,resize(qword(at),64),value)
    return value
   header=[pc(a)for a in [0xa637158,0xa637190,0xa6371d4,0xa637214]]
   if self.pc==pc(0xa6660d4)or self.pc in header:
    j=13-len(self.new_reads)if self.pc==pc(0xa6660d4)else header.index(self.pc);assert n==1 and 0<=j<14;self.address_checks.append(a==self.buffer+j);row=next(r for r in self.fallback_copy_stores if r['index']==j);self.new_reads.append({'source_PC':hex(self.pc),'buffer_index':j,'live_new_buffer_epoch':True});return row['value']
  return super().load(a,n)
 def store(self,a,n,value,source_pc):
  if hasattr(self,'new_receipt'):
   row=next((s for s in self.new_receipt['source']['spans']if int(s['start'],16)<=source_pc<int(s['end_exclusive'],16)),None)
   if row is not None:
    if source_pc==pc(0xa642100):
     self.address_checks.append(z3.Or(a==self.typed,a==self.typed+8));retired=self.retired;self.retired=[]
     try:return super().store(a,n,value,source_pc)
     finally:self.retired=retired
    if source_pc==pc(0xa6660f4):
     j=13-len(self.restore_stores);self.address_checks.append(a==self.original_input+j);self.restore_stores.append({'index':j,'address':a,'value':resize(value,8)})
    else:
     off=source_pc-int(row['start'],16);i=next(DEC.disasm(bytes.fromhex(row['bytes_hex'])[off:off+4],source_pc));o=i.operands[-1];base=i.reg_name(o.mem.base);roots={'x2':self.common['C'],'x4':self.common['S'],'sp':self.common['F']};self.address_checks.append(a==roots[base]+o.mem.disp)
  return super().store(a,n,value,source_pc)
 def run(self,name,take=None):
  if name not in R.SPANS:return super().run(name,take)
  original=self.e;row=next(s for s in original['source']['spans']if s['label']==name);skip=None
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if i.address==skip:continue
   self.pc=i.address;self.new_visited.add(i.address)
   if i.mnemonic.startswith('b.'):
    assert i.address in R.RETAGS and i.mnemonic=='b.eq'and i.operands[0].imm&((1<<64)-1)==i.address+8;self.guards.append(self.condition('eq'));skip=R.RETAGS[i.address];self.count+=1
   else:
    self.e={'source':{'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]}};super().run('one');self.e=original
  return self

def label(a):return 'fp_'+format(a,'x')
def follow(v,a,mod):v.address_checks.append(z3.Not(Publication.edge(v,pc(a),mod)));return v.run(label(a))
def returned(e,mode,nonnull):return Model(e,mode,nonnull).run(label(0xa64209c))
def null_caller(e,mode):
 v=returned(e,mode,False)
 for a,m in [(0xa660ae0,0xcd46),(0xa656c08,0x481b),(0xa65f358,0x8d28),(0xa656f00,0xf918),(0xa665e90,0x82d),(0xa665f8c,0xd784),(0xa665fc8,0x1aac),(0xa66609c,0x7924)]:follow(v,a,m)
 return v
def restored(e,mode):
 v=null_caller(e,mode)
 for j in range(14):follow(v,0xa6660b4,0x8a06)
 return follow(v,0xa666118,0x8a06)
def initialized(e,mode):return follow(returned(e,mode,True),0xa6420f8,0xcd46)
def header_request(e,mode):
 v=initialized(e,mode)
 for a,m in [(0xa642138,0xeba0),(0xa6421dc,0xf25c),(0xa642248,0x55ab),(0xa642330,0x55ab),(0xa656ef0,0x5e04)]:follow(v,a,m)
 return v
def tag_result(e,mode):
 v=header_request(e,mode);follow(v,0xa637138,0xf930);follow(v,0xa638db8,0xb745);return v

def field32(v):return z3.Concat(*v.input_bytes[:4])
def bad(v,kind):
 c=v.common
 if kind=='null_caller':return z3.Or(*[z3.Not(q)for q in v.new_root_equalities],H.cell(v,c['C']+0x228,8)!=0,H.cell(v,c['C']+0x600,8)!=0,H.cell(v,c['S']+0xde4,4)!=ERROR,v.read('x0')!=v.original_input,v.read('x8')!=v.buffer,v.read('x10')!=14,v.read('w19')!=ERROR,Publication.edge(v,pc(0xa6660b4),0x8a06))
 if kind=='restored':return z3.Or(*[r['value']!=v.input_bytes[r['index']]for r in v.restore_stores],v.read('x0')!=v.buffer,v.read('x1')!=14,v.read('w19')!=ERROR,Publication.edge(v,pc(0xc4ba84c),0x85d))
 if kind=='initialized':return z3.Or(H.cell(v,c['C']+0x228,8)!=v.typed,H.cell(v,v.typed,8)!=0,H.cell(v,v.typed+8,8)!=0,H.cell(v,c['C']+0x600,8)!=0,v.read('x26')!=0x02e859d27e491464,Publication.edge(v,pc(0xa642138),0xeba0))
 if kind=='header_request':return z3.Or(H.cell(v,c['C']+0x3d8,8)!=v.buffer,H.cell(v,c['F']+0xbd8,8)!=0,H.cell(v,c['C']+0x600,8)!=0,v.read('x8')!=v.buffer,v.read('x10')+v.read('x1')!=0,Publication.edge(v,pc(0xa637138),0xf930))
 if kind=='tag_result':return z3.Or(H.cell(v,c['S']+0xa18,4)!=(field32(v)^SUCCESS),H.cell(v,c['C']+0x600,8)!=0,H.cell(v,v.typed,8)!=0,H.cell(v,v.typed+8,8)!=0)
 raise AssertionError(kind)
def source_obligations(e):
 out=[];domains=[];ownership=[];visited=set();models={}
 for mode in MODES:
  for kind,factory in [('null_caller',null_caller),('restored',restored),('initialized',initialized),('header_request',header_request),('tag_result',tag_result)]:
   v=factory(e,mode);name=mode+'_'+kind;premises=v.owned()+v.guards+v.extra;s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*premises);assert s.check()==z3.sat,(name,'premises',s.reason_unknown());s.push();s.add(z3.Or(v.common['N']!=14,v.common['L']!=4));q=s.to_smt2();assert s.check()==z3.unsat,(name,'domain');s.pop();domains.append({'name':name,'result':'unsat','premises_nonvacuous':True,'query':q})
   invalid=[]
   for base,extent in v.retired:
    invalid.append(z3.UGT(base,resize((1<<64)-1-extent,64)))
    for a,off,m in IMAGE.segments:invalid.append(z3.Not(z3.Or(z3.ULE(base+extent,a),z3.ULE(a+m,base))))
   os=z3.SolverFor('QF_BV');os.set(timeout=60000);os.add(*v.owned(),*v.extra,z3.simplify(z3.substitute(z3.Or(*invalid),(v.common['L'],resize(4,32)))));q=os.to_smt2();assert os.check()==z3.unsat,(name,'ownership');ownership.append({'name':name,'result':'unsat','premises_nonvacuous':True,'query':q})
   b=z3.simplify(z3.substitute(z3.Or(bad(v,kind),*[z3.Not(q)for q in v.address_checks[v.new_check_start:]]),(v.common['N'],resize(14,32)),(v.common['L'],resize(4,32))));terms=list(b.children())if z3.is_or(b)else[b];parts=[terms[j:j+2]for j in range(0,len(terms),2)]
   for j,terms in enumerate(parts):
    s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*premises,z3.Or(*terms));q=s.to_smt2();r=s.check();assert r==z3.unsat,(name,j,str(r),s.reason_unknown(),s.model()if r==z3.sat else'');out.append({'name':name+'_part_'+str(j+1),'semantic_contract':name,'counterexample_partition':j+1,'counterexample_partitions':len(parts),'result':'unsat','premises_nonvacuous':True,'query':q});print('proved '+name+' '+str(j+1)+'/'+str(len(parts)),flush=True)
   visited.update(v.new_visited);models[name]=v
 captured={int(i['pc'],16)for s in e['source']['spans']for i in s['instructions']};assert captured-visited==set(R.RETAGS.values()),captured-visited
 return out,domains,ownership,models,len(visited&captured)
def prefix_proof(e):
 from audit_userclient_early_header import Lift
 from audit_userclient_entry_execution import proof
 v=Lift({'spans':[e['prefix_source']]});F,C=z3.BitVecs('FP_prefix_F64 FP_prefix_C64',64);v.seed('sp',F);v.seed('x2',C);v.run('prefix_restore_owner');return proof('original_restore_owner_cell',v,H.cell(v,F+0x728,8)!=C+0x3c0)
def controls(e):
 out=[]
 for at,kind in [(pc(0xa6420e4),'saved_error_reload'),(pc(0xa6660f0),'restore_xor'),(pc(0xa637174),'tag_decode_xor')]:
  x=copy.deepcopy(e);row=next(s for s in x['source']['spans']if int(s['start'],16)<=at<int(s['end_exclusive'],16));off=at-int(row['start'],16);raw=bytearray.fromhex(row['bytes_hex']);old=bytes(raw[off:off+4]);raw[off:off+4]=bytes.fromhex('1f2003d5');row['bytes_hex']=raw.hex()
  if kind=='saved_error_reload':v=null_caller(x,'mode_zero');b=v.read('w19')!=ERROR
  elif kind=='restore_xor':v=restored(x,'mode_zero');b=z3.Or(*[r['value']!=v.input_bytes[r['index']]for r in v.restore_stores])
  else:v=tag_result(x,'mode_zero');b=H.cell(v,v.common['S']+0xa18,4)!=(field32(v)^SUCCESS)
  s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*v.owned(),*v.guards,*v.extra,*v.address_checks[v.new_check_start:]);assert s.check()==z3.sat,(kind,'premises');s.add(b);q=s.to_smt2();assert s.check()==z3.sat,kind;out.append({'mutated_PC':hex(at),'kind':kind,'original_word_hex':old.hex(),'replacement_word_hex':'1f2003d5','normal_oracle_rejected':True,'satisfiable_violation_query':q,'native_target_executed':False})
 return out
def audit(e=None):
 e=e if e is not None else json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();prefix=prefix_proof(e);proofs,domains,ownership,models,covered=source_obligations(e);negative=controls(e);prior=[]
 old=json.loads(read(ROOT/'userclient_failure_fallback_audit.json'))
 for p in old['source_proofs']:
  if not p['semantic_contract'].endswith('_parser_request'):continue
  ctx=z3.Context();s=z3.SolverFor('QF_BV',ctx=ctx);s.set(timeout=120000);s.add(*z3.parse_smt2_string(p['query'],ctx=ctx));assert s.check()==z3.unsat,(p['name'],s.reason_unknown());prior.append({'name':p['name'],'result':'unsat','source_audit_sha256':sha(ROOT/'userclient_failure_fallback_audit.json')})
 separation=Parent.static_separation_obligations();totals={'new_source_queries_unsat':len(proofs),'semantic_contracts':len(models),'source_entailed_domain_queries_unsat':len(domains),'retired_image_ownership_queries_unsat':len(ownership),'static_separation_queries_unsat':len(separation),'prefix_queries_unsat':1,'prior_source_queries_unsat':len(prior),'new_source_words_covered':covered,'alternate_retag_words':5,'negative_source_controls':len(negative),'composed_modes':2,'restored_bytes_per_NULL_mode':14,'header_bytes_per_nonnull_mode':4,'additional_prefix_cells':30,'additional_prefix_bytes':240,'native_target_calls':0,'input_content_bytes_supplied':0}
 return {'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],'kernel_collection_sha256':e['kernel_collection_sha256'],'scope':e['scope'],'dependencies':e['dependencies'],'verified_counts':e['verified_counts'],'source_proofs':proofs,'source_entailed_domain_proofs':domains,'retired_image_ownership_proofs':ownership,'static_separation_proofs':separation,'prefix_proofs':[prefix],'negative_source_controls':negative,'rechecked_prior_source_proofs':prior,'new_buffer_reads':{n:v.new_reads for n,v in models.items()if n.endswith(('restored','tag_result'))},'restored_indices':{n:[r['index']for r in v.restore_stores]for n,v in models.items()if n.endswith('restored')},'new_static_reads':{n:v.static_reads[v.new_static_start:]for n,v in models.items()},'allocation_return':{'source_PC':hex(pc(0xa642098)),'return_PC':hex(pc(0xa64209c)),'volatile_registers_havoced':'X0..X18,X30','ordinary_callee_saved_SP_and_surviving_storage_preservation_assumed':True,'native_target_executed':False},'independent_totals':totals,'all_checks_pass':True,'conditional_fallback_parser_established':True,**{n:False for n in R.FALSE}}
if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
