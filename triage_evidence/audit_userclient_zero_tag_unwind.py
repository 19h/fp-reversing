#!/usr/bin/env python3
"""Compose the actual zero-tag path with source-private miss and cleanup.
O(I+A^2+query DAG) construction, O(I+A+query DAG) space; SMT is bounded.
Native callees and authenticated execution are not implemented.
"""
import copy,json
import z3
from kext_port_tools import ROOT,IMAGE,TABLE,qword
from lskd_values_symbolic import resize,mem
from verify_daemon_reader_record_payloads_publication import read,sha
import audit_userclient_fallback_metadata as P
import recover_userclient_zero_tag_unwind as R
pc=R.pc;DEC=P.DEC;SUCCESS=P.SUCCESS;MISS=0xce515bda

class Model(P.Model):
 def owners(self):return [('frame',self.sp,0x10f0),('context',self.ctx,4096),('workspace',self.src,16384),('protected_buffer',self.buffer,14),('typed_container',self.object,16),('original_input',self.input,14)]
 def owned(self):
  out=super().owned();out.extend([self.input!=0,z3.ULE(self.input,resize((1<<64)-15,64))])
  for name,a,n in self.owners()[:-1]:out.append(z3.Or(z3.ULE(self.input+14,a),z3.ULE(a+n,self.input)))
  for a,off,n in IMAGE.segments:out.append(z3.Or(z3.ULE(self.input+14,a),z3.ULE(a+n,self.input)))
  return out
 def classify(self,a,n):
  hits=[]
  for name,b,extent in self.owners():
   d=z3.simplify(a-b)
   if z3.is_bv_value(d)and d.as_long()+n<=extent:hits.append((name,d.as_long(),extent))
  assert len(hits)==1,('unclassified',hex(self.pc),str(a),n)
  assert hits[0][0]not in self.retired,('retired_access',hex(self.pc),hits[0][0]);return hits[0]
 def rom(self,a,n,kind):
  self.accesses.append({'PC':self.pc,'address':a,'size':n,'kind':kind,'write':False})
 def load(self,a,n):
  for name,(lp,rp,pp)in R.BANK_PCS.items():
   r=next(r for r in self.evidence['bank_rules']if r['name']==name)
   if self.pc==lp:
    self.left[name]=z3.Extract(7,0,a-int(r['left'],16));self.left_bytes[name]=z3.BitVec('ZU_bank_'+name+'_'+str(len(self.bank_events)),8);self.address_checks.append(a==int(r['left'],16)+z3.ZeroExt(56,self.left[name]));self.rom(a,n,'original_bank');return self.left_bytes[name]
   if self.pc==rp:
    self.address_checks.append(a==int(r['right'],16)+z3.ZeroExt(56,self.left_bytes[name]^int(r['key'],16)));self.bank_events.append(name);self.rom(a,n,'original_bank');return self.left[name]^int(r['constant'],16)
   if self.pc==pp:
    self.address_checks.append(a==int(r['slot'],16));self.rom(a,n,'original_bank_pointer');return resize(int(r['original_pointer']['target'],16),64)
  if self.pc in R.BRANCHES:
   assert n==8;js=R.BRANCHES[self.pc];self.address_checks.append(z3.Or(*[a==TABLE+8*j for j in js]));value=resize(0,64)
   for j in js:value=z3.If(a==TABLE+8*j,resize(qword(TABLE+8*j),64),value)
   self.rom(a,n,'original_pointer_table');return value
  if self.pc in R.CONTROLLERS:
   assert n==4;self.address_checks.append(a==R.CONTROLLERS[self.pc]);self.controller_events.append(hex(self.pc));self.rom(a,n,'original_controller');return z3.BitVec('ZU_controller_'+str(len(self.controller_events)),32)
  if self.pc==pc(0xa6660d4):
   j=13-len(self.restores);self.address_checks.append(a==self.buffer+j);self.classify(self.buffer+j,n);self.accesses.append({'PC':self.pc,'address':self.buffer+j,'size':n,'kind':'protected_buffer','write':False});return self.plain[j]^P.M.mask(a,resize(P.M.KEY0,64))
  if self.pc not in P.R.BRANCHES:self.classify(a,n)
  return super().load(a,n)
 def store(self,a,n,value,source_pc):
  self.classify(a,n)
  if source_pc==pc(0xa6660f4):self.restores.append({'index':13-len(self.restores),'address':a,'value':resize(value,8)})
  return super().store(a,n,value,source_pc)
 def run(self,label,end=None):
  row=next(s for s in self.e['spans']if s['label']==label);original=self.e;self.tracking=True;skip=None
  try:
   for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
    if end is not None and i.address>=end:break
    if i.address==skip:continue
    self.pc=i.address
    if i.mnemonic in ['bti','nop','braa','blraa']or i.address in R.RETAGS:
     self.visited.add(i.address);self.count+=1
     if i.mnemonic in ['braa','blraa']:
      if i.mnemonic=='blraa':self.write('x30',resize(i.address+4,64))
      self.edges.append({'PC':i.address,'target':self.read(i.reg_name(i.operands[0].reg)),'modifier':self.read(i.reg_name(i.operands[1].reg))});break
     if i.address in R.RETAGS:
      assert i.mnemonic=='b.eq'and i.operands[0].imm&((1<<64)-1)==i.address+8
      self.normal_guards.append(self.equal);self.branch_guards.append(self.equal);skip=R.RETAGS[i.address]
    else:
     self.e={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};P.M.Model.run(self,'one');self.e=original
     if i.mnemonic.startswith('b.')and self.branch_choices.get(i.address,False):break
  finally:self.e=original;self.tracking=False
  return self
 def returned(self,owner):
  self.returns.append({'retired_owner':owner,'call_PC':hex(self.edges[-1]['PC']),'nominal_return_PC':hex(self.edges[-1]['PC']+4),'ordinary_return_assumed':True,'callee_saved_SP_and_surviving_storage_preservation_assumed':True,'native_effects_established':False})
  self.retired.add(owner)
  for j in [*range(19),30]:self.seed('x'+str(j),z3.BitVec('ZU_return_'+owner+'_X'+str(j),64))
  return self

def entry(e):
 old=json.loads(read(ROOT/'userclient_fallback_metadata_checks.json'));v=P.entry(old);v.__class__=Model;v.evidence=e;v.e['spans']+=copy.deepcopy(e['source']['spans']);v.plain+=list(z3.BitVecs('ZU_byte10 ZU_byte11 ZU_byte12 ZU_byte13',8));v.input=z3.BitVec('ZU_input64',64);v.left={};v.left_bytes={};v.bank_events=[];v.controller_events=[];v.restores=[];v.returns=[];v.retired=set()
 v.seed('x5',0xa41a4d891208c018);v.seed('x6',pc(0xccc30d0));v.seed('x28',pc(0x7949dd0))
 for off,x in [(0x988,v.ctx+0x600),(0x5a8,v.ctx+0x1f8),(0xa00,pc(0x792fcc0)),(0xa20,pc(0x79391f0)),(0xa38,pc(0xccc32f8)),(0xa30,pc(0xccc30d0)),(0xa28,v.ctx),(0xa08,v.src),(0xa60,TABLE),(0xa48,pc(0x7949dd0)),(0xa40,pc(0x792fbc0)),(0xa50,pc(0x7941f60)),(0xa58,pc(0x794a0d0)),(0x670,v.ctx+0x90),(0x728,v.ctx+0x3c0),(0x888,v.src+0xbe4),(0x8f8,v.input),(0x930,pc(0x792fdc0)),(0x928,pc(0x79392f0)),(0x9f8,pc(0x7949ed0)),(0x9f0,pc(0x792fec0))]:mem(v,v.sp+off,8,x)
 mem(v,v.ctx+0x90,8,v.buffer);mem(v,v.ctx+0x3c0,8,0);mem(v,v.src+0xbe4,4,SUCCESS);mem(v,v.src+0xe10,8,14+0x621745fcc03f95d4)
 v.entry_memory=copy.copy(v.memory);v.entry_regs=copy.copy(v.regs);return v

PATH=[('caller',0xa656c44,0x8d28),('field_gate',0xa656ca0,0x6d31),('field_request',0xa662ab4,0x0ee9),('search_entry',0xa662be0,0x7250),('search_nonnull',0xa662c00,0xed3d),('search_node',0xa662c44,0xb5a8),('search_result',0xa662b00,0x7250),('search_callback',0xa656cfc,0x8d28),('field_result',0xa656f00,0x1253),('cleanup',0xa656f4c,0x082d),('destroy_request',0xa66229c,0xb23e),('destroy_bridge',0xa660468,0x0189),('destroy_entry',0xa6604a4,0xb775),('destroy_object',0xa6604fc,0x53f6),('destroy_head',0xa660534,0xad37),('container_free',0xc4ba368,0x4d6a),('container_return',0xa660614,0x1fb3),('destroy_resume',0xa665e90,0x4ed7),('aux_gate',0xa665f8c,0xd784),('primary_load',0xa665fc8,0x1aac),('copy_gate',0xa66609c,0x7924),('copy_prepare',0xa6660b4,0x8a06),('primary_free',0xc4ba84c,0x085d),('primary_return',0xa6661bc,0x2d2b),('context_free',0xc4ba368,0x4d6a),('workspace_free',0xc4b9a24,0x84ff)]
def selected(v):return P.chosen(v)+[P.tag(v)==0]
def cell(v,a,n):return P.cell(v,a,n)
def compose(e):
 v=entry(e);snap={}
 def check(label,bad):snap[label]=z3.simplify(bad)
 def step(label,target,modifier):v.run(label);P.add_edge(v,target,modifier)
 step('tag_tail',0xa63930c,0x9c55);v.decode(range(4,6));P.add_edge(v,0xa639dc0,0x1086);step('type_return',0xa637128,0x266f);step('length_bridge',0xa637138,0xf930);v.decode(range(6,10));P.add_edge(v,0xa6390b4,0xb745);step('length_extent',0xa639164,0x685a)
 v.branch_choices[pc(0xa639174)]=True;v.run('type_first_gate');v.address_checks.append(z3.BoolVal(v.direct_target==pc(0xa63a784)));v.branch_choices[pc(0xa63a78c)]=True;v.run('type_selected_gate');v.address_checks.append(z3.BoolVal(v.direct_target==pc(0xa63dc9c)))
 for label,target,mod in [('body_publish',0xa63dcd0,0xa174),('metadata_return',0xa6423c0,0xdfc5),('metadata_outcome_gate',0xa6423f4,0xc9dc),('record_kind_gate',0xa6421b0,0x5ab2),('success',0xa660ac8,0x8ba3),('publish',0xa660ae0,0xcd46),('resume',0xa656c08,0x481b)]:step(label,target,mod)
 check('actual_private_success_publishes_empty_T',z3.Or(cell(v,v.ctx+0x600,8)!=v.object,cell(v,v.object,8)!=0,cell(v,v.object+8,8)!=0,v.read('w23')!=SUCCESS,cell(v,v.sp+0xa80,8)!=10+z3.ZeroExt(32,P.length(v))))
 for label,target,mod in PATH:
  if label=='container_return':v.returned('typed_container')
  if label=='primary_return':v.returned('protected_buffer')
  if label=='workspace_free':v.returned('context')
  step(label,target,mod)
  if label=='field_request':check('command_tag_request_45e5918e',z3.Or(v.read('w9')!=0x45e5918e,v.read('x22')!=v.object,v.read('x10')!=v.ctx+0x1f8))
  if label=='search_node':check('empty_head_selects_raw_miss',z3.Or(v.read('w23')!=MISS,cell(v,v.object,8)!=0))
  if label=='search_callback':check('empty_lookup_returns_zero_result_and_miss',z3.Or(v.read('w23')!=MISS,cell(v,v.ctx+0x1f8,8)!=0))
  if label=='cleanup':check('caller_saves_miss_and_selects_destructor_callback',z3.Or(cell(v,v.src+0xde4,4)!=MISS,v.read('w24')!=0x1a))
  if label=='container_free':check('pending_T16_typed_retirement',z3.Or(v.read('x0')!=pc(0x847bde0),v.read('x1')!=v.object,v.read('x30')!=pc(0xa6605c8),v.read('sp')!=v.sp))
  if label=='container_return':check('after_T_return_output_is_cleared',z3.Or(cell(v,v.ctx+0x600,8)!=0,cell(v,v.src+0xde4,4)!=MISS))
  if label=='aux_gate':check('null_auxiliary_selects_primary_restoration',cell(v,v.ctx+0x3c0,8)!=0)
  if label=='copy_prepare':
   for j in range(13,-1,-1):step('copy_step',0xa6660b4 if j else 0xa666118,0x8a06)
   check('all_14_original_observations_restored_in_reverse',z3.Or(*[z3.Or(r['address']!=v.input+r['index'],r['value']!=v.plain[r['index']])for r in v.restores],cell(v,v.sp+0xa80,8)!=10+z3.ZeroExt(32,P.length(v))))
  if label=='primary_free':check('pending_B14_data_retirement_preserves_raw_miss',z3.Or(v.read('x0')!=v.buffer,v.read('x1')!=14,v.read('x30')!=pc(0xa66618c),v.read('w19')!=MISS))
  if label=='context_free':check('pending_C4096_typed_retirement_preserves_raw_miss',z3.Or(v.read('x0')!=pc(0x847ba60),v.read('x1')!=v.ctx,v.read('x30')!=pc(0xa666264),v.read('w26')!=MISS))
  if label=='workspace_free':check('pending_S16384_aligned_retirement_preserves_raw_miss',z3.Or(v.read('x0')!=v.src,v.read('x1')!=16384,v.read('x30')!=pc(0xa6662b4),v.read('w26')!=MISS))
 assert [r['index']for r in v.restores]==list(range(13,-1,-1))and len(v.returns)==3
 return v,snap

def prefix_proof(e):
 from audit_userclient_early_header import Lift
 from audit_userclient_entry_execution import proof
 v=Lift({'spans':[e['prefix_source']]});F,C=z3.BitVecs('ZU_prefix_F64 ZU_prefix_C64',64);v.seed('sp',F);v.seed('x2',C);v.run('command_result_alias');return proof('original_command_result_alias',v,cell(v,F+0x5a8,8)!=C+0x1f8)

def projection(e,v):
 root=entry(e);regs=sorted(v.live_regs);cells=v.live_cells;proofs=[];domains=[];admissions=[];receipts=[];normal={z3.simplify(g).sexpr():g for g in v.normal_guards}
 for mode in P.Parent.MODES:
  actual=P.Parent.tag_result(json.loads(read(ROOT/'userclient_fallback_parser_checks.json')),mode);c=actual.common
  for off,value in [(0x890,c['C']+0x3d8),(0x5a8,c['C']+0x1f8)]:
   key=(z3.simplify(c['F']+off).sexpr(),8);assert key not in actual.memory;mem(actual,c['F']+off,8,value)
  premises=actual.owned()+actual.guards+actual.extra;domains.append(P.solve(mode+'_entailed_N14_L4',premises,z3.Or(c['N']!=14,c['L']!=4)));premises+=[c['N']==14,c['L']==4]
  pairs=[(root.sp,c['F']),(root.ctx,c['C']),(root.src,c['S']),(root.buffer,actual.buffer),(root.object,actual.typed),(root.input,actual.original_input)]+[(root.plain[j],actual.input_bytes[j])for j in range(14)]+[(z3.BitVec('TI_initial_X'+str(j),64),actual.read('x'+str(j)))for j in range(31)]
  def mapped(x):return z3.simplify(z3.substitute(x,*pairs))
  items=[('reg_'+r,mapped(root.read(r))!=actual.read(r))for r in regs]
  items += [('cell_'+str(j),P.Parent.H.cell(actual,mapped(x['address']),x['size'])!=mapped(root.entry_memory[k]))for j,(k,x)in enumerate(cells.items())]
  for off,n in [(0x600,8),(0x228,8)]:items.append(('side_context_'+hex(off),P.Parent.H.cell(actual,c['C']+off,n)!=mapped(cell(root,root.ctx+off,n))))
  for off in [0,8]:items.append(('side_empty_container_'+str(off),P.Parent.H.cell(actual,actual.typed+off,8)!=0))
  for j in range(14):
   r=next(r for r in actual.fallback_copy_stores if r['index']==j);items.append(('protected_byte_'+str(j),z3.Or(r['address']!=actual.buffer+j,r['value']!=mapped(root.plain[j]^P.M.mask(root.buffer+j,resize(P.M.KEY0,64))))))
  items.append(('weaker_initial_ownership',z3.Or(*[z3.Not(mapped(q))for q in root.owned()])))
  items.append(('entailed_normal_pointer_guards',z3.Or(*[z3.Not(mapped(g))for g in normal.values()])))
  for label,bad in items:proofs.append(P.solve(mode+'_projection_'+label,premises,z3.simplify(z3.substitute(bad,(c['N'],resize(14,32)),(c['L'],resize(4,32))))))
  for n in range(5):
   s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*premises,*[mapped(q)for q in selected(root)],mapped(P.length(root))==n);q=s.to_smt2();assert s.check()==z3.sat,(mode,n,s.reason_unknown());admissions.append({'name':mode+'_zero_tag_body_length_'+str(n),'result':'sat','query':q,'native_reachability_established':False});print('admitted '+mode+' length '+str(n),flush=True)
  receipts.append({'mode':mode,'entry_PC':hex(pc(0xa638dc8)),'live_register_views':regs,'live_saved_cells':[{'first_read_PC':hex(x['PC']),'address_expression':x['address'].sexpr(),'size_bytes':x['size']}for x in cells.values()],'source_written_protected_bytes':14,'original_prefix_aliases_reconstructed':[hex(0x890),hex(0x5a8)],'ordinary_surviving_storage_preservation_assumed':True})
 return proofs,domains,admissions,receipts,len(regs),len(cells),len(normal)

def footprint(v,proofs):
 cells={};static=set();owners=v.owners()
 for r in v.accesses:
  if r['kind'].startswith('original_'):
   static.add(hex(r['PC']));candidates=[]
   if r['PC']in R.BRANCHES or r['PC']in P.R.BRANCHES:candidates=[(TABLE+8*j,8)for j in (R.BRANCHES|P.R.BRANCHES)[r['PC']]]
   elif r['PC']in R.CONTROLLERS:candidates=[(R.CONTROLLERS[r['PC']],4)]
   else:
    for name,(lp,rp,pp)in R.BANK_PCS.items():
     rule=next(x for x in v.evidence['bank_rules']if x['name']==name)
     if r['PC']==lp:candidates=[(int(rule['left'],16),256)]
     if r['PC']==rp:candidates=[(int(rule['right'],16),256)]
     if r['PC']==pp:candidates=[(int(rule['slot'],16),8)]
   assert candidates
   for a,n in candidates:assert any(b<=a and a+n<=b+m for b,off,m in IMAGE.segments)
   continue
  hits=[]
  for name,b,n in owners:
   d=z3.simplify(r['address']-b)
   if z3.is_bv_value(d)and d.as_long()+r['size']<=n:hits.append((name,d.as_long(),n))
  assert len(hits)==1;name,off,n=hits[0];key=(name,off,r['size']);x=cells.setdefault(key,{'owner':name,'offset_bytes':off,'size_bytes':r['size'],'source_PCs':set(),'read':False,'written':False});x['source_PCs'].add(hex(r['PC']));x['read']|=not r['write'];x['written']|=r['write']
  assert not r['write']or name in ['frame','context','workspace','original_input']
 rows=list(cells.values());same=0
 for j,a in enumerate(rows):
  for b in rows[j+1:]:
   if a['owner']==b['owner']:assert a['offset_bytes']+a['size_bytes']<=b['offset_bytes']or b['offset_bytes']+b['size_bytes']<=a['offset_bytes'];same+=1
 A,J,W=z3.BitVecs('ZU_interval_A64 ZU_interval_J64 ZU_interval_W64',64)
 for n in sorted({n for name,b,n in owners}):proofs.append(P.solve('generic_owned_interval_'+str(n),[A!=0,z3.ULE(A,resize((1<<64)-1-n,64)),W!=0,z3.ULE(W,n),z3.ULE(J,resize(n,64)-W)],z3.Or(z3.ULT(A+J,A),z3.UGT(A+J+W,A+n),z3.ULT(A+J+W,A+J))))
 # Reuse and re-solve the previously certified owner-separation lemma.
 old=json.loads(read(ROOT/'userclient_fallback_metadata_audit.json'));p=next(p for p in old['source_proofs']if p['name']=='generic_disjoint_owner_subranges_remain_disjoint');s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*z3.parse_smt2_string(p['query']));assert s.check()==z3.unsat;proofs.append(p)
 return {'cells':[dict(r,source_PCs=sorted(r['source_PCs']))for r in sorted(rows,key=lambda x:(x['owner'],x['offset_bytes'],x['size_bytes']))],'same_owner_disjoint_integer_pairs':same,'static_read_PCs':sorted(static),'all_accesses_classified':True,'retired_owner_accesses':0,'retirement_order':['typed_container','protected_buffer','context'],'workspace_retirement_pending':True,'original_input_write_indices':list(range(13,-1,-1))}

def controls(e):
 out=[]
 for at,name,contract in [(0xa656ca8,'command_tag','command_tag_request_45e5918e'),(0xa6605e0,'output_clear','after_T_return_output_is_cleared'),(0xa6660f0,'restoration_xor','all_14_original_observations_restored_in_reverse')]:
  x=copy.deepcopy(e);a=pc(at);r=next(s for s in x['source']['spans']if int(s['start'],16)<=a<int(s['end_exclusive'],16));raw=bytearray.fromhex(r['bytes_hex']);off=a-int(r['start'],16);old=bytes(raw[off:off+4]);raw[off:off+4]=bytes.fromhex('1f2003d5');r['bytes_hex']=raw.hex();v,snap=compose(x);s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*v.owned(),*v.branch_guards,*selected(v),*v.address_checks);assert s.check()==z3.sat,(name,'premises',s.reason_unknown());s.add(snap[contract]);q=s.to_smt2();assert s.check()==z3.sat,(name,s.reason_unknown());out.append({'kind':name,'mutated_PC':hex(a),'original_word_hex':old.hex(),'replacement_word_hex':'1f2003d5','normal_oracle_rejected':True,'satisfiable_violation_query':q,'native_target_executed':False});print('rejected mutation '+name,flush=True)
 return out

def audit(e=None):
 e=e if e is not None else json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();prefix=prefix_proof(e);v,snap=compose(e);proofs=[]
 premises=v.owned()+v.branch_guards+selected(v)
 for name,bad in snap.items():proofs.append(P.solve(name,premises,z3.Or(*[z3.Not(q)for q in v.address_checks],bad)))
 ledger=footprint(v,proofs);projections,domains,admissions,interfaces,nregs,ncells,nguards=projection(e,v);negative=controls(e);prior=[]
 old=json.loads(read(ROOT/'userclient_fallback_metadata_audit.json'))
 for field in ['source_proofs','projection_proofs','source_entailed_domain_proofs','prefix_proofs']:
  for p in old[field]:
   ctx=z3.Context();s=z3.SolverFor('QF_BV',ctx=ctx);s.set(timeout=120000);s.add(*z3.parse_smt2_string(p['query'],ctx=ctx));assert s.check()==z3.unsat,(p['name'],s.reason_unknown());prior.append({'name':p['name'],'result':'unsat','source_audit_sha256':sha(ROOT/'userclient_fallback_metadata_audit.json')});print('rechecked predecessor '+str(len(prior))+' '+p['name'],flush=True)
 carried=json.loads(read(ROOT/'userclient_fallback_metadata_checks.json'));captured={int(i['pc'],16)for s in carried['source']['spans']+e['source']['spans']for i in s['instructions']};assert captured-v.visited==set(R.RETAGS.values())and not v.visited-captured
 assert v.bank_events==['search_callback_value','container_free','container_descriptor','primary_free','context_free','context_descriptor','workspace_free']and set(v.controller_events)==set(map(hex,R.CONTROLLERS))
 totals={'new_source_queries_unsat':len(proofs),'semantic_contracts':len(snap),'projection_queries_unsat':len(projections),'source_entailed_domain_queries_unsat':len(domains),'actual_cut_admission_SAT_queries':len(admissions),'prefix_queries_unsat':1,'prior_source_queries_unsat':len(prior),'composed_source_words':len(v.visited),'additional_source_words':len(v.visited)-304,'alternate_retag_words':len(R.RETAGS),'instruction_instances':v.count,'negative_source_controls':len(negative),'composed_modes':2,'live_register_views':nregs,'live_saved_cells':ncells,'entailed_normal_pointer_guards':nguards,'additional_prefix_cells':30,'additional_prefix_bytes':240,'restored_bytes':len(v.restores),'ordinary_return_premises':len(v.returns),'retirement_request_boundaries':4,'native_target_calls':0,'input_content_bytes_supplied':0}
 return {'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],'kernel_collection_sha256':e['kernel_collection_sha256'],'scope':e['scope'],'dependencies':e['dependencies'],'verified_counts':e['verified_counts'],'source_proofs':proofs,'projection_proofs':projections,'source_entailed_domain_proofs':domains,'actual_cut_admission_checks':admissions,'prefix_proofs':[prefix],'negative_source_controls':negative,'rechecked_prior_source_proofs':prior,'live_interfaces':interfaces,'memory_footprint':ledger,'ordinary_return_premises':v.returns,'bank_execution_order':v.bank_events,'controller_read_PCs':v.controller_events,'proved_pcs':sorted(map(hex,v.visited)),'source_edges':[{'source_PC':hex(r['PC']),'target_expression':r['target'].sexpr(),'modifier_expression':r['modifier'].sexpr()}for r in v.edges],'independent_totals':totals,'all_checks_pass':True,'conditional_zero_tag_unwind_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
