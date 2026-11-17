#!/usr/bin/env python3
"""Actual staged-input to first-node construction and publication contracts.
O(I+A+query DAG) lifting/space; finite L=0..4, bounded SMT separately.
"""
import copy,json
import z3
from kext_port_tools import ROOT,IMAGE,TABLE,qword
from lskd_values_symbolic import resize,mem
from verify_daemon_reader_record_payloads_publication import read,sha
import audit_userclient_fallback_metadata as P
import recover_userclient_nonzero_tag_record as R
pc=R.pc;DEC=P.DEC;SUCCESS=P.SUCCESS;MISS=0xce515bda
FROOTS={0x350:('C',0x628),0x570:('literal',0x87b),0x60c:('literal',0x3f22ccfb),0x858:('literal',pc(0x847c020)),0xa08:('S',0),0xa28:('C',0),0xa30:('literal',pc(0xccc30d0)),0xa38:('literal',pc(0xccc32f8)),0xa40:('literal',pc(0x792fbc0)),0xa48:('literal',pc(0x7949dd0)),0xa50:('literal',pc(0x7941f60)),0xa58:('literal',pc(0x794a0d0)),0xa60:('literal',TABLE),0x9ec:('literal',0xce515bb2),0xa00:('literal',pc(0x792fcc0)),0xa20:('literal',pc(0x79391f0))}
class Model(P.Model):
 def norm(self,q):
  # Under the explicit BE32 length=n premise, these four byte equalities
  # follow uniquely. The audit certifies them before consuming any profile.
  pairs=[(self.plain[6+j],resize((self.body_length>>(24-8*j))&255,8))for j in range(4)]
  return z3.simplify(z3.substitute(q,*pairs))
 def write(self,r,value):return super().write(r,self.norm(resize(value,32 if r.startswith('w')else 64)))
 def owners(self):
  out=[('frame',self.sp,0x10f0),('context',self.ctx,4096),('workspace',self.src,16384),('protected_input',self.buffer,14),('container',self.object,16),('original_input',self.input,14)]
  if self.with_new_node:out.append(('new_node',self.J,32))
  if self.with_record_buffer:out.append(('record_buffer',self.Z,10+self.body_length))
  return out
 def owned(self):
  spans=self.owners();out=[(self.sp&15)==0]
  for j,(_,a,n)in enumerate(spans):
   out.extend([a!=0,z3.ULE(a,resize((1<<64)-1-n,64))])
   for name,b,m in spans[j+1:]:out.append(z3.Or(z3.ULE(a+n,b),z3.ULE(b+m,a)))
   for b,off,m in IMAGE.segments:out.append(z3.Or(z3.ULE(a+n,b),z3.ULE(b+m,a)))
  return out
 def classify(self,a,n):
  a=self.norm(a);hits=[]
  for name,b,extent in self.owners():
   d=z3.simplify(a-b)
   if z3.is_bv_value(d)and d.as_long()+n<=extent:hits.append((name,d.as_long(),extent))
  assert len(hits)==1,('unclassified',hex(self.pc),str(a),n);return hits[0]
 def rom(self,a,n,kind):self.accesses.append({'PC':self.pc,'address':a,'size':n,'kind':kind,'write':False})
 def load(self,a,n):
  a=self.norm(a)
  for name,(lp,rp,pp)in R.BANK_PCS.items():
   r=next(r for r in self.evidence['bank_rules']if r['name']==name)
   if self.pc==lp:
    assert n==1;self.left[name]=z3.Extract(7,0,a-int(r['left'],16));self.bankbyte[name]=z3.BitVec('NZ_bank_'+name+'_'+str(len(self.bank_events)),8);self.address_checks.append(a==int(r['left'],16)+z3.ZeroExt(56,self.left[name]));self.rom(a,n,'original_bank');return self.bankbyte[name]
   if self.pc==rp:
    assert n==1;self.address_checks.append(a==int(r['right'],16)+z3.ZeroExt(56,self.bankbyte[name]^int(r['key'],16)));self.bank_events.append(name);self.rom(a,n,'original_bank');return self.left[name]^int(r['constant'],16)
   if self.pc==pp:
    assert n==8;self.address_checks.append(a==int(r['slot'],16));self.rom(a,n,'original_bank_pointer');return resize(int(r['original_pointer']['target'],16),64)
  if self.pc in R.BRANCHES:
   assert n==8;indices=R.BRANCHES[self.pc];self.address_checks.append(z3.Or(*[a==TABLE+8*j for j in indices]));out=resize(0,64)
   for j in indices:out=z3.If(a==TABLE+8*j,resize(qword(TABLE+8*j),64),out)
   self.rom(a,n,'original_pointer_table');return out
  if n==4 and z3.is_bv_value(a)and a.as_long()in [pc(0xccc30d0),pc(0xccc32f8)]:
   self.rom(a,n,'original_controller');return z3.BitVec('NZ_controller_'+str(self.count),32)
  if self.pc==pc(0xa655e58):
   assert n==1;d=z3.simplify(a-self.buffer);assert z3.is_bv_value(d)and 10<=d.as_long()<10+self.body_length,('body_read',self.body_length,str(a),str(d),str(self.read('x10')));j=d.as_long();self.classify(a,n);self.accesses.append({'PC':self.pc,'address':a,'size':n,'kind':'protected_body','write':False});self.body_reads.append(j);return self.plain[j]^P.M.mask(a,resize(P.M.KEY0,64))
  if self.pc in P.M.WORD_BYTES|P.M.TYPE_BYTES:return super().load(a,n)
  self.classify(a,n);keys=[z3.simplify(a+j).sexpr()for j in range(n)];values=[self.byte_overlay.get(k)for k in keys]
  if all(v is not None for v in values):
   self.accesses.append({'PC':self.pc,'address':a,'size':n,'kind':'source_versioned_cell','write':False});full=self.word_versions.get((a.sexpr(),n))
   if full and all(self.byte_epochs[k]==full[0]for k in keys):return full[1]
   return values[0]if n==1 else z3.Concat(*reversed(values))
  value=super().load(a,n)
  if any(v is not None for v in values):
   values=[v if v is not None else z3.Extract(8*j+7,8*j,value)for j,v in enumerate(values)];value=values[0]if n==1 else z3.Concat(*reversed(values))
  return value
 def store(self,a,n,value,source_pc):
  a=self.norm(a);value=self.norm(resize(value,8*n));self.classify(a,n)
  self.store_seq+=1;self.word_versions[(a.sexpr(),n)]=(self.store_seq,value)
  for j in range(n):
   key=z3.simplify(a+j).sexpr();self.byte_overlay[key]=z3.Extract(8*j+7,8*j,value);self.byte_epochs[key]=self.store_seq
  return super().store(a,n,value,source_pc)
 def run(self,label,end=None):
  if not any(s['label']==label for s in self.e['spans']):label='nz_'+label
  row=next(s for s in self.e['spans']if s['label']==label);original=self.e;self.tracking=True;skip=None;self.direct_target=None;old_edges=len(self.edges)
  try:
   for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
    if end is not None and i.address>=end:break
    if i.address==skip:continue
    self.pc=i.address
    if i.mnemonic in ['bti','nop','braa','blraa']or i.address in R.RETAGS:
     self.visited.add(i.address);self.count+=1
     if i.mnemonic in ['braa','blraa']:
      if i.mnemonic=='blraa':self.write('x30',resize(i.address+4,64))
      self.edges.append({'PC':i.address,'target':self.read(i.reg_name(i.operands[0].reg)),'modifier':self.read(i.reg_name(i.operands[1].reg)),'arguments':[self.read('x'+str(j))for j in range(4)],'link':self.read('x30')});break
     if i.address in R.RETAGS:
      assert i.mnemonic=='b.eq'and i.operands[0].imm&((1<<64)-1)==i.address+8;self.normal_guards.append(self.equal);self.branch_guards.append(self.equal);skip=R.RETAGS[i.address]
    else:
     self.e={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};P.M.Model.run(self,'one');self.e=original
     if i.mnemonic.startswith('b.')and self.branch_choices.get(i.address,False):break
  finally:self.e=original;self.tracking=False
  self.last_has_edge=len(self.edges)>old_edges;return self
 def connect(self,label):
  label='nz_'+label if not label.startswith('nz_')else label
  target=int(next(s for s in self.e['spans']if s['label']==label)['start'],16)
  if self.last_has_edge:self.address_checks.append(self.edges[-1]['target']==target)
  elif self.direct_target is not None:self.address_checks.append(z3.BoolVal(self.direct_target==target))
  else:
   assert self.pc+4==target,('noncontiguous_without_edge',hex(self.pc),label,hex(target))
  return self.run(label)
 def returned(self,name,value):
  edge=self.edges[-1];self.returns.append({'role':name,'call_PC':hex(edge['PC']),'nominal_return_PC':hex(edge['PC']+4),'ordinary_return_assumed':True,'callee_saved_SP_and_surviving_storage_preservation_assumed':True,'native_effects_established':False})
  for j in [*range(19),30]:self.seed('x'+str(j),z3.BitVec('NZ_return_'+name+'_X'+str(j),64))
  self.seed('x0',value);return self
def entry(e,n):
 old=json.loads(read(ROOT/'userclient_fallback_metadata_checks.json'));v=P.entry(old);v.__class__=Model;v.body_length=n;v.evidence=e;v.e['spans']+=copy.deepcopy(e['source']['spans']);v.plain+=list(z3.BitVecs('NZ_byte10 NZ_byte11 NZ_byte12 NZ_byte13',8));v.J,v.Z,v.input=z3.BitVecs('NZ_node64 NZ_buffer64 NZ_original_input64',64);v.with_new_node=v.with_record_buffer=False;v.byte_overlay={};v.byte_epochs={};v.word_versions={};v.store_seq=0;v.left={};v.bankbyte={};v.bank_events=[];v.body_reads=[];v.returns=[]
 v.seed('x5',0xa41a4d891208c018);v.seed('x6',pc(0xccc30d0));v.seed('x28',pc(0x7949dd0))
 for off,(role,value)in FROOTS.items():
  nbytes=4 if off in [0x60c,0x9ec]else 8;want=v.ctx+value if role=='C'else v.src+value if role=='S'else resize(value,nbytes*8);key=(z3.simplify(v.sp+off).sexpr(),nbytes)
  if key in v.memory:assert z3.is_true(z3.simplify(v.memory[key]==want))
  else:mem(v,v.sp+off,nbytes,want)
 for off in [0x768,0x458,0x140,0x58]:mem(v,v.ctx+off,8,z3.BitVec('NZ_C_'+format(off,'x'),64))
 for off,nbytes in [(0xd30,4),(0x94,4),(0x110,4),(0x1b2,2)]:mem(v,v.src+off,nbytes,z3.BitVec('NZ_S_'+format(off,'x'),8*nbytes))
 mem(v,v.src+0x2ac,4,SUCCESS);mem(v,v.src+0xbb8,8,0x688dbcd0b072e922)
 v.entry_memory=copy.copy(v.memory);v.entry_regs=copy.copy(v.regs);return v
def selected(v):return P.chosen(v)+[P.tag(v)!=0,P.length(v)==v.body_length]
def cell(v,a,n):
 a=v.norm(a);keys=[z3.simplify(a+j).sexpr()for j in range(n)]
 full=v.word_versions.get((a.sexpr(),n))
 if full and all(v.byte_epochs.get(k)==full[0]for k in keys):return full[1]
 if all(k in v.byte_overlay for k in keys):return v.byte_overlay[keys[0]]if n==1 else z3.Concat(*[v.byte_overlay[k]for k in reversed(keys)])
 return P.cell(v,a,n)
def compose(e,n,case='success'):
 v=entry(e,n);checks={}
 def remember(name,bad):checks[name]=z3.simplify(bad)
 v.run('tag_tail')
 P.add_edge(v,0xa63930c,0x9c55);v.decode(range(4,6));P.add_edge(v,0xa639dc0,0x1086)
 for label,target,modifier in [('type_return',0xa637128,0x266f),('length_bridge',0xa637138,0xf930)]:v.run(label);P.add_edge(v,target,modifier)
 v.decode(range(6,10));P.add_edge(v,0xa6390b4,0xb745);v.run('length_extent');P.add_edge(v,0xa639164,0x685a)
 v.branch_choices[pc(0xa639174)]=True;v.run('type_first_gate');v.address_checks.append(z3.BoolVal(v.direct_target==pc(0xa63a784)));v.branch_choices[pc(0xa63a78c)]=True;v.run('type_selected_gate');v.address_checks.append(z3.BoolVal(v.direct_target==pc(0xa63dc9c)))
 for label,target,modifier in [('body_publish',0xa63dcd0,0xa174),('metadata_return',0xa6423c0,0xdfc5),('metadata_outcome_gate',0xa6423f4,0xc9dc),('record_kind_gate',0xa642454,0x5ab2)]:v.run(label);P.add_edge(v,target,modifier)
 for label in ['record_inputs','record_size_gate','node_allocate']:v.connect(label)
 edge=v.edges[-1];remember('typed_node_request',z3.Or(edge['target']!=pc(0xc4ba154),edge['modifier']!=0xd0c8,edge['arguments'][0]!=pc(0x847c020),edge['link']!=pc(0xa6425d0)))
 v.returned('typed_node',resize(0,64)if case=='node_null'else v.J);v.run('node_return')
 if case=='node_null':
  v.connect('node_null');remember('null_node_failure_boundary',z3.Or(v.edges[-1]['target']!=pc(0xa6622bc),cell(v,v.sp+0x50,8)!=0,v.read('w23')!=0xce515bb2));return v,checks
 v.with_new_node=True;v.connect('node_initialize');v.connect('buffer_allocate');edge=v.edges[-1]
 remember('separate_data_request_and_initialized_node',z3.Or(edge['target']!=pc(0xc4ba60c),edge['modifier']!=0xca0c,edge['arguments'][0]!=10+n,edge['link']!=pc(0xa6427c4),cell(v,v.J,8)!=0,cell(v,v.J+8,8)!=0,cell(v,v.J+0x10,4)!=10+n))
 v.returned('record_buffer',resize(0,64)if case=='buffer_null'else v.Z);v.run('buffer_return')
 if case=='buffer_null':
  remember('null_buffer_failure_boundary',z3.Or(v.edges[-1]['target']!=pc(0xa6622bc),cell(v,v.J+0x18,8)!=0,cell(v,v.sp+0x50,8)!=v.J,v.read('w23')!=0xce515bb2));return v,checks
 v.with_record_buffer=True
 for label in ['buffer_prepare','writer_request','writer_setup','word_writer','type_writer','length_bridge','word_writer']:v.connect(label)
 remember('ten_source_observations_reprotected_at_new_buffer',z3.Or(*[cell(v,v.Z+j,1)!=(v.plain[j]^P.M.mask(v.Z+j,resize(P.M.KEY0,64)))for j in range(10)]))
 v.branch_choices[pc(0xa654e7c)]=True;v.connect('type_primary_gate');v.branch_choices[pc(0xa655444)]=True;v.connect('type_secondary_gate');v.connect('payload_size_gate')
 if n:
  v.connect('payload_request');v.connect('payload_copy')
  for j in range(n-1):v.connect('payload_copy')
  assert v.body_reads==list(range(10+n-1,9,-1))
 remember('complete_record_bytes_and_node_fields',z3.Or(*[cell(v,v.Z+j,1)!=(v.plain[j]^P.M.mask(v.Z+j,resize(P.M.KEY0,64)))for j in range(10+n)],cell(v,v.J,8)!=0,cell(v,v.J+8,8)!=0,cell(v,v.J+0x10,4)!=10+n,cell(v,v.J+0x18,8)!=v.Z))
 v.connect('publication_request')
 remember('publication_lookup_uses_same_container_tag_and_output',
          z3.Or(v.read('x22')!=v.object,v.read('w9')!=(P.tag(v)^SUCCESS),
                v.read('x10')!=v.ctx+0x628,cell(v,v.ctx+0x628,8)!=0))
 for label in ['search_entry','search_nonnull','search_node','search_result','search_callback']:v.connect(label)
 remember('first_lookup_returns_miss_and_zero_result',
          z3.Or(v.read('w23')!=MISS,cell(v,v.ctx+0x628,8)!=0,
                v.edges[-1]['target']!=pc(0xa66248c)))
 for label in ['status_success_gate','status_miss_gate','append_prepare','append_empty','parser_cursor_gate']:v.connect(label)
 remember('first_node_publication_and_exact_cursor_split',z3.Or(cell(v,v.object,8)!=v.J,cell(v,v.object+8,8)!=v.J,cell(v,v.J,8)!=0,cell(v,v.J+8,8)!=0,cell(v,v.sp+0xa80,8)!=10+n,v.edges[-1]['target']!=pc(0xa642180 if n==4 else 0xa6421dc),v.read('w23')!=MISS,cell(v,v.ctx+0x600,8)!=0))
 return v,checks
def source_proofs(e):
 from audit_userclient_early_header import Lift
 proofs=[];models={};coverage=[]
 root=entry(e,4)
 for n in range(5):proofs.append(P.solve('BE32_length_'+str(n)+'_entails_unique_byte_specialization',[P.length(root)==n],z3.Or(*[root.plain[6+j]!=((n>>(24-8*j))&255)for j in range(4)])))
 F,C=z3.BitVecs('NZ_prefix_F64 NZ_prefix_C64',64);v=Lift({'spans':e['prefix_source']});v.seed('sp',F);v.run('writer_phase_prefix');v.c={'spans':e['prefix_source']};v.run('writer_control_prefix')
 proofs.append(P.solve('original_writer_saved_controls',[],z3.Or(P.cell(v,F+0x570,8)!=0x87b,P.cell(v,F+0x60c,4)!=0x3f22ccfb)))
 v=Lift({'spans':e['prefix_source']});v.seed('sp',F);v.seed('x2',C);v.run('publication_output_prefix');proofs.append(P.solve('original_publication_output_alias',[],P.cell(v,F+0x350,8)!=C+0x628))
 for n in range(5):
  for case in ['node_null','buffer_null','success']:
   v,checks=compose(e,n,case);name='length_'+str(n)+'_'+case
   proofs.append(P.solve(name+'_actual_first_record_contract',v.owned()+v.branch_guards+selected(v),z3.Or(*checks.values(),*[z3.Not(q)for q in v.address_checks])))
   models[name]=v;coverage.append({'profile':name,'source_instruction_instances':v.count,'distinct_source_words':len(v.visited),'source_access_instances':len(v.accesses),'source_store_instances':len(v.stores),'tracked_entry_register_views':len(v.live_regs),'tracked_entry_cells':len(v.live_cells),'protected_body_read_indices':v.body_reads,'ordinary_return_premises':v.returns,'contract_components':list(checks)})
 return proofs,models,coverage

def projection(e,models):
 from z3.z3util import get_vars
 root=entry(e,4);regs=sorted(set().union(*(v.live_regs for v in models.values())));cells={k:x for v in models.values()for k,x in v.live_cells.items()};normal={z3.simplify(g).sexpr():g for v in models.values()for g in v.normal_guards};old_guards=[g for g in normal.values()if not {'NZ_node64','NZ_buffer64'}&{str(x)for x in get_vars(g)}];proofs=[];domains=[];receipts=[];admissions=[]
 for mode in P.Parent.MODES:
  actual=P.Parent.tag_result(json.loads(read(ROOT/'userclient_fallback_parser_checks.json')),mode);c=actual.common
  additions=[(0x890,8,c['C']+0x3d8),(0x350,8,c['C']+0x628),(0x570,8,resize(0x87b,64)),(0x60c,4,resize(0x3f22ccfb,32))]
  for off,n,value in additions:
   key=(z3.simplify(c['F']+off).sexpr(),n);assert key not in actual.memory;mem(actual,c['F']+off,n,value)
  ps=actual.owned()+actual.guards+actual.extra;domains.append(P.solve(mode+'_entailed_N14_L4',ps,z3.Or(c['N']!=14,c['L']!=4)));ps+=[c['N']==14,c['L']==4]
  pairs=[(root.sp,c['F']),(root.ctx,c['C']),(root.src,c['S']),(root.buffer,actual.buffer),(root.object,actual.typed),(root.input,actual.original_input)]+[(root.plain[j],actual.input_bytes[j])for j in range(14)]+[(z3.BitVec('TI_initial_X'+str(j),64),actual.read('x'+str(j)))for j in range(31)]
  for off in [0x768,0x458,0x140,0x58]:pairs.append((z3.BitVec('NZ_C_'+format(off,'x'),64),P.Parent.H.cell(actual,c['C']+off,8)))
  for off,n in [(0xd30,4),(0x94,4),(0x110,4),(0x1b2,2)]:pairs.append((z3.BitVec('NZ_S_'+format(off,'x'),8*n),P.Parent.H.cell(actual,c['S']+off,n)))
  def mapped(q):return z3.simplify(z3.substitute(q,*pairs))
  items=[('register_'+r,mapped(root.read(r))!=actual.read(r))for r in regs]
  items += [('cell_'+str(j),P.Parent.H.cell(actual,mapped(x['address']),x['size'])!=mapped(root.entry_memory[k]))for j,(k,x)in enumerate(cells.items())]
  for off in [0,8]:items.append(('empty_container_'+str(off),P.Parent.H.cell(actual,actual.typed+off,8)!=0))
  items += [('side_context_'+hex(off),P.Parent.H.cell(actual,c['C']+off,n)!=mapped(P.cell(root,root.ctx+off,n)))for off,n in [(0x228,8),(0x600,8)]]
  for j in range(14):
   row=next(r for r in actual.fallback_copy_stores if r['index']==j);items.append(('protected_observation_'+str(j),z3.Or(row['address']!=actual.buffer+j,row['value']!=mapped(root.plain[j]^P.M.mask(root.buffer+j,resize(P.M.KEY0,64))))))
  items += [('weaker_initial_ownership',z3.Or(*[z3.Not(mapped(q))for q in root.owned()])),('initial_normal_pointer_guards',z3.Or(*[z3.Not(mapped(q))for q in old_guards]))]
  for name,bad in items:proofs.append(P.solve(mode+'_projection_'+name,ps,z3.simplify(z3.substitute(bad,(c['N'],resize(14,32)),(c['L'],resize(4,32))))))
  for name,v in models.items():
   s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*ps,*[mapped(q)for q in selected(v)+v.owned()+v.normal_guards]);assert s.check()==z3.sat,(mode,name,s.reason_unknown());admissions.append({'name':mode+'_'+name,'result':'sat','query':s.to_smt2(),'fresh_allocation_and_normal_pointer_conditions_assumed':True,'native_allocation_outcomes_or_reachability_established':False});print('admitted '+mode+' '+name,flush=True)
  receipts.append({'mode':mode,'entry_PC':hex(pc(0xa638dc8)),'register_views':regs,'initial_cells':[{'first_read_PC':hex(x['PC']),'address_expression':x['address'].sexpr(),'size_bytes':x['size']}for x in cells.values()],'source_protected_observations':14,'additional_frame_cells':[hex(o)for o,n,v in additions],'new_generic_scratch_channels_bound_to_actual_parent':8,'ordinary_surviving_storage_preservation_assumed':True,'fresh_pointer_conditions_inherited_from_parent':False})
 return proofs,domains,admissions,receipts,{'live_register_views':len(regs),'live_initial_cells':len(cells),'normal_pointer_guards':len(normal),'initial_parent_pointer_guards':len(old_guards),'new_allocation_pointer_guards':len(normal)-len(old_guards)}

def footprint(e,models):
 rows={};initial={};static=set();instances=0;overlaps=0;profiles=[]
 for name,v in models.items():
  for r in v.accesses:
   instances+=1
   if r['kind'].startswith('original_'):
    static.add((hex(r['PC']),r['kind']));candidates=[]
    if r['kind']=='original_pointer_table':candidates=[(TABLE+8*j,8)for j in R.BRANCHES[r['PC']]]
    elif r['kind']=='original_controller':candidates=[(pc(0xccc30d0),4),(pc(0xccc32f8),4)]
    else:
     for rule in e['bank_rules']:
      lp,rp,pp=R.BANK_PCS[rule['name']]
      if r['PC']in [lp,rp]:candidates=[(int(rule['left'if r['PC']==lp else'right'],16),256)]
      if r['PC']==pp:candidates=[(int(rule['slot'],16),8)]
    assert candidates and all(any(a<=b and b+n<=a+m for a,off,m in IMAGE.segments)for b,n in candidates);continue
   v.pc=r['PC'];owner,off,extent=v.classify(r['address'],r['size']);key=(owner,off,r['size']);row=rows.setdefault(key,{'owner':owner,'offset_bytes':off,'size_bytes':r['size'],'source_PCs':set(),'read':False,'write':False});row['source_PCs'].add(hex(r['PC']));row['write'if r['write']else'read']=True
  for x in v.live_cells.values():
   v.pc=x['PC'];owner,off,extent=v.classify(x['address'],x['size']);initial[(owner,off,x['size'])]=True
  written=[r for r in v.stores if v.classify(r['address'],r['size_bytes'])[0]=='record_buffer']
  if name.endswith('_success'):
   offsets=[v.classify(r['address'],r['size_bytes'])[1]for r in written];assert sorted(offsets)==list(range(10+v.body_length))and all(r['size_bytes']==1 for r in written)
   node_bytes={j for r in v.stores for owner,off,extent in [v.classify(r['address'],r['size_bytes'])]if owner=='new_node'for j in range(off,off+r['size_bytes'])};assert node_bytes==set(range(32))-set(range(0x14,0x18));profiles.append({'profile':name,'record_bytes_written':len(offsets),'record_offsets':offsets,'unwritten_node_padding_offsets':list(range(0x14,0x18))})
 for j,a in enumerate(initial):
  for b in list(initial)[j+1:]:assert a[0]!=b[0]or a[1]+a[2]<=b[1]or b[1]+b[2]<=a[1]
 keys=list(rows)
 for j,a in enumerate(keys):
  for b in keys[j+1:]:
   if a[0]==b[0]and max(a[1],b[1])<min(a[1]+a[2],b[1]+b[2]):overlaps+=1
 for r in rows.values():r['source_PCs']=sorted(r['source_PCs'])
 proofs=[];B,J,W=z3.BitVecs('NZ_geometry_base64 NZ_geometry_offset64 NZ_geometry_width64',64)
 for n in [10,11,12,13,14,16,32,4096,4336,16384]:proofs.append(P.solve('source_subranges_do_not_wrap_'+str(n),[z3.ULE(B,resize((1<<64)-1-n,64)),W!=0,z3.ULE(J,n),z3.ULE(W,resize(n,64)-J)],z3.Or(z3.ULT(B+J,B),z3.ULT(B+J+W,B+J),z3.UGT(B+J+W,B+n))))
 visited=set().union(*(v.visited for v in models.values()));captured={int(i['pc'],16)for s in e['source']['spans']for i in s['instructions']};excluded=captured-visited;assert excluded==set(R.W.RETAGS.values());prefix={int(i['pc'],16)for s in e['prefix_source']for i in s['instructions']}
 return proofs,{'runtime_cells':sorted(rows.values(),key=lambda r:(r['owner'],r['offset_bytes'],r['size_bytes'])),'initial_cells_disjoint':True,'distinct_initial_cells':len(initial),'same_owner_partial_width_overlap_pairs':overlaps,'overlap_resolution':'Source-ordered byte versions; intact full-cell versions retain their exact expression. Unwritten bytes require an explicit retained entry cell. No unknown load default exists.','static_read_sites':[{'PC':p,'kind':k}for p,k in sorted(static)],'source_access_instances':instances,'successful_record_write_profiles':profiles,'captured_words_proved':len(captured&visited),'alternate_retag_words_not_selected':list(map(hex,sorted(excluded))),'carried_source_words_proved':len(visited-captured),'prefix_source_words_proved':len(prefix),'combined_source_words_proved':len(visited|prefix)}

def controls(e):
 out=[]
 for at,name,pair in [(0xa6550b8,'type_byte_store',False),(0xa655ecc,'body_byte_store',False),(0xa662878,'container_tail_store',True)]:
  changed=copy.deepcopy(e);a=pc(at);row=next(s for s in changed['source']['spans']if int(s['start'],16)<=a<int(s['end_exclusive'],16));raw=bytearray.fromhex(row['bytes_hex']);off=a-int(row['start'],16);old=raw[off:off+4];word=int.from_bytes(old,'little');new=(word&~(31<<10))|(31<<10)if pair else(word&~31)|31;raw[off:off+4]=new.to_bytes(4,'little');row['bytes_hex']=raw.hex();v,checks=compose(changed,4);bad=checks['first_node_publication_and_exact_cursor_split']if pair else checks['complete_record_bytes_and_node_fields'];s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*v.owned(),*v.branch_guards,*selected(v),*v.address_checks);assert s.check()==z3.sat,(name,'premises');s.add(bad);assert s.check()==z3.sat,name;out.append({'name':name,'mutated_PC':hex(a),'original_word_hex':old.hex(),'replacement_word_hex':new.to_bytes(4,'little').hex(),'result':'sat','satisfiable_violation_query':s.to_smt2(),'native_target_executed':False});print('rejected '+name,flush=True)
 return out


def recheck_predecessors():
    """Re-solve the retained source and interface obligations this join uses."""
    artifacts = {
        'userclient_fallback_metadata_audit.json': [
            'source_proofs', 'projection_proofs',
            'source_entailed_domain_proofs', 'prefix_proofs',
        ],
        'userclient_record_nodes_audit.json': ['source_proofs'],
        'userclient_record_writer_audit.json': ['source_proofs'],
        'userclient_record_publication_audit.json': ['source_proofs'],
    }
    receipts = []
    for artifact, groups in artifacts.items():
        evidence = json.loads(read(ROOT / artifact))
        for group in groups:
            for proof in evidence[group]:
                name = proof.get('name', proof.get('label'))
                solver = z3.Solver()
                solver.set(timeout=120000)
                solver.add(*z3.parse_smt2_string(proof['query']))
                assert solver.check() == z3.unsat, (name, solver.reason_unknown())
                receipts.append({
                    'artifact': artifact, 'group': group,
                    'name': name, 'result': 'unsat',
                })
        print('rechecked ' + artifact, flush=True)
    return receipts


def audit(evidence):
    for rule in evidence['bank_rules']:
        left, right = (bytes.fromhex(evidence['banks'][rule[side]]) for side in ('left', 'right'))
        key, constant = (int(rule[field], 16) for field in ('key', 'constant'))
        assert all(j ^ right[left[j] ^ key] == constant for j in range(256))

    source, models, coverage = source_proofs(evidence)
    joins, domains, admissions, projection_receipts, projection_totals = projection(evidence, models)
    geometry, access_receipt = footprint(evidence, models)
    mutations = controls(evidence)
    prior = recheck_predecessors()
    totals = {
        'new_source_queries_unsat': len(source) + len(joins) + len(domains) + len(geometry),
        'continuation_and_setup_queries_unsat': len(source),
        'projection_queries_unsat': len(joins),
        'domain_queries_unsat': len(domains),
        'geometry_queries_unsat': len(geometry),
        'prior_queries_unsat': len(prior),
        'actual_cut_admissions_sat': len(admissions),
        'negative_source_controls': len(mutations),
        'profile_instruction_instances': sum(v.count for v in models.values()),
        'access_instances': access_receipt['source_access_instances'],
        'combined_source_words': access_receipt['combined_source_words_proved'],
        **projection_totals,
    }
    return {
        'auditor_sha256': sha(__file__),
        'checks_sha256': sha(ROOT / (R.P + '_checks.json')),
        'source_sha256': evidence['source_sha256'],
        'kernel_collection_sha256': evidence['kernel_collection_sha256'],
        'scope': evidence['scope'],
        'verified_counts': evidence['verified_counts'],
        'source_proofs': source + joins + domains + geometry,
        'rechecked_prior_proofs': prior,
        'actual_cut_admissions': admissions,
        'negative_source_controls': mutations,
        'coverage': coverage,
        'projection_receipts': projection_receipts,
        'access_footprint': access_receipt,
        'independent_totals': totals,
        'conditional_nonzero_tag_record_established': True,
        'all_checks_pass': True,
        **{flag: False for flag in R.FALSE},
    }


if __name__ == '__main__':
    evidence = json.loads(read(ROOT / (R.P + '_checks.json')))
    assert evidence == R.build()
    receipt = audit(evidence)
    (ROOT / (R.P + '_audit.json')).write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt['independent_totals']), flush=True)
