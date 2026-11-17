#!/usr/bin/env python3
"""Certify original frame custody and actual zero-tag local return.
O(I+C*W+query DAG) construction/space; native PAC/callees stay opaque.
"""
import copy,json
import z3
from z3.z3util import get_vars
from capstone.arm64 import ARM64_OP_IMM,ARM64_OP_MEM
from kext_port_tools import ROOT,IMAGE,qword
from lskd_values_symbolic import resize
from verify_daemon_reader_record_payloads_publication import read,sha
import audit_userclient_zero_tag_unwind as U
import recover_userclient_zero_tag_return as R
P=U.P;pc=R.pc;DEC=U.DEC;SUCCESS=U.SUCCESS;MISS=U.MISS;RESULT=MISS^SUCCESS
def guard_separation(F):return z3.Or(z3.ULE(F+0x10f0,pc(0xcacb000)),z3.ULE(resize(pc(0xcacb008),64),F))

class Frame:
 def __init__(self,e):
  self.e=e;self.F=z3.BitVec('ZR_F64',64);self.initial={r:z3.BitVec('ZR_in_'+r,64)for r in [*('x'+str(j)for j in range(31)),*('d'+str(j)for j in range(8,12))]};self.regs=copy.copy(self.initial);self.regs['sp']=self.F+0x10f0;self.memory={};self.saved_guard,self.current_guard,self.signed_link=z3.BitVecs('ZR_saved_guard64 ZR_current_guard64 ZR_signed_link64',64);self.visited=set();self.count=0;self.reads=[];self.stores=[];self.address_checks=[];self.guards=[];self.edges=[];self.direct_target=None;self.returns=[];self.pac_events=[];self.stop=None;self.flags=(z3.BoolVal(False),z3.BoolVal(False));self.probe_reads=[]
 def owned(self):return [self.F!=0,(self.F&15)==0,z3.ULE(self.F,resize((1<<64)-1-0x10f0,64)),guard_separation(self.F)]+[z3.Or(z3.ULE(self.F+0x10f0,a),z3.ULE(a+n,self.F))for a,off,n in IMAGE.segments]
 def read(self,r):
  r={'fp':'x29','lr':'x30'}.get(r,r)
  if r in ['xzr','wzr']:return resize(0,32 if r=='wzr'else 64)
  return resize(self.regs['x'+r[1:]if r.startswith('w')else r],32 if r.startswith('w')else 64)
 def write(self,r,v):
  r={'fp':'x29','lr':'x30'}.get(r,r)
  if r in ['xzr','wzr']:return
  self.regs['x'+r[1:]if r.startswith('w')else r]=resize(resize(v,32)if r.startswith('w')else v,64)
 def val(self,i,o,n=64):
  if o.type==ARM64_OP_IMM:return resize(o.imm<<o.shift.value,n)
  return resize(self.read(i.reg_name(o.reg)),n)
 def address(self,i,o):return z3.simplify(self.read(i.reg_name(o.mem.base))+o.mem.disp)
 def store(self,a,n,value):
  self.memory[(z3.simplify(a).sexpr(),n)]=resize(value,8*n);self.stores.append({'PC':self.pc,'address':a,'size':n,'value':resize(value,8*n)})
 def load(self,a,n):
  self.reads.append({'PC':self.pc,'address':a,'size':n})
  imports={pc(0xa63523c):pc(0x847c618),pc(0xa63525c):pc(0x847c5f8),pc(0xa6662bc):pc(0x847c5f8),pc(0xa69f29c):pc(0x847c478)}
  if self.pc in imports:
   slot=imports[self.pc];self.address_checks.append(a==slot);return resize(qword(slot),64)
  if self.pc in [pc(0xa635260),pc(0xa6662c0)]:self.address_checks.append(a==pc(0xcacb000));return self.saved_guard if self.pc==pc(0xa635260)else self.current_guard
  if self.pc in [pc(0xa5a1cdc),pc(0xa5a1cf0)]:
   j=len(self.probe_reads);self.address_checks.append(a==self.F+(0x70 if j==0 else 0));self.probe_reads.append(a);return z3.BitVec('ZR_probe_discard_'+str(j),8)
  key=(z3.simplify(a).sexpr(),n);assert key in self.memory,('unclosed_frame_load',hex(self.pc),str(a),n);return self.memory[key]
 def run(self,label):
  row=next(s for s in self.e['source']['spans']if s['label']==label);ii=list(DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)));index={i.address:j for j,i in enumerate(ii)};j=0;self.direct_target=None
  while j<len(ii):
   i=ii[j];self.pc=i.address;self.visited.add(i.address);self.count+=1;assert self.count<300;op=i.operands;m=i.mnemonic;j+=1
   if m in ['bti','nop']:continue
   if m=='pacibsp':
    self.pac_events.append({'PC':hex(i.address),'input_link_expression':self.read('x30').sexpr(),'SP_expression':self.read('sp').sexpr(),'output_link_expression':self.signed_link.sexpr(),'native_signature_computed':False});self.write('x30',self.signed_link);continue
   if m in ['add','sub','eor']:
    r=i.reg_name(op[0].reg);n=32 if r.startswith('w')else 64;a,b=self.val(i,op[1],n),self.val(i,op[2],n);self.write(r,a+b if m=='add'else a-b if m=='sub'else a^b);continue
   if m in ['mov','adrp']:
    self.write(i.reg_name(op[0].reg),self.val(i,op[1]));continue
   if m=='cmp':
    r=i.reg_name(op[0].reg);n=32 if r.startswith('w')else 64;a,b=self.val(i,op[0],n),self.val(i,op[1],n);self.flags=(a==b,z3.ULT(a,b));continue
   if m=='b'or m.startswith('b.'):
    target=op[0].imm&((1<<64)-1);eq,lo=self.flags;condition={'b':z3.BoolVal(True),'b.ne':z3.Not(eq),'b.lo':lo,'b.hi':z3.And(z3.Not(lo),z3.Not(eq))}[m]
    take=self.guard_failure if i.address==pc(0xa6662c8)else z3.is_true(z3.simplify(condition));self.guards.append(condition if take else z3.Not(condition))
    if take:
     if target in index:j=index[target]
     else:self.direct_target=target;break
    continue
   if m in ['ldr','ldur','ldrb','str','stur']:
    r=i.reg_name(op[0].reg);n=1 if m=='ldrb'else 4 if r.startswith('w')else 8;a=self.address(i,op[1])
    if m in ['str','stur']:self.store(a,n,self.read(r))
    else:self.write(r,self.load(a,n))
    continue
   if m in ['stp','ldp']:
    a=self.address(i,op[2]);base=i.reg_name(op[2].mem.base);r0,r1=[i.reg_name(o.reg)for o in op[:2]];assert not r0.startswith('w')
    if m=='stp':self.store(a,8,self.read(r0));self.store(a+8,8,self.read(r1))
    else:self.write(r0,self.load(a,8));self.write(r1,self.load(a+8,8))
    if i.writeback:self.write(base,a if len(op)==3 else self.read(base)+op[3].imm)
    continue
   if m in ['blraa','braa','bl']:
    target=self.val(i,op[0]);modifier=None if m=='bl'else self.val(i,op[1])
    if m in ['blraa','bl']:self.write('x30',resize(i.address+4,64))
    self.edges.append({'PC':i.address,'target':target,'modifier':modifier});break
   if m=='ret':self.edges.append({'PC':i.address,'target':self.read('x30'),'modifier':None});break
   if m=='retab':self.stop={'PC':hex(i.address),'saved_link_expression':self.read('x30').sexpr(),'SP_expression':self.read('sp').sexpr(),'native_authentication_or_return_established':False};break
   raise AssertionError(('unsupported_frame_instruction',hex(i.address),m,i.op_str))
  if label=='guard_gate':self.guard_exit_target=self.direct_target
  return self
 def workspace_return(self):
  self.returns.append({'call_PC':hex(pc(0xa6662b0)),'nominal_return_PC':hex(pc(0xa6662b4)),'retired_owner':'workspace','ordinary_return_assumed':True,'callee_saved_SP_and_frame_storage_preservation_assumed':True,'volatile_registers_forgotten':[*range(19),30],'native_callee_effects_established':False})
  for j in [*range(19),30]:self.write('x'+str(j),z3.BitVec('ZR_workspace_return_X'+str(j),64))
  return self

def prologue(e):
 v=Frame(e);v.guard_failure=False;v.run('frame_entry');assert v.edges[-1]['PC']==pc(0xa635240)
 # Execute the original read-only probe rather than introducing a native summary.
 v.run('stack_probe');assert v.edges[-1]['PC']==pc(0xa5a1cf4)
 row=next(s for s in e['source']['spans']if s['label']=='frame_entry');tail=copy.deepcopy(row);a=pc(0xa635244);tail['label']='frame_entry_tail';tail['bytes_hex']=bytes.fromhex(row['bytes_hex'])[a-int(row['start'],16):].hex();tail['start']=hex(a);v.e=copy.deepcopy(e);v.e['source']['spans'].append(tail);v.run('frame_entry_tail');return v
def frame_cell(v,off):return v.memory[(z3.simplify(v.F+off).sexpr(),8)]
def prepare(e,guard_failure=False,prior=None):
 saved=prologue(e);u=prior if prior is not None else U.compose(json.loads(read(ROOT/'userclient_zero_tag_unwind_checks.json')))[0];v=Frame(e);pairs=[(saved.F,u.sp)];v.F=u.sp;v.regs={r:z3.simplify(z3.substitute(x,*pairs))for r,x in u.regs.items()};v.regs.update({'d'+str(j):z3.BitVec('ZR_before_exit_d'+str(j),64)for j in range(8,12)});v.memory={}
 for role,off,writer in R.SAVES:
  at=z3.simplify(v.F+off);v.memory[(at.sexpr(),8)]=z3.simplify(z3.substitute(frame_cell(saved,off),*pairs))
 v.saved_guard=saved.saved_guard;v.current_guard=saved.current_guard;v.signed_link=saved.signed_link;v.initial=saved.initial;v.write('x29',v.F+0x10e0);v.write('sp',v.F);v.guard_failure=guard_failure;v.workspace_return();v.run('guard_gate');return v
def normal(e,prior=None):return prepare(e,False,prior).run('status_decode').run('frame_exit')
def failed(e,prior=None):return prepare(e,True,prior).run('guard_failure_call').run('guard_failure_veneer')

def solve(name,premises,bad):return P.solve(name,premises,bad)
def variables(q):return {str(x)for x in get_vars(q)}
def protected(v,r):return z3.Or(z3.ULE(r['address']+r.get('size_bytes',r.get('size')),v+0x1060),z3.ULE(v+0x10f0,r['address']))
def preservation(e,u):
 proofs=[];receipts=[];oldchecks=json.loads(read(ROOT/'userclient_fallback_parser_checks.json'))
 for mode in P.Parent.MODES:
  v=P.Parent.tag_result(oldchecks,mode);F=v.common['F'];norm=lambda q:z3.simplify(z3.substitute(q,(v.common['N'],resize(14,32)),(v.common['L'],resize(4,32))))
  proofs.append(solve(mode+'_entailed_N14_L4',v.owned()+v.guards+v.extra,z3.Or(v.common['N']!=14,v.common['L']!=4)))
  # The old finite model intentionally leaves FP opaque. Its exact passthrough
  # is refined by the original frame proof and 30 source-backed prefix records.
  proofs.append(solve(mode+'_opaque_FP_is_preserved',[],v.read('x29')!=z3.BitVec('EW_a_entry_X29',64)))
  roots={k:(v.common[k],n)for k,n in [('F',0x10f0),('C',4096),('S',16384),('J',32),('Z',14),('H',16)]};roots.update({k:(getattr(v,k),n)for k,n in [('attribute',112),('message',128),('buffer',14),('typed',16)]});groups={};ledger=[]
  for r in v.stores:
   hits=[]
   for role,(base,n)in roots.items():
    d=norm(r['address']-base)
    if z3.is_bv_value(d):hits.append((role,d.as_long()if d.as_long()<1<<63 else d.as_long()-(1<<64),n))
   if hits:
    assert len(hits)==1;role,off,n=hits[0]
    if role=='F':assert -0x70<=off and off+r['size_bytes']<=0x1060
    else:assert 0<=off and off+r['size_bytes']<=n
   else:
    at=norm(r['address']);assert z3.is_bv_value(at)and any(a<=at.as_long()and at.as_long()+r['size_bytes']<=a+m for a,offset,m in IMAGE.segments);role='static';off=at.as_long();n=r['size_bytes']
   groups.setdefault(role,[]).append(r);ledger.append({'source_PC':hex(r['pc']),'owner':role,'offset_or_address':hex(off),'size_bytes':r['size_bytes']})
  owned=[norm(q)for q in v.owned()]
  frame_only=[q for q in owned if variables(q)<={str(F)}]
  proofs.append(solve(mode+'_frame_bounds_for_saved_window',frame_only,z3.Or(z3.ULT(F,0x70),z3.UGT(F,resize((1<<64)-1-0x10f0,64)))))
  for role,rows in groups.items():
   if role=='F':continue
   if role=='static':
    for j,r in enumerate(rows):proofs.append(solve(mode+'_static_store_frame_separation_'+str(j),frame_only,z3.Not(norm(protected(F,r)))))
    continue
   B,n=roots[role];allowed={str(F),str(B)};premises=[q for q in owned if variables(q)<=allowed];wanted=z3.And(z3.ULE(B,resize((1<<64)-1-n,64)),z3.Or(z3.ULE(F+0x10f0,B),z3.ULE(B+n,F)))
   proofs.append(solve(mode+'_owner_separation_'+role,premises,z3.Not(wanted)))
  receipts.append({'mode':mode,'parent_source_stores_classified':len(ledger),'source_store_ledger':ledger,'FP_refinement_from_original_prologue_required':True,'opaque_FP_passthrough_preserved':True,'saved_window':'[F+0x1060,F+0x10f0)','native_alias_writer_exclusion_established':False})
 # The composed zero-tag continuation has its own complete affine ledger.
 proofs.append(solve('zero_tag_continuation_preserves_opaque_FP',[],u.read('x29')!=z3.BitVec('TI_initial_X29',64)))
 frame=Frame(e);frame.F=u.sp;proofs.append(solve('zero_tag_frame_plus_explicit_guard_separation_entails_return_ranges',u.owned()+[guard_separation(u.sp)],z3.Or(*[z3.Not(q)for q in frame.owned()])))
 rows=[]
 for r in u.stores:
  a=r['address'];n=r['size_bytes'];hits=[]
  for role,base,extent in u.owners():
   d=z3.simplify(a-base)
   if z3.is_bv_value(d)and d.as_long()+n<=extent:hits.append((role,d.as_long(),extent))
  assert len(hits)==1;role,off,extent=hits[0];assert role!='frame'or off+n<=0x1060;rows.append({'source_PC':hex(r['pc']),'owner':role,'offset_bytes':off,'size_bytes':n})
 # Independent interval facts connect the source-affine ledger with owner separation.
 A,B,J,W=z3.BitVecs('ZR_lemma_A64 ZR_lemma_B64 ZR_lemma_J64 ZR_lemma_W64',64)
 for n in sorted({14,16,32,112,128,4096,4336,16384}):proofs.append(solve('generic_source_subrange_'+str(n),[z3.ULE(B,resize((1<<64)-1-n,64)),W!=0,z3.ULE(W,n),z3.ULE(J,resize(n,64)-W)],z3.Or(z3.ULT(B+J,B),z3.UGT(B+J+W,B+n),z3.ULT(B+J+W,B+J))))
 proofs.append(solve('generic_frame_scratch_and_saved_window_are_disjoint',[z3.UGE(A,0x70),z3.ULE(A,resize((1<<64)-1-0x10f0,64)),z3.ULE(J,0x10d0),W!=0,z3.ULE(W,0x10d0-J)],z3.Not(z3.Or(z3.ULE((A-0x70)+J+W,A+0x1060),z3.ULE(A+0x10f0,(A-0x70)+J)))))
 return proofs,receipts,rows

def frame_proofs(e,u):
 proofs=[];v=prologue(e);bad=[]
 for role,off,writer in R.SAVES:bad.append(frame_cell(v,off)!=(v.saved_guard if role=='guard'else v.signed_link if role=='signed_x30'else v.initial[role]))
 bad.extend([v.read('sp')!=v.F,v.read('x29')!=v.F+0x10e0,v.edges[0]['target']!=pc(0xa5a1cc4),v.edges[0]['modifier']!=pc(0x847c618),v.edges[-1]['target']!=pc(0xa635244),z3.BoolVal(len(v.probe_reads)!=2),*[z3.Not(q)for q in v.address_checks]])
 proofs.append(solve('original_frame_probe_save_and_FP_relation',v.owned()+v.guards,z3.Or(*bad)))
 equal=prepare(e,False,u);premises=equal.owned()+equal.guards+[equal.current_guard==equal.saved_guard]
 proofs.append(solve('equal_guard_selects_local_status_decode',premises,z3.Or(z3.BoolVal(equal.direct_target is not None),*[z3.Not(q)for q in equal.address_checks])))
 n=normal(e,u);proofs.append(solve('normal_return_exact_u32_result_and_restored_frame',n.owned()+n.guards+[n.current_guard==n.saved_guard],z3.Or(n.read('x0')!=RESULT,n.read('sp')!=n.F+0x10f0,*[n.read(r)!=n.initial[r]for r in [*('x'+str(j)for j in range(19,30)),*('d'+str(j)for j in range(8,12))]],n.read('x30')!=n.signed_link,z3.BoolVal(n.stop['PC']!=hex(pc(0xa6662f8))),*[z3.Not(q)for q in n.address_checks])))
 f=failed(e,u);proofs.append(solve('unequal_guard_requests_original_stack_chk_fail',f.owned()+f.guards+[f.current_guard!=f.saved_guard],z3.Or(z3.BoolVal(f.guard_exit_target!=pc(0xa66692c)),f.edges[0]['target']!=pc(0xa69f294),f.edges[-1]['target']!=pc(0xc629694),f.edges[-1]['modifier']!=pc(0x847c478),f.read('x30')!=pc(0xa666930),*[z3.Not(q)for q in f.address_checks])))
 # Exhaustive partition is independent of private status or pointer conditions.
 proofs.append(solve('two_guard_outcomes_exhaustive_disjoint',[],z3.Or(z3.Not(z3.Or(v.current_guard==v.saved_guard,v.current_guard!=v.saved_guard)),z3.And(v.current_guard==v.saved_guard,v.current_guard!=v.saved_guard))))
 return proofs,v,n,f

def frame_footprint(models):
 cells={};static=set();accesses=0
 for v in models:
  for r in v.reads+v.stores:
   accesses+=1;a=z3.simplify(r['address']);d=z3.simplify(a-v.F);n=r['size']
   if z3.is_bv_value(d):
    off=d.as_long();assert off+n<=0x10f0;key=(off,n);cells.setdefault(key,set()).add(hex(r['PC']))
   else:
    assert z3.is_bv_value(a)and (any(b<=a.as_long()and a.as_long()+n<=b+m for b,offset,m in IMAGE.segments)or pc(0xcacb000)<=a.as_long()and a.as_long()+n<=pc(0xcacb008));static.add((hex(r['PC']),hex(a.as_long()),n))
 pairs=0;rows=list(cells)
 for j,(off,n)in enumerate(rows):
  for other,m in rows[j+1:]:assert off+n<=other or other+m<=off;pairs+=1
 return {'frame_cells':[{'offset_bytes':off,'size_bytes':n,'source_PCs':sorted(cells[(off,n)])}for off,n in sorted(cells)],'static_reads':[{'source_PC':p,'address':a,'size_bytes':n}for p,a,n in sorted(static)],'same_frame_disjoint_integer_pairs':pairs,'source_access_instances':accesses,'all_accesses_classified':True,'no_post_workspace_return_context_or_workspace_access':True}

def admissions(e):
 out=[];root=U.entry(json.loads(read(ROOT/'userclient_zero_tag_unwind_checks.json')))
 for mode in P.Parent.MODES:
  v=P.Parent.tag_result(json.loads(read(ROOT/'userclient_fallback_parser_checks.json')),mode);c=v.common;pairs=[(root.plain[j],v.input_bytes[j])for j in range(14)]
  G,H=z3.BitVecs('ZR_admission_saved64 ZR_admission_current64',64)
  for n in range(5):
   for outcome in ['equal','unequal']:
    s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*v.owned(),*v.guards,*v.extra,c['N']==14,c['L']==4,v.read('x29')==c['F']+0x10e0,guard_separation(c['F']),*[z3.substitute(q,*pairs)for q in U.selected(root)],z3.substitute(P.length(root),*pairs)==n,G==H if outcome=='equal'else G!=H);q=s.to_smt2();assert s.check()==z3.sat,(mode,n,outcome,s.reason_unknown());out.append({'name':mode+'_length_'+str(n)+'_'+outcome+'_guard','result':'sat','query':q,'frame_refinement_admitted':True,'additional_frame_guard_separation_assumed':True,'native_reachability_or_guard_equality_established':False});print('admitted '+out[-1]['name'],flush=True)
 return out

def omitted_guard_separation():
 out=[]
 for mode in P.Parent.MODES:
  v=P.Parent.tag_result(json.loads(read(ROOT/'userclient_fallback_parser_checks.json')),mode);F=v.common['F'];s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*v.owned(),*v.guards,*v.extra,F==pc(0xcacb000)-0x1060,v.read('x29')==F+0x10e0);q=s.to_smt2();assert s.check()==z3.sat,(mode,s.reason_unknown());out.append({'name':mode+'_old_model_permits_guard_overlap','result':'sat','query':q,'old_frame_ownership_does_not_entail_guard_separation':True,'native_frame_guard_alias_established':False});print('confirmed omitted guard separation '+mode,flush=True)
 return out

def controls(e,u):
 out=[]
 for at,name in [(0xa6662cc,'status_decode'),(0xa6662c8,'guard_branch'),(0xa6662d8,'saved_FP_link_pair')]:
  x=copy.deepcopy(e);a=pc(at);r=next(s for s in x['source']['spans']if int(s['start'],16)<=a<int(s['end_exclusive'],16));raw=bytearray.fromhex(r['bytes_hex']);off=a-int(r['start'],16);old=bytes(raw[off:off+4]);word=int.from_bytes(old,'little');new=((word&~(0x7f<<15))|(12<<15)).to_bytes(4,'little')if name=='saved_FP_link_pair'else bytes.fromhex('1f2003d5');raw[off:off+4]=new;r['bytes_hex']=raw.hex()
  if name=='guard_branch':v=prepare(x,True,u);premises=v.owned()+v.guards+[v.current_guard!=v.saved_guard];bad=z3.BoolVal(v.direct_target!=pc(0xa66692c))
  else:
   v=normal(x,u);premises=v.owned()+v.guards+[v.current_guard==v.saved_guard];bad=v.read('x0')!=RESULT if name=='status_decode'else z3.Or(v.read('x29')!=v.initial['x29'],v.read('x30')!=v.signed_link)
  s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*premises,*v.address_checks);assert s.check()==z3.sat,(name,'premises');s.add(bad);q=s.to_smt2();assert s.check()==z3.sat,name;out.append({'kind':name,'mutated_PC':hex(a),'original_word_hex':old.hex(),'replacement_word_hex':new.hex(),'normal_oracle_rejected':True,'satisfiable_violation_query':q,'native_target_executed':False});print('rejected mutation '+name,flush=True)
 return out

def audit(e=None):
 e=e if e is not None else json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();u,_=U.compose(json.loads(read(ROOT/'userclient_zero_tag_unwind_checks.json')));proofs,frames,continuation=preservation(e,u);other,entry,n,f=frame_proofs(e,u);proofs+=other;admitted=admissions(e);omitted=omitted_guard_separation();negative=controls(e,u);prior=[];old=json.loads(read(ROOT/'userclient_zero_tag_unwind_audit.json'))
 for field in ['source_proofs','projection_proofs','source_entailed_domain_proofs','prefix_proofs']:
  for p in old[field]:
   ctx=z3.Context();s=z3.SolverFor('QF_BV',ctx=ctx);s.set(timeout=120000);s.add(*z3.parse_smt2_string(p['query'],ctx=ctx));assert s.check()==z3.unsat,(p['name'],s.reason_unknown());prior.append({'name':p['name'],'result':'unsat','source_audit_sha256':sha(ROOT/'userclient_zero_tag_unwind_audit.json')});print('rechecked predecessor '+str(len(prior))+' '+p['name'],flush=True)
 footprint=frame_footprint([entry,n,f]);pcs=entry.visited|n.visited|f.visited;captured={int(i['pc'],16)for s in e['source']['spans']for i in s['instructions']};assert pcs==captured
 totals={'new_source_queries_unsat':len(proofs),'prior_queries_unsat':len(prior),'frame_refined_actual_cut_admission_SAT_queries':len(admitted),'omitted_guard_separation_SAT_queries':len(omitted),'negative_source_controls':len(negative),'new_source_words_covered':len(pcs),'carried_source_words':len(u.visited),'combined_source_words':len(pcs|u.visited),'normal_exit_source_words':len(n.visited),'failure_exit_source_words':len(f.visited),'frame_probe_instruction_instances':entry.count,'parent_source_stores_classified':sum(p['parent_source_stores_classified']for p in frames),'continuation_source_stores_classified':len(continuation),'prefix_saved_cells':510,'prefix_saved_bytes':4080,'original_probe_byte_reads':len(entry.probe_reads),'workspace_return_premises':1,'native_target_calls':0,'input_content_bytes_supplied':0}
 return {'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],'kernel_collection_sha256':e['kernel_collection_sha256'],'scope':e['scope'],'dependencies':e['dependencies'],'verified_counts':e['verified_counts'],'source_proofs':proofs,'rechecked_prior_proofs':prior,'actual_cut_admission_checks':admitted,'omitted_guard_separation_checks':omitted,'negative_source_controls':negative,'frame_preservation_certificates':frames,'continuation_store_ledger':continuation,'frame_access_footprint':footprint,'workspace_return_premise':n.returns[0],'guard_value_model':{'saved':'independent_symbolic_64_bits','current':'independent_symbolic_64_bits','equality_assumed_only_for_normal_exit':True,'native_equality_established':False},'normal_exit':{'local_result_u32':hex(RESULT),'X0_zero_extended':True,'SP_delta_bytes':0x10f0,'restored_GPRs':list(range(19,30)),'restored_D_low64':list(range(8,12)),'signed_link_custody_preserved':True,'RETAB_boundary':n.stop},'failure_exit':{'source_BL':hex(pc(0xa66692c)),'nominal_link':hex(pc(0xa666930)),'veneer':hex(pc(0xa69f294)),'target':hex(pc(0xc629694)),'modifier':hex(pc(0x847c478)),'native_callee_effects_established':False},'prologue_PAC_event':entry.pac_events[0],'proved_pcs':sorted(map(hex,pcs)),'independent_totals':totals,'all_checks_pass':True,'conditional_zero_tag_return_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
