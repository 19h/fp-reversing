#!/usr/bin/env python3
"""Certify a finite live-state projection, then lift the protected continuation.
O(I+C*W+query DAG) construction/space; SMT search has per-query limits.
"""
import copy,json
import z3
from kext_port_tools import ROOT,IMAGE,TABLE,qword
from lskd_values_symbolic import resize,mem
from verify_daemon_reader_record_payloads_publication import read,sha
import audit_userclient_record_metadata as M
import audit_userclient_fallback_parser as Parent
import recover_userclient_fallback_metadata as R
DEC=M.DEC;SUCCESS=M.SUCCESS;pc=R.pc

class Model(M.Model):
 def owned(self):
  spans=[(self.sp,0x10f0),(self.ctx,4096),(self.src,16384),(self.buffer,14),(self.object,16)]
  out=[(self.sp&15)==0]
  for j,(a,n)in enumerate(spans):
   out.extend([a!=0,z3.ULE(a,resize((1<<64)-1-n,64))])
   for b,m in spans[j+1:]:out.append(z3.Or(z3.ULE(a+n,b),z3.ULE(b+m,a)))
   for b,off,m in IMAGE.segments:out.append(z3.Or(z3.ULE(a+n,b),z3.ULE(b+m,a)))
  return out
 def read(self,r):
  if getattr(self,'tracking',False)and r not in ['xzr','wzr']:
   root='x'+r[1:]if r.startswith('w')else r
   if root not in self.written_regs:self.live_regs.add(r)
  return super().read(r)
 def write(self,r,value):
  if getattr(self,'tracking',False):self.written_regs.add('x'+r[1:]if r.startswith('w')else r)
  return super().write(r,value)
 def load(self,a,n):
  aa=z3.simplify(a)
  if self.pc in R.BRANCHES:
   assert n==8;js=R.BRANCHES[self.pc];self.address_checks.append(z3.Or(*[a==TABLE+8*j for j in js]));value=resize(0,64)
   for j in js:value=z3.If(a==TABLE+8*j,resize(qword(TABLE+8*j),64),value)
   self.accesses.append({'PC':self.pc,'address':a,'size':n,'kind':'original_pointer_table','write':False});return value
  if self.pc in M.WORD_BYTES|M.TYPE_BYTES:
   j=self.byte_offsets[self.byte_pos];self.protected_reads.append(j);value=super().load(a,n)
   self.accesses.append({'PC':self.pc,'address':a,'size':n,'kind':'protected_buffer','write':False});return value
  key=(aa.sexpr(),n);assert key in self.memory,('unclosed_read',hex(self.pc),str(aa),n)
  value=self.memory[key]
  if key not in self.written_cells:
   assert key in self.entry_memory
   self.live_cells.setdefault(key,{'address':aa,'size':n,'value':self.entry_memory[key],'PC':self.pc})
  self.accesses.append({'PC':self.pc,'address':a,'size':n,'kind':'saved_cell','write':False});return value
 def store(self,a,n,value,source_pc):
  self.written_cells.add((z3.simplify(a).sexpr(),n));self.accesses.append({'PC':source_pc,'address':a,'size':n,'kind':'saved_cell','write':True})
  return super().store(a,n,value,source_pc)
 def run(self,label,end=None):
  row=next(s for s in self.e['spans']if s['label']==label);skip=None;self.tracking=True;original=self.e
  try:
   for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
    if end is not None and i.address>=end:break
    if i.address==skip:continue
    self.pc=i.address
    if i.mnemonic in ['bti','nop','braa']or i.address in R.RETAGS:
     self.visited.add(i.address);self.count+=1
     if i.mnemonic=='braa':
      self.edges.append({'PC':i.address,'target':self.read(i.reg_name(i.operands[0].reg)),'modifier':self.read(i.reg_name(i.operands[1].reg))});break
     if i.address in R.RETAGS:
      assert i.mnemonic=='b.eq'and i.operands[0].imm&((1<<64)-1)==i.address+8
      self.normal_guards.append(self.equal);self.branch_guards.append(self.equal);skip=R.RETAGS[i.address]
    else:
     self.e={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};M.Model.run(self,'one');self.e=original
     if i.mnemonic.startswith('b.')and self.branch_choices.get(i.address,False):break
  finally:self.e=original;self.tracking=False
  return self

def entry(e):
 old=json.loads(read(ROOT/'userclient_record_metadata_checks.json'));v=M.setup(old)
 v.cursor=resize(0,64);v.outer=resize(14,32);mem(v,v.sp+0xa80,8,0);mem(v,v.src+0xc8c,4,14^SUCCESS)
 for label in ['parser_cursor_gate','parser_input_gate','header_extent','header_prepare','word_bridge']:v.run(label)
 v.decode(range(4));v.run('tag_return',end=pc(0xa638dc8))
 for off,value in [(0x188,v.ctx+0x600),(0x5c8,pc(0xa656c08)),(0x600,0)]:mem(v,v.ctx+off,8,value)
 mem(v,v.object,8,0);mem(v,v.object+8,8,0)
 v.__class__=Model;v.e={'spans':copy.deepcopy(e['source']['spans'])};v.c=v.e;v.branch_guards=[];v.address_checks=[];v.visited=set();v.count=0;v.stores=[];v.edges=[];v.protected_reads=[];v.normal_guards=[];v.tracking=False;v.written_regs=set();v.written_cells=set();v.live_regs=set();v.live_cells={};v.accesses=[];v.entry_memory=copy.copy(v.memory);v.entry_regs=copy.copy(v.regs)
 return v
def edge(v,target,modifier):return z3.Or(v.edges[-1]['target']!=pc(target),v.edges[-1]['modifier']!=modifier)
def add_edge(v,target,modifier):v.address_checks.append(z3.Not(edge(v,target,modifier)))
def typed(e):
 v=entry(e).run('tag_tail');add_edge(v,0xa63930c,0x9c55);v.decode(range(4,6));return v
def length_request(e):
 v=typed(e);add_edge(v,0xa639dc0,0x1086);v.run('type_return');add_edge(v,0xa637128,0x266f);v.run('length_bridge');return v
def decoded(e):
 v=length_request(e);add_edge(v,0xa637138,0xf930);v.decode(range(6,10));return v
def extent(e):
 v=decoded(e);add_edge(v,0xa6390b4,0xb745);v.run('length_extent');return v
def selected(e):
 v=extent(e);add_edge(v,0xa639164,0x685a);v.branch_choices[pc(0xa639174)]=True;v.run('type_first_gate');v.address_checks.append(z3.BoolVal(v.direct_target==pc(0xa63a784)))
 v.branch_choices[pc(0xa63a78c)]=True;v.run('type_selected_gate');v.address_checks.append(z3.BoolVal(v.direct_target==pc(0xa63dc9c)));return v
def metadata(e):
 v=selected(e).run('body_publish');add_edge(v,0xa63dcd0,0xa174);v.run('metadata_return');add_edge(v,0xa6423c0,0xdfc5);v.run('metadata_outcome_gate');return v
def kind_gate(e):
 v=metadata(e);add_edge(v,0xa6423f4,0xc9dc);v.run('record_kind_gate');return v
def published(e):
 v=kind_gate(e);add_edge(v,0xa6421b0,0x5ab2);v.run('success');add_edge(v,0xa660ac8,0x8ba3);v.run('publish');add_edge(v,0xa660ae0,0xcd46);v.run('resume');return v
def tag(v):return z3.Concat(*v.plain[:4])
def kind(v):return M.kind(v)
def length(v):return M.length(v)
def bounded(v):return z3.ULE(length(v),4)
def cell(v,a,n):return M.cell(v,a,n)
def chosen(v):return [bounded(v),kind(v)==0x6685]

def solve(name,premises,bad,timeout=60000):
 s=z3.SolverFor('QF_BV');s.set(timeout=timeout);s.add(*premises);r=s.check();assert r==z3.sat,(name,'vacuous',str(r),s.reason_unknown());s.add(z3.simplify(bad));q=s.to_smt2();r=s.check();assert r==z3.unsat,(name,str(r),s.reason_unknown(),s.model()if r==z3.sat else'')
 print('proved '+name,flush=True);return {'name':name,'result':'unsat','premises_nonvacuous':True,'query':q}

def prefix_proof(e):
 from audit_userclient_early_header import Lift
 from audit_userclient_entry_execution import proof
 v=Lift({'spans':[e['prefix_source']]});F,C=z3.BitVecs('FM_prefix_F64 FM_prefix_C64',64);v.seed('sp',F);v.seed('x2',C);v.run('input_alias_root');return proof('original_staged_input_alias',v,cell(v,F+0x890,8)!=C+0x3d8)

def projection(e,models):
 root=entry(e);regs=sorted(set().union(*(v.live_regs for v in models.values())));cells={k:x for v in models.values()for k,x in v.live_cells.items()};normal={z3.simplify(g).sexpr():g for v in models.values()for g in v.normal_guards};proofs=[];domains=[];receipts=[];admissions=[]
 for mode in Parent.MODES:
  actual=Parent.tag_result(json.loads(read(ROOT/'userclient_fallback_parser_checks.json')),mode);c=actual.common;at=c['F']+0x890;key=(z3.simplify(at).sexpr(),8);assert key not in actual.memory;mem(actual,at,8,c['C']+0x3d8)
  premises=actual.owned()+actual.guards+actual.extra;domains.append(solve(mode+'_entailed_N14_L4',premises,z3.Or(c['N']!=14,c['L']!=4)))
  premises+=[c['N']==14,c['L']==4]
  pairs=[(root.sp,c['F']),(root.ctx,c['C']),(root.src,c['S']),(root.buffer,actual.buffer),(root.object,actual.typed)]+[(root.plain[j],actual.input_bytes[j])for j in range(10)]+[(z3.BitVec('TI_initial_X'+str(j),64),actual.read('x'+str(j)))for j in range(31)]
  def mapped(x):return z3.simplify(z3.substitute(x,*pairs))
  items=[('reg_'+r,mapped(root.read(r))!=actual.read(r))for r in regs]
  items += [('cell_'+str(j),Parent.H.cell(actual,mapped(x['address']),x['size'])!=mapped(root.entry_memory[k]))for j,(k,x)in enumerate(cells.items())]
  for off,n in [(0x600,8),(0x228,8)]:items.append(('side_context_'+hex(off),Parent.H.cell(actual,c['C']+off,n)!=mapped(cell(root,root.ctx+off,n))))
  for off in [0,8]:items.append(('side_empty_container_'+str(off),Parent.H.cell(actual,actual.typed+off,8)!=mapped(cell(root,root.object+off,8))))
  for j in range(10):
   row=next(r for r in actual.fallback_copy_stores if r['index']==j);items.append(('protected_byte_'+str(j),z3.Or(row['address']!=actual.buffer+j,row['value']!=mapped(root.plain[j]^M.mask(root.buffer+j,resize(M.KEY0,64))))))
  items.append(('weaker_live_ownership',z3.Or(*[z3.Not(mapped(q))for q in root.owned()])))
  items.append(('entailed_normal_pointer_guards',z3.Or(*[z3.Not(mapped(g))for g in normal.values()])))
  for label,bad in items:
   normalized=z3.simplify(z3.substitute(bad,(c['N'],resize(14,32)),(c['L'],resize(4,32))));proofs.append(solve(mode+'_projection_'+label,premises,normalized))
  profiles=[('oversized',z3.Not(bounded(root))),('first_type_a129',z3.And(bounded(root),kind(root)==0xa129)),('other_type',z3.And(bounded(root),kind(root)!=0xa129,kind(root)!=0x6685)),('selected_zero_tag',z3.And(*chosen(root),tag(root)==0)),('selected_nonzero_tag',z3.And(*chosen(root),tag(root)!=0)),('zero_length_selected_zero_tag',z3.And(*chosen(root),tag(root)==0,length(root)==0)),('four_byte_selected_zero_tag',z3.And(*chosen(root),tag(root)==0,length(root)==4)),('max_u32_length',length(root)==0xffffffff)]
  for name,condition in profiles:
   s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*premises,mapped(condition));q=s.to_smt2();assert s.check()==z3.sat,(mode,name,s.reason_unknown());admissions.append({'name':mode+'_'+name,'result':'sat','query':q,'native_reachability_established':False});print('admitted '+mode+'_'+name,flush=True)
  receipts.append({'mode':mode,'entry_PC':hex(pc(0xa638dc8)),'live_register_views':regs,'live_saved_cells':[{'first_read_PC':hex(x['PC']),'address_expression':x['address'].sexpr(),'size_bytes':x['size']}for x in cells.values()],'side_empty_container_fields':2,'source_written_protected_bytes':10,'original_prefix_alias_reconstructed':True,'ordinary_surviving_storage_preservation_assumed':True})
 return proofs,domains,receipts,admissions,len(regs),len(cells),len(normal)

def source_proofs(e):
 proofs=[];models={};coverage=[];visited=set()
 def prove(name,v,bad,extra=()):
  saved=z3.Or(*[z3.Not(q)for q in v.address_checks]);proofs.append(solve(name,v.owned()+v.branch_guards+list(extra),z3.Or(saved,bad)));models[name]=v;visited.update(v.visited);coverage.append({'name':name,'instruction_instances':v.count,'stores':len(v.stores),'protected_read_indices':v.protected_reads})
 v=typed(e);prove('remaining_two_header_bytes_decode_transformed_type',v,z3.Or(z3.Extract(15,0,v.read('w8'))!=kind(v),cell(v,v.src+0xa18,4)!=(tag(v)^SUCCESS),edge(v,0xa639dc0,0x1086)))
 v=length_request(e);prove('stored_type_and_word_reader_request_at_original_offset_six',v,z3.Or(cell(v,v.src+0x2a0,2)!=kind(v),v.read('x8')!=v.buffer,v.read('x10')+v.read('x1')!=6,edge(v,0xa637138,0xf930)))
 v=decoded(e);prove('all_ten_header_bytes_decode_length_separate_from_tag',v,z3.Or(v.read('w22')!=(length(v)^SUCCESS),edge(v,0xa6390b4,0xb745)))
 v=extent(e);prove('all_u32_lengths_exact_body_fit_without_wrap',v,z3.Or(cell(v,v.src+0xcf8,8)!=10+z3.ZeroExt(32,length(v)),cell(v,v.src+0xa64,4)!=(length(v)^SUCCESS),v.read('x11')!=10,v.edges[-1]['target']!=z3.If(bounded(v),resize(pc(0xa639164),64),resize(pc(0xa6423c0),64)),v.edges[-1]['modifier']!=0x685a,z3.UGT(cell(v,v.src+0xcf8,8),(1<<32)+9)))
 v=extent(e);add_edge(v,0xa6423c0,0x685a);v.run('metadata_outcome_gate');prove('oversized_body_selects_failure_without_cursor_commit',v,z3.Or(cell(v,v.sp+0xa80,8)!=0,v.read('w10')!=0,v.read('w23')!=0xce515bb8,edge(v,0xa662440,0xc9dc),cell(v,v.ctx+0x600,8)!=0),[z3.Not(bounded(v))])
 for first,take in [('a129',False),('other',True)]:
  v=extent(e);add_edge(v,0xa639164,0x685a);v.branch_choices[pc(0xa639174)]=take;v.run('type_first_gate');prove('first_type_gate_'+first,v,z3.Or(z3.BoolVal((v.direct_target==pc(0xa63a784))!=take),kind(v)==0xa129 if take else kind(v)!=0xa129),[bounded(v)])
 for label,take in [('6685',True),('remaining',False)]:
  v=extent(e);add_edge(v,0xa639164,0x685a);v.branch_choices[pc(0xa639174)]=True;v.run('type_first_gate');v.branch_choices[pc(0xa63a78c)]=take;v.run('type_selected_gate');prove('second_type_gate_'+label,v,z3.Or(z3.BoolVal((v.direct_target==pc(0xa63dc9c))!=take),kind(v)!=0x6685 if take else kind(v)==0x6685),[bounded(v),kind(v)!=0xa129])
 v=metadata(e);n=cell(v,v.sp+0xa80,8);prove('selected_type_bounded_payload_and_committed_metadata',v,z3.Or(cell(v,v.ctx+0x280,8)!=v.buffer+10,n!=10+z3.ZeroExt(32,length(v)),cell(v,v.src+0xaec,4)!=(tag(v)^SUCCESS),cell(v,v.src+0xa08,2)!=0x6685,cell(v,v.src+0x9e8,4)!=(length(v)^SUCCESS),v.read('w10')!=1,v.read('w23')!=SUCCESS,edge(v,0xa6423f4,0xc9dc),z3.UGT(n,14),z3.ULT(n,10)),chosen(v))
 prove('selected_payload_half_open_interval_and_wire_type',v,z3.Or(cell(v,v.ctx+0x280,8)+z3.ZeroExt(32,length(v))!=v.buffer+n,z3.UGT(v.buffer+n,v.buffer+14),z3.ULT(v.buffer+10,v.buffer),z3.Concat(*v.plain[4:6])!=0x50db),chosen(v))
 v=kind_gate(e);prove('zero_tag_selects_private_success',v,edge(v,0xa6421b0,0x5ab2),chosen(v)+[tag(v)==0])
 prove('nonzero_tag_selects_ordinary_record_construction',v,edge(v,0xa642454,0x5ab2),chosen(v)+[tag(v)!=0])
 v=published(e);prove('zero_tag_publishes_empty_container_and_resumes_saved_caller',v,z3.Or(cell(v,v.ctx+0x600,8)!=v.object,cell(v,v.object,8)!=0,cell(v,v.object+8,8)!=0,cell(v,v.ctx+0x228,8)!=v.object,cell(v,v.src+0xc10,4)!=SUCCESS,v.read('w23')!=SUCCESS,cell(v,v.sp+0xa80,8)!=10+z3.ZeroExt(32,length(v)),edge(v,0xa656c08,0x481b)),chosen(v)+[tag(v)==0])
 prove('zero_tag_success_can_leave_one_to_four_suffix_bytes',v,z3.Or(z3.UGE(cell(v,v.sp+0xa80,8),14),edge(v,0xa656c08,0x481b)),chosen(v)+[tag(v)==0,z3.ULT(length(v),4)])
 prove('zero_length_body_consumes_only_ten_header_bytes',v,cell(v,v.sp+0xa80,8)!=10,chosen(v)+[tag(v)==0,length(v)==0])
 prove('four_byte_body_consumes_the_whole_selected_extent',v,cell(v,v.sp+0xa80,8)!=14,chosen(v)+[tag(v)==0,length(v)==4])
 root=entry(e);ledger=footprint_proofs(root,models,proofs)
 partitions=[z3.Not(bounded(root)),z3.And(bounded(root),kind(root)==0xa129),z3.And(bounded(root),kind(root)!=0xa129,kind(root)!=0x6685),z3.And(*chosen(root),tag(root)==0),z3.And(*chosen(root),tag(root)!=0)]
 overlap=[z3.And(a,b)for j,a in enumerate(partitions)for b in partitions[j+1:]]
 proofs.append(solve('first_two_type_gates_and_tag_split_are_exhaustive_disjoint',root.owned(),z3.Or(z3.Not(z3.Or(*partitions)),*overlap)))
 captured={int(i['pc'],16)for s in e['source']['spans']for i in s['instructions']};assert captured-visited==set(R.RETAGS.values()),{'missing':list(map(hex,captured-visited)),'extra':list(map(hex,visited-captured))};assert not visited-captured
 return proofs,models,coverage,len(visited),ledger

def footprint_proofs(root,models,proofs):
 # Certify source-affine cells first; prove interval arithmetic independently
 # of the unrelated decoder conditions. No additional storage premise is used.
 owners=[('frame',root.sp,0x10f0),('context',root.ctx,4096),('workspace',root.src,16384),('protected_buffer',root.buffer,14),('typed_container',root.object,16)];ledger={};static=[]
 for v in models.values():
  for row in v.accesses:
   if row['kind']=='original_pointer_table':
    for j in R.BRANCHES[row['PC']]:
     at=TABLE+8*j;assert any(a<=at and at+8<=a+m for a,off,m in IMAGE.segments)
    static.append(hex(row['PC']));continue
   candidates=[]
   for name,base,extent in owners:
    delta=z3.simplify(row['address']-base)
    if z3.is_bv_value(delta)and delta.as_long()+row['size']<=extent:candidates.append((name,delta.as_long(),extent))
   assert len(candidates)==1,('unclassified_address',hex(row['PC']),str(row['address']))
   name,off,extent=candidates[0];assert not row['write']or name in ['frame','context','workspace'];assert row['kind']!='protected_buffer'or name=='protected_buffer'
   key=(name,off,row['size']);r=ledger.setdefault(key,{'owner':name,'owner_extent_bytes':extent,'offset_bytes':off,'size_bytes':row['size'],'source_PCs':set(),'written':False,'read':False});r['source_PCs'].add(hex(row['PC']));r['written']|=row['write'];r['read']|=not row['write']
 for off in [0,8]:ledger[('typed_container',off,8)]={'owner':'typed_container','owner_extent_bytes':16,'offset_bytes':off,'size_bytes':8,'source_PCs':set(),'written':False,'read':False,'entry_side_fact_only':True}
 cells=list(ledger.values());same_owner_checks=0
 for j,a in enumerate(cells):
  for b in cells[j+1:]:
   if a['owner']==b['owner']:
    assert a['offset_bytes']+a['size_bytes']<=b['offset_bytes']or b['offset_bytes']+b['size_bytes']<=a['offset_bytes'];same_owner_checks+=1
 A,J,W=z3.BitVecs('FM_interval_base64 FM_interval_offset64 FM_interval_width64',64)
 for extent in sorted({n for name,base,n in owners}):
  premises=[A!=0,z3.ULE(A,resize((1<<64)-1-extent,64)),W!=0,z3.ULE(W,extent),z3.ULE(J,resize(extent,64)-W)]
  proofs.append(solve('generic_owned_interval_'+str(extent),premises,z3.Or(z3.ULT(A+J,A),z3.UGT(A+J+W,A+extent),z3.ULT(A+J+W,A+J))))
 B,N,H,X,Y,V=z3.BitVecs('FM_sep_B64 FM_sep_N64 FM_sep_H64 FM_sep_X64 FM_sep_Y64 FM_sep_V64',64);maximum=resize((1<<64)-1,64)
 premises=[N!=0,H!=0,W!=0,V!=0,z3.ULE(A,maximum-N),z3.ULE(B,maximum-H),z3.Or(z3.ULE(A+N,B),z3.ULE(B+H,A)),z3.UGE(X,A),z3.ULE(X,maximum-W),z3.ULE(X+W,A+N),z3.UGE(Y,B),z3.ULE(Y,maximum-V),z3.ULE(Y+V,B+H)]
 proofs.append(solve('generic_disjoint_owner_subranges_remain_disjoint',premises,z3.Not(z3.Or(z3.ULE(X+W,Y),z3.ULE(Y+V,X)))))
 return {'cells':[dict(r,source_PCs=sorted(r['source_PCs']))for r in sorted(cells,key=lambda r:(r['owner'],r['offset_bytes'],r['size_bytes']))],'same_owner_disjoint_integer_pairs':same_owner_checks,'cross_owner_separation_in_entry_ownership':True,'static_pointer_read_PCs':sorted(set(static)),'all_accesses_classified':True,'no_continuation_store_to_B_or_T':True}

def controls(e):
 out=[]
 for at,label,factory,oracle,extra in [
  (0xa6393bc,'type_transform',typed,lambda v:z3.Extract(15,0,v.read('w8'))!=kind(v),lambda v:[]),
  (0xa63dce0,'cursor_commit',metadata,lambda v:cell(v,v.sp+0xa80,8)!=10+z3.ZeroExt(32,length(v)),chosen),
  (0xa660ad0,'output_publication',published,lambda v:cell(v,v.ctx+0x600,8)!=v.object,lambda v:chosen(v)+[tag(v)==0])]:
  x=copy.deepcopy(e);a=pc(at);row=next(s for s in x['source']['spans']if int(s['start'],16)<=a<int(s['end_exclusive'],16));raw=bytearray.fromhex(row['bytes_hex']);off=a-int(row['start'],16);old=bytes(raw[off:off+4]);raw[off:off+4]=bytes.fromhex('1f2003d5');row['bytes_hex']=raw.hex();v=factory(x);s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*v.owned(),*v.branch_guards,*extra(v),*v.address_checks);assert s.check()==z3.sat,(label,'premises');s.add(oracle(v));q=s.to_smt2();assert s.check()==z3.sat,label;out.append({'kind':label,'mutated_PC':hex(a),'original_word_hex':old.hex(),'replacement_word_hex':'1f2003d5','normal_oracle_rejected':True,'satisfiable_violation_query':q,'native_target_executed':False});print('rejected mutation '+label,flush=True)
 return out

def audit(e=None):
 e=e if e is not None else json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();prefix=prefix_proof(e);proofs,models,coverage,covered,ledger=source_proofs(e);projections,domains,interfaces,admissions,nregs,ncells,nguards=projection(e,models);negative=controls(e);prior=[]
 old=json.loads(read(ROOT/'userclient_fallback_parser_audit.json'))
 for p in old['source_proofs']:
  if not p['semantic_contract'].endswith('_tag_result'):continue
  ctx=z3.Context();s=z3.SolverFor('QF_BV',ctx=ctx);s.set(timeout=120000);s.add(*z3.parse_smt2_string(p['query'],ctx=ctx));assert s.check()==z3.unsat,(p['name'],s.reason_unknown());prior.append({'name':p['name'],'result':'unsat','source_audit_sha256':sha(ROOT/'userclient_fallback_parser_audit.json')});print('rechecked predecessor '+str(len(prior))+' '+p['name'],flush=True)
 totals={'new_source_queries_unsat':len(proofs),'semantic_contracts':len(models),'projection_queries_unsat':len(projections),'source_entailed_domain_queries_unsat':len(domains),'actual_cut_admission_SAT_queries':len(admissions),'prefix_queries_unsat':1,'prior_source_queries_unsat':len(prior),'new_source_words_covered':covered,'alternate_retag_words':len(R.RETAGS),'negative_source_controls':len(negative),'composed_modes':2,'live_register_views':nregs,'live_saved_cells':ncells,'entailed_normal_pointer_guards':nguards,'additional_prefix_cells':30,'additional_prefix_bytes':240,'header_bytes':10,'new_header_byte_reads':6,'native_target_calls':0,'input_content_bytes_supplied':0}
 return {'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],'kernel_collection_sha256':e['kernel_collection_sha256'],'scope':e['scope'],'dependencies':e['dependencies'],'verified_counts':e['verified_counts'],'source_proofs':proofs,'projection_proofs':projections,'source_entailed_domain_proofs':domains,'actual_cut_admission_checks':admissions,'prefix_proofs':[prefix],'negative_source_controls':negative,'rechecked_prior_source_proofs':prior,'live_interfaces':interfaces,'memory_footprint':ledger,'proof_coverage':coverage,'proved_pcs':sorted(map(hex,set().union(*(v.visited for v in models.values())))),'selected_completion_edges':[{'source_PC':hex(r['PC']),'target_expression':r['target'].sexpr(),'modifier_expression':r['modifier'].sexpr()}for r in models['zero_tag_publishes_empty_container_and_resumes_saved_caller'].edges],'independent_totals':totals,'all_checks_pass':True,'conditional_fallback_metadata_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
