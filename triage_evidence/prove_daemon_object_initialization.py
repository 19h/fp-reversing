#!/usr/bin/env python3
"""Original source proofs of cursor,cache/mask,mixer,fields and sampler steps.
O(lifted instructions+solver resources) time/space;30 s/query. Owner/frame and
publication-preservation premises are explicit. No native APIs or PAC execute.
"""
import json
from pathlib import Path
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64_const import ARM64_SFT_ROR
from daemon_receive_tools import ROOT,TABLE
from recover_daemon_object_creation import sha,span
from prove_daemon_registry_lookup import RegistryLift
from lskd_values_symbolic import part,mem,cell,resize
from daemon_object_initialization_model import word,rotate
class InitLift(RegistryLift):
 def operand(self,i,o,n):
  if o.shift.type==ARM64_SFT_ROR:return z3.RotateRight(resize(self.read(i.reg_name(o.reg)),n),o.shift.value)
  return super().operand(i,o,n)
 def run(self,label):
  row=next(s for s in self.c['spans']if s['label']==label);old=self.c;cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
  for i in cs.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   self.pc=i.address;o=i.operands;m=i.mnemonic
   if m=='sxtw':self.write(i.reg_name(o[0].reg),z3.SignExt(32,self.read(i.reg_name(o[1].reg))));self.count+=1
   elif m=='ldrsw':self.write(i.reg_name(o[0].reg),z3.SignExt(32,resize(self.load(self.address(i,o[1]),4),32)));self.count+=1
   elif m=='ror':self.write(i.reg_name(o[0].reg),z3.RotateRight(self.read(i.reg_name(o[1].reg)),o[2].imm));self.count+=1
   else:self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};RegistryLift.run(self,'one')
  self.c=old;return self
def obligations(context):
 c={'spans':context['spans']+[span(n,a,z)for n,a,z in [('sampler_step',0x100b8e7e0,0x100b8e800),('sampler_gate',0x100b8e800,0x100b8e814),('window_reader',0x100b8e774,0x100b8e7a8),('port_read',0x100bd7204,0x100bd720c),('object_word_codec',0x100b1e860,0x100b1e90c)]]};qs=[];counts={};F=0x6800050000;O=0x6800005000;B=0x6800030000;S=F+0x3a20;A,T,Q,R=z3.BitVecs('init_address64 init_cached64 init_counter64 init_return64',64);H,M,PORT,CAND,CTR,LIMIT,PHASE=z3.BitVecs('init_classifier32 init_mask32 init_port32 init_candidate32 init_cursor32 init_limit32 init_phase32',32)
 def run(n,a,z,seeds=(),memory=()):
  v=InitLift(part(c,n,a,z))
  for reg,x in seeds:v.seed(reg,x)
  for at,nb,x in memory:mem(v,at,nb,x)
  v.run(n);counts[n]=v.count;return v
 def add(n,p,pre=z3.BoolVal(True)):qs.append((n,z3.And(pre,p)))
 p=run('cursor',0x100a59d74,0x100a59d84,[('sp',F)]);add('source_cursor48_and_second_cursor32',z3.Or(cell(p,F+0x3620,8)!=48,cell(p,F+0x3690,8)!=32))
 setup=run('bump',0x1006534bc,0x100653514,[('sp',F),('x0',O),('x22',R),('w19',0x1fd7)],[(F+0x3620,8,Q)]);add('all_u64_scratch_bump_and_saved_object',z3.Or(setup.read('w8')!=0x47f8,setup.read('w12')!=0x48df,cell(setup,F+0x3620,8)!=Q+640,cell(setup,F+0x32b0,8)!=F+0x39f0+Q,cell(setup,F+0x2fc0,8)!=F+0x39f0+Q+48,cell(setup,F+0x2a68,8)!=O))
 load=run('cache_load',0x100653514,0x100653524,[('sp',F),('x21',0x1010c8268),('x30',TABLE),('w12',0x48df)],[(F+0x2720,8,0x1010c67d4),(0x1010c67d4,4,M),(0x1010c8268,8,B),(TABLE+0x48df*8,8,0x100a19bb8)]);add('all_u32_signed_mask_and_cache_pointer',z3.Or(load.read('x11')!=z3.SignExt(32,M),load.read('x12')!=B))
 const=run('constants',0x100653524,0x100653644,[('sp',F),('x9',S),('x8',0x47f8),('x30',TABLE)]);names=['x'+str(j)for j in range(8)]+['x15','x16','x20','x22','x23','x24','x26','x27'];constants={n:z3.simplify(const.read(n)).as_long()for n in names};add('source_mixer_phase_and_selector',z3.Or(cell(const,F+0x2a70,8)!=0xae4,const.read('x13')!=S*8,const.read('x30')!=S,const.read('x19')!=TABLE))
 address=run('table_address',0x100a19bb8,0x100a19bdc,[('x30',A),('x11',255),('x12',B)]);idx=z3.simplify(address.read('x17')-B);add('all_u64_table_offsets_in_first256',z3.Or(z3.UGT(idx,248),idx&7!=0));add('aligned_address_table_index',idx!=z3.ZeroExt(32,(resize(A,32)+0x466d4638)&255),A&7==0)
 seeds=[('x25',rotate(A,8)),('x17',T),('x9',S),('x10',Q),('x13',(S+Q)*8)]+list(constants.items());body=run('mixer',0x100a19be0,0x100a19cac,seeds);raw=word(A,T,constants,False);add('all_address_cached_word_original_mixer',body.read('x14')!=z3.LShR(raw,((S+Q)*8)&0x38))
 X=z3.BitVec('init_mba64',64);K=0x1bae835e9c76d854;add('complementary_OR_seed_reduction',((X|K)-(X|constants['x16'])+constants['x16'])!=(X^K))
 for name,op,other in [('and','x4','x5'),('or7','x7','x15'),('or23','x23','x24')]:
  k=constants[op];assert k&1==0;mask=k//2;original=((X<<1)&k)-X+constants[other]if name=='and'else((X<<1)|k)-X+constants[other];compact=mask+constants[other]-(X^mask)if name=='and'else(X^mask)+mask+constants[other];add('mixer_'+name+'_reduction',original!=compact)
 gate=run('scratch_gate',0x100a19cac,0x100a19cc4,[('x10',Q),('w28',0xf27),('x25',S+Q),('w14',CAND),('w8',0x47f8)]);assert len(gate.stores)==1;add('source48_byte_counter_and_gate',z3.Or(gate.read('x10')!=Q+1,gate.read('w14')!=z3.If(Q==47,z3.BitVecVal(0x47f8,32),z3.BitVecVal(0x48df,32)),gate.stores[0]['address']!=S+Q,gate.stores[0]['value']!=resize(CAND,8)));add('scratch_owner_bounds',z3.UGT(Q,47),z3.ULT(Q,48))
 clear=run('initial_clears',0x10094c688,0x10094c698,[('sp',F)],[(F+0x2a68,8,O)]);add('object_zero_fields350_310',z3.Or(cell(clear,O+0x350,4)!=0,cell(clear,O+0x310,8)!=0))
 alloc=run('buffer48_size',0x10094c6f0,0x10094c6f8);add('source_second_allocation48',z3.Or(alloc.read('w0')!=48,alloc.read('x17')!=0x6aa4))
 fields=run('fields',0x10094c6fc,0x10094c764,[('sp',F),('x22',O),('x0',R),('w21',0xae4),('w20',0x6938)]);add('all_u64_buffer_return_and_object_fields',z3.Or(cell(fields,O+0xd8,8)!=R,cell(fields,O+0xe0,4)!=44,cell(fields,O+0x104,4)!=0x8b3dc644,cell(fields,O+0x118,4)!=0x8b3dc641,cell(fields,O+0x2f4,4)!=32,cell(fields,F+0x3698,8)!=O+0x2f8))
 classifier=run('classifier',0x10095784c,0x100957868,[('sp',F)],[(F+0x2a70,4,0xae4),(F+0x2c08,8,O),(F+0x2fac,4,H)]);add('conditional_classifier_store_at_objectCC',cell(classifier,O+0xcc,4)!=H)
 port=run('port',0x100bd7204,0x100bd720c,[('sp',F),('x13',0x7c004b00)],[(0x7c004b00,4,PORT)]);add('all_u32_imported_port_frame_forwarding',z3.Or(port.read('x13')!=z3.ZeroExt(32,PORT),cell(port,F+0x2a18,4)!=PORT))
 codecbase=0xd834fc56d597dbf2;encoded=run('object_word_codec',0x100b1e860,0x100b1e90c,[('x30',TABLE),('w24',0),('x8',O+0x2f8),('x9',R),('x10',(-codecbase)&((1<<64)-1)),('x3',codecbase),('x5',codecbase+1),('x7',codecbase+2),('x19',codecbase+3),('x15',codecbase+4),('x14',codecbase+5),('w4',0x59),('x0',0)],[(TABLE,8,0)]);encodedword=R^0xff590be3c05a7786;add('all_u64_object24_byte_group_codec',z3.Or(*[cell(encoded,O+0x2f8+j,1)!=z3.Extract(63-j*8,56-j*8,encodedword)for j in range(8)]))
 OUT=F+0x3a50;I=z3.BitVec('init_offset64',64);step=run('sampler_step',0x100b8e7e0,0x100b8e800,[('sp',F),('x16',OUT+I),('w13',CAND),('x15',I),('x24',z3.ZeroExt(32,CTR)),('w9',PHASE)],[(F+0x32d0,8,OUT)]);add('inplace_nonzero_sampler_counter',z3.Or(step.read('w16')!=CTR-z3.If(resize(CAND,8)==0,z3.BitVecVal(0,32),z3.BitVecVal(1,32)),cell(step,OUT+I,1)!=resize(CAND,8),step.read('w9')!=PHASE+8),z3.ULT(I,587))
 choose=run('sampler_gate',0x100b8e800,0x100b8e814,[('w16',CTR),('w4',LIMIT),('w8',PHASE)]);add('sampler_exact_counter_exit',choose.read('w8')!=(PHASE^z3.If(CTR==LIMIT,z3.BitVecVal(14,32),z3.BitVecVal(0,32))))
 WINDOW=0x100001058;INDEX=z3.BitVec('init_text_index32',32);window=run('window_reader',0x100b8e774,0x100b8e7a8,[('x0',z3.ZeroExt(32,INDEX)),('x1',32767^0xfff0c012a7a730ec),('x2',R)],[(0x1010ca2a8,8,WINDOW^0x12af5504870a589f)]);add('all_u32_self_text_window_mask',window.read('x0')!=WINDOW+z3.ZeroExt(32,INDEX&32767))
 return qs,counts,constants
def main():
 context=json.loads((ROOT/'daemon_object_initialization_context.json').read_text());qs,counts,constants=obligations(context);rows=[]
 for n,p in qs:
  a=ROOT/f'daemon_object_initialization_{n}_original.smt2';b=ROOT/f'daemon_object_initialization_{n}.smt2';s=z3.Solver();s.add(p);a.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(p));answer=str(s.check());print(json.dumps({'proof':n,'result':answer}),flush=True);assert answer=='unsat',(n,answer,str(s.model())if answer=='sat'else'');b.write_text(s.to_smt2());rows.append({'name':n,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':answer})
 deps=['daemon_object_initialization_context.json','daemon_object_initialization_model.py','prove_daemon_registry_lookup.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':rows,'source_lift_counts':counts,'source_derived_mixer_constants':{n:hex(x)for n,x in constants.items()},'compact_model_composition':'Original mixer equality plus four universal MBA reductions; finite compact model checked independently against generated bytes.','native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_object_initialization_proofs.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'proof_pairs':len(rows),'source_lift_visits':sum(counts.values())}),flush=True)
if __name__=='__main__':main()
