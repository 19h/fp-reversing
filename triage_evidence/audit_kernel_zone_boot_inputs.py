#!/usr/bin/env python3
"""Original boot-input source proofs and independently replayed source cuts.
O(source + formula DAG + visits + journals + RAM) construction/space; solver
search separate,30 s/query. Native boot, physical units and ownership untested.
"""
import json,struct
from collections import Counter
import z3
from capstone.arm64 import ARM64_EXT_SXTW
from unicorn import arm64_const as ar
from kext_port_tools import ROOT
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_kernel_magazine_bootstrap import Model as Parent,DEC
from lskd_values_symbolic import resize
from probe_kernel_vm_mig import Probe as CPU,P,SIZE,SP,HALT
from probe_kernel_magazine_bootstrap import Probe as Storage
from probe_rpc502_vm_handoff import compressed,decode
from replay_kernel_magazine_bootstrap import Replay
import recover_kernel_zone_boot_inputs as R
import recover_kernel_magazine_bootstrap as M
ARG=P+0x2000;ROOTARG=P+0x3000;DESC=P+0x20000

class Model(Parent):
 def __init__(self,e):super().__init__({**e,'reused_caller_spans':[]});self.arithmetic_flags=None
 def operand(self,i,o,n):
  if o.ext==ARM64_EXT_SXTW:return resize(z3.SignExt(32,resize(self.read(i.reg_name(o.reg)),32)),n)
  return super().operand(i,o,n)
 def condition(self,name):
  if self.arithmetic_flags is not None:
   zero,carry=self.arithmetic_flags
   if name in ['eq','ne','lo','hs','ls','hi']:return {'eq':zero,'ne':z3.Not(zero),'lo':z3.Not(carry),'hs':carry,'ls':z3.Or(z3.Not(carry),zero),'hi':z3.And(carry,z3.Not(zero))}[name]
  if name=='ls':return z3.ULE(self.cmp_left,self.cmp_right)
  return super().condition(name)
 def run(self,label):
  row=next(s for s in self.e['spans'] if s['label']==label)
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   m=i.mnemonic;o=i.operands
   if m in ['cmp','tst']:self.arithmetic_flags=None
   if m not in ['ands','subs','ret']:
    old_e,old_c=self.e,self.c;self.e=self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]}
    super().run('one');self.e,self.c=old_e,old_c;continue
   if self.next is not None:self.edge_checks.append(self.next==i.address)
   self.next=resize(i.address+4,64);self.pc=i.address;self.visited.add(i.address);self.count+=1
   if m=='ret':self.next=self.read('x30');continue
   n=self.width(i.reg_name(o[0].reg));a=self.operand(i,o[1],n);b=self.operand(i,o[2],n);value=a&b if m=='ands' else a-b
   self.write(i.reg_name(o[0].reg),value);self.equal=value==0;self.arithmetic_flags=(value==0,z3.BoolVal(False) if m=='ands' else z3.UGE(a,b))
  return self

def configurations():
 cases=[]
 for override,early,physical,word_478 in [(0,8<<30,0x800000000,0x800100000),(0x3fff,8<<30,0x800000000,0x800100000),
  (4<<30,8<<30,0x800000000,0x800100000),(16<<30,8<<30,0x800000000,0x800100000),
  (4<<30,8<<30,0x800000003,0x800100000),(4<<30,8<<30,0x800000000,1),
  (0,(1<<64)-1,0x10001,0x100000)]:cases.append({'mode':'memory','override':override,'early':early,'physical':physical,'word_478':word_478,'root_478':word_478})
 cases.append({'mode':'memory','override':4<<30,'early':8<<30,'physical':0x800000000,'word_478':0,'root_478':16<<30})
 for maximum,delta,physical in [(8<<30,0x100000,0x800000000),(4<<30,0,0x800000000),(1024,1024,0x10000),(1024,1025,0x10000),
  (0,0,0x10000),((1<<64)-1,-2,0x10000)]:cases.append({'mode':'sane','maximum':maximum,'available':physical+delta,'physical':physical})
 for index,old in [(0,0),(1,0),(9,3),(2,9),(0,0xffffffff)]:cases.append({'mode':'cpu','index':index,'old_max':old})
 for maximum in [0,1,9,0xffffffff]:cases.append({'mode':'getter','maximum':maximum})
 return cases

class Probe(Storage):
 def __init__(self,image,c,mutate=None):
  CPU.__init__(self,image,'selector',{'id':0});self.mode='inputs';self.c=c;self.mutate=mutate;self.parent=None
  self.regions=[];self.envelopes=[];self.leaves=[];self.magazines=[];self.create_entries=[]
  intervals={'memory':R.SPANS['memory_prefix'],'sane':R.SPANS['sane_publication'],'cpu':R.SPANS['cpu_publication'],'getter':R.SPANS['getter']}
  self.entry,self.finish_PC=intervals[c['mode']];self.allowed=[intervals[c['mode']]]
  for j in range(31):self.set(j,0x2020202000000000+j)
  self.set(30,HALT);self.u.reg_write(ar.UC_ARM64_REG_SP,SP);self.u.reg_write(ar.UC_ARM64_REG_NZCV,0)
  if c['mode']=='memory':
   boot=bytearray(0x480);struct.pack_into('<QQ',boot,8,0xfffffe0012340000,c['physical']);struct.pack_into('<Q',boot,0x478,c['word_478']);self.fixture(ARG,bytes(boot))
   self.fixture(ROOTARG+0x478,struct.pack('<Q',c['root_478']));self.set(0,c['override']);self.set(1,ARG)
   fixtures=[(R.EARLY,struct.pack('<Q',c['early'])),(0xfffffe0007ef9168,struct.pack('<Q',ROOTARG)),
    *[(a,bytes([0xa5])*8) for a in [0xfffffe0007f36920,R.PHYS,0xfffffe0007e6daa0,R.MEMSIZE,0xfffffe0007f36960,0xfffffe000cb1e2c0,R.MAXMEM,0xfffffe000cb51650]]]
  elif c['mode']=='sane':
   self.set(27,0xfffffe0007e6d000);self.set(22,0xfffffe000cb5b000)
   fixtures=[(R.AVAILABLE,struct.pack('<Q',c['available'])),(R.PHYS,struct.pack('<Q',c['physical'])),(R.MAXMEM,struct.pack('<Q',c['maximum'])),(R.SANE,bytes([0xa5])*8)]
  elif c['mode']=='cpu':
   self.set(24,R.CPUCOUNT);self.set(8,c['index']);at=DESC+136*c['index']
   fixtures=[(R.CPUCOUNT,struct.pack('<II',c['index'],c['old_max'])),(R.CPUCOUNT+0x1c,struct.pack('<Q',DESC)),(at-16,bytes([0xa5])*168)]
  else:fixtures=[(R.CPUMAX,struct.pack('<I',c['maximum']))]
  for a,b in fixtures:
   if P<=a<a+len(b)<=P+SIZE:self.fixture(a,b);self.regions.append((a,len(b)))
   else:self.image_fixture(a,b,'Declared independent source-cut input/storage; no native epoch claimed')
  self.entry_regs=[hex(self.reg(j)) for j in range(31)];self.before=bytes(self.u.mem_read(P,SIZE))
  if mutate is not None:self.ensure(mutate);self.u.mem_write(mutate,bytes.fromhex('1f2003d5'))
 def code(self,u,a,n,d):
  self.flush()
  if a in [self.finish_PC,HALT,0xfffffe000be75900,0xfffffe000be758c8]:return self.stop('source_cut_complete' if a in [self.finish_PC,HALT] else 'before_original_diagnostic')
  return Storage.code(self,u,a,n,d)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=1000);self.flush();assert self.reason in ['source_cut_complete','before_original_diagnostic'],self.boundary
  return {'configuration':self.c,'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_registers31':self.entry_regs,'entry_NZCV':'0x0',
   'private_RAM':{'address':hex(P),'size_bytes':SIZE,'initial_byte':0},'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,
   'initial_private_RAM':compressed(self.before),'final_private_RAM':compressed(bytes(self.u.mem_read(P,SIZE))),
   'private_system_registers':[],'final_image_globals':[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()} for a,n in self.regions],
   'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'logical_envelopes':self.envelopes,
   'string_leaf_inputs':self.leaves,'boundary':self.boundary,'source_word_mutated_to_NOP':hex(self.mutate) if self.mutate else None,**{k:False for k in R.FALSE}}

def oracle(row):
 c=row['configuration'];mode=c['mode'];regions={r['address'] for r in row['final_image_globals']}
 initial={int(r['address'],16):bytes.fromhex(r['bytes_hex']) for r in row['initial_private_fixtures']+row['initial_image_fixtures'] if r['address'] in regions};want=dict(initial)
 actual={int(r['address'],16):bytes.fromhex(r['bytes_hex']) for r in row['final_image_globals']};checks=[];mask=(1<<64)-1
 def check(name,p):assert p,(name,c);checks.append(name)
 def put(a,n,value):
  for lo,b in list(want.items()):
   if lo<=a<a+n<=lo+len(b):out=bytearray(b);out[a-lo:a-lo+n]=(value&((1<<(8*n))-1)).to_bytes(n,'little');want[lo]=bytes(out);return
  raise AssertionError(('unowned oracle store',hex(a),n))
 expected_PC=int(row['entry_PC'],16)
 if mode=='memory':
  phys=c['physical'];aligned=((phys+c['early'])&mask)&~0x3fff;extent=(aligned-phys)&mask;override=c['override']&~0x3fff
  clamp=bool(override and extent>override);admit=not clamp or c['root_478']>=c['early'];other_word=c['word_478']
  for a,value in [(0xfffffe0007f36920,0xfffffe0012340000),(R.PHYS,phys),(0xfffffe0007e6daa0,c['early']),
   (R.MEMSIZE,extent),(0xfffffe0007f36960,extent),(0xfffffe000cb1e2c0,c['word_478'])]:put(a,8,value)
  if admit:
   if clamp:extent=override;other_word=(c['root_478']-c['early']+override)&mask;put(R.MEMSIZE,8,extent)
   put(R.MAXMEM,8,extent);put(0xfffffe000cb51650,8,other_word);expected_PC=R.SPANS['memory_prefix'][1]
  else:expected_PC=0xfffffe000be75900
  check('memory_prefix_exact_clamp_gate_and_publications',actual==want)
 elif mode=='sane':
  delta=(c['available']-c['physical'])&mask;admit=c['maximum']>delta
  if admit:put(R.SANE,8,c['maximum']-delta)
  expected_PC=R.SPANS['sane_publication'][1] if admit else 0xfffffe000be758c8
  check('sane_size_strict_positive_modular_subtraction_and_unchanged_rejection',actual==want)
 elif mode=='cpu':
  ptr=DESC+136*c['index'];put(R.CPUCOUNT,4,c['index']+1);put(ptr,4,c['index']);put(R.CPUMAX,4,max(c['index'],c['old_max']))
  expected_PC=R.SPANS['cpu_publication'][1];check('logical_index_count_max_and_all_descriptor_guard_bytes_exact',actual==want)
 else:
  expected_PC=HALT;check('exported_getter_zero_extends_maximum_number',int(row['boundary']['registers31'][0],16)==c['maximum']);check('getter_preserves_image_bytes',actual==want)
 check('exact_cut_or_diagnostic_boundary',int(row['boundary']['pc'],16)==expected_PC)
 before=decode(row['initial_private_RAM']);after=decode(row['final_private_RAM']);expected=bytearray(before)
 if mode=='cpu':struct.pack_into('<I',expected,DESC-P+136*c['index'],c['index'])
 check('all_nonstack_private_RAM_matches_independent_oracle',expected[:SP-P-512]==after[:SP-P-512] and expected[SP-P+256:]==after[SP-P+256:])
 check('no_callee_or_native_effect_models_needed',not row['API_models'] and not row['logical_envelopes'])
 return checks

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();proofs=[];coverage=[]
 def local():v=Model(e);v.regions=[];return v
 def prove(label,v,bad,premises=()):
  common=[*v.owned(),*premises];counter=z3.simplify(z3.Or(*[z3.Not(x) for x in v.edge_checks],bad))
  s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000);s.add(*common,*v.bindings_for(common));assert s.check()==z3.sat,('vacuous',label)
  s.add(*v.bindings_for([*common,counter]),counter);r=s.check();assert r==z3.unsat,(label,str(r),s.reason_unknown())
  proofs.append({'label':label,'query':s.to_smt2(),'result':'unsat','premises_nonvacuous':True,'logic':'QF_AUFBV'})
  coverage.append({'label':label,'PCs':sorted(map(hex,v.visited)),'instruction_instances':v.count,'linked_edge_obligations':len(v.edge_checks),
   'checked_read_store_rewrites':list(v.separation_rewrites.values())});print(label,flush=True)
 def block(label,a,b):
  f=next(f for f in e['functions'] if int(f['start'],16)<=a<b<=int(f['end'],16));offset=a-int(f['start'],16)
  return {**e,'spans':[{'label':label,'start':hex(a),'bytes_hex':bytes.fromhex(f['bytes'])[offset:offset+b-a].hex()}]}
 v=local();v.regions=[(ARG,0x480),(R.EARLY,8),*[(a,8) for a in [0xfffffe0007f36920,R.PHYS,0xfffffe0007e6daa0,R.MEMSIZE,0xfffffe0007f36960,0xfffffe000cb1e2c0]]]
 physical=v.load(ARG+16,8);virtual=v.load(ARG+8,8);early=v.load(R.EARLY,8);top=v.load(ARG+0x478,8)
 v.seed('x1',ARG);v.e=v.c=block('memory_core',0xfffffe000be74030,0xfffffe000be74080);v.enter('memory_core')
 aligned=(physical+early)&resize(~0x3fff,64);extent=aligned-physical
 prove('memory_prefix_argument_offsets_alignment_and_unclamped_publications',v,z3.Or(v.load(R.PHYS,8)!=physical,
  v.load(0xfffffe0007f36920,8)!=virtual,v.load(0xfffffe0007e6daa0,8)!=early,v.load(R.MEMSIZE,8)!=extent,
  v.load(0xfffffe0007f36960,8)!=extent,v.load(0xfffffe000cb1e2c0,8)!=top,v.read('x11')!=top,v.read('x9')!=extent,v.read('x10')!=early))
 v=local();override=z3.BitVec('BI_override64',64);v.seed('x0',override);v.e=v.c=block('override_zero_gate',0xfffffe000be74080,0xfffffe000be74088);v.enter('override_zero_gate');rounded=override&resize(~0x3fff,64)
 prove('memory_override_clears_low14_bits_and_zero_rounded_value_bypasses_clamp',v,z3.Or(v.read('x12')!=rounded,
  v.next!=z3.If(rounded==0,resize(0xfffffe000be740b0,64),resize(0xfffffe000be74088,64))))
 # Prefix arithmetic is checked in linked straight-line pieces; source branch
 # choices are explicit premises, not an execution of the intervening ARM body.
 v=local();v.regions=[(R.AVAILABLE,8),(R.PHYS,8),(R.MAXMEM,8),(R.SANE,8)];available=v.load(R.AVAILABLE,8);physical=v.load(R.PHYS,8);maximum=v.load(R.MAXMEM,8)
 v.seed('x27',0xfffffe0007e6d000);v.seed('x22',0xfffffe000cb5b000)
 v.e=v.c=block('sane_gate',0xfffffe000be752a4,0xfffffe000be752c0);v.enter('sane_gate');delta=available-physical
 prove('sane_size_gate_is_strict_unsigned_maximum_greater_than_modular_reservation',v,z3.Or(v.read('x8')!=maximum-delta,
  v.next!=z3.If(z3.ULE(maximum,delta),resize(0xfffffe000be758c8,64),resize(0xfffffe000be752c0,64))))
 v.e=v.c=block('sane_store',0xfffffe000be752c0,0xfffffe000be752c8);v.run('sane_store')
 prove('admitted_sane_publication_stores_exact_positive_difference',v,v.load(R.SANE,8)!=maximum-delta,[z3.UGT(maximum,delta)])
 v=local();v.regions=[(R.CPUCOUNT,8)];desc=z3.BitVec('BI_descriptor64',64);index=z3.BitVec('BI_logical_index32',32);v.regions.append((desc,136));old=v.load(R.CPUMAX,4)
 v.seed('x24',R.CPUCOUNT);v.seed('x26',desc);v.seed('w8',index);v.e=v.c=block('cpu_stores',0xfffffe000be8331c,0xfffffe000be83338);v.enter('cpu_stores')
 prove('CPU_source_stores_sequential_index_increment_and_unsigned_maximum',v,z3.Or(v.load(R.CPUCOUNT,4)!=index+1,v.load(desc,4)!=index,v.load(R.CPUMAX,4)!=z3.If(z3.UGT(old,index),old,index)))
 v=local();v.enter('cpu_base');prove('CPU_counter_and_maximum_are_adjacent_at_recovered_base',v,v.read('x24')!=R.CPUCOUNT)
 v=local();v.regions=[(R.CPUMAX,4)];maximum=v.load(R.CPUMAX,4);ret=v.read('x30');v.enter('getter')
 prove('exported_max_CPU_number_getter_zero_extends_same_u32',v,z3.Or(v.read('x0')!=z3.ZeroExt(32,maximum),v.next!=ret))
 v=local();v.regions=[(R.CPUMAX,4),(M.COUNT,4)];maximum=v.load(R.CPUMAX,4);v.enter('policy_count')
 prove('policy_instances_are_exported_maximum_plus_one_modulo_u32',v,v.load(M.COUNT,4)!=maximum+1)
 v=local();v.regions=[(R.SANE,8)];sane=v.load(R.SANE,8);v.enter('policy_high_word')
 prove('policy_small_count_input_is_high32_of_source_sane_size',v,z3.Or(v.read('w9')!=z3.Extract(63,32,sane),
  v.next!=z3.If(z3.ULT(sane,resize(1<<32,64)),resize(0xfffffe000c631ff8,64),resize(0xfffffe000c632198,64))))
 composition=[];m,d=z3.BitVecs('BI_maximum64 BI_reservation64',64);s=z3.SolverFor('QF_BV');s.set(timeout=30000);s.add(z3.UGT(m,d));assert s.check()==z3.sat
 s.add(z3.UGE(m-d,1<<32)!=z3.UGE(z3.ZeroExt(1,m),z3.ZeroExt(1,d)+(1<<32)));assert s.check()==z3.unsat
 composition.append({'label':'admitted_sane_highword_nonzero_iff_maximum_at_least_reservation_plus2pow32_in65bits','query':s.to_smt2(),'result':'unsat','premises_nonvacuous':True,'logic':'QF_BV'})
 separations=[]
 for p in json.loads(read(ROOT/'kernel_zone_bitmap_release_audit.json'))['rechecked_separation_lemmas']:
  solver=z3.Solver();solver.set(timeout=30000);solver.add(*z3.parse_smt2_string(p['query']));assert solver.check()==z3.unsat
  separations.append({'label':p['label'],'query':p['query'],'result':'unsat','source_artifact_sha256':sha(ROOT/'kernel_zone_bitmap_release_audit.json')})
 image=Image();components=[];replays=[];totals=Counter()
 for c in configurations():
  row=Probe(image,c).run();row['independent_oracle_checks']=oracle(row);components.append(row);r=Replay(image,row).run();replays.append(r);totals.update(r)
 negative=[]
 for case,pc in [(8,0xfffffe000be752c4),(15,0xfffffe000be83334)]:
  row=Probe(image,configurations()[case],pc).run()
  try:oracle(row)
  except AssertionError as err:negative.append({'component':row,'oracle_rejection':err.args[0][0]})
  else:raise AssertionError('changed source accepted')
 source={i['ea'] for f in e['functions'] for i in f['instructions']};visited={i['pc'] for r in components for i in r['source_visits']}
 stats={'source_queries_unsat':len(proofs),'composition_queries_unsat':len(composition),'rechecked_separation_lemmas_unsat':len(separations),'components':len(components),
  'component_source_visits':sum(len(r['source_visits']) for r in components),'executed_source_PCs':len(source&visited),
  'proved_source_PCs':len({p for r in coverage for p in r['PCs']}),'proof_instruction_instances':sum(r['instruction_instances'] for r in coverage),
  'linked_edge_obligations':sum(r['linked_edge_obligations'] for r in coverage),'checked_read_store_rewrites':sum(len(r['checked_read_store_rewrites']) for r in coverage),
  'independent_oracle_checks':sum(len(r['independent_oracle_checks']) for r in components),'changed_source_controls':len(negative)}
 return {'generator_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],
  'kernel_collection_sha256':e['kernel_collection_sha256'],'scope':R.SCOPE,'source_proofs':proofs,'composition_proofs':composition,'rechecked_separation_lemmas':separations,'coverage':coverage,
  'components':components,'independent_replays':replays,'independent_replay_totals':dict(totals),'negative_controls':negative,
  'unexecuted_source_PCs':sorted(source-visited),'independent_totals':stats,'conditional_kernel_zone_boot_inputs_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True);print(json.dumps(a['independent_replay_totals']),flush=True)
