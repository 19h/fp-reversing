#!/usr/bin/env python3
"""Original selector21 workspace/record and initial scalar-admission contracts.

Read-only KC and normalized bytes; exhaustive 256-input bank identities and
bounded source lifts. O(B+I+256R) time/space plus 30 s per solver query.
No native allocator, provider, IPC, cryptographic operation or IDB executes.
"""
import hashlib,json,struct
from pathlib import Path
import z3
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,POOL,TABLE,qword,selected
from recover_kext_cold_init import pointer
from recover_kext_aes_handoff import function
from recover_carrier_control import span
from lskd_values_symbolic import Lift,part,mem,cell
from verify_daemon_reader_record_payloads_publication import read,sha

P='versioned_core_entry'
ENTRY=0xfffffe000a5a2bac
DISPATCH=0xfffffe000a5a5470
ACCEPT=0xfffffe000a5a5bf4
ALTERNATE=0xfffffe000a5a58a0
REJECT=0xfffffe000a5a7290
SCOPE='Selector21 original core wrapper, successful-allocation-conditioned workspace and marshalled record, initial mode/marker admission, count/result/cleanup channels. Scalar admission is not complete processing, native admission, ownership or daemon/kext pairing.'
PINS={'versioned_request_abi_source.json':'43319db5d7d5471ded1d52b78319db4821b460088e407ccbb5a44091d9a6285d','versioned_request_abi_checks.json':'2e5decc7fdc4c39fd5a3a01be9d6dced22749aea75c581ac2b0b458dafa86da0','daemon_postblock_dispatch_checks.json':'3cd216630458c65aa34c0f2b1f6155c35a7cfc8206eb97b0fdcc6788e0b401b0'}
DEPS=['kernel_native_reader.py','kext_port_tools.py','recover_kext_cold_init.py','recover_kext_aes_handoff.py','recover_carrier_control.py','lskd_values_symbolic.py',*PINS]
SPECIAL=[0xb4d3a486,0xc23729b3,0xd03b7ae1,0xfd029d6d,0x13f0ac06,0x14a96160,0x19967e25,0x2070d6b0,0x30a3976e,0x39b124b2,0x39c84ba4,0x39e897b5,0x3f5e9413,0x4653e2e2,0x525e5ba4,0x57e209d2,0x57e209d5,0x5b0895c9,0x5e5171e3,0x7184b44f,0x757ff287,0x7ed2ca46,0x7a975b93]
OTHER=[0xc8584bc4,0x7a975b93,0x7184b44f]

def source():
 k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit')
 f=function(k,e,ENTRY);assert IMAGE.read(ENTRY,int(f['end'],16)-ENTRY).hex()==f['bytes_hex']
 spans=[dict(span(k,ENTRY,0xfffffe000a5a3060),label='wrapper'),dict(span(k,DISPATCH,0xfffffe000a5a58a0),label='entry_prefix'),dict(span(k,0xfffffe000a5a5a70,0xfffffe000a5a5bf4),label='marker_tree_low'),dict(span(k,REJECT,0xfffffe000a5a72bc),label='rejection_return'),dict(span(k,0xfffffe000a687ecc,0xfffffe000a687ee0),label='ordering_guard')]
 return k,spans

def rules(k):
 a,b=qword(POOL+0xc08)-8,qword(POOL+0x158)-4
 specs=[('state_C',0xfffffe0007949ed0,0xfffffe000792fec0,0x32,-0x41,POOL,0),('state_D',qword(POOL+0x4f0)-4,qword(POOL+0x578)-4,0x37,-0x1e,POOL,0),('transfer_base',0xfffffe000792fcc0,0xfffffe00079391f0,0x47,-0x48,POOL,-12),('aligned_allocate',qword(POOL+0xf50)-4,qword(POOL+0xf20)-4,0x93,0xe4f,TABLE,0),('typed_allocate',qword(POOL+0x840),qword(POOL+0xbb8),0x3e,0xebf,TABLE,0),('allocate_view',a,b,0x6d,0x88,POOL,-8),('ordering_guard',a,b,0x98,0xe8c,TABLE,0),('core_dispatch',a,b,0x98,0xec4,TABLE,0),('typed_free',a,b,0x6d,0xf18,TABLE,0),('free_view',a,b,5,0xa2,POOL,-12),('aligned_free',a,b,0x6d,0xf12,TABLE,0),('dispatch_state_C',qword(POOL+0x840),qword(POOL+0xbb8),0x3e,0x11c,POOL,0),('dispatch_state_D',qword(POOL+0xb70),qword(POOL+0xa10),0x32,-0xdd,POOL,-4),('dispatch_transfer_base',0xfffffe000792fdc0,0xfffffe00079392f0,0x93,-0xb9,POOL,-12),('dispatch_ordering_guard',a,b,5,0xef4,TABLE,0)]
 out=[]
 for name,l,r,key,add,base,bias in specs:
  row=selected(l,r,key,add,base,bias);p=pointer(k,int(row['slot'],16));assert (int(p['target'],16)+bias)&((1<<64)-1)==int(row['target'],16)
  row.update(label=name,base=hex(base),left256_hex=IMAGE.read(l,256).hex(),right256_hex=IMAGE.read(r,256).hex(),original_pointer=p);out.append(row)
 return out

def admission_paths(mode,marker):
 """Symbolically follow original scalar tree; address-only loads excluded.

 Excluded address-only LDUR instructions write X8/X11; comparisons use W9/W10.
 Paths terminate before either admitted continuation or rejection epilogue.
 """
 dc=__import__('capstone').Cs(__import__('capstone').CS_ARCH_ARM64,__import__('capstone').CS_MODE_LITTLE_ENDIAN);dc.detail=True
 ins={i.address:i for a,n in [(0xfffffe000a5a57e4,0xbc),(0xfffffe000a5a5a70,0x184)]for i in dc.disasm(IMAGE.read(a,n),a)}
 work=[(0xfffffe000a5a57e4,{'w8':mode,'w9':marker},z3.BoolVal(True),None)];out=[]
 # The unsigned mode <=8 check precedes this tree in the original prefix.
 while work:
  pc,regs,path,cmp=work.pop()
  if pc in [ACCEPT,ALTERNATE,REJECT]:out.append((pc,z3.And(z3.ULE(mode,8),path)));continue
  i=ins[pc];m=i.mnemonic;ops=i.operands;regs=dict(regs)
  if m=='mov':regs[i.reg_name(ops[0].reg)]=z3.BitVecVal(ops[1].imm&0xffffffff,32)
  elif m=='movk':
   d=i.reg_name(ops[0].reg);shift=ops[1].shift.value;regs[d]=(regs[d]&~(0xffff<<shift))|(ops[1].imm<<shift)
  elif m=='lsl':regs[i.reg_name(ops[0].reg)]=regs[i.reg_name(ops[1].reg)]<<(regs[i.reg_name(ops[2].reg)]&31)
  elif m=='tst':cmp=(regs[i.reg_name(ops[0].reg)]&regs[i.reg_name(ops[1].reg)],z3.BitVecVal(0,32))
  elif m=='cmp':cmp=(regs[i.reg_name(ops[0].reg)],regs[i.reg_name(ops[1].reg)])
  elif m in ['stur','ldur']:
   assert i.op_str in ['x22, [x29, #-0xd0]','x11, [x29, #-0x88]','x8, [x29, #-0xd0]']
  elif m=='ldr':assert i.op_str=='w11, [x8, #0x10]';regs['w11']=z3.BitVec('admission_unused_scalar2',32)
  elif m=='b':work.append((ops[0].imm&((1<<64)-1),regs,path,cmp));continue
  elif m.startswith('b.'):
   a,b=cmp;condition={'b.eq':a==b,'b.ne':a!=b,'b.le':a<=b,'b.gt':a>b}[m];target=ops[0].imm&((1<<64)-1)
   work.append((target,regs,z3.And(path,condition),cmp));work.append((pc+4,regs,z3.And(path,z3.Not(condition)),cmp));continue
  else:raise AssertionError((hex(pc),m,i.op_str))
  work.append((pc+4,regs,path,cmp))
 out.append((REJECT,z3.UGT(mode,8)))
 return out

def obligations(spans):
 c={'spans':spans};qs=[];counts={};F=0x51010000
 def run(label,a,z,seeds=(),memory=()):
  v=Lift(part(c,label,a,z))
  for reg,value in seeds:v.seed(reg,value)
  for addr,n,value in memory:mem(v,addr,n,value)
  v.run(label);counts[label]=v.count;return v
 W,A=z3.BitVecs('versioned_workspace64 versioned_auxiliary64',64);Q=z3.BitVec('versioned_count_pointer64',64)
 args=[z3.BitVec('versioned_arg'+str(j),64 if j in [0,4,5,7,8,9]else 32)for j in range(10)]
 v=run('save_register_arguments',0xfffffe000a5a2bd0,0xfffffe000a5a2be8,[('sp',F),*[(f'x{j}',z3.ZeroExt(32,args[j])if args[j].size()==32 else args[j])for j in range(8)]])
 fields=[(0,8,7),(0x44,4,6),(0x30,8,4),(0x38,8,5),(0x28,4,2),(0x2c,4,3),(0x24,4,1),(0x18,8,0)]
 qs.append(('save_register_arguments',z3.Or(*[cell(v,F+off,n)!=args[j]for off,n,j in fields])))
 v=run('incoming_stack_arguments',0xfffffe000a5a2c58,0xfffffe000a5a2c68,[('sp',F),('x29',F+0xf0)],[(F+0x108,8,args[9]),(F+0x100,8,args[8])]);qs.append(('incoming_stack_arguments',z3.Or(cell(v,F+0x10,8)!=args[9],cell(v,F+8,8)!=args[8])))
 v=run('marshal_argument_record',0xfffffe000a5a2e6c,0xfffffe000a5a2ea8,[('sp',F),('x28',A)],[(F+0x10,8,Q),(F+0x18,8,args[0]),(F+0x24,4,args[1]),(F+0x28,4,args[2]),(F+0x2c,4,args[3]),(F+0x30,8,args[4]),(F+0x38,8,args[5]),(F+0x44,4,args[6]),(F,8,args[7]),(F+8,8,args[8]),(Q,4,args[9]&0xffffffff)])
 qs.append(('marshal_argument_record',z3.Or(v.read('x24')!=Q,v.read('x8')!=A+4096,*[cell(v,F+off,n)!=(args[j]if j!=9 else z3.Extract(31,0,args[j]))for off,n,j in [(0x48,8,0),(0x50,4,1),(0x54,4,2),(0x58,4,3),(0x60,8,4),(0x68,8,5),(0x70,4,6),(0x78,8,7),(0x80,8,8),(0x88,4,9)]])))
 v=run('workspace_record_and_key',0xfffffe000a5a2ea8,0xfffffe000a5a2ef8,[('sp',F),('x27',W),('x28',A),('x20',W+16384),('x19',W+64),('x8',A+4096)])
 key=(z3.Extract(31,0,W)^0x97099bc0)*0xef54ff65
 qs.append(('workspace_record_and_key',z3.Or(cell(v,W+8,8)!=A,cell(v,W+0x18,8)!=A+4096,cell(v,W+0x20,8)!=F+0x48,cell(v,W+0x28,8)!=W+16384,cell(v,W+0x30,8)!=W+64,cell(v,W+0x10,4)!=key+0x3da4b356)))
 E=z3.BitVec('versioned_operation_encoded32',32)
 v=run('dispatcher_operation_decode',0xfffffe000a5a564c,0xfffffe000a5a568c,[('x29',F),('x23',W),('w24',E)])
 qs.append(('dispatcher_operation_decode',z3.Or(cell(v,F-0xac,4)!=E-key,cell(v,F-0xac,4)-(E-key)!=0)))
 qs.append(('wrapper_dispatch_operation_join',z3.simplify((key+0x3da4b356)-key)!=0x3da4b356))
 GC,GD=z3.BitVecs('versioned_global_C64 versioned_global_D64',64);constant=0xa41a4d891208c018;multiplier=0x4d08a3fb
 v=run('wrapper_global_state_update',0xfffffe000a5a2ca8,0xfffffe000a5a2cd8,[('x25',0x52002004),('x23',0x52001004),('x29',F+0xf0),('x10',GC),('x20',constant)],[(0x52002000,8,GD)])
 t=(GC+GD)^(F+0x90)
 qs.append(('wrapper_global_state_update',z3.Or(cell(v,0x52001000,8)!=(t*multiplier)^constant,cell(v,0x52002000,8)!=(t^constant)*multiplier)))
 v=run('dispatcher_global_state_update',0xfffffe000a5a554c,0xfffffe000a5a5570,[('x27',0x52003000),('x28',0x52002000),('x29',F-0x10),('x10',GC),('x11',GD),('x25',multiplier),('x26',constant)])
 t=GC^GD^(F-0x70)
 qs.append(('dispatcher_global_state_update',z3.Or(cell(v,0x52003000,8)!=t*multiplier-constant,cell(v,0x52002000,8)!=(t^constant)*multiplier)))
 C,S=z3.BitVecs('versioned_mutated_count32 versioned_result_encoded32',32)
 v=run('count_and_result_copyback',0xfffffe000a5a2f54,0xfffffe000a5a2f60,[('sp',F),('x27',W),('x24',Q)],[(W,4,S),(F+0x88,4,C)])
 qs.append(('count_and_result_copyback',z3.Or(cell(v,Q,4)!=C,v.read('w19')!=S)))
 v=run('wrapper_result_decode',0xfffffe000a5a3034,0xfffffe000a5a3040,[('w19',S)])
 qs.append(('wrapper_result_decode',v.read('w0')!=S^0x31ae0066))
 mode,marker=z3.BitVecs('versioned_mode32 versioned_marker32',32)
 v=run('source_marker_load',0xfffffe000a5a575c,0xfffffe000a5a5760,[('x22',F+0x48)],[(F+0x54,4,marker)])
 qs.append(('source_marker_load',v.read('w9')!=marker))
 v=run('source_mode_bound_and_rejection_word',0xfffffe000a5a5630,0xfffffe000a5a5648,[('sp',F),('x22',W),('x23',W)],[(W+8,4,mode)])
 qs.append(('source_mode_bound_and_rejection_word',z3.Or(v.cmp_left!=mode,v.cmp_right!=8,v.read('w2')!=0xce515b51)))
 paths=admission_paths(mode,marker)
 actual=lambda address:z3.Or(*[p for a,p in paths if a==address])
 expected=z3.And(z3.Or(*[mode==n for n in [2,5,8]]),z3.Or(*[marker==n for n in SPECIAL]))
 alternate=z3.And(z3.Or(mode==4,mode==7),z3.Or(*[marker==n for n in OTHER]))
 qs.append(('source_full_scalar_admission_partition',z3.Or(actual(ACCEPT)!=expected,actual(ALTERNATE)!=alternate,actual(REJECT)!=z3.Not(z3.Or(expected,alternate)))))
 qs.append(('daemon_mode_marker_admission',z3.And(z3.Or(mode==2,mode==5),marker==0xb4d3a486,z3.Not(actual(ACCEPT)))))
 out=[]
 for name,q in qs:
  s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(q));assert s.check()==z3.unsat,name
  out.append({'label':name,'query':s.to_smt2(),'result':'unsat'})
 return out,counts

def build():
 for name,digest in PINS.items():assert sha(ROOT/name)==digest,name
 k,ss=source();rr=rules(k);views=[]
 for name,a in [('allocation',0xfffffe000847bea0),('free',0xfffffe000847ba60)]:
  raw=IMAGE.read(a,64);ps=[pointer(k,a+j)for j in [16,32]];flags,n=struct.unpack_from('<II',raw,40);nm=k.read(int(ps[0]['target'],16),64).split(b'\0',1)[0].decode();assert nm=='site.AllocType'and(flags,n)==(0xe4,4096)
  views.append({'role':name,'address':hex(a),'original64_hex':k.read(a,64).hex(),'normalized64_hex':raw.hex(),'pointer_fields':ps,'site_name':nm,'flags32':flags,'size_bytes':n})
 proof,lifts=obligations(ss)
 return {'scope':SCOPE,'generator_sha256':sha(__file__),'parent_pins':PINS,'dependencies':{n:sha(ROOT/n)for n in DEPS},'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'source_regions':ss,'bank_rules':rr,'pool_pointer_records':[pointer(k,POOL+off)for off in [0x4f0,0x578,0xf50,0xf20,0x840,0xbb8,0xc08,0x158,0xb70,0xa10]],'typed_views':views,'exact_symbols':k.symbols([0xfffffe000c4b9a08,0xfffffe000c4ba154,0xfffffe000c4ba368,0xfffffe000c4b9a24]),'source_proofs':proof,'source_lift_counts':lifts,'special_markers':[hex(n)for n in SPECIAL],'alternate_markers':[hex(n)for n in OTHER],'verified_counts':{'source_regions':len(ss),'source_instruction_instances':sum(len(s['instructions'])for s in ss),'source_bytes_instances':sum(len(bytes.fromhex(s['bytes_hex']))for s in ss),'bank_rules':len(rr),'bank_inputs':256*len(rr),'proofs_unsat':len(proof),'typed_views':len(views)},'native_target_executed':False,'native_API_executed':False,'IDB_mutated':False,'live_IDA_claim':False,'native_caller_admission_established':False,'native_daemon_kext_pairing_established':False,'full_goal_complete':False}

if __name__=='__main__':
 obj=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(obj,indent=2)+'\n');print(json.dumps(obj['verified_counts']),flush=True)
