#!/usr/bin/env python3
"""Source-linked state proofs and independent nine-word CPU controls.
O(source + query DAG + cases*state bytes) construction/space; SMT separate.
No native operation, continuous bootstrap transition or DAIF value is supplied.
"""
import json
import z3
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE
from unicorn import arm64_const as ar
from kext_port_tools import ROOT
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_kernel_timeout_execution import Model
from lskd_values_symbolic import resize
import recover_kernel_early_logging_contract as R

def cut(e,v,a,b,linked=False):
 f=next(f for f in e['functions'] if int(f['start'],16)<=a<b<=int(f['end'],16));off=a-int(f['start'],16)
 v.e=v.c={'spans':[{'label':'cut','start':hex(a),'bytes_hex':bytes.fromhex(f['bytes'])[off:off+b-a].hex()}]}
 return v.run('cut') if linked else v.enter('cut')

def source_proofs(e):
 proofs=[];coverage=[]
 def prove(label,v,bad,premises=()):
  common=[*v.owned(),*premises];counter=z3.simplify(z3.Or(*[z3.Not(x) for x in v.edge_checks],bad));s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000);s.add(*common,*v.bindings_for(common));assert s.check()==z3.sat,('vacuous',label);s.add(*v.bindings_for([*common,counter]),counter);assert s.check()==z3.unsat,(label,s.reason_unknown())
  proofs.append({'label':label,'query':s.to_smt2(),'result':'unsat','premises_nonvacuous':True});coverage.append({'label':label,'PCs':sorted(map(hex,v.visited)),'instruction_instances':v.count,'linked_edges':len(v.edge_checks)});print('proved',label,flush=True)
 def fresh():v=Model(e);v.regions=[];return v
 daif=z3.BitVec('EL_arbitrary_DAIF64',64);phase=z3.BitVec('EL_phase32',32);v=fresh()
 for j in range(31):v.seed('x'+str(j),z3.BitVec('EL_entry_X'+str(j),64))
 v.seed('x8',daif);v.regions=[(R.PHASE,4)];v.setmem(R.PHASE,4,phase);before=dict(v.regs);memory=dict(v.memory);vectors=dict(v.vectors);system=dict(v.system)
 cut(e,v,R.START,R.START+16);cut(e,v,R.SECOND,R.JOIN,True)
 assert not v.stores and v.memory.keys()==memory.keys() and v.vectors==vectors and v.system==system
 assert all(z3.eq(v.memory[k],memory[k]) for k in memory)
 a,b=v.cmp_left,v.cmp_right;assert z3.is_true(z3.simplify(a==phase)) and z3.is_true(z3.simplify(b==19))
 delta=a-b;n=z3.Extract(31,31,delta)==1;zero=delta==0;carry=z3.UGE(a,b);overflow=z3.And(z3.Extract(31,31,a)!=z3.Extract(31,31,b),z3.Extract(31,31,delta)!=z3.Extract(31,31,a))
 nzcv=z3.If(n,resize(1<<31,32),resize(0,32))|z3.If(zero,resize(1<<30,32),resize(0,32))|z3.If(carry,resize(1<<29,32),resize(0,32))|z3.If(overflow,resize(1<<28,32),resize(0,32))
 selector=z3.If(z3.UGE(phase,19),z3.If((~z3.Extract(31,0,daif)&0x1c0)!=0,resize(1,64),resize(0,64)),resize(1,64))
 invariant=[v.read(k)!=value for k,value in before.items() if k not in ['x8','x9','x24']]
 prove('all_phase_full_GPR_SP_PC_and_memory_relation',v,z3.Or(*invariant,v.read('x8')!=0xfffffe0007f34000,v.read('x9')!=z3.ZeroExt(32,phase),v.read('x24')!=selector,v.next!=R.JOIN))
 prove('early_phase_full_join_and_NZCV_independent_of_DAIF',v,z3.Or(*invariant,v.read('x8')!=0xfffffe0007f34000,v.read('x9')!=z3.ZeroExt(32,phase),v.read('x24')!=1,nzcv!=0x80000000,v.next!=R.JOIN),[z3.ULT(phase,19)])
 pointer=z3.BitVec('EL_varargs64',64);fmt=z3.BitVec('EL_format64',64);v=fresh();v.seed('sp',v.sp0);v.seed('x28',fmt);v.setmem(v.sp0+0x78,8,pointer);cut(e,v,0xfffffe000c48fc2c,0xfffffe000c48fc3c)
 prove('logger_forwards_original_format_varargs_and_saved_cursor',v,z3.Or(v.read('x0')!=fmt,v.read('x1')!=pointer,v.load(v.sp0+0x1b0,8)!=pointer,v.next!=R.FORMAT))
 state=0x6500010000;ch=z3.BitVec('EL_character32',32);v=fresh();v.regions=[(state+0x10,1)];v.seed('x20',state);v.seed('w21',ch);cut(e,v,0xfffffe000c2ffd34,0xfffffe000c2ffd40)
 prove('character_callback_stores_exact_u32_LF_test',v,v.load(state+0x10,1)!=z3.If(ch==10,resize(1,8),resize(0,8)))
 value=z3.BitVec('EL_formatter_state8',8);v=fresh();v.seed('sp',v.sp0);v.setmem(v.sp0+0x18,1,value);cut(e,v,0xfffffe000c30039c,0xfffffe000c3003a4)
 prove('formatter_returns_low_bit_of_callback_newline_byte',v,v.read('x0')!=z3.ZeroExt(56,value&1))
 return proofs,coverage

def concrete(e,phase,daif,mutation=None):
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);pages=set();f=next(f for f in e['functions'] if int(f['start'],16)==R.B.LOG_BODY)
 for pg in range(int(f['start'],16)&~4095,(int(f['end'],16)+4095)&~4095,4096):u.mem_map(pg,4096);pages.add(pg)
 u.mem_write(int(f['start'],16),bytes.fromhex(f['bytes']));pg=R.PHASE&~4095;u.mem_map(pg,4096);pages.add(pg);u.mem_write(R.PHASE,phase.to_bytes(4,'little'))
 if mutation is not None:u.mem_write(mutation,bytes.fromhex('1f2003d5'))
 regs=[getattr(ar,'UC_ARM64_REG_X'+str(j)) for j in range(31)];initial=[((j+1)*0x1122334455667789)&((1<<64)-1) for j in range(31)];initial[8]=daif
 for reg,value in zip(regs,initial):u.reg_write(reg,value)
 u.reg_write(ar.UC_ARM64_REG_SP,0x6500020000);u.reg_write(ar.UC_ARM64_REG_NZCV,0xf0000000)
 vectors=[(j+1)*0x112233445566778899aabbccddeeff for j in range(32)]
 for j,value in enumerate(vectors):u.reg_write(getattr(ar,'UC_ARM64_REG_Q'+str(j)),value)
 visits=[];reads=[];writes=[]
 u.hook_add(UC_HOOK_CODE,lambda uc,a,n,d:visits.append(hex(a)))
 u.hook_add(UC_HOOK_MEM_READ,lambda uc,t,a,n,v,d:reads.append({'address':hex(a),'size_bytes':n}))
 u.hook_add(UC_HOOK_MEM_WRITE,lambda uc,t,a,n,v,d:writes.append({'address':hex(a),'size_bytes':n}))
 memory={pg:bytes(u.mem_read(pg,4096)) for pg in pages};u.emu_start(R.START,R.JOIN,count=9)
 out=[u.reg_read(reg) for reg in regs];expected=list(initial);expected[8]=0xfffffe0007f34000;expected[9]=phase;expected[24]=1 if phase<19 else int((~daif&0x1c0)!=0)
 d=(phase-19)&0xffffffff;n=d>>31;z=int(d==0);c=int(phase>=19);overflow=int(((phase^19)&(phase^d)&0x80000000)!=0);flags=(n<<31)|(z<<30)|(c<<29)|(overflow<<28)
 checks={'GPR31':out==expected,'SP':u.reg_read(ar.UC_ARM64_REG_SP)==0x6500020000,'PC':u.reg_read(ar.UC_ARM64_REG_PC)==R.JOIN,'NZCV':u.reg_read(ar.UC_ARM64_REG_NZCV)==flags,'vectors32':all(u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j)))==value for j,value in enumerate(vectors)),'RAM':all(bytes(u.mem_read(pg,4096))==raw for pg,raw in memory.items()),'phase_read_only':reads==[{'address':hex(R.PHASE),'size_bytes':4}] and writes==[],'nine_visits':len(visits)==9}
 return {'phase_u32':phase,'post_MRS_X8_proxy':hex(daif),'source_word_mutation':None if mutation is None else hex(mutation),'visits':visits,'reads':reads,'writes':writes,'output_X8_X9_X24':[hex(out[j]) for j in [8,9,24]],'NZCV':hex(u.reg_read(ar.UC_ARM64_REG_NZCV)),'checks':checks,'all_checks_pass':all(checks.values()),'DAIF_read_or_seeded':False}

def build():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();proofs,coverage=source_proofs(e);im=Image()
 for f in e['functions']:assert im.k.read(int(f['start'],16),len(bytes.fromhex(f['bytes']))).hex()==f['bytes']
 cases=[concrete(e,p,d) for p in [*range(19),19,20,0x7fffffff,0x80000000,0xffffffff] for d in [0,0x1c0,0xffffffffffffffff,0x123456789abcdef0]];assert all(c['all_checks_pass'] for c in cases)
 controls=[concrete(e,3,0x1c0,pc) for pc in [0xfffffe000c48f92c,0xfffffe000c48f930]];assert all(not c['all_checks_pass'] for c in controls)
 old=json.loads(read(ROOT/(R.B.P+'_audit.json')));row=old['components'][2];assert row['boundary']['pc']=='0xfffffe000c48faf4' and 'daif' not in row['final_system']
 writers=[w for w in row['source_writes'] if int(w['address'],16)<=R.PHASE<int(w['address'],16)+w['size_bytes']];last=writers[-1];assert last['address']==hex(R.PHASE) and last['after_hex']=='03000000'
 custody={'prior_audit_sha256':sha(ROOT/(R.B.P+'_audit.json')),'prior_component':row['configuration']['label'],'unchanged_boundary':row['boundary'],'last_phase_write':last,'prior_continuous_source_visits':len(row['source_visits']),'system_keys':sorted(row['final_system']),'continued_bootstrap':False}
 stats={'source_queries_unsat':len(proofs),'proof_instruction_instances':sum(c['instruction_instances'] for c in coverage),'proved_source_PCs':len({p for c in coverage for p in c['PCs']}),'linked_edges':sum(c['linked_edges'] for c in coverage),'CPU_source_cut_cases':len(cases),'CPU_source_visits':sum(len(c['visits']) for c in cases),'rejected_NOP_controls':len(controls),'continuous_bootstrap_visits_added':0,'native_target_executions':0,'new_system_register_values':0}
 return {'generator_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'scope':R.SCOPE,'source_proofs':proofs,'proof_coverage':coverage,'CPU_source_cut_cases':cases,'negative_controls':controls,'prior_frontier_custody':custody,'independent_totals':stats,'full_goal_complete':False,'native_target_executed':False}
if __name__=='__main__':
 a=build();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
