#!/usr/bin/env python3
"""Audit PID to process-path interface, zero-fill loop and result comparison.

Two source continuations follow declared void BSM returns to an undefined
phase. Separate phase/bank/PID premises admit the path call; path returns
remain separate API fixtures. O(cases*(visits+effects)+source+queries)
time/space; 30 s/query. No native API/IPC, allocation/free or hardware PAC.
"""
import itertools,json,struct
from collections import Counter
from unicorn import arm64_const as ar
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,TABLE,FIXUPS,qword,selected
from verify_daemon_reader_record_payloads_publication import read,sha
from recover_daemon_return_bank_origins import Algebra
from lskd_values_symbolic import mem,cell,resize
import recover_daemon_audit_scratch as Parent

P='daemon_pidpath_consumer';Env=Parent.Parent.Parent;Base=Env.Base
AFTER_BSM=0x100810244;PHASE=0x1008310f8;PID=0x100693820;PATH=0x100693890
RESULT=0x100693894;COMPARE=0x100412e1c;POSITIVE=0x1007d04d4;NONPOSITIVE=0x1005f2acc
ERROR=0x100709868;MASK=(1<<64)-1
SPECS=[('BSM_continuation',AFTER_BSM,0x100810270),('fill_setup',0x10066565c,0x1006656b4),
       ('fill_entry',0x10075f198,0x10075f1e4),('fill_iteration',0x100761644,0x10076169c),
       ('fill_exit',0x10067018c,0x1006701ac),('phase_reset',0x1008310e4,0x10083119c),
       ('PID_and_path',0x10069381c,PATH+4),('path_result_record',RESULT,0x1006939b8),
       ('comparison_helper',COMPARE,0x100412ebc),('nonpositive_return',NONPOSITIVE,0x1005f2b14),
       ('cursor_restore',Parent.RESTORE,0x10079af64),('saved_continuation',Parent.NEXT,0x1006f776c)]
DEPS=['daemon_receive_tools.py','daemon_receive_fixups.txt','recover_daemon_audit_scratch.py',
      'daemon_audit_scratch_checks.json','daemon_audit_scratch_audit.json','audit_daemon_audit_scratch.py',
      'recover_daemon_notification_failure.py','recover_daemon_notification_registration.py',
      'recover_daemon_environment_outputs.py','recover_daemon_return_bank_origins.py',
      'probe_daemon_descriptor_producers.py','audit_daemon_environment_outputs.py']

class Run(Parent.Run):
    def interval(self,start,role):
        self.visits=[];self.reads=[];self.writes=[];self.pending=[];self.edges=[];self.calls=[];self.frames=[];self.checkpoints=[]
        self.reason=None;self.boundary=None;self.seq=0
        entry=[hex(self.reg(j)) for j in range(31)];sp=hex(self.u.reg_read(ar.UC_ARM64_REG_SP));nz=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))
        initial=list(self.initial);image=list(self.image_fixtures)
        self.ensure(start);self.u.emu_start(start,0,count=100000);self.flush();assert self.reason
        out={'role':role,'configuration':self.cfg,'entry_PC':hex(start),'caller_SP':sp,'entry_registers31':entry,'entry_NZCV':nz,
             'initial_private_fixtures':initial,'initial_image_fixtures':image,'source_visits':self.visits,
             'source_frames':self.frames,'source_reads':self.reads,'source_writes':self.writes,'logical_edges':self.edges,
             'source_calls':[{k:v for k,v in r.items() if k!='record'} for r in self.calls],
             'boundary':self.boundary,'boundary_NZCV':hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV)),'native_target_executed':False}
        for w in self.writes:
            f={'address':w['address'],'bytes_hex':w['after_hex'],'provenance':'preceding_source_interval_effect'}
            (self.initial if Base.P<=int(w['address'],16)<Base.P+Base.SIZE else self.image_fixtures).append(f)
        return out

def basis(placement):
    c=next(c for c in Parent.configuration() if c['placement']==placement and c['pointer']==('alignment_0' if not placement else 'alignment_7'))
    v=Run(c);s=v.C;p=Base.P+0x3000+int(c['pointer'].split('_')[1]);r=s+0xc070+c['cursor64']
    for off,x in [(0x9b8,p),(0x16d0,c['cursor64']),(0x600,0x100e99a00),(0x5f8,0x100f4e390)]:v.fixture(s+off,struct.pack('<Q',x))
    v.fixture(p,bytes((j*7+c['pattern'])&255 for j in range(32)))
    prefix=v.interval(Parent.ENTRY,'separate_audit_component_prefix');assert prefix['boundary']['pc']==hex(Parent.BSM)
    event=v.imported_return(prefix,0,(s+0x571c,struct.pack('<I',0)));event.pop('return32');event['void_return_premise']=True
    unspecified=0xabcdef0123456789^c['pattern'];v.set(0,unspecified);event['return_registers31'][0]=hex(unspecified)
    event['unspecified_X0_fixture']=hex(unspecified);v.cut_stops=set();fill=v.interval(AFTER_BSM,'original_zero_fill_to_unknown_phase')
    assert fill['boundary']['pc']==hex(PHASE) and fill['boundary']['kind']=='before_unknown_private_read'
    assert fill['boundary']['detail']['address']==hex(s+0x9d0) and fill['boundary']['detail']['snapshot']['known_mask_hex']=='00'*8
    assert bytes(v.u.mem_read(r+32,1024))==bytes(1024) and all(v.known[r+32-Base.P:r+1056-Base.P])
    assert int.from_bytes(v.u.mem_read(s+0x9b8,8),'little')==8
    return {'configuration':c,'prefix':prefix,'BSM_return_premise':event,'fill':fill,'scratch_base64':hex(r),
            'zero_span':{'address':hex(r+32),'size_bytes':1024},'unknown_phase_bytes':8,'native_target_executed':False}

def restore(b):
    c=b['configuration'];v=Run(c);row=b['fill']
    for j,x in enumerate(row['boundary']['registers31']):v.set(j,int(x,16))
    v.u.reg_write(ar.UC_ARM64_REG_SP,int(row['boundary']['SP'],16));v.u.reg_write(ar.UC_ARM64_REG_NZCV,int(row['boundary_NZCV'],16))
    for old in [b['prefix'],b['fill']]:
        for f in old['initial_private_fixtures']:v.fixture(int(f['address'],16),bytes.fromhex(f['bytes_hex']))
        for w in old['source_writes']:
            at=int(w['address'],16)
            if Base.P<=at<at+w['size_bytes']<=Base.P+Base.SIZE:v.fixture(at,bytes.fromhex(w['after_hex']))
    return v

def continuation(b,pid):
    v=restore(b);s=v.C
    for off,x in [(0x9d0,0x6cf4),(0x870,0x100e99700),(0x868,0x100f4e190)]:v.fixture(s+off,struct.pack('<Q',x))
    v.fixture(s+0x571c,struct.pack('<I',pid));v.cfg={**b['configuration'],'PID32':pid};v.cut_stops=set()
    row=v.interval(PHASE,'separate_phase_banks_and_PID_continuation')
    assert row['boundary']['pc']==hex(PATH) and row['boundary']['detail']['symbol']=='libSystem/_proc_pidpath'
    r=int(b['scratch_base64'],16);assert row['boundary']['registers31'][:3]==[hex(pid),hex(r+32),'0x400']
    return {'configuration':v.cfg,'phase64_premise':'0x6cf4','bank_root_premises':['0x100e99700','0x100f4e190'],
            'PID_output32_premise':hex(pid),'trace':row,'native_target_executed':False}

def source():
    return [{'name':n,'start':hex(a),'end':hex(b),'bytes_hex':IMAGE.read(a,b-a).hex(),
             'instructions':[{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str}
                             for i in CS.disasm(IMAGE.read(a,b-a),a)]} for n,a,b in SPECS]

def banks():
    rows=[]
    for name,l,r,k,add in [('process_path',0x100e99700,0x100f4e190,0x56,0xcccf),
                          ('comparison',0x100e99a00,0x100f4e390,0x78,0xce35)]:
        row=selected(l,r,k,add);left=IMAGE.read(l,256);right=IMAGE.read(r,256)
        row.update(name=name,left256_hex=left.hex(),right256_hex=right.hex(),XOR_outputs_256=[j^right[left[j]^k] for j in range(256)])
        rows.append(row)
    return rows

def reify(row,c):
    v=Run(c)
    for j,x in enumerate(row['boundary']['registers31']):v.set(j,int(x,16))
    v.u.reg_write(ar.UC_ARM64_REG_SP,int(row['boundary']['SP'],16));v.u.reg_write(ar.UC_ARM64_REG_NZCV,int(row['boundary_NZCV'],16))
    for f in row['initial_private_fixtures']:v.fixture(int(f['address'],16),bytes.fromhex(f['bytes_hex']))
    for w in row['source_writes']:
        at=int(w['address'],16)
        if Base.P<=at<at+w['size_bytes']<=Base.P+Base.SIZE:v.fixture(at,bytes.fromhex(w['after_hex']))
    return v

def result_case(c,result32):
    v=reify(c['trace'],c['configuration']);v.cfg={**c['configuration'],'path_result32':result32}
    event=v.imported_return(c['trace'],result32);full=(0xfedcba98 if v.cfg['pattern']==0x35 else 0x87654321)<<32|result32
    v.set(0,full);event['return_registers31'][0]=hex(full);event['unspecified_upper_X0_fixture']=True
    event['output_memory_effects_modeled']=False;v.cut_stops={POSITIVE,ERROR}
    row=v.interval(RESULT,'separate_int_path_return_and_original_result_consumer')
    signed=result32-(1<<32) if result32>>31 else result32
    assert row['boundary']['pc']==hex(POSITIVE if signed>=1 else ERROR),row['boundary']
    if signed<1:
        assert row['boundary']['registers31'][28]=='0x74c29dee'
        assert int.from_bytes(v.u.mem_read(v.C+0x16d0,8),'little')==v.cfg['cursor64']
    return {'configuration':v.cfg,'return_premise':event,'trace':row,
            'scratch_cursor64':hex(int.from_bytes(v.u.mem_read(v.C+0x16d0,8),'little')),
            'native_target_executed':False}

def obligations():
    qs=[];s,d=z3.BitVecs('pc_SP64 pc_record64',64);status,upper=z3.BitVecs('pc_result32 pc_unspecified_upper32',32)
    def prove(label,bad,premise=z3.BoolVal(True)):
        q=z3.Solver();q.set(timeout=30000);q.add(premise);assert q.check()==z3.sat;q.add(z3.simplify(bad));result=q.check()
        assert result==z3.unsat,(label,str(result),q.reason_unknown())
        qs.append({'label':label,'query':q.to_smt2(),'premise_query':premise.sexpr(),'premises_nonvacuous':True,'result':'unsat'})
    v=Algebra();v.seed('w23',0x86a);v.seed('x19',d);v.seed('x27',TABLE);v.seed('sp',s)
    mem(v,TABLE+8*0x1cfe,8,0x10066565c);v.run_block(AFTER_BSM,0x10081026c)
    prove('BSM_return_X0_unused_and_constant_fill_entry',z3.Or(v.read('x0')!=d,v.read('x9')!=0x10066565c,
          v.read('x8')!=0x2d772bf7ac5078ca,v.read('x12')!=s+0x8000,v.read('x17')!=0xd770))
    v=Algebra();v.seed('w24',0x6cf4);v.seed('w23',0x86a);v.seed('sp',s);v.seed('x12',s+0x8000)
    mem(v,s+0x9d8,8,TABLE);mem(v,TABLE+8*0x86a,8,0x10069381c);mem(v,TABLE+8*0x51b3,8,0x10075f198)
    v.run_block(0x10066565c,0x1006656b0)
    prove('fill_setup_exact_constants_and_saved_PID_continuation',z3.Or(v.read('w9')!=0x773d,v.read('x10')!=0x10075f198,
          cell(v,s+0x9110,8)!=0x10069381c,v.read('x1')!=0xc45418bd,v.read('x2')!=0xffffffff3babe743,
          v.read('w15')!=0xc45418bc,v.read('w16')!=0x1bc9,v.read('w3')!=0xffff9374,v.read('x17')!=0x7c16))
    v=Algebra();v.seed('x8',0x2d772bf7ac5078ca);v.seed('w9',0x773d)
    # Stop before the selected table load; the comparison is over full u64.
    v.run_block(0x10075f198,0x10075f1d4)
    prove('fill_entry_selects_original_iteration',z3.Or(v.read('x8')!=0xc4541cbc,v.read('x10')!=0,v.read('w11')!=0x773d))
    i=z3.BitVec('pc_iteration64',64)
    class Loop(Algebra):
        def load(self,a,n):
            if self.pc==0x10076168c:assert n==8;self.slot=a;return z3.BitVecVal(0,64)
            return super().load(a,n)
    v=Loop()
    for name,x in [('sp',s),('x0',d),('x10',i),('x8',0xc4541cbc),('x15',0xc45418bc),('w9',0x773d),
                   ('w16',0x1bc9),('x1',0xc45418bd),('x2',0xffffffff3babe743),('w3',0xffff9374)]:v.seed(name,x)
    mem(v,s+0x9d8,8,TABLE);v.run_block(0x100761644,0x100761698)
    prove('all_1024_iterations_write_one_zero_and_exit_exactly_at_1023',z3.Or(cell(v,d+i,1)!=0,v.read('x10')!=i+1,
          v.slot!=TABLE+8*z3.If(i==1023,z3.BitVecVal(0x7755,64),z3.BitVecVal(0x773d,64))),z3.ULE(i,1023))
    v=Algebra();v.seed('sp',s);v.seed('w11',0x6cf4);mem(v,s+0x9110,8,0x10069381c);mem(v,s+0x9d8,8,TABLE)
    mem(v,TABLE+8*0x3fe4,8,0x1008310e4);v.run_block(0x10067018c,0x1006701a8)
    prove('fill_exit_exact_phase_reset_and_saved_continuation',z3.Or(v.read('x20')!=0x10069381c,v.read('x8')!=0x1008310e4,v.read('x17')!=0x1a74))
    v=Algebra();v.seed('sp',s);v.run_block(0x1008310e4,PHASE)
    prove('phase_reset_reuses_saved_pointer_cell_as_integer_eight',cell(v,s+0x9b8,8)!=8)
    c0,c1,pid=z3.BitVecs('pc_controller0_32 pc_controller1_32 pc_PID32',32)
    lo,hi,a0,a1=z3.BitVecs('pc_left64 pc_right64 pc_controller_root0 pc_controller_root1',64)
    b0,b1=z3.BitVecs('pc_bank_byte0 pc_bank_byte1',8)
    class Bank(Algebra):
        def load(self,a,n):
            if self.pc==0x100693854:assert n==1;self.left_address=a;return b0
            if self.pc==0x100693864:assert n==1;self.right_address=a;return b1
            if self.pc==0x100693880:assert n==8;self.target_slot=a;return z3.BitVecVal(0,64)
            return super().load(a,n)
    v=Bank();v.seed('sp',s);mem(v,s+0x571c,4,pid)
    for off,x in [(0x9c8,a0),(0x9c0,a1),(0x870,lo),(0x868,hi),(0x9d8,TABLE),(0xa808,d)]:mem(v,s+off,8,x)
    mem(v,a0,4,c0);mem(v,a1,4,c1);v.run_block(0x10069381c,PATH)
    byte=z3.Extract(7,0,((c0+c1)^0xa6)*0xa5cd4cf)
    prove('all_PID_bits_bank_addresses_and_1024_byte_process_path_ABI',z3.Or(v.read('x0')!=z3.ZeroExt(32,pid),v.read('x1')!=d,
          v.read('x2')!=1024,v.read('x17')!=0x4469,v.left_address!=lo+z3.ZeroExt(56,byte),
          v.right_address!=hi+z3.ZeroExt(56,b0^0x56),v.target_slot!=TABLE+8*(z3.BitVecVal(0xcccf,64)+z3.ZeroExt(56,byte^b1))))
    v=Algebra();v.seed('sp',s);v.seed('x0',z3.Concat(upper,status));mem(v,s+0x9d0,8,0x6cf4)
    v.run_block(RESULT,0x100693900);key=v.read('x11');c=s+0x10cb8
    h=Algebra();h.seed('x0',c);h.run_block(COMPARE,0x100412e6c)
    prove('exact_address_key_agreement_domain_is_even_SP',(key==h.read('x8'))!=((s&1)==0))
    prove('caller_address_key_is_always_even',z3.Extract(0,0,key)!=0)
    v.run_block(0x100693900,0x100693958)
    prove('result_record_exact_widths_and_signed_value',z3.Or(cell(v,c,4)!=0x741bcfad-resize(key,32),
          cell(v,c+8,8)!=(z3.SignExt(32,status)^key),cell(v,c+0x18,8)!=1-key,
          cell(v,c+0x20,4)!=(resize(key,32)|1),cell(v,c+0x24,4)!=(0x741bd951^resize(key,32)),
          cell(v,c+0x28,4)!=0x741bcfae-resize(key,32),cell(v,c+0x14,4)!=(0x54b7f654^resize(key,32))))
    # Compose the proved key identity/parity and exact record layout. The
    # helper body receives an arbitrary even common key, avoiding repeated
    # bit-blasting of the already proved 64-bit address hash.
    common=z3.BitVec('pc_common_even_key64',64)
    abstract=Algebra();abstract.seed('sp',s);abstract.seed('x0',z3.Concat(upper,status));mem(abstract,s+0x9d0,8,0x6cf4)
    abstract.run_block(RESULT,0x100693900);abstract.seed('x11',common);abstract.run_block(0x100693900,0x100693958)
    class Choice(Algebra):
        def load(self,a,n):
            if self.pc==0x100412ea8:
                assert n==4;self.chosen_address=a
                return z3.If(a==c+0x28,cell(abstract,c+0x28,4),cell(abstract,c,4))
            return super().load(a,n)
    h=Choice();h.seed('x0',c);h.seed('x8',common);h.memory=abstract.memory.copy();h.run_block(0x100412e6c,0x100412eb8)
    aligned=z3.And((s&15)==0,(common&1)==0)
    prove('composed_even_key_record_selects_signed_result_below_one_and_exact_branch_indices',z3.Or(
          h.chosen_address!=z3.If(status<1,c+0x28,c),
          cell(h,c+0x10,4)!=z3.If(status<1,z3.BitVecVal(0x16ff,32),z3.BitVecVal(0x16fc,32))),aligned)
    v=Algebra();v.seed('sp',s);v.seed('w21',status);mem(v,s+0x9d0,8,0x6cf4)
    v.run_block(NONPOSITIVE,0x1005f2af4)
    prove('nonpositive_result_sets_zero_cursor_restore_addend',v.read('w8')!=0,status<1)
    return qs

def intervals(e):
    return [r for b in e['basis_cases'] for r in [b['prefix'],b['fill']]]+[c['trace'] for c in e['PID_cases']+e['result_cases']]

def build():
    bases=[basis(p) for p in [0,0x100]]
    pids=[0,1,0x7fffffff,0x80000000,0xffffffff,1234,0x12345678,0xffff5037]
    pidcases=[{'basis_index':j,**continuation(b,p)} for j,b in enumerate(bases) for p in pids]
    returns=[0,1,1023,1024,0x7fffffff,0x80000000,0xffffffff,0xfffffffe]
    results=[{'PID_case_index':j,**result_case(c,r)} for j,c in enumerate(pidcases) if c['configuration']['PID32']==0 for r in returns]
    e={'basis_cases':bases,'PID_cases':pidcases,'result_cases':results};counts=Counter()
    for row in intervals(e):counts.update(source_visits=len(row['source_visits']),reads=len(row['source_reads']),
                                        writes=len(row['source_writes']),logical_edges=len(row['logical_edges']))
    used={int(x['address'],16) for row in intervals(e) for x in row['source_reads'] if int(x['address'],16) in FIXUPS}
    used.update(int(r['slot'],16) for r in banks())
    e.update(scope=__doc__,generator_sha256=sha(__file__),source_sha256=sha(SOURCE),dependencies={n:sha(ROOT/n) for n in DEPS},
             source_regions=source(),bank_rules=banks(),source_fixups=Env.fixups(used),source_proofs=obligations(),
             verified_counts={'basis_cases':2,'PID_cases':16,'result_cases':16,'intervals':len(intervals(e)),**counts},
             native_API_executed=False,native_daemon_kext_pairing_established=False,full_goal_complete=False)
    return e

if __name__=='__main__':
    e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
