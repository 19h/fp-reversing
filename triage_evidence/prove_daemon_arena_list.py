#!/usr/bin/env python3
"""Source-local arena contracts. O(lifted instructions + BV DAGs) construction;
solver resources separate, 30 s/query. Fixed disjoint cells are component
premises; no native epoch, general allocator invariant or PAC execution.
"""
import json
import z3
from daemon_receive_tools import ROOT
from capture_daemon_record720 import sha
from daemon_arena_list_symbolic import ListFlags
from lskd_values_symbolic import part,mem,cell,resize

def obligations(c):
    qs=[];counts={}
    def run(name,a,z,seeds=(),memory=()):
        v=ListFlags(part(c,name,a,z))
        for reg,val in seeds:v.seed(reg,val)
        for at,n,val in memory:mem(v,at,n,val)
        v.run(name);counts[name]=v.count;return v
    H=z3.BitVec('list_head64',64);L=0x1010b5f20
    v=run('sentinel',0x1004a0624,0x1004a063c,[('x15',H),('x20',L),('w14',0x7a3a),('w16',0x7164)])
    qs.append(('all_u64_head_sentinel_index',v.read('w13')!=z3.If(H==L,z3.BitVecVal(0x7164,32),z3.BitVecVal(0x71db,32))))
    A,B,C=z3.BitVecs('fit_A64 fit_B64 fit_C64',64)
    v=run('signed_conditional_compare',0x100552d00,0x100552d0c,[('x2',A),('x17',B),('x16',C)])
    qs.append(('all_u64_signed_conditional_compare',v.read('w17')!=z3.If(z3.Or(A<=B,A>=C),z3.BitVecVal(1,32),z3.BitVecVal(0,32))))
    v=run('malloc_size',0x100477838,0x100477840)
    qs.append(('fallback_size_and_modifier',z3.Or(v.read('x0')!=5000,v.read('x17')!=0x6aa4)))
    S=0x680001f250;P=z3.BitVec('arena_continuation_pointer64',64)
    v=run('save_continuation',0x100637e04,0x100637e08,[('sp',S),('x8',P)])
    v.c=part(c,'reload',0x100634284,0x10063428c);before=v.count;v.run('reload');counts['reload_continuation']=v.count-before
    qs.append(('all_u64_continuation_spill_reload',z3.Or(v.read('x8')!=P,v.read('x17')!=0x7315,cell(v,S+0x258,8)!=P)))
    # Addresses are fixed, disjoint component cells; data operands arbitrary.
    H=0x6500000000;B=H+0x158ec;E=H+0x15f78;D=0x1010b5ef0;M=0x5e878c613b8123ea
    R,d,account=z3.BitVecs('patch_remaining64 patch_debit64 patch_account64',64);phase=z3.BitVec('patch_phase32',32);z=z3.BitVec('patch_auxiliary_byte8',8)
    v=run('metadata_patch',0x10058833c,0x1005883e0,[('x16',M+R-0x65a62badb39f1f54),('x26',H),('x12',d-0x680),('x15',d),('x6',D),('sp',S),('w13',phase)],[(S+0xf0,8,B),(S+0xe8,8,E),(S+0x1e7,1,z),(D+40,8,account)])
    qs.append(('all_u64_boundary_words_and_accounting',z3.Or(cell(v,H+8,8)!=M+R,cell(v,B,8)!=M+R,cell(v,B+8,8)!=M-d,cell(v,E,8)!=M,cell(v,D+40,8)!=account+d)))
    aux=resize((phase^0x7942)*15,64)^(resize(z,64)^0xb77ffbb9fbd98fc5);aux=aux+(resize(z,64)<<1)+0xa4c2f1dfc330882f
    qs.append(('all_u32_u8_auxiliary_word',cell(v,B+16,8)!=aux))
    qs.append(('payload_register_and_boundary_register',z3.Or(v.read('x23')!=B+24,v.read('x0')!=B)))
    v=run('gate_restore',0x100634280,0x100634284,[('w13',0x5d96),('x21',0x1010b5de0)])
    qs.append(('gate_restore_u32',cell(v,0x1010b5de0,4)!=0x5d96))
    return qs,counts,{'metadata_component_cells_fixed_and_disjoint':True,'native_epoch_continuity':False,'PAC_executed':False,'machine_arithmetic':'u32/u64 modular, signed comparisons where explicit; little endian'}

if __name__=='__main__':
    c=json.loads((ROOT/'daemon_arena_list_source.json').read_text());qs,counts,meta=obligations(c);rows=[]
    for name,expr in qs:
        a=ROOT/f'daemon_arena_list_{name}_original.smt2';b=ROOT/f'daemon_arena_list_{name}.smt2';s=z3.Solver();s.add(expr);a.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(expr));answer=str(s.check());print(name,answer,flush=True);assert answer=='unsat';b.write_text(s.to_smt2());rows.append({'name':name,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':answer})
    out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['daemon_arena_list_source.json','daemon_arena_list_symbolic.py','prove_daemon_record720_fingerprint.py','lskd_values_symbolic.py']},'source_lift_counts':counts,'metadata':meta,'proofs':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_arena_list_proofs.json').write_text(json.dumps(out,indent=2)+'\n')
