#!/usr/bin/env python3
"""Source save/restore, byte-copy and symbolic control-independence proofs.
O(lifted instructions + BV DAGs + solver resources) time/space; 30 s/query.
No unavailable frame value or native predecessor is manufactured.
"""
import json
import z3
from daemon_receive_tools import ROOT
from capture_daemon_record720 import sha
from daemon_record720_spill_symbolic import analyze
from prove_daemon_record720_fingerprint import FingerprintLift
from lskd_values_symbolic import part,mem,cell,resize

def obligations(source):
    S=0x680001f250;regs={n:z3.BitVec('spill_entry_'+n,64)for n in ['x24','x26','x22','x19','x4','x8','x9']};offsets=[0xd0,0xd8,0xe0,0xe8,0xf0,0xf8,0x138,0x148];words={o:z3.BitVec('spill_entry_stack_%x'%o,64)for o in offsets};qs=[];counts={}
    v=FingerprintLift(part(source,'save',0x100638710,0x10063875c));v.seed('sp',S)
    for n,x in regs.items():v.seed(n,x)
    for o,x in words.items():mem(v,S+o,8,x)
    v.run('save');counts['save']=v.count
    expected={0x2e8:regs['x24'],0x338:regs['x26'],0x220:words[0xe0],0x238:words[0xf8],0x178:regs['x22'],0x2f8:regs['x19'],0x2d8:words[0xf0],0x160:words[0xe8],0x358:words[0xd8],0x1e8:regs['x4'],0x288:regs['x8'],0x2d0:words[0x148],0x1c8:regs['x9'],0x1d0:words[0x138]}
    qs.append(('all_u64_save_fourteen_fields',z3.Or(*[cell(v,S+o,8)!=x for o,x in expected.items()])))
    v.c=part(source,'restore',0x100633f04,0x100633f5c);v.seed('w11',0x14b0);v.seed('w12',0x8e89b1c5);before=v.count;v.run('restore');counts['restore']=v.count-before
    qs.append(('all_u64_partial_register_roundtrip',z3.Or(v.read('sp')!=S,*[v.read(n)!=x for n,x in regs.items()])))
    qs.append(('all_u64_seven_stack_words_roundtrip',z3.Or(*[cell(v,S+o,8)!=words[o]for o in [0xd8,0xe0,0xe8,0xf0,0xf8,0x138,0x148]])))
    result,observables,stores,state=analyze(source);variables={r['variable']:z3.BitVec(r['variable'],8)for r in result['unknown_bytes']};replacements=[(x,z3.BitVec('other_'+name,8))for name,x in variables.items()]
    differences=[]
    for role,pc,expr in observables:
        differences.append(expr!=z3.substitute(expr,*replacements))
        assert z3.is_bv_value(z3.simplify(expr)),(role,hex(pc))
    qs.append(('all_832_bits_control_and_address_independence',z3.Or(*differences)))
    copied=[];copy_map=[]
    for pc,address,n,value in stores:
        for j in range(n):
            b=z3.simplify(z3.Extract(j*8+7,j*8,value))
            if z3.is_bv_value(b):continue
            assert z3.is_const(b)and b.decl().name()in variables,('non-copy symbolic store',hex(pc),b)
            name=b.decl().name();copied.append(b!=variables[name]);copy_map.append({'pc':hex(pc),'address':hex(address+j),'variable':name})
    assert len(variables)==104 and len(copy_map)==56
    qs.append(('all_448_bits_opaque_stores_are_byte_copies',z3.Or(*copied)))
    D=0x1010b5ef0;H=z3.BitVec('arena_published_pointer64',64)
    w=FingerprintLift(part(source,'publish',0x10032a568,0x10032a570));w.seed('x0',H);w.seed('x15',D);w.seed('x9',D+48);w.run('publish');counts['arena_publication']=w.count
    w.c=part(source,'consume',0x1004a0620,0x1004a0624);w.seed('x6',D);before=w.count;w.run('consume');counts['descriptor_consumer']=w.count-before
    qs.append(('all_u64_arena_publication_consumer_component',z3.Or(cell(w,D+72,8)!=H,cell(w,D+80,8)!=H,w.read('x15')!=H)))
    meta={'save_field_map':{hex(o):x.sexpr()for o,x in expected.items()},'roundtrip_registers':list(regs),'roundtrip_stack_offsets':[hex(o)for o in [0xd8,0xe0,0xe8,0xf0,0xf8,0x138,0x148]],'symbolic_source_steps':len(result['steps']),'observables_checked':len(observables),'unknown_byte_variables':len(variables),'opaque_store_byte_map':copy_map,'symbolic_boundary':result['boundary'],'arena_component_continuity_is_assumed':False}
    return qs,counts,meta

if __name__=='__main__':
    source=json.loads((ROOT/'daemon_record720_spill_source.json').read_text());qs,counts,meta=obligations(source);rows=[]
    for name,expr in qs:
        a=ROOT/f'daemon_spill720_{name}_original.smt2';b=ROOT/f'daemon_spill720_{name}.smt2';s=z3.Solver();s.add(expr);a.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(expr));answer=str(s.check());print(name,answer,flush=True);assert answer=='unsat',(name,answer,str(s.model())if answer=='sat'else'');b.write_text(s.to_smt2());rows.append({'name':name,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':answer})
    out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['daemon_record720_spill_source.json','daemon_record720_spill_symbolic.py','prove_daemon_record720_fingerprint.py']},'proofs':rows,'source_lift_counts':counts,'metadata':meta,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_record720_spill_proofs.json').write_text(json.dumps(out,indent=2)+'\n')
