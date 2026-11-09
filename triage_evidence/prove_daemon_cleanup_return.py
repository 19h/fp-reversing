#!/usr/bin/env python3
"""Original-opcode component obligations for cleanup/output/stack restoration;
source-observable scalar-ABI noninterference under the declared normal return.
O(lift + expression DAGs + solver resources) time/space. Valid fixed component
cells, no native reachability, allocator or frame-producer equivalence claim.
"""
import json
import z3
from daemon_receive_tools import ROOT,IMAGE
from capture_daemon_record720 import sha
from daemon_arena_lifetime_symbolic import LifetimeFlags
from daemon_cleanup_return_symbolic import analyze
from validate_daemon_record720_spill import parse_value
from lskd_values_symbolic import mem,cell

def obligations():
    qs=[];counts={};S=0x680001ffa0;R=0x680002de90;F=0x6800020000
    def run(name,a,z,seeds=(),memory=()):
        v=LifetimeFlags({'spans':[{'label':name,'start':hex(a),'bytes_hex':IMAGE.read(a,z-a).hex()}]})
        for r,x in seeds:v.seed(r,x)
        for a,n,x in memory:mem(v,a,n,x)
        v.run(name);counts[name]=v.count;return v
    v=run('cleanup_literal',0x1001c6108,0x1001c6110)
    q=run('cleanup_record_store',0x100270ac4,0x100270ac8,[('x19',R),('w8',v.read('w8'))]);qs.append(('cleanup_raw_record_word',cell(q,R,4)!=0x364c5349))
    words={o:z3.BitVec('cleanup_saved_%x'%o,64)for o in range(16,96,8)};x=z3.BitVec('cleanup_epilogue_X0',64)
    v=run('cleanup_epilogue',0x100270ac8,0x100270ae0,[('sp',S),('x0',x)],[(S+o,8,w)for o,w in words.items()]);mapping={'x29':80,'x30':88,'x20':64,'x19':72,'x22':48,'x21':56,'x24':32,'x23':40,'x26':16,'x25':24};qs.append(('all_u64_cleanup_restore_SP_X0',z3.Or(v.read('sp')!=S+96,v.read('x0')!=x,*[v.read(r)!=words[o]for r,o in mapping.items()])))
    v=run('outer_literal',0x100952aa8,0x100952ab0);q=run('outer_spill',0x10095129c,0x1009512a0,[('sp',F),('w19',v.read('w19'))]);t=run('outer_reload',0x100b90ec8,0x100b90ecc,[('sp',F)],[(F+0x393c,4,cell(q,F+0x393c,4))]);qs.append(('outer_raw_word_to_W23',t.read('x23')!=0x74c29f37))
    x=z3.BitVec('cleanup_saved_output_base64',64);v=run('candidate_X0_spill',0x10064cea8,0x10064ceac,[('sp',F),('x0',x)]);q=run('output_base_reload',0x100b90ef4,0x100b90ef8,[('sp',F)],[(F+0x24f8,8,cell(v,F+0x24f8,8))]);qs.append(('all_u64_spill_reload_component',q.read('x0')!=x))
    P=0x6900000000;value=z3.BitVec('cleanup_output_word32',32);v=run('output_field',0x10095f074,0x10095f078,[('x0',P),('w23',value)],[(P+j,1,0xab)for j in range(32)]);qs.append(('all_u32_output_field_and_surroundings',z3.Or(cell(v,P+16,4)!=value,*[cell(v,P+j,1)!=0xab for j in list(range(16))+list(range(20,32))])))
    stored=json.loads((ROOT/'daemon_cleanup_return_symbolic.json').read_text());observed=[];newbytes=[]
    for row in stored['cases']:
        r=row['result'];variables={b['variable']:z3.BitVec(b['variable'],8)for b in r['unknown_bytes']};variables['lifetime_runtime_flag32']=z3.BitVec('lifetime_runtime_flag32',32);pairs=[]
        for b in r['ABI_symbolic_variables']:
            n=b['variable'];a=z3.Bool(n)if b['sort']=='Bool'else z3.BitVec(n,b['width_bits']);other=z3.Bool(n+'_other')if b['sort']=='Bool'else z3.BitVec(n+'_other',b['width_bits']);variables[n]=a;pairs.append((a,other))
        base=z3.Concat(*[variables['consumer_unavailable_byte_%x'%(F+0x24f8+j)]for j in reversed(range(8))]);addr=parse_value(r['boundary']['expression'],64,variables);newbytes.append(addr!=base+16)
        rebuilt,obs,stores,v=analyze({'context':r['context']});assert rebuilt==r
        values=[x for _,_,x in obs]+[x for _,_,_,x in stores]
        for e in r['effects']:values.append(parse_value(e['expression'],e['size_bytes']*8,variables))
        values.append(v.read('w23'));observed.extend(x!=z3.substitute(x,*pairs)for x in values)
    qs.append(('all_u64_opaque_output_address',z3.Or(*newbytes)));qs.append(('scalar_ABI_observable_noninterference',z3.Or(*observed)))
    return qs,counts,{'cleanup_restore_map':mapping,'source_cases':4,'component_frame_producer_join_established':False,'scalar_ABI_bits':1220,'noninterference_scope':'accepted memory effects, branch/access addresses, frontier address and W23; not all final volatile registers','native_PAC_executed':False}
if __name__=='__main__':
    qs,counts,meta=obligations();rows=[]
    for name,q in qs:
        a=ROOT/f'daemon_cleanup_return_{name}_original.smt2';b=ROOT/f'daemon_cleanup_return_{name}.smt2';s=z3.Solver();s.add(q);a.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(q));answer=str(s.check());assert answer=='unsat',(name,answer);b.write_text(s.to_smt2());rows.append({'name':name,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':answer});print(name,answer,flush=True)
    r={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['daemon_cleanup_return_source.json','daemon_cleanup_return_symbolic.json','daemon_cleanup_return_symbolic.py','lskd_values_symbolic.py']},'proofs':rows,'source_lift_counts':counts,'metadata':meta,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_cleanup_return_proofs.json').write_text(json.dumps(r,indent=2)+'\n')
