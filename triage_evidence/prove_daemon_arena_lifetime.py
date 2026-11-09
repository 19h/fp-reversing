#!/usr/bin/env python3
"""Source-local account, output, cursor and stack-return contracts plus exact
universal flag-class address certificates. O(lift + BV DAGs + solver resources)
time/space. Fixed valid component cells; no general allocator or native PAC proof.
"""
import json
import z3
from daemon_receive_tools import ROOT,IMAGE
from daemon_arena_lifetime_symbolic import LifetimeFlags
from capture_daemon_record720 import sha
from lskd_values_symbolic import mem,cell
from validate_daemon_record720_spill import parse_value

def obligations():
    qs=[];counts={};S=0x680001f250;M=0x5e878c613b8123ea;D=0x1010b5ef0
    def run(name,a,z,seeds=(),memory=()):
        v=LifetimeFlags({'spans':[{'label':name,'start':hex(a),'bytes_hex':IMAGE.read(a,z-a).hex()}]})
        for r,x in seeds:v.seed(r,x)
        for at,n,x in memory:mem(v,at,n,x)
        v.run(name);counts[name]=v.count;return v
    words={off:z3.BitVec('lifetime_saved_%x'%off,64)for off in range(0,96,8)};out=z3.BitVec('lifetime_X0_at_epilogue64',64)
    v=run('dispatcher_epilogue',0x10061aad8,0x10061aaf4,[('sp',S),('x0',out)],[(S+0xd00+off,8,x)for off,x in words.items()]);mapping={'x28':0,'x27':8,'x26':16,'x25':24,'x24':32,'x23':40,'x22':48,'x21':56,'x20':64,'x19':72,'x29':80,'x30':88}
    dispatcher_map=dict(mapping)
    qs.append(('all_u64_dispatcher_restore_and_SP',z3.Or(v.read('sp')!=S+0xd60,v.read('x0')!=out,*[v.read(r)!=words[o]for r,o in mapping.items()])))
    now,old=z3.BitVecs('lifetime_cursor_now32 lifetime_cursor_before32',32);C=0x680001ffa0;O=0x6800023988
    v=run('cursor_output',0x100537104,0x100537114,[('x20',C),('w21',old),('x19',O)],[(C,4,now)])
    qs.append(('all_u32_adapter_cursor_output',cell(v,O,8)!=(z3.ZeroExt(32,(now-old)&0xffff)<<4)))
    F=0x680001fff0;saved={o:z3.BitVec('lifetime_adapter_saved_%x'%(o+32),64)for o in range(-32,16,8)}
    v=run('adapter_epilogue',0x100537114,0x100537124,[('x29',F),('sp',S),('x0',out)],[(F+o,8,x)for o,x in saved.items()]);mapping={'x22':-32,'x21':-24,'x20':-16,'x19':-8,'x29':0,'x30':8}
    qs.append(('all_u64_adapter_restore_and_SP',z3.Or(v.read('sp')!=F+16,v.read('x0')!=out,*[v.read(r)!=saved[o]for r,o in mapping.items()])))
    R=0x680002de90;status=z3.BitVec('lifetime_record_status32',32)
    v=run('record_status',0x10061aab8,0x10061aac0,[('sp',S),('w9',status)],[(S+32,8,R)])
    qs.append(('all_u32_record_status_store',cell(v,R+28,4)!=status))
    account,debit=z3.BitVecs('lifetime_account64 lifetime_debit64',64)
    v=run('account_debit',0x10061d6b4,0x10061d6d4,[('x16',D),('x13',M-debit)],[(D+40,8,account)])
    qs.append(('all_u64_modular_account_debit',cell(v,D+40,8)!=account-debit))
    v=run('checkpoint_flags',0x10062b2ac,0x10062b2d0,[('w9',0xa220),('x25',0x1010c5798)],[(0x1010c5798,1,1)])
    qs.append(('source_checkpoint_NZCV_0110',z3.Or(v.negative,z3.Not(v.equal),z3.Not(v.carry),v.overflow)))
    stored=json.loads((ROOT/'daemon_arena_lifetime_symbolic.json').read_text());seen={};bindings=[]
    for case in stored['cases']:
        r=case['result'];variables={b['variable']:z3.BitVec(b['variable'],8)for b in r['unknown_bytes']};variables['lifetime_runtime_flag32']=z3.BitVec('lifetime_runtime_flag32',32)
        for item in r['resolution_certificates']:
            expr=parse_value(item['expression'],item['width_bits'],variables);path=z3.parse_smt2_string('(assert '+item['path_condition']+')',decls=variables)[0];s=z3.Solver();s.add(path);assert s.check()==z3.sat
            query=z3.And(path,expr!=int(item['unique_value'],16));key=query.sexpr()
            if key not in seen:
                name='universal_flag_'+r['context']['path_class']+'_address';seen[key]=name;qs.append((name,query))
            bindings.append({'case':case['label'],'pc':item['pc'],'role':item['role'],'theorem':seen[key],'unique_value':item['unique_value']})
    return qs,counts,{'dispatcher_restore_map':dispatcher_map,'adapter_restore_map':mapping,'resolution_bindings':bindings,'frame_cells_valid_by_component_premise':True,'native_PAC_executed':False}
if __name__=='__main__':
    qs,counts,meta=obligations();rows=[]
    for name,query in qs:
        a=ROOT/f'daemon_arena_lifetime_{name}_original.smt2';b=ROOT/f'daemon_arena_lifetime_{name}.smt2';s=z3.Solver();s.add(query);a.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(query));answer=str(s.check());assert answer=='unsat',(name,answer);b.write_text(s.to_smt2());rows.append({'name':name,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':answer});print(name,answer,flush=True)
    r={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['daemon_arena_lifetime_source.json','daemon_arena_lifetime_symbolic.json','daemon_arena_lifetime_symbolic.py','lskd_values_symbolic.py']},'proofs':rows,'source_lift_counts':counts,'metadata':meta,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_arena_lifetime_proofs.json').write_text(json.dumps(r,indent=2)+'\n')
