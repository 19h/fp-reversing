#!/usr/bin/env python3
"""Independent original-A64 replay, source/proof checks and geometry audit.
Finite unknown-byte witnesses are not source definitions. PAC branches are
checked logical edges; no PAC instruction or imported API executes.
O(source bytes + proof resources + witnesses*steps) time, O(case + map) space.
"""
import json,random,hashlib
from collections import Counter
import z3
import unicorn as uc
from unicorn import arm64_const as ar
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from capture_daemon_record720 import sha
from capture_daemon_arena_list import capture
from daemon_arena_list_symbolic import ListFlags
from prove_daemon_arena_list import obligations
from validate_daemon_record720_spill import materializations,parse_value
from validate_daemon_object_clock import logical_read
CS=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);CS.detail=True

def replay(symbolic,label,values,parsed):
    c=symbolic['context'];u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);pages=set();counts=Counter();index=0;pending=[];current=0
    def ensure(a,n):
        for pg in range(a&~4095,(a+n+4095)&~4095,4096):
            if pg in pages:continue
            if 0x100000000<=pg<0x102000000:
                try:b=logical_read(pg,4096)
                except ValueError:b=bytes(4096)
            else:b=bytes([0x39 if label=='zero'else 0xc7])*4096
            u.mem_map(pg,4096);u.mem_write(pg,b);pages.add(pg)
    def reg(name):return getattr(ar,'UC_ARM64_REG_'+name.upper())
    def get(name):return u.reg_read(reg(name))
    replacements=[(z3.BitVec(r['variable'],8),z3.BitVecVal(b,8))for r,b in zip(symbolic['unknown_bytes'],values,strict=True)]
    def evaluated(expr):
        value=z3.simplify(z3.substitute(expr,*replacements));assert z3.is_bv_value(value);return value.as_long()
    for g in c['known_byte_groups']:
        a=int(g['address'],16);b=bytes.fromhex(g['bytes_hex']);ensure(a,len(b));u.mem_write(a,b)
    for r,b in zip(symbolic['unknown_bytes'],values,strict=True):
        a=int(r['address'],16);ensure(a,1);u.mem_write(a,bytes([b]))
    for name,value in c['known_GPRs'].items():u.reg_write(reg(name),int(value,16))
    u.reg_write(ar.UC_ARM64_REG_SP,int(c['SP'],16));u.reg_write(ar.UC_ARM64_REG_NZCV,0x50000000 if label in['zero','a5']else 0xa0000000)
    def hook(_,kind,a,n,value,__):
        nonlocal index
        expected=symbolic['effects'][index];expr=parsed[index];index+=1;assert expected['pc']==hex(current)and int(expected['address'],16)==a and expected['size_bytes']==n
        if kind==uc.UC_MEM_READ:
            assert expected['kind']=='read';actual=int.from_bytes(bytes(u.mem_read(a,n)),'little');assert actual==evaluated(expr);counts['reads_checked']+=1
        else:assert expected['kind']=='write';pending.append((a,n,expr));counts['writes_checked']+=1
    u.hook_add(uc.UC_HOOK_MEM_READ|uc.UC_HOOK_MEM_WRITE,hook);edge_iter=iter(symbolic['edges']);pc=int(c['entry_PC'],16)
    for expected,raw in symbolic['steps']:
        assert pc==expected;current=pc;i=next(CS.disasm(IMAGE.read(pc,4),pc));assert bytes(i.bytes).hex()==raw;ensure(pc,4)
        if i.mnemonic=='braa':
            edge=next(edge_iter);target,modifier=[get(x.strip())for x in i.op_str.split(',')];slot=int(edge['slot'],16);word=int.from_bytes(IMAGE.read(slot,8),'little');assert edge['pc']==hex(pc)and edge['target']==hex(target)and edge['modifier']==hex(modifier)and FIXUPS[slot]['target']==target and word>>63==1 and(word>>32)&0xffff==modifier and(word>>48)&7==0;pc=target;counts['logical_PAC_edges_checked']+=1;continue
        # Map only the known fixed address recorded by the symbolic source
        # model; Unicorn computes and checks the actual effective address.
        j=index
        while j<len(symbolic['effects'])and symbolic['effects'][j]['pc']==hex(pc):
            e=symbolic['effects'][j];ensure(int(e['address'],16),e['size_bytes']);j+=1
        u.emu_start(pc,0,count=1);pc=u.reg_read(ar.UC_ARM64_REG_PC);counts['A64_instructions_checked']+=1
        for a,n,expr in pending:assert int.from_bytes(bytes(u.mem_read(a,n)),'little')==evaluated(expr)
        pending.clear()
    assert index==len(symbolic['effects'])and next(edge_iter,None)is None and pc==int(symbolic['boundary']['pc'],16)
    for name,text in symbolic['end_GPR_expressions'].items():assert get(name)==evaluated(parse_value(text,64,{r['variable']:z3.BitVec(r['variable'],8)for r in symbolic['unknown_bytes']})),name
    counts['witnesses_checked']+=1;counts['opaque_byte_materializations']+=len(values)
    return {'label':label,'bytes_hex':values.hex(),'materialization_sha256':hashlib.sha256(values).hexdigest(),'counts':dict(counts),'same_symbolic_frontier':True,'source_definitions_added':False}

def check_ccmp():
    pc=0x100552d04;raw=IMAGE.read(pc,4);i=next(CS.disasm(raw,pc));assert i.mnemonic=='ccmp'and i.op_str=='x2, x16, #0, gt'
    u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);u.mem_map(pc&~4095,4096);u.mem_write(pc,raw);r=random.Random(730);corners=[0,1,(1<<63)-1,1<<63,(1<<64)-1];pairs=[(a,b)for a in corners for b in corners]+[(r.getrandbits(64),r.getrandbits(64))for _ in range(7)];count=0
    for bits in range(16):
        for a,b in pairs:
            v=ListFlags({'spans':[{'label':'ccmp','start':hex(pc),'bytes_hex':raw.hex()}]});v.seed('x2',a);v.seed('x16',b)
            v.negative=z3.BoolVal(bool(bits&8));v.equal=z3.BoolVal(bool(bits&4));v.carry=z3.BoolVal(bool(bits&2));v.overflow=z3.BoolVal(bool(bits&1));v.run('ccmp');expected=sum(int(z3.is_true(z3.simplify(expr)))<<shift for expr,shift in [(v.negative,3),(v.equal,2),(v.carry,1),(v.overflow,0)])
            u.reg_write(ar.UC_ARM64_REG_X2,a);u.reg_write(ar.UC_ARM64_REG_X16,b);u.reg_write(ar.UC_ARM64_REG_NZCV,bits<<28);u.emu_start(pc,0,count=1);assert u.reg_read(ar.UC_ARM64_REG_NZCV)>>28==expected;count+=1
    return count

def number(text,n=64):
    v=z3.simplify(parse_value(text,n,{}));assert z3.is_bv_value(v);return v.as_long()

def audit_case(case,row,parent):
    result=row['result'];c=case['context'];assert result['context']==c and len(result['unknown_bytes'])==104 and result['unknown_bytes']==parent['unknown_bytes'];assert result['steps'][:240]==parent['steps']and result['effects'][:39]==parent['effects']and result['edges'][:7]==parent['edges']
    assert all(IMAGE.read(pc,4).hex()==raw for pc,raw in result['steps']);assert not result['unknown_bytes_assigned_values']
    if case['label']=='sentinel_equal':
        assert result['boundary']['kind']=='before_import_call'and result['boundary']['pc']=='0x100477840'and result['boundary']['argument_X0']=='0x1388'and result['boundary']['binding']['symbol']=='_malloc';assert len(result['steps'])==296
        return {'label':case['label'],'original_prefix_steps':240,'source_steps':len(result['steps']),'source_effects':len(result['effects']),'logical_edges':len(result['edges']),'declared_empty_fixture':True}
    H=int(case['arena_owner'],16);D=0x1010b5ef0;M=0x5e878c613b8123ea;N=90000;d=1676;T=N-24;R=T-d;B=H+R;payload=B+24
    assert result['boundary']=={'pc':'0x10031f248','kind':'before_allocator_continuation','payload_X23':hex(payload),'boundary_X0':hex(B)}and len(result['steps'])==64295
    fills=[e for e in result['effects']if e['kind']=='write'and e['pc']=='0x1006081f8'];assert len(fills)==d+48 and [int(e['address'],16)for e in fills]==list(range(H+T-1,H+R-49,-1));assert len({number(e['expression'],8)for e in fills})>1
    late=[e for e in result['effects']if e['kind']=='write'and int(e['pc'],16)in [0x10058835c,0x100588378,0x1005883b4,0x1005883cc,0x1005883d8,0x100634280]]
    values={int(e['address'],16):number(e['expression'],e['size_bytes']*8)for e in late};old=0x1aa4071f0801765b
    for at,value in {H+8:M+R,B:M+R,B+8:M-d,H+T:M,D+40:old+d,0x1010b5de0:0x5d96}.items():assert values[at]==value
    assert result['edges'][-1]=={'pc':'0x10063428c','target':'0x10031f248','slot':'0x10103b7c0','modifier':'0x7315','kind':'braa'}
    return {'label':case['label'],'original_prefix_steps':240,'source_steps':len(result['steps']),'source_effects':len(result['effects']),'logical_edges':len(result['edges']),'arena_bytes':N,'initial_known_heap_bytes':48,'initial_unknown_heap_bytes':N-48,'debit_bytes':d,'old_span_bytes':T,'remaining_bytes':R,'boundary':hex(B),'payload':hex(payload),'gap_from_payload_to_old_end_bytes':T-R-24,'fill_bytes':len(fills),'fill_start':hex(H+R-48),'fill_end_exclusive':hex(H+T),'metadata_writes':late}

def main():
    source=json.loads((ROOT/'daemon_arena_list_source.json').read_text());assert source==capture();symbolic=json.loads((ROOT/'daemon_arena_list_symbolic.json').read_text());proofs=json.loads((ROOT/'daemon_arena_list_proofs.json').read_text());parent=json.loads((ROOT/'daemon_record720_spill_symbolic.json').read_text())
    for obj,script in [(source,'capture_daemon_arena_list.py'),(symbolic,'daemon_arena_list_symbolic.py'),(proofs,'prove_daemon_arena_list.py')]:
        assert obj['generator_sha256']==sha(ROOT/script)
        for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h,(script,n)
    qs,counts,meta=obligations(source);assert counts==proofs['source_lift_counts']and meta==proofs['metadata'];out=Counter();totals=Counter();audits=[];witnesses=[]
    for (name,query),row in zip(qs,proofs['proofs'],strict=True):
        assert row['name']==name
        for key,expr in [('original_file',query),('file',z3.simplify(query))]:
            p=ROOT/row[key];assert sha(p)==row['original_sha256'if key=='original_file'else'sha256'];items=z3.parse_smt2_file(str(p));s=z3.Solver();s.set(timeout=30000);s.add(*items);assert s.check()==z3.unsat;s=z3.Solver();s.set(timeout=30000);s.add(z3.Xor(z3.And(*items),expr));assert s.check()==z3.unsat;out['SMT_files_checked']+=1
        out['source_obligations_rebuilt']+=1
    expected={r[k]for r in proofs['proofs']for k in ['file','original_file']};assert expected=={p.name for p in ROOT.glob('daemon_arena_list_*.smt2')}
    out['independent_CCMP_flag_cases']=check_ccmp();print('CCMP flag cases',out['independent_CCMP_flag_cases'],flush=True)
    for case,row in zip(source['cases'],symbolic['cases'],strict=True):
        assert case['label']==row['label'];audit=audit_case(case,row,parent);audits.append(audit);result=row['result'];variables={r['variable']:z3.BitVec(r['variable'],8)for r in result['unknown_bytes']};cache={}
        def parsed_effect(e):
            k=(e['expression'],e['size_bytes'])
            if k not in cache:cache[k]=parse_value(e['expression'],e['size_bytes']*8,variables)
            return cache[k]
        parsed=[parsed_effect(e)for e in result['effects']]
        for label,values in [materializations(104)[j]for j in [0,2,3,6]]:
            w=replay(result,label,values,parsed);w['case']=case['label'];witnesses.append(w);totals.update(w['counts']);print(case['label'],label,w['counts']['A64_instructions_checked'],flush=True)
        out.update(symbolic_source_steps_checked=len(result['steps']),symbolic_effects_checked=len(result['effects']),logical_edges_checked=len(result['edges']),unchanged_parent_steps_checked=240,unconstrained_frame_byte_instances=104)
    out.update(unconstrained_frame_bytes_per_case=104,IDB_ranges=len(source['live_IDB_matches']),IDB_bytes=sum(r['size_bytes']for r in source['live_IDB_matches']),cases=3,source_data_lift_visits=sum(counts.values()))
    r={'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['daemon_arena_list_source.json','daemon_arena_list_symbolic.json','daemon_arena_list_proofs.json','daemon_arena_list_symbolic.py','prove_daemon_arena_list.py','validate_daemon_record720_spill.py','validate_daemon_object_clock.py']},'verified_counts':dict(out),'independent_witness_totals':dict(totals),'audits':audits,'witnesses':witnesses,'all_checks_pass':True,'native_target_executed':False,'PAC_executed':False,'unknown_bytes_assigned_source_values':False,'new_port_emission_established':False,'registry_publication_established':False,'full_goal_complete':False};(ROOT/'daemon_arena_list_checks.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'verified_counts':dict(out),'witnesses':dict(totals)}),flush=True)
if __name__=='__main__':main()
