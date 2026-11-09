#!/usr/bin/env python3
"""Rebuild the symbolic successor and source proofs; independently execute
finite materializations of its opaque bytes in Unicorn, instruction by
instruction. O(parent bytes/visits + census + symbolic DAGs + witnesses*steps
+ solver resources) time; O(parent case + one private map + DAGs) space.
Materializations are witnesses, not source definitions or native values.
"""
import json,random,hashlib
from collections import Counter
import z3
import unicorn as uc
from unicorn import arm64_const as ar
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from capture_daemon_record720 import sha
from capture_daemon_record720_spill import capture
from daemon_record720_spill_symbolic import analyze
from prove_daemon_record720_spill import obligations
from validate_daemon_object_clock import logical_read

CS=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);CS.detail=True
def materializations(n):
    rows=[('zero',bytes(n)),('ones',bytes([255])*n),('a5',bytes([0xa5])*n),('5a',bytes([0x5a])*n),('ascending',bytes(j&255 for j in range(n))),('descending',bytes((255-j)&255 for j in range(n)))]
    for seed in range(10):
        r=random.Random(seed);rows.append(('seed_'+str(seed),bytes(r.randrange(256)for _ in range(n))))
    return rows

def parse_value(text,n,variables):
    result=z3.BitVec('check_value',n);decls={'check_value':result,**variables};expr=z3.parse_smt2_string('(assert (= check_value '+text+'))',decls=decls)[0];return expr.arg(1)

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
    assert get('x6')==0x1010b5ef0 and all(e['address']!='0x1010b5f38'for e in symbolic['effects']);counts['witnesses_checked']+=1;counts['opaque_byte_materializations']+=len(values)
    return {'label':label,'bytes_hex':values.hex(),'materialization_sha256':hashlib.sha256(values).hexdigest(),'counts':dict(counts),'same_symbolic_frontier':True,'source_definitions_added':False}

def main():
    source=json.loads((ROOT/'daemon_record720_spill_source.json').read_text());assert source==capture();stored=json.loads((ROOT/'daemon_record720_spill_symbolic.json').read_text());result,obs,stores,v=analyze(source)
    for k,value in result.items():assert stored[k]==value,k
    proofs=json.loads((ROOT/'daemon_record720_spill_proofs.json').read_text());qs,counts,meta=obligations(source);assert counts==proofs['source_lift_counts']and meta==proofs['metadata'];totals=Counter();out=Counter();witnesses=[]
    for obj,script in [(source,'capture_daemon_record720_spill.py'),(stored,'daemon_record720_spill_symbolic.py'),(proofs,'prove_daemon_record720_spill.py')]:
        assert obj['generator_sha256']==sha(ROOT/script)
        for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h
    for (name,query),row in zip(qs,proofs['proofs'],strict=True):
        assert row['name']==name
        for key,expr in [('original_file',query),('file',z3.simplify(query))]:
            p=ROOT/row[key];assert sha(p)==row['original_sha256'if key=='original_file'else'sha256'];items=z3.parse_smt2_file(str(p));s=z3.Solver();s.set(timeout=30000);s.add(*items);assert s.check()==z3.unsat;s=z3.Solver();s.set(timeout=30000);s.add(z3.Xor(z3.And(*items),expr));assert s.check()==z3.unsat;out['SMT_files_checked']+=1
        out['source_obligations_rebuilt']+=1
    expected={r[k]for r in proofs['proofs']for k in ['file','original_file']};assert expected=={p.name for p in ROOT.glob('daemon_spill720_*.smt2')}
    variables={r['variable']:z3.BitVec(r['variable'],8)for r in result['unknown_bytes']};parsed=[parse_value(e['expression'],e['size_bytes']*8,variables)for e in result['effects']]
    for label,values in materializations(len(variables)):
        w=replay(result,label,values,parsed);witnesses.append(w);totals.update(w['counts'])
    assert len(result['steps'])==240 and len(result['unknown_bytes'])==104 and len(meta['opaque_store_byte_map'])==56
    assert result['boundary']=={'pc':'0x1004a0620','kind':'before_unmodeled_runtime_read','address':'0x1010b5f38','size_bytes':8,'first_missing_byte':'0x1010b5f38'}
    out.update(parent_source_visits_checked=source['context']['source_visits_consumed'],parent_known_bytes_reconstructed=source['context']['known_byte_count'],symbolic_source_steps_checked=len(result['steps']),symbolic_effects_checked=len(result['effects']),logical_edges_checked=len(result['edges']),unconstrained_frame_bytes=104,unconstrained_frame_bits=832,opaque_copy_bytes=56,source_data_lift_visits=sum(counts.values()),literal_STR64_candidates=len(source['STR64_SP_2E8_census']),immediate_store_overlap_candidates=len(source['immediate_SP_store_overlap_census']),IDB_ranges=len(source['live_IDB_matches']),IDB_bytes=sum(r['size_bytes']for r in source['live_IDB_matches']))
    r={'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['daemon_record720_spill_source.json','daemon_record720_spill_symbolic.json','daemon_record720_spill_proofs.json','daemon_record720_spill_symbolic.py']},'verified_counts':dict(out),'independent_witness_totals':dict(totals),'witnesses':witnesses,'all_checks_pass':True,'native_target_executed':False,'unknown_bytes_assigned_source_values':False,'new_port_emission_established':False,'full_goal_complete':False};(ROOT/'daemon_record720_spill_checks.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'verified_counts':dict(out),'witnesses':dict(totals)}),flush=True)

if __name__=='__main__':main()
