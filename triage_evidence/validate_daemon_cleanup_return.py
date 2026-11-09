#!/usr/bin/env python3
"""Independent original-A64 replay from each retained pre-lifetime checkpoint,
through its frozen suffix and the new normal-free-return continuation. Finite
frame, flag and ABI witnesses remain separate from universal source semantics.
O(replay visits + expression evaluation + source bytes) time, O(case/map) space.
Logical PAC only; no native allocator, target, port operation or pointer source.
"""
import json,random,hashlib
from collections import Counter
import z3
import unicorn as uc
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from capture_daemon_record720 import sha
from capture_daemon_cleanup_return import capture
from daemon_cleanup_return_symbolic import analyze,CS
from validate_daemon_record720_spill import parse_value
from validate_daemon_object_clock import logical_read

def replay(parent,child,witness,flag_value):
    c=parent['context'];r=child;u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);pages=set();counts=Counter();index=0;pending=[];current=0;rng=random.Random(7800+witness)
    def ensure(a,n):
        for p in range(a&~4095,(a+n+4095)&~4095,4096):
            if p in pages:continue
            if 0x100000000<=p<0x102000000:
                try:b=logical_read(p,4096)
                except ValueError:b=bytes(4096)
            else:b=bytes([0xa5 if witness else 0x39])*4096
            u.mem_map(p,4096);u.mem_write(p,b);pages.add(p)
    def reg(n):return getattr(ar,'UC_ARM64_REG_'+n.upper())
    def get(n):return u.reg_read(reg(n))
    variables={b['variable']:z3.BitVec(b['variable'],8)for b in r['unknown_bytes']};variables['lifetime_runtime_flag32']=z3.BitVec('lifetime_runtime_flag32',32)
    framevalues=[rng.getrandbits(8)if witness else 0 for _ in r['unknown_bytes']];replacements=[(variables[b['variable']],z3.BitVecVal(x,8))for b,x in zip(r['unknown_bytes'],framevalues,strict=True)]+[(variables['lifetime_runtime_flag32'],z3.BitVecVal(flag_value,32))];abi={}
    for b in r['ABI_symbolic_variables']:
        n=b['variable'];v=z3.Bool(n)if b['sort']=='Bool'else z3.BitVec(n,b['width_bits']);variables[n]=v;value=bool(rng.getrandbits(1))if b['sort']=='Bool'else rng.getrandbits(64);abi[n]=value;replacements.append((v,z3.BoolVal(value)if b['sort']=='Bool'else z3.BitVecVal(value,64)))
    def evaluate(expr):
        v=z3.simplify(z3.substitute(expr,*replacements));assert z3.is_bv_value(v)or z3.is_true(v)or z3.is_false(v);return v.as_long()if z3.is_bv_value(v)else z3.is_true(v)
    initial_defined=set()
    for g in c['known_byte_groups']:
        a=int(g['address'],16);b=bytes.fromhex(g['bytes_hex']);ensure(a,len(b));u.mem_write(a,b);initial_defined.update(range(a,a+len(b)))
    for b in c['symbolic_bytes']:
        a=int(b['address'],16);ensure(a,1);u.mem_write(a,bytes([evaluate(parse_value(b['expression'],8,variables))]));initial_defined.add(a)
    # Only newly discovered missing output-base bytes receive initial witnesses.
    # Old unavailable variables already enter through checkpoint expressions.
    oldvars={b['variable']for b in parent['unknown_bytes']}
    for b,x in zip(r['unknown_bytes'],framevalues,strict=True):
        if b['variable']in oldvars:continue
        a=int(b['address'],16);assert a not in initial_defined;ensure(a,1);u.mem_write(a,bytes([x]))
    for g in c['symbolic_global_words']:
        a=int(g['address'],16);ensure(a,4);u.mem_write(a,flag_value.to_bytes(4,'little'))
    for n,x in c['known_GPRs'].items():u.reg_write(reg(n),int(x,16))
    for n,t in c['symbolic_GPR_expressions'].items():u.reg_write(reg(n),evaluate(parse_value(t,64,variables)))
    u.reg_write(reg('sp'),int(c['SP'],16));u.reg_write(ar.UC_ARM64_REG_NZCV,int(c['NZCV'],16))
    effects=parent['effects']+r['effects'];parsed=[parse_value(e['expression'],e['size_bytes']*8,variables)for e in effects]
    def hook(_,kind,a,n,value,__):
        nonlocal index
        e=effects[index];expr=parsed[index];index+=1;assert e['pc']==hex(current)and int(e['address'],16)==a and e['size_bytes']==n
        if kind==uc.UC_MEM_READ:assert e['kind']=='read'and int.from_bytes(bytes(u.mem_read(a,n)),'little')==evaluate(expr);counts['reads_checked']+=1
        else:assert e['kind']=='write';pending.append((a,n,expr));counts['writes_checked']+=1
    u.hook_add(uc.UC_HOOK_MEM_READ|uc.UC_HOOK_MEM_WRITE,hook);edges=iter(parent['edges']+r['edges']);returns=iter(parent['return_edges']+r['return_edges']);pc=int(c['entry_PC'],16);checkpoint=False
    for expected,raw in parent['steps']+r['steps']:
        assert expected==pc;current=pc;i=next(CS.disasm(IMAGE.read(pc,4),pc));assert bytes(i.bytes).hex()==raw;ensure(pc,4)
        if pc==0x1001c6100:
            assert not checkpoint and index==len(parent['effects']);cc=r['context']
            for g in cc['known_byte_groups']:
                a=int(g['address'],16);b=bytes.fromhex(g['bytes_hex']);assert bytes(u.mem_read(a,len(b)))==b;counts['checkpoint_known_bytes_checked']+=len(b)
            for b in cc['symbolic_bytes']:
                a=int(b['address'],16);assert bytes(u.mem_read(a,1))[0]==evaluate(parse_value(b['expression'],8,variables));counts['checkpoint_symbolic_bytes_checked']+=1
            for n,x in cc['known_GPRs'].items():assert get(n)==int(x,16);counts['checkpoint_GPRs_checked']+=1
            assert u.reg_read(ar.UC_ARM64_REG_NZCV)==int(cc['NZCV'],16);counts['checkpoint_NZCV_checked']+=1
            api=r['API_models'][0];assert i.mnemonic=='blraa'and get('x0')==int(api['argument_X0'],16)and get('x17')==0x46a2 and int(api['binding']['slot'],16)==0x10109ff30
            owner=int(api['argument_X0'],16);ensure(owner,720);u.mem_write(owner,bytes([0x5a if witness else 0xc3])*720)
            h=api['modeled_stack_havoc'];lo,hi=int(h['start'],16),int(h['end'],16)
            for p in sorted(pages):
                a,z=max(lo,p),min(hi,p+4096)
                if a<z:u.mem_write(a,bytes([0xe1 if witness else 0x27])*(z-a))
            for b in r['ABI_symbolic_variables']:
                if 'register'in b:u.reg_write(reg(b['register']),abi[b['variable']])
            bits=sum(int(abi['cleanup_free_NZCV_'+n])<<shift for n,shift in [('N',3),('Z',2),('C',1),('V',0)]);u.reg_write(ar.UC_ARM64_REG_NZCV,bits<<28);pc+=4;checkpoint=True;counts['modeled_API_returns']+=1;continue
        if i.mnemonic in ['braa','blraa']:
            e=next(edges);target,modifier=[get(n.strip())for n in i.op_str.split(',')];slot=int(e['slot'],16);word=int.from_bytes(IMAGE.read(slot,8),'little');assert e['pc']==hex(pc)and int(e['target'],16)==target and int(e['modifier'],16)==modifier and FIXUPS[slot]['target']==target and word>>63==1 and(word>>32)&0xffff==modifier and(word>>48)&7==0
            if i.mnemonic=='blraa':u.reg_write(reg('x30'),pc+4);counts['logical_calls']+=1
            pc=target;counts['logical_PAC_edges']+=1;continue
        if i.mnemonic=='retab':
            e=next(returns);assert e['pc']==hex(pc)and get('x30')==int(e['target'],16)and get('sp')==int(e['SP'],16);pc=int(e['target'],16);counts['logical_returns']+=1;continue
        if i.mnemonic=='pacibsp':assert pc==0x100435b9c and get('x30')==0x100be0c54;pc+=4;counts['logical_signs']+=1;continue
        j=index
        while j<len(effects)and effects[j]['pc']==hex(pc):e=effects[j];ensure(int(e['address'],16),e['size_bytes']);j+=1
        u.emu_start(pc,0,count=1);pc=u.reg_read(ar.UC_ARM64_REG_PC);counts['A64_instructions_checked']+=1
        for a,n,expr in pending:assert int.from_bytes(bytes(u.mem_read(a,n)),'little')==evaluate(expr)
        pending.clear()
    assert checkpoint and pc==0x10095f074 and index==len(effects)and next(edges,None)is None and next(returns,None)is None
    for n,t in r['end_GPR_expressions'].items():assert get(n)==evaluate(parse_value(t,64,variables)),n
    for n,shift in [('N',3),('Z',2),('C',1),('V',0)]:assert bool((u.reg_read(ar.UC_ARM64_REG_NZCV)>>28)&(1<<shift))==evaluate(z3.parse_smt2_string('(assert '+r['end_NZCV_expressions'][n]+')',decls=variables)[0])
    assert get('x23')==0x74c29f37;counts['witnesses_checked']+=1
    return {'witness':witness,'flag_value':hex(flag_value),'frame_materialization_sha256':hashlib.sha256(bytes(framevalues)).hexdigest(),'output_base_witness':hex(get('x0')),'boundary_store_executed':False,'counts':dict(counts),'source_definitions_added':False}

def output_component():
    rng=random.Random(19351);out=[]
    for j in range(16):
        u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);base=0x6900000000+j*0x1000;pc=0x10095f074;u.mem_map(base,4096);u.mem_write(base,bytes([0xab])*64);u.mem_map(pc&~4095,4096);u.mem_write(pc,IMAGE.read(pc,4));x=0x74c29f37 if j==0 else rng.getrandbits(32);u.reg_write(ar.UC_ARM64_REG_X0,base);u.reg_write(ar.UC_ARM64_REG_X23,x);u.emu_start(pc,0,count=1);assert bytes(u.mem_read(base,64))==bytes([0xab])*16+x.to_bytes(4,'little')+bytes([0xab])*44;out.append({'base':hex(base),'W23':hex(x),'only_bytes_16_to_19_changed':True})
    return out

def main():
    source=json.loads((ROOT/'daemon_cleanup_return_source.json').read_text());symbolic=json.loads((ROOT/'daemon_cleanup_return_symbolic.json').read_text());parents=json.loads((ROOT/'daemon_arena_lifetime_symbolic.json').read_text());assert capture()==source;contracts=json.loads((ROOT/'daemon_cleanup_return_contracts.json').read_text());proofs=json.loads((ROOT/'daemon_cleanup_return_proofs.json').read_text());audits=[];witnesses=[];total=Counter()
    for old,case,row in zip(parents['cases'],source['cases'],symbolic['cases'],strict=True):
        r=row['result'];assert old['label']==case['label']==row['label'];rebuilt,obs,stores,v=analyze(case);assert rebuilt==r
        assert len(r['steps'])==133 and len(r['effects'])==24 and len(r['edges'])==9 and len(r['return_edges'])==1 and len(r['unknown_bytes'])==112 and not r['ABI_reads_before_definition']and len(r['ABI_symbolic_variables'])==23 and not r['active_calls'];assert r['boundary']['kind']=='nonunique_write_address'and r['boundary']['solver_answer']=='sat'
        assert all(0x6800070000>=int(e['address'],16)+e['size_bytes']or int(e['address'],16)>=0x68000702d0 for e in r['effects'])
        assert all(not(0x680001c000<=int(e['address'],16)<0x680001ffa0)for e in r['effects'])
        vals=[]
        for w in range(2):
            flag=0 if case['context']['path_class']=='zero'else (1 if w==0 else 0xffffffff);one=replay(old['result'],r,w,flag);total.update(one['counts']);vals.append(one);print(row['label'],w,one['counts'],flush=True)
        witnesses.append({'case':row['label'],'runs':vals});audits.append({'case':row['label'],'source_journal_rebuilt':True,'caller_saved_reads_before_definition':0,'opaque_output_base_bits':64,'retired_owner_accesses':0,'API_clobbered_stack_accesses':0})
    from prove_daemon_cleanup_return import obligations
    qs,_,_=obligations();assert len(qs)==len(proofs['proofs'])
    for (name,q),p in zip(qs,proofs['proofs'],strict=True):
        assert name==p['name']
        for f,h in [('file','sha256'),('original_file','original_sha256')]:
            path=ROOT/p[f];assert sha(path)==p[h];solver=z3.Solver();solver.set(timeout=30000);solver.add(z3.parse_smt2_file(str(path)));assert solver.check()==z3.unsat
        solver=z3.Solver();solver.add(q);assert solver.check()==z3.unsat
    components=output_component();assert contracts['candidate_count']==7 and contracts['X0_candidate_count']==5 and len(contracts['live_IDA_matches'])==5
    result={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['daemon_cleanup_return_source.json','daemon_cleanup_return_symbolic.json','daemon_cleanup_return_symbolic.py','daemon_cleanup_return_contracts.json','daemon_cleanup_return_proofs.json','daemon_arena_lifetime_symbolic.json']},'audits':audits,'witnesses':witnesses,'independent_A64_totals':dict(total),'owned_output_component_cases':components,'verified_counts':{'source_cases_rebuilt':4,'source_obligations_rebuilt':len(qs),'accepted_SMT_files':2*len(qs),'original_IDA_ranges':5,'original_IDA_matching_bytes':960,'output_component_cases':len(components),'literal_SP_spill_candidates':7},'normal_free_return_assumed':True,'native_target_executed':False,'host_free_executed':False,'runtime_flag_concretized_in_source':False,'full_goal_complete':False,'all_checks_pass':True};(ROOT/'daemon_cleanup_return_checks.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'totals':dict(total),'all_checks_pass':True}))
if __name__=='__main__':main()
