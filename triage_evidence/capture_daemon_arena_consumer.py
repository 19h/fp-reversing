#!/usr/bin/env python3
"""Reconstruct byte-exact symbolic checkpoints and original pointer origins
from verified arena journals. O(parent visits + effects + byte-expression DAGs)
time, O(defined memory + journal) space. No fresh state or native epoch.
"""
import json,copy
import z3
from capstone.arm64_const import ARM64_OP_REG
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from daemon_arena_list_symbolic import CS
from daemon_digest_output_access import key
from capture_daemon_record720 import sha
from capture_daemon_arena_list import group_bytes
from validate_daemon_record720_spill import parse_value

def reconstruct(result):
    c=result['context'];variables={r['variable']:z3.BitVec(r['variable'],8)for r in result['unknown_bytes']};ram={};cache={};origins={};memory_origins={int(a,16):int(o,16)for a,o in c['memory_pointer_origins'].items()};at_event=0;pac=0
    for g in c['known_byte_groups']:
        ram.update({int(g['address'],16)+j:z3.BitVecVal(b,8)for j,b in enumerate(bytes.fromhex(g['bytes_hex']))})
    for r in result['unknown_bytes']:
        a=int(r['address'],16);assert a not in ram;ram[a]=variables[r['variable']]
    def parsed(e):
        k=(e['expression'],e['size_bytes'])
        if k not in cache:cache[k]=parse_value(e['expression'],8*e['size_bytes'],variables)
        return cache[k]
    for pc,raw in result['steps']:
        assert IMAGE.read(pc,4).hex()==raw;i=next(CS.disasm(bytes.fromhex(raw),pc));old=origins.copy();events=[]
        while at_event<len(result['effects'])and result['effects'][at_event]['pc']==hex(pc):
            e=result['effects'][at_event];events.append(e);at_event+=1
        if i.mnemonic=='braa':
            r=key(i.op_str.split(',')[0].strip());assert origins[r]==int(result['edges'][pac]['slot'],16);pac+=1;assert not events;continue
        for e in events:
            if e['kind']=='write':
                a=int(e['address'],16);n=e['size_bytes'];value=parsed(e)
                for j in range(n):ram[a+j]=z3.simplify(z3.Extract(8*j+7,8*j,value))
                for q in list(memory_origins):
                    if a<q+8 and q<a+n:memory_origins.pop(q)
        writes=[e for e in events if e['kind']=='write'];reads=[e for e in events if e['kind']=='read']
        if i.mnemonic in ['str','stur']and i.reg_name(i.operands[0].reg).startswith('x'):
            origin=old.get(key(i.reg_name(i.operands[0].reg)))
            if origin is not None and len(writes)==1 and writes[0]['size_bytes']==8:memory_origins[int(writes[0]['address'],16)]=origin
        elif i.mnemonic=='stp'and all(i.reg_name(o.reg).startswith('x')for o in i.operands[:2]):
            assert len(writes)==2
            for op,e in zip(i.operands,writes):
                origin=old.get(key(i.reg_name(op.reg)))
                if origin is not None:memory_origins[int(e['address'],16)]=origin
        for r in i.regs_access()[1]:origins.pop(key(i.reg_name(r)),None)
        if i.mnemonic in ['ldr','ldur']and i.reg_name(i.operands[0].reg).startswith('x'):
            assert len(reads)==1;e=reads[0];a=int(e['address'],16);origin=a if a in FIXUPS and e['size_bytes']==8 else memory_origins.get(a)if e['size_bytes']==8 else None
            if origin is not None:origins[key(i.reg_name(i.operands[0].reg))]=origin
        elif i.mnemonic=='mov'and i.operands[1].type==ARM64_OP_REG:
            origin=old.get(key(i.reg_name(i.operands[1].reg)))
            if origin is not None:origins[key(i.reg_name(i.operands[0].reg))]=origin
    assert at_event==len(result['effects'])and pac==len(result['edges'])
    known={a:b.as_long()for a,b in ram.items()if z3.is_bv_value(b)};symbolic=[{'address':hex(a),'expression':b.sexpr()}for a,b in sorted(ram.items())if not z3.is_bv_value(b)];gprs={};sgprs={}
    for name,expr in result['end_GPR_expressions'].items():
        value=z3.simplify(parse_value(expr,64,variables))
        if z3.is_bv_value(value):gprs[name]=hex(value.as_long())
        else:sgprs[name]=value.sexpr()
    return {'entry_PC':result['boundary']['pc'],'SP':gprs['sp'],'known_GPRs':gprs,'symbolic_GPR_expressions':sgprs,'frame_owner':c['frame_owner'],'additional_owners':c['additional_owners'],'known_byte_groups':group_bytes(known),'symbolic_bytes':symbolic,'unknown_variable_origins':result['unknown_bytes'],'register_pointer_origins':{n:hex(a)for n,a in origins.items()},'memory_pointer_origins':{hex(n):hex(a)for n,a in memory_origins.items()}}, {'parent_source_visits_checked':len(result['steps']),'parent_effects_applied':at_event,'parent_authenticated_edges_reconstructed':pac,'known_checkpoint_bytes':len(known),'symbolic_checkpoint_bytes':len(symbolic),'symbolic_checkpoint_registers':len(sgprs),'unconstrained_original_frame_bytes':len(variables)}

def capture():
    parent=json.loads((ROOT/'daemon_arena_list_symbolic.json').read_text());cases=[]
    for row in parent['cases']:
        if row['label']=='sentinel_equal':continue
        c,audit=reconstruct(row['result']);cases.append({'label':row['label'],'context':c,'checkpoint_audit':audit,'parent_case':row['label'],'native_epoch_continuity':False})
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['daemon_arena_list_symbolic.json','daemon_arena_list_checks.json','daemon_arena_list_symbolic.py','validate_daemon_record720_spill.py']},'cases':cases,'native_target_executed':False,'full_goal_complete':False}
if __name__=='__main__':
    r=capture();(ROOT/'daemon_arena_consumer_source.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps([{'label':c['label'],**c['checkpoint_audit']}for c in r['cases']]),flush=True)
