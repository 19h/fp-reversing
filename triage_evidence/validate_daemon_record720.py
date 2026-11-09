#!/usr/bin/env python3
"""Fresh isolated original-A64 allocation/initializer checks and source audit.
O(text words + cases*instructions + solver resources) time, O(one mapped case
+ retained output) space. API outcomes and private owners are declared premises.
"""
import hashlib,json,itertools,random
from pathlib import Path
from collections import Counter
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,IMAGE,TABLE,FIXUPS
from capture_daemon_record720 import capture,sha
from prove_daemon_record720 import obligations,expected_stores
from daemon_digest_output_access import register_access,key

MASK=(1<<64)-1
def regid(n):
    n=key(n)
    return ar.UC_ARM64_REG_SP if n=='sp' else ar.UC_ARM64_REG_NZCV if n=='nzcv' else getattr(ar,'UC_ARM64_REG_'+n.upper())

def replay(F,P,phase,controller,pattern,nonnull):
    u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);pages=set();defined=set();effects=[];visits=[];known=set();cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
    def mapping(a,n):
        for p in range(a&~4095,(a+n+4095)&~4095,4096):
            if p not in pages:u.mem_map(p,4096);pages.add(p)
    def put(a,b,is_defined=True):
        mapping(a,len(b));u.mem_write(a,b)
        if is_defined:defined.update(range(a,a+len(b)))
    def word(a,v):put(a,(v&MASK).to_bytes(8,'little'))
    def seed(n,v):u.reg_write(regid(n),v&MASK);known.add(key(n))
    mapping(F,0x10000);put(P,bytes([pattern])*720,False)
    for a,n in [(0x100badfc0,208),(0x100b0b6fc,384),(0x100fc4230,256),(0x101031fa0,256)]:put(a,IMAGE.read(a,n))
    for a in [0x10109ff58,TABLE+0x5691*8,TABLE+0x5692*8]:
        value=FIXUPS[a]['target'];word(a,value if isinstance(value,int)else 0x7f00000100)
    word(F+0x2978,0x100fc4230);word(F+0x2970,0x100e99a00);word(F+0x29a0,TABLE)
    put(0x1010c4e18,controller[0].to_bytes(4,'little'));put(0x1010c4670,controller[1].to_bytes(4,'little'))
    for n,v in [('sp',F),('x29',F+0xdf40),('x25',0x100fc4230),('x22',0x123456789abcdef0),('x23',0x1010c4670),('w9',phase),('x28',0x1010c4e18),('x13',0x101031fa0),('x30',TABLE)]:seed(n,v)
    current=[0];api=[]
    def hook(_,access,a,n,value,__):
        if access==16:
            assert all(a+j in defined for j in range(n)),('undefined read',hex(current[0]),hex(a),n)
            effects.append({'pc':hex(current[0]),'kind':'read','address':hex(a),'size_bytes':n,'hex':bytes(u.mem_read(a,n)).hex()})
        else:
            assert F<=a<a+n<=F+0x10000 or (nonnull and P<=a<a+n<=P+720),('outside owner write',hex(current[0]),hex(a),n)
            defined.update(range(a,a+n));effects.append({'pc':hex(current[0]),'kind':'write','address':hex(a),'size_bytes':n,'hex':(value&((1<<(8*n))-1)).to_bytes(n,'little').hex()})
    u.hook_add(UC_HOOK_MEM_READ|UC_HOOK_MEM_WRITE,hook)
    pc=0x100badfc0;abstracted=0
    while pc not in [0x100b0b87c,0x1009687c8]:
        current[0]=pc;raw=IMAGE.read(pc,4);i=next(cs.disasm(raw,pc));assert bytes(u.mem_read(pc,4))==raw
        reads,writes=register_access(i)
        for r in reads:
            n=key(i.reg_name(r));assert n in known or n in ['xzr','wzr'],('undefined register',hex(pc),n)
        visits.append(pc)
        if pc==0x100bae048:
            assert i.mnemonic=='blraa' and u.reg_read(regid('x8'))==0x7f00000100 and u.reg_read(regid('x17'))==0x6aa4 and u.reg_read(regid('x0'))==720
            api.append({'pc':hex(pc),'slot':'0x10109ff58','symbol':'_malloc','requested_bytes':720,'returned_X0':hex(P if nonnull else 0),'native_call_executed':False})
            for j in range(18):seed('x'+str(j),int.from_bytes(bytes([pattern])*8,'little'))
            seed('nzcv',0x50000000 if pattern==0xa5 else 0xa0000000);seed('x0',P if nonnull else 0);seed('x30',pc+4)
            pc+=4;abstracted+=1;continue
        if pc==0x100bae08c:
            assert i.mnemonic=='braa' and u.reg_read(regid('x17'))==0x1774
            pc=u.reg_read(regid('x8'));assert pc==(0x100b0b6fc if nonnull else 0x1009687c8);abstracted+=1;continue
        u.emu_start(pc,pc+4,count=1)
        for r in writes:known.add(key(i.reg_name(r)))
        pc+=4
        assert len(visits)<200
    assert len(api)==1 and int.from_bytes(u.mem_read(F+0x3118,8),'little')==(P if nonnull else 0)
    writes=[e for e in effects if e['kind']=='write' and P<=int(e['address'],16)<P+720];mask=[P+j in defined for j in range(720)];expected={}
    if nonnull:
        spec=expected_stores();assert len(writes)==len(spec)
        for e,(_,off,n,value)in zip(writes,spec):
            assert int(e['address'],16)==P+off and e['size_bytes']==n and e['hex']==value.to_bytes(n,'little').hex()
            for j,b in enumerate(value.to_bytes(n,'little')):expected[off+j]=b
        assert mask==[j in expected for j in range(720)]
        for j,b in expected.items():assert bytes(u.mem_read(P+j,1))==bytes([b])
        assert len(expected)==161 and not any(mask[716:720])
    else:assert not writes and not any(mask)
    return {'configuration':{'SP':hex(F),'owner':hex(P),'phase32':hex(phase),'controllers32':[hex(x)for x in controller],'ABI_pattern':hex(pattern),'nonnull':nonnull},'boundary_PC':hex(pc),'source_visits':len(visits),'A64_executed_instructions':len(visits)-abstracted,'modeled_edges_or_calls':abstracted,'API_models':api,'ordered_effects':effects,'defined_object_bytes':len(expected),'defined_object_offsets':sorted(expected),'source_stream_sha256':hashlib.sha256(b''.join(v.to_bytes(8,'little')+IMAGE.read(v,4)for v in visits)).hexdigest(),'native_target_executed':False}

def main():
    c=json.loads((ROOT/'daemon_record720_source.json').read_text());fresh=capture();assert c==fresh
    p=json.loads((ROOT/'daemon_record720_proofs.json').read_text());qs,counts=obligations(c);assert counts==p['source_lift_counts'];proofs=0
    for (name,formula),row in zip(qs,p['proofs']):
        assert name==row['name'];s=z3.Solver();s.set(timeout=30000);s.add(formula);assert str(s.check())=='unsat'
        for keyname,hashname in [('original_file','original_sha256'),('file','sha256')]:
            path=ROOT/row[keyname];assert sha(path)==row[hashname];s=z3.Solver();s.set(timeout=30000);s.from_file(str(path));assert str(s.check())=='unsat'
        proofs+=1
    assert len(qs)==len(p['proofs'])==proofs
    rows=[]
    for F,P,controller,pattern,nonnull in itertools.product([0x6800010000,0x6800022060],[0x6800040000,0x6800041010],[(0,0),(0xffffffff,0),(0x12345678,0xabcdef01),(0xffffffff,0xffffffff)],[0xa5,0x5a],[False,True]):
        rows.append(replay(F,P,0x471c,controller,pattern,nonnull))
    # Exhaustive small-width witnesses only; do not substitute them for a native phase producer.
    phases=[q for q in range(65536)if ((((q+0x29fb14db)&0xd604ff8d)^0x5b86)^(q+0xf75))==0x5692]
    assert len(phases)==240 and 0x471c in phases
    totals=Counter()
    for r in rows:
        for n in ['source_visits','A64_executed_instructions','modeled_edges_or_calls']:totals[n]+=r[n]
        totals['ordered_reads']+=sum(e['kind']=='read'for e in r['ordered_effects']);totals['ordered_writes']+=sum(e['kind']=='write'for e in r['ordered_effects'])
    out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['daemon_record720_source.json','daemon_record720_proofs.json','capture_daemon_record720.py','prove_daemon_record720.py','daemon_digest_output_access.py']},'verified_counts':{'fresh_A64_cases':len(rows),'source_proofs_rebuilt':proofs,'SMT_files_checked':2*proofs,'source_lift_visits':sum(counts.values()),'IDB_ranges':len(c['live_IDB_matches']),'IDB_bytes':sum(x['size_bytes']for x in c['live_IDB_matches']),'exhaustive_bank_inputs':256,'u16_phase_witnesses':len(phases),'initializer_stores_per_nonnull_case':75,'initializer_defined_bytes':161},'totals':dict(totals),'u16_phase_witnesses':[hex(q)for q in phases],'cases':rows,'registry_value_identity_established':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False,'all_checks_pass':True}
    (ROOT/'daemon_record720_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':out['verified_counts'],'totals':out['totals']}),flush=True)
if __name__=='__main__':main()
