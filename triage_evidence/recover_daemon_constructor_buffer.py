#!/usr/bin/env python3
"""Address-dependent constructor root, U validation, growth and cleanup.

One further 8 B source-compatible root is an explicit separate entry premise.
Four classes cover 76 parents. Each crosses NULL/fresh57B malloc returns and
two ABI patterns; declared void frees retire exactly the requested owners.
No native target API/IPC/filesystem/allocation/free, PAC or IDB mutation runs.
O(parents+visits+effects+source) time/storage; source slices admit at most
1000000 instructions without changing guest instructions or state.
"""
import json
from collections import Counter,defaultdict
from copy import deepcopy
from functools import lru_cache
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_daemon_network_record import state_bytes
import recover_daemon_constructor_gate as Parent
import recover_daemon_state_container_construction as APIParent

P='daemon_constructor_buffer';ENTRY=Parent.UNKNOWN;MALLOC=0x10083dd38
F=0x6600070000;N=57;S=Parent.Parent.S;T=Parent.Parent.T;U=Parent.Parent.U;J=Parent.Parent.J
FAIL=0x10074abc8;WARM=0x1008a2704;BIAS=0x44b9fd860c43a9f6;ROOT_OFFSET=0x260
API=APIParent.API;pack=Parent.pack;unpack=Parent.unpack;restore=Parent.restore;rc=Parent.rc;key=Parent.key
machine=Parent.Parent.Parent.machine;terminal=Parent.terminal
DEPS=['daemon_receive_tools.py','daemon_receive_fixups.txt','probe_daemon_descriptor_producers.py',
      'recover_daemon_constructor_gate.py','replay_daemon_constructor_gate.py','audit_daemon_constructor_gate.py',
      'daemon_constructor_gate_checks.json','daemon_constructor_gate_replay.json','daemon_constructor_gate_audit.json',
      'recover_daemon_state_container_construction.py','recover_daemon_state_file_admission.py',
      'recover_daemon_context_lock_use.py','recover_daemon_context_state_publish.py','daemon_return_bank_origins_checks.json']

@lru_cache(maxsize=None)
def accesses(pc):
    norm=Parent.Parent.Parent.normalized;i=next(Parent.Parent.Parent.DEC.disasm(IMAGE.read(pc,4),pc))
    if i.mnemonic in ['pacibsp','paciasp','autibsp','autiasp','paciza']:return frozenset(),frozenset()
    rr,ww=i.regs_access();reads={norm(i.reg_name(x)) for x in rr};writes={norm(i.reg_name(x)) for x in ww}
    # Capstone reports a destination write for some compare aliases. These
    # aliases read their explicit register operands and define only NZCV.
    if i.mnemonic in ['cmp','cmn','tst']:
        reads={norm(i.reg_name(o.reg)) for o in i.operands if o.type==1};writes={'NZCV'}
    if i.mnemonic in ['braa','br','blraa','blr','blraaz']:
        reads.update(norm(x.strip()) for x in i.op_str.split(','))
        if i.mnemonic.startswith('bl'):writes.add('X30')
    if i.mnemonic in ['ret','retab','retaa']:reads.add('X30')
    reads.discard(None);writes.discard(None);return frozenset(reads),frozenset(writes)

def registers(rows):
    need=set();written=set();counts=Counter();vectors=0
    for row in rows:
        for visit in row['source_visits']:
            reads,writes=accesses(int(visit['pc'],16));need.update(reads-written);written.update(writes)
            vectors+=sum(x.startswith('Q') for x in reads|writes);counts['source_register_accesses_checked']+=len(reads)+len(writes)
    return {'required':sorted(need),'written':sorted(written),'vector_accesses':vectors,'verified_counts':dict(counts)}

def premised(parent):
    p=deepcopy(parent);sp=int(p['boundary']['SP'],16);a=sp+ROOT_OFFSET;m=state_bytes(parent)
    assert p['boundary']['pc']==hex(ENTRY) and all(a+j not in m for j in range(8))
    f={'address':hex(a),'bytes_hex':((sp+BIAS)&((1<<64)-1)).to_bytes(8,'little').hex(),
       'provenance':'explicit_separate_address_dependent_initializer_compatible_root'}
    p['initial_private_fixtures'].append(f);p['role']='conditional_entry_with_additional_SP_dependent_root';return p,f

def interval(v,pc,role):
    original=v.u.emu_start
    v.u.emu_start=lambda begin,until,timeout=0,count=0:original(begin,until,timeout=timeout,count=1000000)
    try:return v.interval(pc,role)
    finally:v.u.emu_start=original

def external(before,pattern,pointer=None):
    b=before['boundary'];v=restore(before);invalid=[(APIParent.E,4)];retired=None;allocated=None
    if pointer is None:
        assert b['detail']['symbol']=='libSystem/_free';a=int(b['registers31'][0],16)
        owners=[(p,n) for p,n in v.foreign_owners if p==a];assert len(owners)==1
        retired=owners[0];invalid.append(retired)
    else:
        assert b['pc']==hex(MALLOC) and b['detail']['symbol']=='libSystem/_malloc' and b['registers31'][0]==hex(N)
    ev=API.event(v,before,pattern,invalid=invalid);ev.pop('return32');ev.pop('int_return_upper32_unspecified_fixture')
    if pointer is None:
        v.set(0,0xa5b6c7d8e9f01234^pattern);v.foreign_owners.remove(retired)
        ev.update(void_return_premise=True,retired_owner_premise={'address':hex(retired[0]),'size_bytes':retired[1]},effect_kind='declared_free_return')
    else:
        assert pointer in [0,F];v.set(0,pointer)
        if pointer:
            assert all(not(a<F+N and F<a+n) for a,n in v.foreign_owners);APIParent.owner(v,F,N)
            allocated={'address':hex(F),'size_bytes':N,'initial_bytes_defined':False}
        ev.update(pointer_return64=hex(pointer),allocated_owner_premise=allocated,effect_kind='declared_malloc57_return')
    ev['return_registers31']=[hex(v.reg(j)) for j in range(31)];API.compact(v);v.cut_stops=set()
    row=interval(v,int(b['pc'],16)+4,ev['effect_kind']);return ev,row

def fixture_state(parent,event):
    """Reconstruct a declared ABI entry; no target instruction executes."""
    p=deepcopy(parent);memory=state_bytes(parent)
    for span in event['invalidated_spans']:
        a=int(span['address'],16);memory={k:v for k,v in memory.items() if not a<=k<a+span['size_bytes']}
    owners=p['foreign_owners'].copy()
    if event.get('retired_owner_premise'):owners.remove(event['retired_owner_premise'])
    if event.get('allocated_owner_premise'):
        o=event['allocated_owner_premise'];owners.append({k:o[k] for k in ['address','size_bytes']})
    p.update(foreign_owners=owners,source_writes=[],source_visits=[],source_reads=[],logical_edges=[],source_calls=[],source_frames=[],
             boundary_NZCV=event['return_NZCV'],role='explicit_ABI_return_entry')
    p['boundary']={**p['boundary'],'pc':event['continuation_PC'],'registers31':event['return_registers31'],'Q_registers32':event['return_Q_registers32']}
    for kind in ['private','image']:
        addresses=sorted(a for a in memory if (0x6800000000<=a<0x6800100000)==(kind=='private'));ff=[];j=0
        while j<len(addresses):
            k=j+1
            while k<len(addresses) and addresses[k]==addresses[k-1]+1:k+=1
            a=addresses[j];ff.append({'address':hex(a),'bytes_hex':bytes(memory[at] for at in addresses[j:k]).hex(),
                                    'provenance':'inherited_state_after_explicit_ABI_invalidation'});j=k
        p['initial_'+kind+'_fixtures']=ff
    return p

def export(parent,row,pr):
    p=terminal(parent,[row],pr);p['role']='conditional_constructor_buffer_terminal'
    for kind in ['private','image']:
        for f in p['initial_'+kind+'_fixtures']:f['provenance']='inherited_definitions_explicit_root_and_ABI_premises_original_effects'
    return p

def build():
    old=json.loads(read(ROOT/(Parent.P+'_checks.json')));parents={x['parent_index']:unpack(x['derived_terminal_state_packed']) for x in old['coverage']}
    assert sha(ROOT/(Parent.P+'_checks.json'))=='9c4ad519628142f228742dd3a011a6b10f94aa106783bd6ba30caffad70af6ff'
    groups=defaultdict(list)
    for j,p in parents.items():groups[key(p)].append(j)
    prefixes=[];branches=[];coverage=[];prefix_coverage=[];counts=Counter();pcs=set();used=set()
    def collect(row):
        counts.update(rc(row));pcs.update(int(x['pc'],16) for x in row['source_visits']);used.update(int(x['address'],16) for x in row['source_reads'] if int(x['address'],16) in FIXUPS)
    for members in groups.values():
        ci=len(prefixes);pi=members[0];before,root=premised(parents[pi]);v=restore(before);v.cut_stops=set();r=interval(v,ENTRY,'address_coded_root_and_U_validation')
        assert r['boundary']['pc']==hex(MALLOC) and r['boundary']['registers31'][0]==hex(N)
        pr=registers([r]);prefixes.append({'representative_parent_index':pi,'member_parent_indices':members,'class_key':key(before),
                                        'entry_premise':root,'interval_packed':pack(r),'register_projection':pr});collect(r)
        states={i:export(premised(parents[i])[0],r,pr) for i in members}
        for i,s in states.items():prefix_coverage.append({'parent_index':i,'class_index':ci,'derived_terminal_state_packed':pack(s)})
        for pattern in [0,1]:
            for pointer in [0,F]:
                bi=len(branches);current=states.copy();r0=states[pi];items=[]
                ev,row=external(r0,pattern,pointer)
                while True:
                    projection=registers([row]);collect(row)
                    items.append({'API_return_premise':ev,'interval_packed':pack(row),'register_projection':projection})
                    current={i:export(fixture_state(s,ev),row,projection) for i,s in current.items()}
                    if row['boundary']['kind']!='before_unmodeled_import_call':break
                    assert row['boundary']['detail']['symbol']=='libSystem/_free' and len(items)<4
                    ev,row=external(current[pi],pattern)
                assert row['boundary']['pc']==hex(WARM if pointer else FAIL)
                branches.append({'prefix_class_index':ci,'representative_parent_index':pi,'member_parent_indices':members,
                                 'ABI_clobber_pattern':pattern,'pointer_return64':hex(pointer),'intervals':items})
                for i,s in current.items():coverage.append({'parent_index':i,'branch_index':bi,'derived_terminal_state_packed':pack(s)})
                print(json.dumps({'class':ci,'pattern':pattern,'pointer':hex(pointer),'intervals':len(items),'visits':sum(rc(unpack(x['interval_packed']))['source_visits'] for x in items),'boundary':row['boundary']['pc']}),flush=True)
    source=[];ordered=sorted(pcs);j=0
    while j<len(ordered):
        k=j+1
        while k<len(ordered) and ordered[k]==ordered[k-1]+4:k+=1
        a,b=ordered[j],ordered[k-1]+4;source.append({'start':hex(a),'end':hex(b),'bytes_hex':IMAGE.read(a,b-a).hex(),
            'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(IMAGE.read(a,b-a),a)]});j=k
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n) for n in DEPS},
            'prefixes':prefixes,'prefix_coverage':prefix_coverage,'branches':branches,'coverage':coverage,'source_regions':source,
            'source_fixups':APIParent.API.Parent.fixups(used),'verified_counts':{'incoming_parents':76,'representative_classes':4,'prefixes':4,
            'branch_classes':16,'terminal_exports':304,'new_root_premise_bytes_per_parent':8,'intervals':4+sum(len(c['intervals']) for c in branches),**counts},
            'native_API_executed':False,'native_epoch_join_established':False,'continuous_initializer_join_established':False,
            'native_daemon_kext_pairing_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
