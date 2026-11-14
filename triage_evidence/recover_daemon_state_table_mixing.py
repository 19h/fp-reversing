#!/usr/bin/env python3
"""Original constructor table initialization, complete mixing and next interface.

One retained execution; projected incoming-register/byte dependencies must
independently admit every inherited state before shared effects are claimed.
Loop batches stop before original instructions and change no target state.
No new API return/input byte, native target operation, PAC or IDB mutation.
O(parent bytes+retained visits+effects+source) extraction time/storage.
"""
import json,re
from collections import Counter,defaultdict
from functools import lru_cache
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_daemon_network_record import state_bytes
import recover_daemon_state_emitter_completion as Parent

P='daemon_state_table_mixing';ENTRY=Parent.AFTER_COPY;HEAD=0x1004f69cc;EXIT=0x1004d5cb0
NEXT_CALL=0x1004d5df0;BATCH=64;S=Parent.S;T=Parent.T;U=Parent.U;J=Parent.J
FIRST=0x680006c5f0;SECOND=0x680006c6f0
pack=Parent.pack;unpack=Parent.unpack;restore=Parent.restore;rc=Parent.rc
DEC=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);DEC.detail=True
DEPS=['daemon_receive_tools.py','daemon_receive_fixups.txt','probe_daemon_descriptor_producers.py',
      'recover_daemon_state_emitter_completion.py','audit_daemon_state_emitter_completion.py',
      'daemon_state_emitter_completion_checks.json','daemon_state_emitter_completion_audit.json',
      'recover_daemon_context_lock_use.py','recover_daemon_context_unseal.py','recover_daemon_network_identity.py',
      'recover_daemon_state_file_admission.py','recover_daemon_state_container_construction.py']

def intervals(e):
    yield from shared_intervals(e)
    for x in e['handoff_classes']:yield unpack(x['interval_packed'])

def shared_intervals(e):
    for x in e['shared_intervals']:yield unpack(x['interval_packed'])

def normalized(name):
    if name in ['xzr','wzr']:return None
    if name in ['sp','wsp']:return 'SP'
    if name=='nzcv':return 'NZCV'
    if name=='fp':return 'X29'
    if name=='lr':return 'X30'
    m=re.fullmatch(r'[xw](\d+)',name)
    if m:return 'X'+m[1]
    m=re.fullmatch(r'[vqdsbh](\d+)',name)
    if m:return 'Q'+m[1]
    raise AssertionError(name)

@lru_cache(maxsize=None)
def accesses(pc):
    ins=next(DEC.disasm(IMAGE.read(pc,4),pc))
    if ins.mnemonic in ['pacibsp','paciasp','autibsp','autiasp','paciza']:return frozenset(),frozenset()
    rr,ww=ins.regs_access();reads={normalized(ins.reg_name(x)) for x in rr};writes={normalized(ins.reg_name(x)) for x in ww}
    if ins.mnemonic in ['braa','br','blraa','blr','blraaz']:
        reads.update(normalized(x.strip()) for x in ins.op_str.split(','))
        if ins.mnemonic.startswith('bl'):writes.add('X30')
    if ins.mnemonic in ['ret','retab','retaa']:reads.add('X30')
    reads.discard(None);writes.discard(None);assert not any(x.startswith('Q') for x in reads|writes)
    return frozenset(reads),frozenset(writes)

def registers(rows):
    """Conservative whole-register dependency projection; u32 writes zero-extend.

    No vector instructions are admitted by this source interval. Logical PAC
    instructions, if any, must retain the existing explicit no-op semantics.
    """
    need=set();written=set();counts=Counter()
    for row in rows:
        for visit in row['source_visits']:
            reads,writes=accesses(int(visit['pc'],16))
            need.update(reads-written);written.update(writes);counts['source_register_accesses_checked']+=len(reads)+len(writes)
    return {'required':sorted(need),'written':sorted(written),'vector_accesses':0,'verified_counts':dict(counts)}

def machine(row):
    b=row['boundary'];return {**{'X'+str(j):x for j,x in enumerate(b['registers31'])},
        **{'Q'+str(j):x for j,x in enumerate(b['Q_registers32'])},'SP':b['SP'],'NZCV':row['boundary_NZCV']}

def terminal(parent,rows,projection):
    memory=state_bytes(parent)
    for row in rows:
        for w in row['source_writes']:
            a=int(w['address'],16);memory.update({a+j:b for j,b in enumerate(bytes.fromhex(w['after_hex']))})
    last=rows[-1];values=machine(parent);end=machine(last)
    for name in projection['written']:values[name]=end[name]
    out={'configuration':parent['configuration'],'foreign_owners':parent['foreign_owners'],
         'boundary':{**last['boundary'],'registers31':[values['X'+str(j)] for j in range(31)],
                     'Q_registers32':[values['Q'+str(j)] for j in range(32)],'SP':values['SP']},
         'boundary_NZCV':values['NZCV'],'role':'derived_terminal_from_verified_register_and_byte_dependencies',
         'source_visits':[],'source_frames':[],'source_reads':[],'source_writes':[],'source_calls':[],
         'logical_edges':[],'native_target_executed':False}
    for kind in ['private','image']:
        addresses=sorted(a for a in memory if (0x6800000000<=a<0x6800100000)==(kind=='private'));fixtures=[];j=0
        while j<len(addresses):
            k=j+1
            while k<len(addresses) and addresses[k]==addresses[k-1]+1:k+=1
            a=addresses[j];fixtures.append({'address':hex(a),'bytes_hex':bytes(memory[x] for x in addresses[j:k]).hex(),
                                          'provenance':'inherited_definitions_and_original_source_effects'});j=k
        out['initial_'+kind+'_fixtures']=fixtures
    return out

def source(rows):
    pcs=sorted({int(v['pc'],16) for row in rows for v in row['source_visits']});out=[];j=0
    while j<len(pcs):
        k=j+1
        while k<len(pcs) and pcs[k]==pcs[k-1]+4:k+=1
        a,b=pcs[j],pcs[k-1]+4
        out.append({'start':hex(a),'end':hex(b),'bytes_hex':IMAGE.read(a,b-a).hex(),
                    'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(IMAGE.read(a,b-a),a)]});j=k
    return out

def build():
    p=json.loads(read(ROOT/(Parent.P+'_checks.json')));parents={x['parent_index']:unpack(x['derived_terminal_state_packed']) for x in p['coverage']}
    before=parents[0];v=restore(before);items=[]
    def run(pc,label,cuts):
        v.cut_stops=set(cuts);row=v.interval(pc,label);items.append({'label':label,'interval_packed':pack(row)})
        Parent.Parent.API.compact(v);return row
    row=run(ENTRY,'original256B_initialization_to_mix_entry',[HEAD]);assert row['boundary']['pc']==hex(HEAD)
    original_preflight=v.preflight;headers=[0]
    def preflight(ins):
        if ins.address==HEAD:
            if headers[0]==BATCH:v.stop('before_original_loop_batch_header',{'completed_iterations':BATCH});return False
            headers[0]+=1
        return original_preflight(ins)
    v.preflight=preflight;iterations=0
    for batch in range(100):
        headers[0]=0;row=run(HEAD,'original_mix_batch',[EXIT]);iterations+=headers[0]
        if batch%8==0:print(json.dumps({'batch':batch,'iterations':iterations,'boundary':row['boundary']['pc']}),flush=True)
        if row['boundary']['pc']==hex(EXIT):break
        assert row['boundary']['pc']==hex(HEAD) and headers[0]==BATCH
    else:raise AssertionError('finite batch bound exceeded')
    v.preflight=original_preflight;assert iterations==2569
    rows=[unpack(x['interval_packed']) for x in items];projection=registers(rows)
    shared={i:terminal(parents[i],rows,projection) for i in parents};groups=defaultdict(list)
    for i,state in shared.items():groups[Parent.key(state)].append(i)
    assert len(groups)==4;classes=[];coverage=[]
    for ci,(class_key,members) in enumerate(groups.items()):
        representative=members[0];u=restore(shared[representative]);u.cut_stops={NEXT_CALL}
        row=u.interval(EXIT,'original_mixed_table_handoff');assert row['boundary']['pc']==hex(NEXT_CALL)
        classes.append({'representative_parent_index':representative,'class_key':class_key,'member_parent_indices':members,'interval_packed':pack(row)})
        pr=registers([row])
        for i in members:coverage.append({'parent_index':i,'handoff_class_index':ci,'derived_terminal_state_packed':pack(terminal(shared[i],[row],pr))})
    all_rows=rows+[unpack(c['interval_packed']) for c in classes];counts=Counter();used=set()
    for r in all_rows:
        counts.update(rc(r));used.update(int(x['address'],16) for x in r['source_reads'] if int(x['address'],16) in FIXUPS)
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n) for n in DEPS},
            'representative_parent_index':0,'shared_intervals':items,'register_projection':projection,
            'handoff_classes':classes,'coverage':coverage,
            'source_regions':source(all_rows),'source_fixups':Parent.Parent.API.Parent.fixups(used),
            'verified_counts':{'incoming_parents':76,'shared_loop_executions':1,'handoff_executions':4,'intervals':len(all_rows),'mix_iterations':iterations,**counts},
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'native_epoch_join_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
