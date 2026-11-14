#!/usr/bin/env python3
"""Complete conditional21B emitter and caller continuation from76 parents.

Four register/vector/flags/SP/owner/configuration/live-controller classes share original
source journals; independent incoming-byte requirements establish each member.
No new API returns, input bytes, allocation/free or callback effects supplied.
Native target API/IPC/filesystem/allocation/free/PAC and IDB mutation never run.
O(parent bytes+representative visits+effects+source) extraction time/storage.
"""
import json
from collections import Counter,defaultdict
from hashlib import sha256
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_daemon_network_record import state_bytes
import recover_daemon_state_allocation_cascade as Parent
import recover_daemon_generated_stream as GS

P='daemon_state_emitter_completion';ENTRY=Parent.TWIST;RETURN=0x10093ca84
COPY=0x1006d7fa4;AFTER_COPY=COPY+4
pack=Parent.pack;unpack=Parent.unpack;rc=Parent.rc;restore=Parent.restore
T=Parent.T;U=Parent.U;S=Parent.S;J=Parent.J;OUTPUT=0x680006c5d0;N=21;G=GS.G
DEPS=['daemon_receive_tools.py','daemon_receive_fixups.txt','probe_daemon_descriptor_producers.py',
      'recover_daemon_state_allocation_cascade.py','daemon_state_allocation_cascade_checks.json',
      'daemon_state_allocation_cascade_audit.json','recover_daemon_generated_stream.py',
      'recover_daemon_postseed_output.py','recover_daemon_state_file_admission.py',
      'recover_daemon_context_lock_use.py','recover_daemon_context_state_publish.py']

def key(row):
    b=row['boundary'];obj={k:b[k] for k in ['pc','registers31','Q_registers32','SP']}
    obj.update(NZCV=row['boundary_NZCV'],owners=row['foreign_owners'],configuration=row['configuration'])
    memory=state_bytes(row)
    obj['live_controller_words']=[bytes(memory[a+j] for j in range(4)).hex() for a in [0x1010c4f48,0x1010c4670]]
    return sha256(json.dumps(obj,sort_keys=True).encode()).hexdigest()

def case(index,parent,members):
    before=unpack(parent['refill_comparison']['interval_packed']);v=restore(before);pc=ENTRY;rows=[]
    def run(pc,targets,label):
        v.cut_stops=set(targets);r=v.interval(pc,label);rows.append({'label':label,'interval_packed':pack(r)})
        Parent.API.compact(v);return r
    while True:
        if pc in [ENTRY,GS.REFILL]:targets=[GS.Parent.TWIST1];label='refill_to_twist227'
        elif pc==GS.Parent.TWIST1:targets=[GS.Parent.TWIST2];label='twist227'
        elif pc==GS.Parent.TWIST2:targets=[GS.Parent.TWIST_LAST];label='twist396'
        elif pc==GS.Parent.TWIST_LAST:targets=[GS.Parent.SELECT];label='twist_last_and_index'
        elif pc==GS.Parent.SELECT:targets=[GS.Parent.COUNTER];label='selection_counter_comparison'
        elif pc==GS.Parent.COUNTER:targets=[GS.BYTE];label='counter_and_temper'
        elif pc==GS.BYTE:targets=[GS.ENTRY,GS.DONE];label='byte_attempt'
        elif pc==GS.ENTRY:targets=[GS.BYTE,GS.REFILL];label='shift_route'
        elif pc==GS.DONE:targets=[RETURN];label='completion_and_adapter_return'
        else:raise AssertionError(hex(pc))
        row=run(pc,targets,label);pc=int(row['boundary']['pc'],16)
        assert row['boundary']['kind']=='before_explicit_source_cut' and len(rows)<150
        if pc==RETURN:break
    completed=state_bytes(row);generated=bytes(completed[OUTPUT+j] for j in range(N))
    row=run(RETURN,[COPY],'caller_setup_to256B_copy')
    assert row['boundary']['pc']==hex(COPY),row['boundary']
    row=run(COPY,[AFTER_COPY],'original256B_copy')
    assert row['boundary']['pc']==hex(AFTER_COPY),row['boundary']
    print(json.dumps({'representative':index,'members':len(members),'generated21_hex':generated.hex(),
                      'intervals':len(rows),'boundary':row['boundary']['pc'],'kind':row['boundary']['kind'],
                      'detail':row['boundary']['detail']}),flush=True)
    return {'representative_parent_index':index,'class_key':key(before),'member_parent_indices':members,
            'generated21_hex':generated.hex(),'intervals':rows,'final_boundary':row['boundary'],'final_NZCV':row['boundary_NZCV']}

def context_intervals(c):
    for x in c['intervals']:yield unpack(x['interval_packed'])

def intervals(e):
    for c in e['classes']:yield from context_intervals(c)

def terminal(parent,rows):
    """Derived state export; no additional instructions or input definitions."""
    initial=unpack(parent['refill_comparison']['interval_packed']);memory=state_bytes(initial)
    for row in rows:
        for w in row['source_writes']:
            a=int(w['address'],16);memory.update({a+j:b for j,b in enumerate(bytes.fromhex(w['after_hex']))})
    last=rows[-1];out={k:last[k] for k in ['configuration','boundary','boundary_NZCV','foreign_owners']}
    out.update(role='derived_terminal_state_from_verified_class_effects',source_writes=[],source_visits=[],source_frames=[],
               source_reads=[],source_calls=[],logical_edges=[],native_target_executed=False)
    for kind in ['private','image']:
        addresses=sorted(a for a in memory if (0x6800000000<=a<0x6800100000)==(kind=='private'));fixtures=[];j=0
        while j<len(addresses):
            k=j+1
            while k<len(addresses) and addresses[k]==addresses[k-1]+1:k+=1
            a=addresses[j];fixtures.append({'address':hex(a),'bytes_hex':bytes(memory[x] for x in addresses[j:k]).hex(),
                                          'provenance':'parent_definitions_and_verified_shared_original_source_effects'})
            j=k
        out['initial_'+kind+'_fixtures']=fixtures
    return out

def source():
    spans=[('twist_entry',ENTRY,ENTRY+0xb0),('generator_completion',GS.DONE,0x100a6d3d0),
           ('adapter_return',0x100add7d8,0x100add7fc),('caller_return',RETURN,0x10093cacc),
           ('copy_request',0x1006d7f78,AFTER_COPY),('copy_return',AFTER_COPY,0x1006d8008)]
    return [{'name':n,'start':hex(a),'end':hex(b),'bytes_hex':IMAGE.read(a,b-a).hex(),
             'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}
                             for i in CS.disasm(IMAGE.read(a,b-a),a)]} for n,a,b in spans]

def build():
    p=json.loads(read(ROOT/(Parent.P+'_checks.json')));groups=defaultdict(list)
    for j,c in enumerate(p['contexts']):groups[key(unpack(c['refill_comparison']['interval_packed']))].append(j)
    assert len(p['contexts'])==76 and len(groups)==4
    classes=[case(members[0],p['contexts'][members[0]],members) for members in groups.values()]
    coverage=[]
    for ci,c in enumerate(classes):
        rows=list(context_intervals(c))
        for member in c['member_parent_indices']:
            coverage.append({'parent_index':member,'class_index':ci,'derived_terminal_state_packed':pack(terminal(p['contexts'][member],rows))})
    e={'classes':classes};counts=Counter();used=set();number=0
    for row in intervals(e):
        number+=1;counts.update(rc(row));used.update(int(x['address'],16) for x in row['source_reads'] if int(x['address'],16) in FIXUPS)
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n) for n in DEPS},
            'classes':classes,'coverage':coverage,'source_regions':source(),'source_fixups':Parent.API.Parent.fixups(used),
            'verified_counts':{'incoming_parents':76,'representative_classes':len(classes),'intervals':number,**counts},
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,
            'native_epoch_join_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
