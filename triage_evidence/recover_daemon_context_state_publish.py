#!/usr/bin/env python3
"""Original cached-path publication, network-record copy and entropy boundaries.

Frozen first-allocation success, second malloc/import returns, foreign owners,
four initializer-compatible roots and constructor-compatible metadata remain
separate premises. Nonzero network bytes are a separate local input control.
O(receipts+cases*(visits+effects)) time/space. No native API/IPC, allocation,
free, hardware PAC or IDB mutation executes.
"""
import json,struct,itertools
from collections import Counter
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha
from recover_daemon_callback_revisit import snapshot_read
import recover_daemon_context_lock_use as Parent

P='daemon_context_state_publish';ENTRY=0x1004b4580;B=0x6600004000
ROOTS={0x3f8:(0x1010c6830,0x1004c2f18),0x408:(0x1010b5d70,0x1004c2854),
       0x400:(0x1010c6818,0x1004c2ea4),0x410:(0x1010b8d78,0x1004c354c)}
METADATA=[(0x1010c6830,4),(0x1010b5d70,28),(0x1010c6818,1),(0x1010b8d78,8)]
RECORD=0x1010c5764;ARC=0x100a8c0c0;CLOCK=0x100b4db4c;STOP=0x1006a6a08
DEPS=['daemon_receive_tools.py','daemon_receive_fixups.txt','recover_daemon_context_lock_use.py',
      'daemon_context_lock_use_checks.json','daemon_context_lock_use_audit.json',
      'recover_daemon_context_unseal.py','daemon_context_lock_snapshot.json',
      'recover_daemon_callback_revisit.py','daemon_return_bank_origins_checks.json',
      'recover_daemon_return_bank_origins.py','probe_daemon_descriptor_producers.py']

def owner(v,a,n):
    for pg in range(a&~4095,((a+n-1)&~4095)+4096,4096):
        if pg not in v.pages:v.u.mem_map(pg,4096);v.pages.add(pg)
    v.foreign_owners.append((a,n))

def pointer_return(v,row,value,pattern):
    e=Parent.imported_return(v,row,0,pattern);v.set(0,value);e['return_registers31'][0]=hex(value)
    e.pop('return32');e.pop('int_return_upper32_unspecified_fixture');e['pointer_return64']=hex(value)
    e['allocated_owner_premise']={'address':hex(value),'size_bytes':21,'initial_bytes_defined':False} if value else None
    if value:owner(v,value,21)
    return e

def api_return(v,row,pattern):
    e=Parent.imported_return(v,row,35 if pattern else 0,pattern)
    if row['boundary']['detail']['symbol']=='libSystem/_free':
        a=int(row['boundary']['registers31'][0],16);assert a==Parent.ALLOC
        assert (a,21) in v.foreign_owners;v.foreign_owners.remove((a,21));v.foreign_defined.difference_update(range(a,a+21))
        e['retired_owner_premise']={'address':hex(a),'size_bytes':21}
        v.set(0,0xa5b6c7d8e9f01234^pattern);e['return_registers31'][0]=hex(v.reg(0))
        e.pop('return32');e.pop('int_return_upper32_unspecified_fixture');e['void_return_premise']=True
    return e

def root_evidence():
    out=[]
    for j,c in enumerate(json.loads(read(ROOT/'daemon_return_bank_origins_checks.json'))['upstream_cases']):
        s=int(c['frame_base'],16);fields=[]
        for off,(value,pc) in ROOTS.items():
            ws=[w for w in c['source_writes'] if int(w['address'],16)<s+off+8 and s+off<int(w['address'],16)+w['size_bytes']]
            assert len(ws)==1 and ws[0]['pc']==hex(pc) and ws[0]['size_bytes']==8 and ws[0]['after_hex']==struct.pack('<Q',value).hex()
            fields.append({'offset_bytes':off,'writer':ws[0],'later_overwrites':0})
        out.append({'initializer_profile_index':j,'frame_base':hex(s),'fields':fields})
    assert len(out)==12;return out

def metadata():
    snap=json.loads(read(ROOT/'daemon_context_lock_snapshot.json'))
    return [{'address':hex(a),'bytes_hex':snapshot_read(snap,a,n).hex(),'provenance':'separate_constructor_compatible_metadata'} for a,n in METADATA]

def case(index,parent,result,mac):
    before=parent['intervals'][-1];v=Parent.restore(before);pattern=index//2;assert index in [1,3]
    pattern=0 if index==1 else 1;effects=[];rows=[];transitions=[]
    if mac is not None:
        f={'address':hex(RECORD+4),'bytes_hex':mac.hex(),'provenance':'separate_nonzero_network_data_control'}
        v.image_fixture(RECORD+4,mac,f['provenance']);effects.append(f)
    ev=pointer_return(v,before,result,pattern)
    def run(start,role,additions=(),event=None):
        transitions.append({'effects':list(additions),'import_return':event});r=v.interval(start,role);rows.append(r);return r
    r=run(ENTRY,'second_allocation_return_and_raw_context_publication',effects,ev)
    if not result:
        assert r['boundary']['pc']=='0x100836124'
        while r['boundary']['kind']=='before_unmodeled_import_call':
            pc=int(r['boundary']['pc'],16);symbol=r['boundary']['detail']['symbol']
            assert symbol in ['libSystem/_free','libSystem/_pthread_once','libSystem/_pthread_rwlock_unlock','libSystem/_pthread_rwlock_wrlock']
            ev=api_return(v,r,pattern);r=run(pc+4,'declared_release_and_original_failure_suffix',event=ev)
        assert r['boundary']['pc']==hex(STOP) and r['boundary']['detail']['address']==hex(v.C+0x12a0)
    else:
        for j,(off,(value,pc)) in enumerate(ROOTS.items()):
            b=r['boundary'];assert b['kind']=='before_unknown_private_read' and b['detail']['address']==hex(v.C+off)
            assert b['detail']['snapshot']['known_mask_hex']=='00'*8
            fs=[{'address':hex(v.C+off),'bytes_hex':struct.pack('<Q',value).hex(),'source_initializer_writer':hex(pc),'separate_caller_premise':True}]
            v.fixture(v.C+off,bytes.fromhex(fs[0]['bytes_hex']))
            if not j:
                for f in metadata():v.image_fixture(int(f['address'],16),bytes.fromhex(f['bytes_hex']),f['provenance']);fs.append(f)
            r=run(int(b['pc'],16),'additional_initializer_compatible_metadata_root',fs)
        assert r['boundary']['pc']==hex(ARC) and r['boundary']['detail']['symbol']=='libSystem/_arc4random'
        assert bytes(v.u.mem_read(B,21))==Parent.PATH
    return {'parent_allocation_case_index':index,'second_pointer_return64':hex(result),'ABI_clobber_pattern':pattern,
            'MAC6_premise_hex':mac.hex() if mac is not None else None,'intervals':rows,'transitions':transitions,
            'final_context_hex':bytes(v.u.mem_read(Parent.Parent.D,552)).hex(),
            'final_reference64':hex(int.from_bytes(v.u.mem_read(Parent.Parent.CELL,8),'little')),
            'decoded_path_hex':bytes(v.u.mem_read(B,21)).hex() if result else None,'native_API_executed':False}

def entropy_case(index,parent,seed):
    before=parent['intervals'][-1];v=Parent.restore(before);pattern=parent['ABI_clobber_pattern']
    ev=Parent.imported_return(v,before,seed,pattern);ev['unsigned_random_return32']=hex(seed)
    r=v.interval(ARC+4,'declared_random_word_to_clock_boundary')
    assert r['boundary']['pc']==hex(CLOCK) and r['boundary']['detail']['symbol']=='libSystem/_gettimeofday'
    return {'parent_case_index':index,'random_return32':hex(seed),'import_return':ev,'intervals':[r],'native_API_executed':False}

def intervals(e):return [r for c in e['cases']+e['entropy_cases'] for r in c['intervals']]

def source():
    specs=[('publish_path_pointer_and_test',ENTRY,0x1004b45a8),('decode_path_byte',0x1004d4ca0,0x1004d4cd8),
           ('context_count',0x100597958,0x100597984),('network_byte_copy',0x10059ccd0,0x10059cd04),
           ('metadata_state',0x1005d21d4,0x1005d22c0),('random_import',ARC-12,ARC+20),
           ('clock_import',CLOCK-20,CLOCK+16)]
    return [{'name':name,'start':hex(a),'end':hex(b),'bytes_hex':IMAGE.read(a,b-a).hex(),
             'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(IMAGE.read(a,b-a),a)]} for name,a,b in specs]

def build():
    parent=json.loads(read(ROOT/'daemon_context_lock_use_checks.json'));cases=[case(j,parent['allocation_cases'][j],result,mac)
        for j in [1,3] for result,mac in [(0,None),(B,None),(B,bytes.fromhex('0132456789ab'))]]
    entropy=[entropy_case(j,c,seed) for j,c in enumerate(cases) if int(c['second_pointer_return64'],16) for seed in [0,0xffffffff]]
    e={'cases':cases,'entropy_cases':entropy};counts=Counter()
    for r in intervals(e):counts.update(source_visits=len(r['source_visits']),reads=len(r['source_reads']),writes=len(r['source_writes']),logical_edges=len(r['logical_edges']),source_calls=len(r['source_calls']))
    used={int(x['address'],16) for r in intervals(e) for x in r['source_reads'] if int(x['address'],16) in FIXUPS}
    e.update(scope=__doc__,generator_sha256=sha(__file__),source_sha256=sha(SOURCE),dependencies={n:sha(ROOT/n) for n in DEPS},
        source_regions=source(),source_fixups=Parent.Parent.Parent.Parent.Parent.Env.fixups(used),root_writer_evidence=root_evidence(),metadata_premises=metadata(),
        verified_counts={'cases':len(cases),'entropy_cases':len(entropy),'intervals':len(intervals(e)),**counts},
        native_API_executed=False,native_daemon_kext_pairing_established=False,native_epoch_join_established=False,full_goal_complete=False)
    return e

if __name__=='__main__':
    e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
