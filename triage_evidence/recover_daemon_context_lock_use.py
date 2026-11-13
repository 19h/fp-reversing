#!/usr/bin/env python3
"""Original raw arena-context field consumers and synchronization arguments.

Frozen unseal boundaries remain conditional on constructor-compatible state.
Imported returns and extra initializer-compatible caller roots are separate
premises. O(receipts+cases*(visits+effects)) time/space. No native API/IPC,
allocation/free or hardware PAC executes.
"""
import json,struct,itertools
from collections import Counter
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_daemon_context_unseal as Parent

P='daemon_context_lock_use';ENTRY=Parent.END
ROOTS={0x968:(0x100fc4130,0x1004c2534),0x960:(0x101031ea0,0x1004c2b30)}
PATH_OFFSET=0x103db;PATH=b'/var/db/fpsd/SC Info\0';ALLOC=0x6600003000
DEPS=['daemon_receive_tools.py','daemon_receive_fixups.txt','recover_daemon_context_unseal.py',
      'daemon_context_unseal_checks.json','daemon_context_unseal_audit.json',
      'recover_daemon_return_bank_origins.py','daemon_return_bank_origins_checks.json',
      'recover_daemon_network_record.py','recover_daemon_network_identity.py',
      'recover_daemon_notification_registration.py','probe_daemon_descriptor_producers.py']

def restore(row):
    v=Parent.Run(row['configuration']);v.foreign_owners=[(int(r['address'],16),r['size_bytes']) for r in row['foreign_owners']]
    v.foreign_defined=set();v.cut_stops=set()
    for j,x in enumerate(row['boundary']['registers31']):v.set(j,int(x,16))
    for j,x in enumerate(row['boundary']['Q_registers32']):v.u.reg_write(getattr(ar,'UC_ARM64_REG_Q'+str(j)),int(x,16))
    v.u.reg_write(ar.UC_ARM64_REG_SP,int(row['boundary']['SP'],16));v.u.reg_write(ar.UC_ARM64_REG_NZCV,int(row['boundary_NZCV'],16))
    for f in row['initial_private_fixtures']:v.fixture(int(f['address'],16),bytes.fromhex(f['bytes_hex']))
    for f in row['initial_image_fixtures']:
        a=int(f['address'],16);raw=bytes.fromhex(f['bytes_hex'])
        if a>=0x6000000000:v.foreign_fixture(a,raw,f['provenance'])
        else:v.image_fixture(a,raw,f['provenance'])
    for w in row['source_writes']:
        a=int(w['address'],16);raw=bytes.fromhex(w['after_hex'])
        if 0x6800000000<=a<a+len(raw)<=0x6800100000:v.fixture(a,raw)
        elif a>=0x6000000000:v.foreign_fixture(a,raw,'preceding_original_source_write')
        else:v.image_fixture(a,raw,'preceding_original_source_write')
    return v

def imported_return(v,row,status,pattern):
    e=v.imported_return(row,status)
    v.set(0,((0x01234567 if pattern else 0xfedcba98)<<32)|status);e['return_registers31'][0]=hex(v.reg(0))
    for j in range(32):
        low=v.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j)))&((1<<64)-1)
        bits=((j+1)*0x123456789abcdef0123456789abcdef+pattern*0xfedcba9876543210fedcba9876543210)&((1<<128)-1)
        if 8<=j<16:bits=(bits&~((1<<64)-1))|low
        v.u.reg_write(getattr(ar,'UC_ARM64_REG_Q'+str(j)),bits)
    flags=0x50000000 if pattern else 0xa0000000;v.u.reg_write(ar.UC_ARM64_REG_NZCV,flags)
    e['return_NZCV']=hex(flags);e['return_Q_registers32']=[hex(v.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j)))) for j in range(32)]
    e['int_return_upper32_unspecified_fixture']=True;e['separate_SIMD_clobber_premise']=True
    return e

def root_evidence():
    out=[]
    for j,c in enumerate(json.loads(read(ROOT/'daemon_return_bank_origins_checks.json'))['upstream_cases']):
        s=int(c['frame_base'],16);fields=[]
        for off,(value,pc) in ROOTS.items():
            ws=[w for w in c['source_writes'] if int(w['address'],16)<s+off+8 and s+off<int(w['address'],16)+w['size_bytes']]
            assert len(ws)==1 and ws[0]['pc']==hex(pc) and ws[0]['size_bytes']==8
            assert ws[0]['after_hex']==struct.pack('<Q',value).hex()
            fields.append({'offset_bytes':off,'writer':ws[0],'later_overwrites':0})
        ws=[w for w in c['source_writes'] if int(w['address'],16)<s+PATH_OFFSET+len(PATH) and s+PATH_OFFSET<int(w['address'],16)+w['size_bytes']]
        assert len(ws)==len(PATH) and all(w['size_bytes']==1 for w in ws)
        assert [w['address'] for w in ws]==[hex(s+PATH_OFFSET+k) for k in range(len(PATH))]
        assert bytes.fromhex(''.join(w['after_hex'] for w in ws))==PATH
        out.append({'initializer_profile_index':j,'frame_base':hex(s),'fields':fields,'path_writers':ws,'path_later_overwrites':0})
    assert len(out)==12;return out

def case(index,parent,pattern):
    v=restore(parent['intervals'][-1]);rows=[];transitions=[];status=35 if pattern else 0
    def run(start,role,effects=(),event=None):
        transitions.append({'effects':list(effects),'import_return':event})
        r=v.interval(start,role);rows.append(r);return r
    r=run(ENTRY,'raw_context_publication_to_cleanup_once')
    assert r['boundary']['pc']=='0x100442650'
    for pc,symbol in [(0x100442650,'libSystem/_pthread_once'),(0x100208efc,'libSystem/_pthread_rwlock_unlock')]:
        assert r['boundary']['pc']==hex(pc) and r['boundary']['detail']['symbol']==symbol
        if pc==0x100208efc:assert r['boundary']['registers31'][0]=='0x1010b7478'
        ev=imported_return(v,r,status,pattern);r=run(pc+4,'declared_cleanup_return',event=ev)
    for off,(value,pc) in ROOTS.items():
        b=r['boundary'];assert b['kind']=='before_unknown_private_read' and b['detail']['address']==hex(v.C+off)
        assert b['detail']['snapshot']['known_mask_hex']=='00'*8
        f={'address':hex(v.C+off),'bytes_hex':struct.pack('<Q',value).hex(),'source_initializer_writer':hex(pc),'separate_caller_premise':True}
        v.fixture(v.C+off,bytes.fromhex(f['bytes_hex']));r=run(int(b['pc'],16),'separate_initializer_compatible_bank_root',[f])
    assert r['boundary']['pc']=='0x10043e508'
    assert r['boundary']['registers31'][:2]==['0x1010b8cd0','0x10040ebd4']
    assert r['boundary']['registers31'][19]==parent['final_raw_lock64']
    for pc,symbol in [(0x10043e508,'libSystem/_pthread_once'),(0x100361df4,'libSystem/_pthread_rwlock_wrlock')]:
        assert r['boundary']['pc']==hex(pc) and r['boundary']['detail']['symbol']==symbol
        if pc==0x100361df4:assert r['boundary']['registers31'][0]==parent['final_raw_lock64']
        ev=imported_return(v,r,status,pattern);r=run(pc+4,'declared_acquisition_return',event=ev)
    b=r['boundary'];assert b['pc']=='0x10052da40' and b['kind']=='before_unknown_private_read'
    assert b['detail']['address']==hex(v.C+PATH_OFFSET) and b['detail']['snapshot']['known_mask_hex']=='00'
    assert not any(v.known[v.C+PATH_OFFSET-0x6800000000:v.C+PATH_OFFSET+len(PATH)-0x6800000000])
    f={'address':hex(v.C+PATH_OFFSET),'bytes_hex':PATH.hex(),'source_initializer_writer_ledger':'root_writer_evidence.path_writers',
       'separate_caller_premise':True};v.fixture(v.C+PATH_OFFSET,PATH)
    r=run(int(b['pc'],16),'initializer_state_path_scan_to_allocation',[f])
    assert r['boundary']['pc']=='0x1006b6fb0' and r['boundary']['detail']['symbol']=='libSystem/_malloc'
    assert int(r['boundary']['registers31'][0],16)==len(PATH)
    return {'parent_case_index':index,'producer_name':parent['producer_name'],'raw_lock_word64':parent['final_raw_lock64'],
            'ABI_clobber_pattern':pattern,'import_status32':status,'intervals':rows,'transitions':transitions,
            'final_allocation_size_bytes':len(PATH),'native_API_executed':False}

def allocation_case(index,parent,result):
    before=parent['intervals'][-1];v=restore(before);pattern=parent['ABI_clobber_pattern']
    if result:
        pg=result&~4095
        if pg not in v.pages:v.u.mem_map(pg,4096);v.pages.add(pg)
        v.foreign_owners.append((result,len(PATH)))
    ev=imported_return(v,before,0,pattern);v.set(0,result);ev['return_registers31'][0]=hex(result)
    ev.pop('return32');ev.pop('int_return_upper32_unspecified_fixture');ev['pointer_return64']=hex(result)
    ev['allocated_owner_premise']={'address':hex(result),'size_bytes':len(PATH),'initial_bytes_defined':False} if result else None
    r=v.interval(0x1006b6fb4,'separate_malloc_pointer_return')
    assert r['boundary']['pc']==('0x1004b457c' if result else '0x100442650')
    assert r['boundary']['detail']['symbol']==('libSystem/_malloc' if result else 'libSystem/_pthread_once')
    if result:
        assert bytes(v.u.mem_read(result,len(PATH)))==bytes(x^0x98 for x in PATH)
        assert int(r['boundary']['registers31'][0],16)==len(PATH)
    return {'parent_case_index':index,'pointer_return64':hex(result),'import_return':ev,'intervals':[r],
            'encoded_path_hex':bytes(v.u.mem_read(result,len(PATH))).hex() if result else None,'native_API_executed':False}

def intervals(e):return [r for c in e['cases']+e['allocation_cases'] for r in c['intervals']]

def source():
    specs=[('context_fields',0x1006150f4,0x10061512c),('lock_capture_and_call',0x1005fadd0,0x1005faec0),
           ('path_byte_test',0x10052da40,0x10052da6c),('allocation_request_and_result',0x1006b6fa0,0x1006b6fd8)]
    return [{'name':name,'start':hex(a),'end':hex(b),'bytes_hex':IMAGE.read(a,b-a).hex(),
             'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(IMAGE.read(a,b-a),a)]} for name,a,b in specs]

def build():
    p=json.loads(read(ROOT/'daemon_context_unseal_checks.json'));cases=[case(j,c,pattern) for j,c in enumerate(p['cases']) for pattern in [0,1]]
    allocations=[allocation_case(j,c,result) for j,c in list(enumerate(cases))[-2:] for result in [0,ALLOC]]
    e={'cases':cases,'allocation_cases':allocations};counts=Counter()
    for r in intervals(e):counts.update(source_visits=len(r['source_visits']),reads=len(r['source_reads']),writes=len(r['source_writes']),logical_edges=len(r['logical_edges']),source_calls=len(r['source_calls']))
    used={int(x['address'],16) for r in intervals(e) for x in r['source_reads'] if int(x['address'],16) in FIXUPS}
    e.update(scope=__doc__,generator_sha256=sha(__file__),source_sha256=sha(SOURCE),dependencies={n:sha(ROOT/n) for n in DEPS},
        source_regions=source(),source_fixups=Parent.Parent.Parent.Parent.Env.fixups(used),root_writer_evidence=root_evidence(),
        verified_counts={'cases':len(cases),'allocation_cases':len(allocations),'intervals':len(intervals(e)),**counts},
        native_API_executed=False,native_daemon_kext_pairing_established=False,native_epoch_join_established=False,full_goal_complete=False)
    return e

if __name__=='__main__':
    e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
