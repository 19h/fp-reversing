#!/usr/bin/env python3
"""Conditional network-record synchronization and adjacent cache gate.

Frozen caller contexts, once completion/callback invocation, imported returns,
two caller roots and two writable cache cells are explicit separate premises.
O(receipt bytes+cases*(visits+effects)+queries) time/space; 30 s/query.
No native API/IPC, allocation/free or hardware PAC executes.
"""
import json,struct,itertools
from collections import Counter
from unicorn import arm64_const as ar
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha
from recover_daemon_return_bank_origins import Algebra
from lskd_values_symbolic import mem,cell
import recover_daemon_network_record as Parent

P='daemon_network_gate';CALLBACK=0x10040ebd4;GATE=0x1004f753c
FLAG=0x1010c5760;CACHE=0x1010c9298;FALLBACK=0x1010b9638
ROOTS={0x570:(FLAG,0x1004c2c0c),0x568:(CACHE,0x1004c2f88)}
CUTS={0x10048192c,0x10080a464,0x1005fadd4}
DEPS=['daemon_receive_tools.py','daemon_receive_fixups.txt','recover_daemon_network_record.py',
      'daemon_network_record_checks.json','daemon_network_record_audit.json',
      'recover_daemon_network_identity.py','recover_daemon_pidpath_consumer.py',
      'probe_daemon_descriptor_producers.py','recover_daemon_return_bank_origins.py',
      'daemon_return_bank_origins_checks.json']

def root_evidence():
    rows=json.loads(read(ROOT/'daemon_return_bank_origins_checks.json'))['upstream_cases'];out=[]
    for j,c in enumerate(rows):
        s=int(c['frame_base'],16);fields=[]
        for off,(value,pc) in ROOTS.items():
            writes=[w for w in c['source_writes'] if int(w['address'],16)<s+off+8 and s+off<int(w['address'],16)+w['size_bytes']]
            assert len(writes)==1 and writes[0]['size_bytes']==8 and writes[0]['pc']==hex(pc)
            assert writes[0]['after_hex']==struct.pack('<Q',value).hex()
            fields.append({'offset_bytes':off,'writer':writes[0],'later_overwrites':0})
        out.append({'initializer_profile_index':j,'frame_base':hex(s),'fields':fields})
    assert len(out)==12;return out

def acquire(index,before,invoke,status):
    v=Parent.restore(before);rows=[];callback=None
    if invoke:
        once_sp=int(before['boundary']['SP'],16);token=v.C+0x1000
        v.u.reg_write(ar.UC_ARM64_REG_SP,once_sp-0x100);v.set(30,token);v.cut_stops={token}
        callback=v.interval(CALLBACK,'separate_once_callback_invocation')
        b=callback['boundary'];assert b['pc']==hex(token) and b['SP']==hex(once_sp-0x100)
        assert b['registers31'][18:30]==before['boundary']['registers31'][18:30]
        assert [(c['pc'],c['target']) for c in callback['source_calls']]==[('0x10040ee2c','0x10044fc34')]
        assert {(w['pc'],w['address']) for w in callback['source_writes'] if int(w['address'],16)<0x6000000000}=={
            ('0x10040ecfc','0x1010c5088'),('0x10040ed00','0x1010c4670')}
        v.u.reg_write(ar.UC_ARM64_REG_SP,once_sp)
    once=v.imported_return(before,status);v.cut_stops=set()
    row=v.interval(Parent.ONCE+4,'once_completion_to_fallback_write_lock');rows.append(row)
    assert row['boundary']['pc']=='0x100361df4' and row['boundary']['detail']['symbol']=='libSystem/_pthread_rwlock_wrlock'
    assert row['boundary']['registers31'][0]=='0x1010b7478'
    lock=v.imported_return(row,status);row=v.interval(0x100361df8,'write_lock_return_to_original_caller');rows.append(row)
    assert row['boundary']['pc']==hex(GATE) and row['boundary']['detail']['address']==hex(v.C+0x570)
    return {'parent_warm_case_index':index,'invoke_callback':invoke,'import_status32':status,
            'callback_invocation_premise':{'callback_entry':hex(CALLBACK),'SP_gap_bytes':256,'return_token':hex(v.C+0x1000),
                'native_pthread_stack_layout_claimed':False} if invoke else None,
            'callback':callback,'once_return_premise':once,'lock_return_premise':lock,'intervals':rows,
            'native_API_executed':False}

def consumer(index,acq,flag,pointer):
    before=acq['intervals'][-1];v=Parent.restore(before);rows=[];effects=[]
    image=[{'address':hex(FLAG),'bytes_hex':struct.pack('<I',flag).hex(),'provenance':'separate_adjacent_cache_control32_premise'},
           {'address':hex(CACHE),'bytes_hex':struct.pack('<Q',pointer).hex(),'provenance':'separate_cache_pointer64_premise'}]
    for f in image:v.image_fixture(int(f['address'],16),bytes.fromhex(f['bytes_hex']),f['provenance'])
    row=before
    for off,(value,pc) in ROOTS.items():
        assert row['boundary']['kind']=='before_unknown_private_read'
        assert row['boundary']['detail']['address']==hex(v.C+off)
        assert row['boundary']['detail']['snapshot']['known_mask_hex']=='00'*8
        f={'address':hex(v.C+off),'bytes_hex':struct.pack('<Q',value).hex(),'source_initializer_writer':hex(pc),
           'separate_caller_premise':True};effects.append(f);v.fixture(v.C+off,struct.pack('<Q',value))
        v.cut_stops=CUTS;row=v.interval(int(row['boundary']['pc'],16),'cache_gate_with_separate_root_and_image_premises');rows.append(row)
    returns=[]
    if row['boundary']['pc']=='0x100442650':
        for pc,symbol in [(0x100442650,'libSystem/_pthread_once'),(0x100208efc,'libSystem/_pthread_rwlock_unlock')]:
            assert row['boundary']['pc']==hex(pc) and row['boundary']['detail']['symbol']==symbol
            if pc==0x100208efc:assert row['boundary']['registers31'][0]=='0x1010b7478'
            event=v.imported_return(row,acq['import_status32']);returns.append(event)
            row=v.interval(pc+4,'cleanup_return_and_next_original_consumer');rows.append(row)
    assert int(row['boundary']['pc'],16) in CUTS
    return {'acquisition_index':index,'flag32':flag,'cache_pointer64':hex(pointer),'root_premises':effects,
            'image_premises':image,'intervals':rows,'cleanup_return_premises':returns,
            'final_boundary':row['boundary']['pc'],'native_API_executed':False}

def intervals(e):
    return [r for c in e['acquisition_cases'] for r in ([c['callback']] if c['callback'] else [])+c['intervals']]+[
        r for c in e['consumer_cases'] for r in c['intervals']]

def source():
    specs=[('once_callback',CALLBACK,0x10040ee54),('callback_leaf',0x10044fc34,0x10044fc38),
           ('once_selection',0x10043e50c,0x10043e574),('cache_gate',GATE,0x1004f7578),
           ('counter_and_cleanup_record',0x10050fe90,0x10050ff54),('zero_leaf',0x1000056c8,0x1000056d0),
           ('selected_descriptor_frontier',0x10048192c,0x10048194c),
           ('cached_pointer_field_frontier',0x1005fadd0,0x1005fadd8)]
    return [{'name':name,'start':hex(a),'end':hex(b),'bytes_hex':IMAGE.read(a,b-a).hex(),
             'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(IMAGE.read(a,b-a),a)]} for name,a,b in specs]

def obligations():
    out=[]
    def prove(name,bad,premise=z3.BoolVal(True)):
        q=z3.Solver();q.set(timeout=30000);q.add(premise);assert q.check()==z3.sat;q.add(bad);assert q.check()==z3.unsat,name
        out.append({'label':name,'query':q.to_smt2(),'premises_nonvacuous':True,'result':'unsat'})
    flag=z3.BitVec('ng_flag32',32);ptr=z3.BitVec('ng_pointer64',64);s=z3.BitVec('ng_SP64',64)
    v=Algebra();v.seed('sp',s);mem(v,s+0x570,8,FLAG);mem(v,s+0x568,8,CACHE);mem(v,FLAG,4,flag);mem(v,CACHE,8,ptr)
    v.seed('w23',0x92e1);v.seed('w25',0x46d0);v.seed('w24',0x9e4b);v.run_block(GATE,0x1004f756c)
    prove('cache_gate_selects_descriptor_iff_control_zero_and_pointer_nonzero',v.read('w10')!=z3.If(z3.And(flag==0,ptr!=0),z3.BitVecVal(0x9e4b,32),z3.BitVecVal(0x9e69,32)))
    v=Algebra();v.seed('w8',flag);v.seed('w25',0x46d0);v.seed('x3',FLAG);v.seed('sp',s);v.run_block(0x10050fe9c,0x10050feb8)
    prove('cleanup_route_increments_adjacent_control_modulo_2_32',cell(v,FLAG,4)!=flag+1)
    a,b,h=z3.BitVecs('ng_controller_A64 ng_controller_B64 ng_callback_SP64',64)
    v=Algebra();v.seed('x15',a);v.seed('x17',b);v.seed('sp',h);v.seed('x9',0xa5cd4cf);v.seed('x13',0x1010c5088);v.seed('x14',0x1010c4670)
    v.run_block(0x10040ecc4,0x10040ed04);d=(a^b)+(h+8)
    prove('callback_two_controller_updates_exact_u64',z3.Or(cell(v,0x1010c5088,8)!=d*0xa5cd4cf+0x673e3a80075f02c6,
        cell(v,0x1010c4670,8)!=(d^0x73d046208eaed1a6)*0xa5cd4cf))
    v=Algebra();v.seed('x0',ptr);v.run_block(0x1000056c8,0x1000056cc);prove('post_cleanup_leaf_returns_zero',v.read('x0')!=0)
    return out

def build():
    p=json.loads(read(ROOT/(Parent.P+'_checks.json')));selected=[];seen=set()
    for j,c in enumerate(p['warm_cases']):
        if c['parent_case_index'] not in seen:selected.append((j,c));seen.add(c['parent_case_index'])
    assert len(selected)==8
    acq=[acquire(j,c['continuation']['intervals'][-1],invoke,status) for (j,c),invoke,status in itertools.product(selected,[False,True],[0,35])]
    cases=[consumer(j,c,flag,ptr) for (j,c),(flag,ptr) in itertools.product(enumerate(acq),[(0,0),(1,0),(0,Parent.RECORD),(0xffffffff,Parent.RECORD)])]
    e={'acquisition_cases':acq,'consumer_cases':cases};counts=Counter()
    for r in intervals(e):counts.update(source_visits=len(r['source_visits']),reads=len(r['source_reads']),writes=len(r['source_writes']),logical_edges=len(r['logical_edges']))
    used={int(r['address'],16) for row in intervals(e) for r in row['source_reads'] if int(r['address'],16) in FIXUPS}
    e.update(scope=__doc__,generator_sha256=sha(__file__),source_sha256=sha(SOURCE),dependencies={n:sha(ROOT/n) for n in DEPS},
        source_regions=source(),source_fixups=Parent.Parent.Parent.Env.fixups(used),root_writer_evidence=root_evidence(),source_proofs=obligations(),
        verified_counts={'acquisition_cases':len(acq),'callback_cases':16,'consumer_cases':len(cases),'intervals':len(intervals(e)),**counts},
        native_API_executed=False,native_daemon_kext_pairing_established=False,native_epoch_join_established=False,full_goal_complete=False)
    return e

if __name__=='__main__':
    e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
