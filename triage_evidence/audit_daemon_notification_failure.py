#!/usr/bin/env python3
"""Independent source lift for notification failure cleanup and caller return.

O(intervals*(visits*(registers+byte effects))+source+queries) time/space,
excluding solver cost; 30 s/query. No native API/IPC, allocation/free or PAC.
Record retirement is a source-request boundary, not observed native ownership.
"""
import json,subprocess
from pathlib import Path
from collections import Counter
import z3
from daemon_receive_tools import ROOT,IMAGE,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_daemon_notification_failure as R
import audit_daemon_notification_registration as RegAudit

Lift=RegAudit.Lift

def nonclobber():
    rows=[]
    for i in RegAudit.Parent.DEC.disasm(IMAGE.read(0x100e1e69c,0x100e1e718-0x100e1e69c),0x100e1e69c):
        _,writes=i.regs_access();names=[i.reg_name(j) for j in writes]
        assert not set(names)&{'x15','w15','sp','wsp'}
        rows.append({'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'written_registers':names})
    assert len(rows)==31
    return rows

def sdk_checks():
    code='''#include <stdlib.h>
_Static_assert(sizeof(void*)==8,"pointer64");
_Static_assert(__builtin_types_compatible_p(__typeof__(&free),void(*)(void*)),"free_void_ABI");
'''
    cmd=['xcrun','clang','-target','arm64e-apple-macos14','-std=c11','-fsyntax-only','-x','c','-']
    p=subprocess.run(cmd,input=code,text=True,capture_output=True,timeout=30);assert p.returncode==0 and not p.stderr
    sdk=Path(subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip())
    return {'command':cmd,'source':code,'exit_code':0,'SDK_relative_header':'usr/include/stdlib.h',
            'header_sha256':sha(sdk/'usr/include/stdlib.h'),'scope':'Current arm64e prototype comparison only.',
            'API_executed':False,'emitted_artifact':False}

def interface(c):
    cfg=c['configuration'];rows=c['cleanup_intervals'];prefix=c['root_prefix'];s=int(prefix['caller_SP'],16);f=s-0x4a0
    entry=next(r for r in prefix['source_frames'] if r['pc']==hex(R.Parent.ENTRY))
    assert [r['target'] for r in prefix['source_calls']]==['0x100001e0c',hex(R.Parent.ENTRY)]
    assert entry['registers31'][0]=='0xfffffffffffffffe' and entry['SP']==hex(s)
    assert entry['registers31'][1:5]==[hex(s+off) for _,off,_ in R.Parent.OUTPUTS]
    for off,sentinel,pc in [(0x160,R.SENTINELS[0],'0x100e1e72c'),(0x1c0,R.SENTINELS[1],'0x100e1e728')]:
        w=next(w for w in prefix['source_writes'] if w['pc']==pc and int(w['address'],16)==f+off)
        assert w['size_bytes']==8 and int.from_bytes(bytes.fromhex(w['after_hex']),'little')==sentinel
    phase=rows[0]['entry_registers31'];assert phase[25]=='0x1f8' and phase[28]=='0x0'
    returned=rows[-1]['boundary'];assert returned['pc']==hex(R.Parent.RETURN) and returned['registers31'][0]=='0x0'
    assert returned['SP']==hex(s) and returned['registers31'][19:31]==entry['registers31'][19:31]
    call=c['caller_consumer'];assert call['entry_registers31']==returned['registers31'] and call['entry_NZCV']==rows[-1]['boundary_NZCV']
    assert call['boundary']['pc']=='0x1006cdaf8' and call['boundary']['registers31'][28]=='0x8b3dc651'
    assert call['boundary']['SP']==hex(s) and c['final_ready8']==cfg['flag8']
    tokens=[0x7001+j for j in range(3)]
    for event in c['registration_return_premises']:
        if event['symbol']=='libSystem/_notify_register_check' and 'output'in event:
            j=R.Reg.TOKENS.index(int(event['output']['address'],16));tokens[j]=int.from_bytes(bytes.fromhex(event['output']['bytes_hex']),'little')
    assert c['final_tokens32']==tokens
    for row in c['registration_intervals']+rows+[call]:
        for w in row['source_writes']:
            at=int(w['address'],16)
            for _,off,n in R.Parent.OUTPUTS:assert not(at<s+off+n and s+off<at+w['size_bytes'])
    states=cfg['record_states'];expected=[]
    for j,state in enumerate(states):
        if state==2:expected.append((R.FREES[2*j],R.PAYLOADS[j]))
        if state:expected.append((R.FREES[2*j+1],R.RECORDS[j]))
    actual=[(int(r['boundary']['pc'],16),int(r['boundary']['registers31'][0],16)) for r in rows[:-1]]
    assert actual==expected and len(c['free_return_premises'])==len(expected)
    headers=[];retired=[]
    for ix,row in enumerate(rows):
        for record in retired:
            for event in row['source_reads']+row['source_writes']:
                at=int(event['address'],16);assert not (at<record+16 and record<at+event['size_bytes'])
        pc=int(row['boundary']['pc'],16)
        if pc in [R.FREES[1],R.FREES[3]]:
            j=0 if pc==R.FREES[1] else 1;record=R.RECORDS[j]
            writes=[w for prior in rows[:ix+1] for w in prior['source_writes'] if record<=int(w['address'],16)<record+16]
            assert [(int(w['address'],16)-record,w['size_bytes'],w['after_hex']) for w in writes]==[
                (0,8,'00'*8),(8,4,('6a944e37' if j==0 else 'fe1e6d1d')),(12,4,('00000000' if j==0 else 'a7535b65'))]
            headers.append({'record':hex(record),'header_extent_bytes':16,'source_header_writes':writes});retired.append(record)
    assert not any('notify_cancel'in r['boundary'].get('detail',{}).get('symbol','') for r in rows if r['boundary'].get('detail'))
    return {'kind':cfg['kind'],'source_free_requests':[{'site':hex(p),'pointer':hex(a)} for p,a in expected],
            'header_rewrites':headers,'no_source_access_after_record_free_request_return':True,
            'helper_return64':'0x0','caller_target':'0x1006cdaf8','saved_registers_restored':True,
            'native_retirement_or_daemon_kext_pairing_established':False,'all_checks_pass':True}

def alternate(cfg):return {**cfg,'pattern':cfg['pattern']^255,'changed32':cfg['changed32']^0xffffffff}

def build():
    e=json.loads(read(ROOT/(R.P+'_checks.json')))
    assert e['generator_sha256']==sha(R.__file__) and e['dependencies']=={n:sha(ROOT/n) for n in e['dependencies']}
    assert e['source_regions']==R.source() and e['bank_rules']==R.banks()
    assert [c['configuration'] for c in e['cases']]==list(R.configurations())
    used={int(x['address'],16) for c in e['cases'] for row in R.intervals(c) for x in row['source_reads']
          if x['size_bytes']==8 and int(x['address'],16) in FIXUPS}
    used.update(int(x['slot'],16) for x in e['bank_rules'])
    used.update(int(q[k],16) for q in e['source_proofs'] for k in ['zero_slot','nonzero_slot'] if k in q)
    assert e['source_fixups']==R.Parent.fixups(used)
    for pc,row in e['source_pool'].items():
        i=next(RegAudit.Parent.DEC.disasm(IMAGE.read(int(pc,16),4),int(pc,16)))
        assert row=={'pc':pc,'bytes_hex':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str}
    fresh=R.obligations();assert len(fresh)==len(e['source_proofs'])==12
    for q,w in zip(e['source_proofs'],fresh):
        assert q['label']==w['label'] and q['premises_nonvacuous'];s=z3.Solver();s.set(timeout=30000);s.from_string(q['query']);assert s.check()==z3.unsat
    lifts=[];totals=Counter();interfaces=[];controls=[]
    for c in e['cases']:
        interfaces.append(interface(c));alt=R.probe(alternate(c['configuration']))
        aa,bb=R.intervals(c),R.intervals(alt);assert len(aa)==len(bb)
        for a,b in zip(aa,bb):
            for key in ['source_visits','source_writes','logical_edges','source_calls']:assert a[key]==b[key],(key,a['role'])
            assert a['boundary']['pc']==b['boundary']['pc'] and a['boundary']['SP']==b['boundary']['SP']
        for variant in [c,alt]:
            for ix,row in enumerate(R.intervals(variant)):
                checked=Lift(row).run();checked['interval_index']=ix;checked['role']=row['role'];lifts.append(checked);totals.update(checked['verified_counts'])
        controls.append({'configuration':c['configuration'],'alternate_configuration':alt['configuration'],
                         'same_source_control_stores_and_calls':True,'helper_and_caller_result_preserved':True})
    return {'scope':__doc__,'generator_sha256':e['generator_sha256'],'auditor_sha256':sha(__file__),
            'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],'dependencies':e['dependencies'],
            'verified_counts':e['verified_counts'],'source_queries_unsat':12,'interfaces':interfaces,
            'independent_lifts':lifts,'independent_totals':dict(totals),'alternate_controls':controls,
            'sentinel_slice_nonclobber':nonclobber(),'SDK_checks':sdk_checks(),
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'full_goal_complete':False,'all_checks_pass':True}

if __name__=='__main__':
    a=build();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n')
    print(json.dumps({k:a[k] for k in ['verified_counts','independent_totals','all_checks_pass']}),flush=True)
