#!/usr/bin/env python3
"""Independent source lift and interface audit for daemon notification lifecycle.

O(intervals*(visits*(registers+byte effects))+source+queries) time/space,
excluding solver cost; 30 s/query. Imports remain unexecuted. The fresh
alternate CPU controls invert undefined backing, caller-saved clobbers,
baseline outputs and atexit status, without asserting native equivalence.
"""
import json,subprocess
from pathlib import Path
from collections import Counter
import z3
from daemon_receive_tools import ROOT,IMAGE,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha
import audit_daemon_environment_outputs as Parent
import recover_daemon_notification_registration as R

class Lift(Parent.Lift):
    def one(self,i):
        if i.mnemonic=='paciza':return
        return super().one(i)

def sdk_checks():
    code='''#include <notify.h>
#include <stdint.h>
#include <stdlib.h>
_Static_assert(sizeof(int)==4,"int32");
_Static_assert(sizeof(uint32_t)==4,"uint32");
_Static_assert(sizeof(void*)==8,"pointer64");
_Static_assert(__builtin_types_compatible_p(__typeof__(&notify_register_check),uint32_t(*)(const char*,int*)),"register_check_ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&notify_check),uint32_t(*)(int,int*)),"check_ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&notify_cancel),uint32_t(*)(int)),"cancel_ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&atexit),int(*)(void(*)(void))),"atexit_ABI");
'''
    cmd=['xcrun','clang','-target','arm64e-apple-macos14','-std=c11','-fsyntax-only','-x','c','-']
    p=subprocess.run(cmd,input=code,text=True,capture_output=True,timeout=30);assert p.returncode==0 and not p.stderr
    sdk=Path(subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip())
    return {'command':cmd,'source':code,'exit_code':0,'headers':[{'SDK_relative_header':n,'sha256':sha(sdk/n)}
            for n in ['usr/include/notify.h','usr/include/stdlib.h']],
            'scope':'Current arm64e SDK prototype comparison only; original SDK and native library pairing unknown.',
            'API_executed':False,'emitted_artifact':False}

def intervals(c):return ([c['root_prefix']] if 'root_prefix'in c else [])+c['intervals']

def interface(c):
    cfg=c['configuration'];rows=c['intervals'];events=c['API_return_premises'];calls=[int(r['boundary']['pc'],16) for r in rows]
    if cfg['kind']=='exit':
        assert calls==[0x100df3114,0x100df318c,R.TAIL]
        for j,r in enumerate(rows):assert r['boundary']['registers31'][0]==hex(0x7001+j)
        assert rows[-1]['boundary']['registers31'][1]==hex(R.Parent.Base.IMPORTS['libSystem/_notify_cancel'])
        assert rows[-1]['boundary']['SP']==rows[0]['caller_SP']
        assert rows[-1]['boundary']['registers31'][19:31]==rows[0]['entry_registers31'][19:31]
        assert len(events)==2 and all(e['symbol']=='libSystem/_notify_cancel' and e['return32']==hex(cfg['failure_status32']) for e in events)
        assert not any(int(w['address'],16) in R.TOKENS+[R.Parent.FLAG] for r in rows for w in r['source_writes'])
        return {'kind':'exit_callback','cancel_call_sites':['0x100df3114','0x100df318c'],
                'third_cancel_tail_site':'0x100df3228','tail_guard_unexecuted':True,'SP_and_saved_registers_restored':True,
                'native_exit_or_registration_lifetime_join_established':False,'all_checks_pass':True}
    f=int(c['root_prefix']['caller_SP'],16)-0x4a0
    root=c['root_prefix'];prefix_writes=root['source_writes']
    for off,at in [(0x60,R.TOKENS[0]),(0x58,R.TOKENS[1]),(0x68,R.TOKENS[2]),(0x80,R.Parent.FLAG)]:
        w=next(w for w in prefix_writes if int(w['address'],16)==f+off)
        assert int.from_bytes(bytes.fromhex(w['after_hex']),'little')==at and w['size_bytes']==8
    for r in rows:
        pc=int(r['boundary']['pc'],16);args=r['boundary']['registers31']
        if pc in R.REG:
            j=R.REG.index(pc);assert args[:2]==[R.banks()[1+2*j]['target'],hex(R.TOKENS[j])]
            assert r['boundary']['detail']['symbol']=='libSystem/_notify_register_check' and r['boundary']['detail']['modifier']=='0x6463'
        elif pc in R.CHECK:
            j=R.CHECK.index(pc);offset=[0x1d4,0x1dc,0x154][j]
            assert args[:2]==[hex(0x7101+j),hex(f+offset)] and r['boundary']['detail']['modifier']=='0x89e0'
        elif pc==R.ATEXIT:assert args[0]==hex(R.EXIT) and r['boundary']['detail']['symbol']=='libSystem/_atexit'
        elif pc==R.CLOCK:assert args[:2]==[hex(R.Parent.Base.P+0x3000),'0x0']
        else:assert pc==0x100e24d08
    if cfg['flag8']&1:
        assert calls==[R.CLOCK] and not events and c['final_ready8']==cfg['flag8']
        return {'kind':'already_ready','ready8':c['final_ready8'],'registration_calls':0,'all_checks_pass':True}
    order=R.REG+list(reversed(R.CHECK))+[R.ATEXIT,R.CLOCK]
    failed=cfg['outcome'].startswith(('register_fail','check_fail'))
    if failed:
        j=int(cfg['outcome'][-1]);site=(R.REG if cfg['outcome'].startswith('register_fail') else R.CHECK)[j]
        assert calls==order[:order.index(site)+1]+[0x100e24d08] and c['final_ready8']==cfg['flag8']
        assert events[-1]['return32']==hex(cfg['failure_status32'])
    else:assert calls==order and c['final_ready8']==1
    ready_stores=[w for r in rows for w in r['source_writes'] if int(w['address'],16)==R.Parent.FLAG]
    assert len(ready_stores)==int(not failed)
    if ready_stores:assert ready_stores[0]['pc']=='0x100e20328' and ready_stores[0]['after_hex']=='01'
    assert not any('cancel' in e['symbol'] for e in events)
    return {'kind':'failure_before_ready' if failed else 'registration_and_baseline_success',
            'original_call_sites':[hex(p) for p in calls], 'ready8':c['final_ready8'],
            'registration_calls':sum(p in R.REG for p in calls),'baseline_check_calls':sum(p in R.CHECK for p in calls),
            'atexit_result_ignored':not failed,'native_registration_or_delivery_established':False,'all_checks_pass':True}

def alternate(cfg):
    c={**cfg,'pattern':cfg['pattern']^255}
    if c['kind']=='registration':c.update(changed32=cfg['changed32']^0xffffffff,atexit_status32=cfg['atexit_status32']^0xffffffff)
    return c

def build():
    e=json.loads(read(ROOT/(R.P+'_checks.json')))
    assert e['generator_sha256']==sha(R.__file__) and e['dependencies']=={n:sha(ROOT/n) for n in e['dependencies']}
    assert e['source_regions']==R.source() and e['bank_rules']==R.banks()
    assert [c['configuration'] for c in e['cases']]==list(R.configurations())
    used={int(x['address'],16) for c in e['cases'] for r in intervals(c) for x in r['source_reads']
          if x['size_bytes']==8 and int(x['address'],16) in FIXUPS}
    used.update(int(x['slot'],16) for x in e['bank_rules'])
    used.update(int(q[k],16) for q in e['source_proofs'] for k in ['zero_slot','nonzero_slot'] if k in q)
    assert e['source_fixups']==R.Parent.fixups(used)
    for pc,row in e['source_pool'].items():
        i=next(Parent.DEC.disasm(IMAGE.read(int(pc,16),4),int(pc,16)))
        assert row=={'pc':pc,'bytes_hex':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str}
    fresh=R.obligations(e['cases']);assert len(fresh)==len(e['source_proofs'])==9
    for q,w in zip(e['source_proofs'],fresh):
        assert q['label']==w['label'] and q['premises_nonvacuous'];s=z3.Solver();s.set(timeout=30000);s.from_string(q['query']);assert s.check()==z3.unsat
    lifts=[];totals=Counter();interfaces=[];controls=[]
    for c in e['cases']:
        interfaces.append(interface(c));alt=R.probe(alternate(c['configuration']))
        aa,bb=intervals(c),intervals(alt);assert len(aa)==len(bb)
        for a,b in zip(aa,bb):
            for key in ['source_visits','source_writes','logical_edges']:assert a[key]==b[key],(key,a['role'])
            assert a['boundary']['pc']==b['boundary']['pc'] and a['boundary']['SP']==b['boundary']['SP']
        for variant in [c,alt]:
            for ix,row in enumerate(intervals(variant)):
                checked=Lift(row).run();checked['interval_index']=ix;checked['role']=row['role'];lifts.append(checked);totals.update(checked['verified_counts'])
        controls.append({'configuration':c['configuration'],'alternate_configuration':alt['configuration'],
                         'same_source_control_and_stores':True,'unread_baseline_and_atexit_results_do_not_change_control':True})
    return {'scope':__doc__,'generator_sha256':e['generator_sha256'],'auditor_sha256':sha(__file__),
            'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],'dependencies':e['dependencies'],
            'verified_counts':e['verified_counts'],'source_queries_unsat':9,'interfaces':interfaces,
            'independent_lifts':lifts,'independent_totals':dict(totals),'alternate_controls':controls,'SDK_checks':sdk_checks(),
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'full_goal_complete':False,'all_checks_pass':True}

if __name__=='__main__':
    a=build();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n')
    print(json.dumps({k:a[k] for k in ['verified_counts','independent_totals','all_checks_pass']}),flush=True)
