#!/usr/bin/env python3
"""Independent original-source replay and explicit inter-interval join audit.

O(receipts+visits*(register state+byte effects)+source+queries) time/space.
No native API/IPC, allocation/free or hardware PAC executes.
"""
import json,struct,subprocess
from pathlib import Path
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_daemon_network_record import Lift,join,state_bytes,fixture_bytes
import recover_daemon_network_gate as R

def return_join(before,event,after,memory=None):
    assert before['boundary']['kind']=='before_unmodeled_import_call'
    assert event['call_site']==before['boundary']['pc'] and event['symbol']==before['boundary']['detail']['symbol']
    assert event['ABI_return_and_output_premise'] and not event['native_API_executed']
    assert after['entry_PC']==event['continuation_PC']==hex(int(event['call_site'],16)+4)
    assert after['entry_registers31']==event['return_registers31'] and after['entry_NZCV']==event['return_NZCV']
    assert after['entry_registers31'][18:30]==before['boundary']['registers31'][18:30]
    assert after['caller_SP']==before['boundary']['SP']
    assert fixture_bytes(after,'private')|fixture_bytes(after,'image')==(state_bytes(before) if memory is None else memory)

def interfaces(e):
    parent=json.loads(read(ROOT/(R.Parent.P+'_checks.json')));counts=Counter();outcomes=Counter()
    for c in e['acquisition_cases']:
        before=parent['warm_cases'][c['parent_warm_case_index']]['continuation']['intervals'][-1];cb=c['callback']
        assert before['boundary']['pc']==hex(R.Parent.ONCE) and before['boundary']['registers31'][:2]==['0x1010b8cd0',hex(R.CALLBACK)]
        if cb:
            assert cb['entry_PC']==hex(R.CALLBACK)
            assert cb['entry_registers31'][:30]==before['boundary']['registers31'][:30]
            assert int(cb['caller_SP'],16)==int(before['boundary']['SP'],16)-256
            assert cb['entry_registers31'][30]==cb['boundary']['pc']==c['callback_invocation_premise']['return_token']
            assert cb['boundary']['registers31'][18:30]==before['boundary']['registers31'][18:30]
            assert cb['boundary']['SP']==cb['caller_SP']
            assert state_bytes(before)==fixture_bytes(cb,'private')|fixture_bytes(cb,'image')
            writes=[w for w in cb['source_writes'] if int(w['address'],16)<0x6000000000]
            assert [(w['pc'],w['address'],w['size_bytes']) for w in writes]==[
                ('0x10040ecfc','0x1010c5088',8),('0x10040ed00','0x1010c4670',8)]
            assert len(cb['source_calls'])==1 and cb['source_calls'][0]['target']=='0x10044fc34'
            assert IMAGE.read(0x10044fc34,4).hex()=='c0035fd6';counts['callback_invocation_and_return_joins']+=1
        row=c['intervals'][0];return_join(before,c['once_return_premise'],row,state_bytes(cb) if cb else None)
        assert row['boundary']['pc']=='0x100361df4' and row['boundary']['registers31'][0]=='0x1010b7478'
        rr=[r for r in row['source_reads'] if r['address']==hex(R.FALLBACK)]
        assert len(rr)==1 and rr[0]['size_bytes']==8 and rr[0]['bytes_hex']=='78740b0101000000'
        assert FIXUPS[R.FALLBACK]['target']==0x1010b7478
        return_join(row,c['lock_return_premise'],c['intervals'][1]);counts['acquisition_import_return_joins']+=2
        b=c['intervals'][1]['boundary'];assert b['pc']==hex(R.GATE) and b['detail']['snapshot']['known_mask_hex']=='00'*8
        counts['caller_returns_with_undefined_root']+=1
    for c in e['consumer_cases']:
        before=e['acquisition_cases'][c['acquisition_index']]['intervals'][-1]
        for j,(after,effect) in enumerate(zip(c['intervals'],c['root_premises'])):
            assert before['boundary']['detail']['address']==effect['address'] and before['boundary']['detail']['snapshot']['known_mask_hex']=='00'*8
            assert before['boundary']['pc']==after['entry_PC']
            join(before,after,[effect]+(c['image_premises'] if j==0 else []));before=after;counts['root_and_image_joins']+=1
        for event,after in zip(c['cleanup_return_premises'],c['intervals'][2:]):
            return_join(before,event,after);before=after;counts['cleanup_import_return_joins']+=1
        assert len(c['intervals'])==2+len(c['cleanup_return_premises'])
        assert before['boundary']['pc']==c['final_boundary'];outcomes[c['final_boundary']]+=1
        counter=[w for row in c['intervals'] for w in row['source_writes'] if w['address']==hex(R.FLAG)]
        descriptor=c['flag32']==0 and int(c['cache_pointer64'],16)!=0
        assert len(counter)==(0 if descriptor else 1)
        if counter:
            assert counter[0]['pc']=='0x10050feb4' and counter[0]['size_bytes']==4
            assert int.from_bytes(bytes.fromhex(counter[0]['after_hex']),'little')==(c['flag32']+1)&0xffffffff
            assert c['intervals'][1]['boundary']['registers31'][:2]==['0x1010b8cd0',hex(R.CALLBACK)]
            assert c['intervals'][2]['boundary']['registers31'][0]=='0x1010b7478'
            calls=[call for row in c['intervals'] for call in row['source_calls']]
            assert [(call['pc'],call['target']) for call in calls]==[('0x10050ff50','0x1004423f8'),('0x10050ff98','0x1000056c8')]
            counts['matching_fallback_lock_argument_pairs']+=1
        else:
            assert c['final_boundary']=='0x10048192c' and not c['cleanup_return_premises']
            assert before['boundary']['kind']=='before_explicit_source_cut'
            assert not any(row['source_calls'] for row in c['intervals'])
        for row in c['intervals']:
            assert not any(int(w['address'],16)<R.Parent.RECORD+10 and R.Parent.RECORD<int(w['address'],16)+w['size_bytes'] for w in row['source_writes'])
        counts['network_record_prefix_preserved']+=1
    assert outcomes=={'0x10080a464':64,'0x10048192c':32,'0x1005fadd4':32}
    # Imported status variation preserves the exact source PC sequences in every pair.
    for ix in range(0,len(e['acquisition_cases']),2):
        a,b=e['acquisition_cases'][ix:ix+2];assert [a['import_status32'],b['import_status32']]==[0,35]
        assert [[v['pc'] for v in r['source_visits']] for r in a['intervals']]==[[v['pc'] for v in r['source_visits']] for r in b['intervals']]
        for k in range(4):
            aa,bb=e['consumer_cases'][4*ix+k],e['consumer_cases'][4*(ix+1)+k]
            assert [[v['pc'] for v in r['source_visits']] for r in aa['intervals']]==[[v['pc'] for v in r['source_visits']] for r in bb['intervals']]
            counts['status_variation_source_path_pairs']+=1
    return {'verified_counts':dict(counts),'boundary_counts':dict(outcomes),
            'scope':'Argument-address pairing and source path agreement; native lock validity, successful ownership and concurrency remain unknown.'}

def sdk_checks():
    code='''#define _DARWIN_C_SOURCE 1
#include <pthread.h>
_Static_assert(sizeof(void*)==8 && sizeof(int)==4,"widths");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_once),int(*)(pthread_once_t*,void(*)(void))),"once_prototype");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_rwlock_wrlock),int(*)(pthread_rwlock_t*)),"write_lock_prototype");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_rwlock_unlock),int(*)(pthread_rwlock_t*)),"unlock_prototype");
int gate_probe(pthread_once_t *p,void(*f)(void),pthread_rwlock_t *l) {return pthread_once(p,f)+pthread_rwlock_wrlock(l)+pthread_rwlock_unlock(l);}
'''
    cmd=['xcrun','clang','-target','arm64e-apple-macos14','-std=c11','-S','-O1','-x','c','-','-o','-']
    p=subprocess.run(cmd,input=code,text=True,capture_output=True,timeout=30);assert p.returncode==0 and not p.stderr,p.stderr
    sdk=Path(subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip())
    return {'command':cmd,'source':code,'assembly':p.stdout,'exit_code':0,
            'headers':[{'SDK_relative_header':n,'sha256':sha(sdk/n)} for n in ['usr/include/pthread.h','usr/include/pthread/pthread.h']],
            'scope':'Current compile-only ABI comparison; historical implementation and object lifetime unknown.','native_API_executed':False}

def build():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e['generator_sha256']==sha(R.__file__)
    assert e['dependencies']=={n:sha(ROOT/n) for n in R.DEPS};counts=Counter();lifts=[]
    for j,row in enumerate(R.intervals(e)):
        result=Lift(row).run();result['interval_index']=j;lifts.append(result);counts.update(result['verified_counts'])
    assert R.source()==e['source_regions'] and R.root_evidence()==e['root_writer_evidence']
    assert len(R.obligations())==len(e['source_proofs'])==4
    for q in e['source_proofs']:
        s=z3.Solver();s.set(timeout=30000);s.from_string(q['query']);assert s.check()==z3.unsat and q['premises_nonvacuous']
    return {'generator_sha256':sha(R.__file__),'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
            'source_sha256':sha(SOURCE),'dependencies':e['dependencies'],'verified_counts':e['verified_counts'],
            'independent_lifts':lifts,'independent_totals':dict(counts),'interfaces':interfaces(e),'source_queries_unsat':4,'SDK_checks':sdk_checks(),
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'native_epoch_join_established':False,
            'full_goal_complete':False,'all_checks_pass':True}

if __name__=='__main__':
    e=build();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps({'replay':e['independent_totals'],'interfaces':e['interfaces']}),flush=True)
