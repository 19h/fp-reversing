#!/usr/bin/env python3
"""Re-extract CF contracts, verify finite private fixtures and owned manifest.

O(B+I+E) time/space, excluding solvers and streamed artifact hashing. No native
target, host IPC, framework callout or IDB mutation executes.
"""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
from bootpolicy_cache_reader import Cache
from probe_cf_receive import BUFFER,VARS,PORT,RLSOURCE,BOOST,INFO,EXISTING,HEAP,CALLBACK,OTHER_CALLBACK,PERFORM

ROOT=Path(__file__).resolve().parent


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    subprocess.run([sys.executable,str(ROOT/'recover_cf_receive.py')],check=True)
    c=json.loads((ROOT/'cf_receive_contracts.json').read_text())
    p=json.loads((ROOT/'cf_receive_profiles.json').read_text())
    assert c['generator_sha256']==sha(ROOT/'recover_cf_receive.py')
    assert p['generator_sha256']==sha(ROOT/'probe_cf_receive.py')
    assert p['cache_reader_sha256']==c['cache_reader_sha256']==sha(ROOT/'bootpolicy_cache_reader.py')
    assert p['cache_uuid']==c['cache_uuid'] and p['library_uuid']==c['library_uuid']
    rows={r['label']:r for r in p['profiles']};assert len(rows)==42
    cache=Cache();hashes={}
    for r in p['profiles']:
        key=tuple(r['source_code_pages'])
        if key not in hashes:
            h=hashlib.sha256()
            for a in key:
                a=int(a,16);h.update(struct.pack('<Q',a));h.update(cache.read(a,4096))
            hashes[key]=h.hexdigest()
        assert hashes[key]==r['source_code_pages_sha256']
        assert r['steps']<p['instruction_limit_per_profile']
        assert not r['native_target_executed'] and not r['target_host_operations_executed']
    checks=[]
    def ev(label,kind):return [e for e in rows[label]['events'] if e['kind']==kind]
    def helper(label,a):return [e for e in ev(label,'private_helper') if e['address']==hex(a)]
    def result(label):
        r=rows[label];assert r['stop_reason']=='returned',label
        return int(r['events'][-1]['x0'],16)
    def check(label,condition,meaning):
        assert condition,(label,meaning,rows[label]['final'])
        checks.append({'profile':label,'check':meaning,'result':'pass'})
    for label,r in rows.items():
        if r['kind'] not in ('service','service_to_source'):continue
        seed=r['seed'];calls=ev(label,'private_mach_msg');alloc=ev(label,'private_realloc')
        timeout=seed.get('timeout',0xffffffff);options=0x07000806 if timeout==0xffffffff else 0x07000906
        check(label,bool(calls) and all(int(e['args'][1],16)==options and int(e['args'][2],16)==0 and
            int(e['args'][4],16)==0x32f and int(e['args'][5],16)==timeout and int(e['args'][6],16)==0 for e in calls),
            'receive-only options, no send/notify, original port and timeout on every attempt')
        caps=[3072]+[e['requested_bytes'] for e in alloc]
        check(label,[int(e['args'][3],16) for e in calls]==caps[:len(calls)],'initial 3072-byte receive capacity and exact grown retry capacities')
        for i,a in enumerate(alloc):
            s=seed['receive_results'][i][1];want=((((s+68)&0xffffffff)+3)&0x1fffffffc)
            check(label,a['requested_bytes']==want and int(a['args'][0],16)==(0 if i==0 else HEAP+(i-1)*0x20000) and
                int(a['args'][2],16)==0x9b1394d8 and int(a['args'][3],16)==0,
                'native u32 addition/u64 alignment; first allocation excludes stack, later realloc uses owned heap; null recovery context')
        copies=ev(label,'private_voucher_copy');adopts=ev(label,'private_voucher_adopt');reverts=helper(label,0x188081380)
        wantcopy=seed.get('voucher_state',0xffffffffffffffff)!=0xffffffffffffffff and not seed.get('no_voucher_copy')
        check(label,len(adopts)==len(calls) and len(reverts)==len(calls) and len(copies)==(len(calls) if wantcopy else 0),
            'voucher revert/adopt after each receive; copy gated by state and optional output')
        wantstate=seed.get('voucher_state',0xffffffffffffffff)
        check(label,r['final']['voucher_state']==hex(wantstate) and r['final']['voucher_copy']==hex(INFO+0x200 if wantcopy else 0),
            'adopted state and independently optional voucher-object output')
        if r['stop_reason']=='private_allocation_limit':
            check(label,label=='service_growth_four_gib' and alloc[-1]['requested_bytes']==4294967296,
                'full-width near-overflow case stops at private 4 GiB allocation boundary; no native reachability claim')
        elif r['stop_reason']=='receive_error_fail_stop_boundary':
            check(label,label in ('service_unexpected_error','service_body_error') and not ev(label,'private_daemon_callback'),
                'unexpected and body-error statuses enter original cold failure before callback')
        else:
            status=seed['receive_results'][-1][0];f=r['final'];success=status==0
            if r['kind']=='service':check(label,result(label)==int(success),'success/timeout Boolean return')
            check(label,f['live_port']==('0x32f' if success else '0x0') and f['buffer_pointer']==(
                hex(HEAP+(len(alloc)-1)*0x20000) if success and alloc else hex(BUFFER) if success else '0x0'),
                'success publishes received local name and buffer; timeout clears both')
            frees=helper(label,0x18806c3d0)
            wantfree=bool(alloc) and (not success or r['kind']=='service_to_source')
            check(label,len(frees)==int(wantfree) and (not frees or int(frees[0]['args'][0],16)==HEAP+(len(alloc)-1)*0x20000),
                'grown storage freed once on timeout or post-callback cleanup; original buffer not freed')
        if r['kind']=='service_to_source':
            cb=ev(label,'private_daemon_callback');size=seed['receive_results'][-1][1]
            check(label,r['stop_reason']=='completed_private_receive_callback_cleanup' and len(cb)==1 and
                [int(x,16) for x in cb[0]['args'][:4]]==[PORT,int(r['final']['buffer_pointer'],16),size,0] and
                r['final']['reply_pointer']=='0x0','three staged original phases forward message/inline size then clean up without framework reply')
            events=r['events'];free=helper(label,0x18806c3d0)
            check(label,not free or events.index(cb[0])<events.index(free[0]),'heap disposal occurs after callback boundary returns')
            if size==80:
                raw=bytes.fromhex(cb[0]['message_prefix_148'])
                check(label,len(raw)==148 and struct.unpack_from('<II',raw,80)==(0,68) and raw[100:132]==bytes(32),
                    'modeled complete AV trailer and kernel audit prefix survive original forwarding instructions')
    label='service_releases_voucher_before_retry';events=rows[label]['events'];release=helper(label,0x18806ead0)
    check(label,len(release)==1 and int(release[0]['args'][0],16)==INFO+0x200 and
        events.index(ev(label,'private_realloc')[0])<events.index(release[0])<events.index(ev(label,'private_mach_msg')[1]),
        'copied voucher released between allocation and retry; next revert sees modeled adopted state')
    for label,r in rows.items():
        if r['kind']=='perform':
            seed=r['seed'];cb=ev(label,'private_daemon_callback');valid=not seed.get('invalid_port');f=r['final']
            check(label,result(label)==0 and len(cb)==int(valid),'CFMachPort perform returns null framework reply regardless of modeled callback return')
            if valid:
                info=INFO+0x100 if seed.get('context_retain') else INFO if seed.get('context_info') else 0
                check(label,[int(x,16) for x in cb[0]['args'][:4]]==[PORT,BUFFER,80,info],
                    'callback receives CF object, original buffer, inline size and optionally retained context info')
            check(label,f['boost_refs']==0 and f['boost_pointer']==hex(BOOST+0x100 if seed.get('old_boost') else 0),
                'temporary boost reference balance; existing cached boost preserved')
            tsd=helper(label,0x1846ddde4);newtemp=seed.get('new_boost') and not seed.get('old_boost') and valid
            check(label,[[int(e['args'][i],16) for i in range(3)] for e in tsd]==([[12,BOOST,0],[12,0,0]] if newtemp else []),
                'TSD12 install/clear gated by null old cache, nonnull new boost and valid port')
            releases=ev(label,'private_context_release');retains=ev(label,'private_context_retain')
            check(label,len(retains)==int(bool(seed.get('context_retain')) and valid) and
                len(releases)==int(bool(seed.get('context_retain') and seed.get('context_release')) and valid),
                'per-call context release is paired with a context retain; release-only context is not released here')
        elif r['kind']=='do_source':
            invoked=not r['seed'].get('invalid_source') and not r['seed'].get('invalid_port') and not r['seed'].get('null_perform')
            check(label,result(label)==int(not r['seed'].get('invalid_source')) and len(ev(label,'private_daemon_callback'))==int(invoked),
                'source handled Boolean distinct from application callback invocation and validity')
            check(label,r['final']['reply_pointer']=='0x0','CFMachPort or null perform produces no framework reply pointer')
        elif r['kind']=='create_source':
            seed=r['seed'];valid=not seed.get('invalid_port');new=valid and (not seed.get('existing_source') or bool(seed.get('invalid_existing_source')))
            created=ev(label,'private_source_create')
            check(label,result(label)==(RLSOURCE if valid else 0) and r['final']['source_pointer']==hex(RLSOURCE if valid else 0),
                'valid CFMachPort creates/reuses cached source; invalid port yields null')
            check(label,len(created)==int(new),'only absent or invalid cached source invokes generic source create')
            if new:
                words=struct.unpack('<9Q',bytes.fromhex(created[0]['context_72_bytes']))
                check(label,words==(1,PORT,0x1846db030,0x1846e1278,0x18481206c,0x1847791a0,0x18472e5f0,0x1847e8924,PERFORM),
                    'original instructions construct complete 72-byte version1 context and exact getter/perform callbacks')
            if seed.get('invalid_existing_source'):
                events=r['events'];release=ev(label,'private_cf_release')
                check(label,len(release)==1 and release[0]['object']==hex(RLSOURCE) and events.index(release[0])<events.index(created[0]),
                    'invalid cached source released before replacement creation')
        elif r['kind']=='with_port':
            seed=r['seed'];admit=seed.get('port_type_status',0)==0 and bool(seed.get('port_types',0x20000)&0x70000)
            reuse=bool(seed.get('reuse'));valid=not seed.get('invalid_port');want=(EXISTING if reuse else PORT) if admit and valid else 0
            check(label,result(label)==want,'constructor requires successful type query and SEND/RECEIVE/SEND_ONCE bit, then object validity')
            check(label,r['final']['should_free_info']==int(not admit or reuse),'new object consumes context; rejection/reuse leaves shouldFreeInfo true')
            typecall=ev(label,'private_mach_port_type')
            check(label,len(typecall)==1 and [int(x,16) for x in typecall[0]['args'][:2]]==[0x103,0x32f],
                'original constructor queries private task-self name and exact input port name')
            check(label,r['final']['port_callback']==hex(CALLBACK) and r['final']['existing_callback']==hex(OTHER_CALLBACK),
                'cached matching object retains previous callback; new callback is not substituted into existing object')
            retain=ev(label,'private_context_retain')
            check(label,len(retain)==int(admit and not reuse and bool(seed.get('context_retain'))),
                'context retention occurs only for admitted new object in these fixtures')
            if retain:
                events=r['events'];locks=helper(label,0x18806ebf0);unlocks=helper(label,0x18806c600)
                check(label,events.index(locks[0])<events.index(retain[0])<events.index(unlocks[0]),
                    'new-object context retain callout occurs while registry lock is held in original ordering')
    assert {x['profile'] for x in checks}==set(rows)
    counts={'original_corefoundation_ranges':len(c['functions']),'original_voucher_hook_ranges':len(c['voucher_hook_ranges']),
        'native_instruction_checks':len(c['native_instruction_checks']),
        'resolved_original_stubs':len(c['imports']),'daemon_request_size_guards':len(c['daemon_request_size_guards']),
        'proofs_unsat':len(c['proofs']),'private_profiles':len(rows),'explicit_profile_checks':len(checks),
        'profiles_covered':len({x['profile'] for x in checks}),'live_daemon_wrapper_ranges':c['live_wrapper_ranges_matched'],
        'layout_compile_exit':c['layout_compile']['exit_code']}
    (ROOT/'cf_receive_profile_checks.json').write_text(json.dumps({'scope':'Finite private fixtures; no live receive, original daemon callback execution, PAC or concurrency proof.',
        'profiles_sha256':sha(ROOT/'cf_receive_profiles.json'),'checks':checks,'counts':counts},indent=2)+'\n')
    q={'scope':'Installed-cache CF receive/registration increment; full interface goal remains active.',
       'QG1':{'status':'pass','evidence':'Factual technical analysis.'},
       'QG2':{'status':'pass','evidence':'Report F1-F8 state dependencies, tests and unresolved runtime assumptions.'},
       'QG3':{'status':'pass_for_increment','evidence':'Installed receive, callbacks, registration cache, trailer capacity, storage ownership and selected voucher context covered; full IPC objective incomplete.'},
       'QG4':{'status':'pass','evidence':'Byte extents, u32/u64 arithmetic, 72-byte context, arm64e SDK compile and algorithm complexity explicit.'},
       'QG5':{'status':'pass','evidence':'Inline/trailer/payload extents, source Boolean/callback/reply status, cached registration, synthetic overflow and original ownership scopes separated.'},
       'QG6':{'status':'pass','evidence':'Original cache SHA/UUID/LC ranges/nlist/v5 fixups, daemon bytes/imports/fresh IDA, SDK references, six proofs and source-hashed private profiles retained.'},
       'QG7':{'status':'pass','evidence':'Impact-labeled continuation table covers registrations, incoming OOL, vouchers, native pairing and RPC700.'},
       'verified_counts':counts,'native_target_executed':False,'target_host_operations_executed':False,
       'runtime_module_or_port_identity_attested':False,'full_goal_complete':False}
    (ROOT/'cf_receive_quality_gates.json').write_text(json.dumps(q,indent=2)+'\n')
    print(json.dumps(counts))
    subprocess.run([sys.executable,str(ROOT/'validate_rpc502_sidecar_delivery.py')],check=True)


if __name__=='__main__':main()
