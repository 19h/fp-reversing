#!/usr/bin/env python3
"""Re-extract original namespace contracts, check private profiles and manifest.

O(B+I+E) time/space, excluding solver complexity. No target host operation.
"""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
from kernel_native_reader import Kernel
from probe_kernel_namespace import OBJ,OLD,DEST,THREAD,RIGHTS,NAME,TS,SMR

ROOT=Path(__file__).resolve().parent


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    subprocess.run([sys.executable,str(ROOT/'recover_kernel_namespace.py')],check=True)
    c=json.loads((ROOT/'kernel_namespace_contracts.json').read_text())
    p=json.loads((ROOT/'kernel_namespace_profiles.json').read_text())
    assert p['generator_sha256']==sha(ROOT/'probe_kernel_namespace.py')
    assert p['reader_sha256']==sha(ROOT/'kernel_native_reader.py') and p['source_sha256']==c['source']['sha256']
    rows={r['label']:r for r in p['profiles']};assert len(rows)==93
    k=Kernel();hashes={}
    for r in p['profiles']:
        key=tuple(r['source_code_pages'])
        if key not in hashes:
            h=hashlib.sha256()
            for a in key:
                a=int(a,16);h.update(struct.pack('<Q',a));h.update(k.read(a,4096))
            hashes[key]=h.hexdigest()
        assert hashes[key]==r['source_code_pages_sha256'] and r['steps']<p['instruction_limit_per_profile']
        assert not r['native_target_executed'] and not r['target_host_operations_executed']
    checks=[]
    def row(label):return rows[label]
    def ev(label,kind):return [e for e in row(label)['events'] if e['kind']==kind]
    def result(label):
        r=row(label);assert r['stop_reason']=='returned',label
        return int(r['events'][-1]['x0'],16)
    def check(label,condition,meaning):
        assert condition,(label,meaning,row(label)['final'])
        checks.append({'profile':label,'check':meaning,'result':'pass'})
    # Every lookup case tests status, output definedness, lock state and the
    # protected-section cleanup, not just one return value.
    for label,r in rows.items():
        if r['kind']!='lookup':continue
        seed=r['seed'];f=r['final'];status=0
        if label.startswith('lookup_name_'):status=15
        if label in ('lookup_inactive','lookup_after_lock_null_table'):status=16
        if label in ('lookup_null_object','lookup_lock_fail','lookup_no_rights',
            'lookup_after_lock_growth_changed','lookup_after_lock_changed_object',
            'lookup_after_lock_clear_rights','lookup_after_lock_change_generation'):status=15
        check(label,result(label)==status,'native lookup status for name/generation/table/lock interleaving')
        if status==0:
            check(label,f['out_object']==hex(OBJ) and int(f['out_bits'],16)==seed.get('bits',RIGHTS) and f['locked_objects']==[hex(OBJ)],
                  'success publishes locked object and capability bits without adding an object reference')
        else:
            early=seed.get('name',NAME)<=255
            check(label,f['out_object']==('0x0' if early else '0xbadcafe') and f['out_bits']==('0x0' if early else '0xdeadbeef') and not f['locked_objects'],
                  'only index-zero rejection clears caller outputs; entered failures leave seeds unchanged and unlock')
        check(label,f['object_refs']==2 and f['preemption_count']==seed.get('initial_preemption_count',0) and int(f['smr_slot'],16)==0,
              'lookup balances protected-section counter/slot and does not retain object')
    label='lookup_cpu_slot';writes=ev(label,'native_private_write')
    check(label,[(e['address'],e['value']) for e in writes if int(e['address'],16)==SMR+128]==[(hex(SMR+128),'0x100'),(hex(SMR+128),'0x0')],
          'native SMR slot selection uses CPU index times128 bytes')
    label='lookup_ast_exit';check(label,any(e.get('address')=='0xfffffe000be8663c' for e in ev(label,'private_helper')),'last preemption-counter exit observes pending-work helper')
    for label,r in rows.items():
        if r['kind'] not in ('mqueue','mqueue_then_release'):continue
        if label=='mqueue_zero_refs':
            check(label,r['stop_reason']=='reference_failure_boundary','reference increment guard catches zero old count');continue
        success=not r['seed'].get('null_table') and bool(r['seed'].get('bits',RIGHTS)&0xa0000)
        if r['kind']=='mqueue_then_release':
            mid=r['phase_snapshots'][0]
            check(label,r['stop_reason']=='receive_reference_release_boundary' and mid['object_refs']==3 and r['final']['object_refs']==2,
                  'original receive-name increment and receive-results decrement balance in paired private phases');continue
        check(label,result(label)==(0 if success else 0x10004002),'receive-name lookup accepts RECEIVE or PORT_SET and maps errors')
        check(label,r['final']['object_refs']==(3 if success else 2) and r['final']['out_object']==(hex(OBJ) if success else '0xbadcafe') and not r['final']['locked_objects'],
              'receive wrapper retains/unlocks/publishes only on success')
        guard=any(e.get('address')=='0xfffffe000c629ba0' for e in ev(label,'private_helper'))
        want_guard=not success and not r['seed'].get('null_table') and not r['seed'].get('bits',RIGHTS)&0x200000
        check(label,guard==want_guard,'EX_RECEIVE bit suppresses selected guard callback; guard effect is modeled')
    for label,r in rows.items():
        if r['kind']!='translate':continue
        right=r['seed']['right'];present=label.endswith('_present') and right<=4
        check(label,result(label)==(0 if present else 17),'generic translation checks requested capability bit and right<=4')
        check(label,r['final']['object_refs']==2 and r['final']['out_object']==(hex(OBJ) if present else '0xbadcafe') and bool(r['final']['locked_objects'])==present,
              'successful translation returns locked object without acquiring reference; rejected bit unlocks')
        if right==5:check(label,not ev(label,'private_trylock'),'invalid translation selector rejected before namespace lookup')
    for label,r in rows.items():
        if r['kind'] not in ('link','link_then_adjust'):continue
        if label=='link_reference_failure':check(label,r['stop_reason']=='reference_failure_boundary','destination retain guard reached before link publication');continue
        seed=r['seed'];initial=r['initial'];f=r['final'];linked=seed.get('type',11)==11 and seed.get('state',0)==0 and seed.get('inheritor',0)==0
        if r['kind']=='link_then_adjust':
            mid=r['phase_snapshots'][0];state=0 if seed.get('adjust_flags')==1 else 4
            check(label,mid['dest_refs']==6 and mid['turnstile_count']==2 and mid['inheritor']==hex(DEST) and int(mid['flags'],16)&0x7000==0x1000,
                  'link phase adds separate destination object and turnstile holds')
            check(label,f['dest_refs']==5 and f['turnstile_count']==1 and f['inheritor']=='0x0' and int(f['flags'],16)&0x7000==state<<12,
                  'unlink/reset phase releases both holds and selects NO_LINKAGE or ANY')
            check(label,f['owner']==(hex(THREAD) if state==0 else '0x0'),'UNLINK_THREAD clears owner while ALLOW_SYNC_LINKAGE preserves it')
            if state==4:check(label,f['diagnostic_pid']==4242,'unlink-to-NO_LINKAGE stores modeled current PID')
            continue
        check(label,result(label)>=0 and f['dest_refs']==initial['dest_refs']+int(linked),
              'new linkage retains destination; skipped linkage acquires no object hold')
        if linked:
            check(label,f['inheritor']==hex(DEST) and int(f['flags'],16)&0x7000==0x1000,'ANY/null special reply publishes signed inheritor and PORT state')
            check(label,f['turnstile_count']==(1 if seed.get('turnstile_count')==0 else 2),'link keeps prepared turnstile reference')
        else:check(label,f['inheritor']==initial['inheritor'] and f['turnstile_count']==initial['turnstile_count'],'skipped link completes temporary turnstile prepare and preserves union')
        if seed.get('bootstrap'):check(label,int(f['flags'],16)&0x8000!=0,'bootstrap-checkin bit set on special reply path')
        if seed.get('group_tracking'):check(label,int(f['thread_flags'],16)&0x2000!=0 and any(e.get('address')=='0xfffffe000be81ebc' for e in ev(label,'private_helper')),'blocked-group callout marker set on selected path')
    for label,r in rows.items():
        if r['kind']!='adjust':continue
        f=r['final'];seed=r['seed'];state=seed.get('state',0);flags=seed.get('adjust_flags',4)
        final_state=0 if flags in (1,0x20) or state==0 else 4
        check(label,int(f['flags'],16)&0x7000==final_state<<12 and f['inheritor']=='0x0','selected adjustment clears state union and writes expected state')
        check(label,f['owner']==('0x0' if flags&4 else hex(THREAD)),'owner clearing is controlled by UNLINK_THREAD flag')
        if state==1:check(label,f['dest_refs']==4 and f['turnstile_count']==0,'PORT-state unlink drops object and turnstile holds')
        if label=='adjust_allow_state_4':check(label,f['diagnostic_pid']==0,'NO_LINKAGE-to-ANY clears stashed PID')
        if label=='adjust_unlink_stash':check(label,any(e.get('address')=='0xfffffe000bd683e0' and e['args'][0]==hex(TS) for e in ev(label,'private_helper')),'WORKLOOP_STASH unlink deallocates held turnstile through modeled helper')
        if flags==0x20:check(label,int(f['flags'],16)&0x8000==0,'RESET_BOOTSTRAP_CHECKIN clears bit15')
    for label,r in rows.items():
        if r['kind']!='user_reply':continue
        fail=bool(r['seed'].get('allocation_error'));f=r['final']
        check(label,result(label)==(0 if fail else NAME) and f['user_reply']==('0x0' if fail else hex(OBJ)),
              'user special-reply allocation failure returns null and does not restore old binding')
        check(label,f['kernel_reply']=='0x0','user trap does not populate kernel reply slot')
        if not fail:check(label,f['object_refs']==2 and f['owner']==hex(THREAD),'user binding adds one object reference and publishes owner')
        if r['seed'].get('old_binding'):
            old=r['seed'].get('old_refs',3)
            check(label,f['old_refs']==old-1 and f['old_owner']=='0x0','old user binding clears owner and releases one object reference')
            events=r['events'];alloc=next(i for i,e in enumerate(events) if e['kind']=='private_port_alloc')
            clear=next(i for i,e in enumerate(events) if e['kind']=='native_private_write' and e['address']==hex(THREAD+0x450) and e['value']=='0x0')
            check(label,clear<alloc,'old binding cleared before new allocation is attempted')
    label='kernel_reply_new';f=row(label)['final']
    check(label,result(label)==0 and f['kernel_reply']==hex(OBJ) and f['user_reply']=='0x0' and f['object_refs']==1,'kernel binding adds thread hold then drops initializer hold in explicit initial-ref1 fixture')
    for label in ('kernel_reply_unbind','kernel_reply_unbind_linked'):
        r=row(label);check(label,r['stop_reason']=='native_port_destroy_boundary' and r['final']['kernel_reply']=='0x0' and r['final']['owner']=='0x0','kernel unbind clears field/owner then reaches destruction with port locked')
    for count in (1,2):
        label=f'turnstile_complete_{count}';f=row(label)['final']
        check(label,f['turnstile_count']==count-1,'native turnstile primary count decremented')
        check(label,bool(ev(label,'private_turnstile_complete'))==(count==1),'last primary count enters modeled final completion')
    for label,want in [('native_lock_guard_port',1),('native_lock_guard_pset',1),('native_lock_guard_lock_failure',0)]:check(label,result(label)==want,'native lock wrapper checks port/pset metadata around modeled lock result')
    for label in ('native_lock_guard_bad_zone','native_lock_guard_pset_zone_mismatch'):check(label,row(label)['stop_reason']=='zone_failure_boundary','metadata mismatch enters fail-stop zone-validation boundary')
    for refs in (0,1,2):
        label=f'receive_release_{refs}';r=row(label)
        check(label,r['stop_reason']==('reference_failure_boundary' if refs==0 else 'receive_reference_release_boundary'),'receive-results release underflow/ordinary boundary')
        if refs:check(label,r['final']['object_refs']==refs-1,'native receive-results atomic decrement')
    assert {x['profile'] for x in checks}==set(rows)
    counts={'original_ranges':len(c['functions']),'native_instruction_checks':len(c['native_instruction_checks']),
        'proofs_unsat':len(c['proofs']),'private_profiles':len(rows),'explicit_profile_checks':len(checks),
        'profiles_covered':len({x['profile'] for x in checks}),'layout_compile_exit':c['layout_compile']['exit_code']}
    (ROOT/'kernel_namespace_profile_checks.json').write_text(json.dumps({'scope':'Finite private fixtures only; no native concurrency/PAC/port identity attestation.',
        'profiles_sha256':sha(ROOT/'kernel_namespace_profiles.json'),'checks':checks,'counts':counts},indent=2)+'\n')
    q={'scope':'Namespace and reply-link increment; full goal remains active.',
       'QG1':{'status':'pass','evidence':'Factual technical analysis.'},
       'QG2':{'status':'pass','evidence':'Report N1-N7 include dependencies, probes and status.'},
       'QG3':{'status':'pass_for_increment','evidence':'Native lookup, selected rights/refs, reply binding/linking/unlinking and receive ref release covered; wider IPC/lifecycle remains open.'},
       'QG4':{'status':'pass','evidence':'u32 generation/rights, u64 encoded arrays,24-byte entries,128-byte CPU slots, reference arithmetic and partial compiled layouts explicit.'},
       'QG5':{'status':'pass','evidence':'Namespace names/objects, lookup locks/retains, message/object/turnstile references, user/kernel lifetimes and native/model effects separated.'},
       'QG6':{'status':'pass','evidence':'Original SHA/UUID/compiler ranges/words, source URLs/hashes, six proofs and93 source-hashed private profiles.'},
       'QG7':{'status':'pass','evidence':'Impact-labeled continuation includes namespace writes, actual objects, full locking/PAC, destruction, workloops and control effects.'},
       'verified_counts':counts,'native_target_executed':False,'target_host_operations_executed':False,
       'runtime_pac_or_concurrency_attested':False,'full_goal_complete':False}
    (ROOT/'kernel_namespace_quality_gates.json').write_text(json.dumps(q,indent=2)+'\n')
    print(json.dumps(counts))
    subprocess.run([sys.executable,str(ROOT/'validate_rpc502_sidecar_delivery.py')],check=True)


if __name__=='__main__':main()
