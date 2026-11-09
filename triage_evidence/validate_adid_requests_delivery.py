#!/usr/bin/env python3
"""Independent readback of request persistence source, predicates and cases.

Fresh files, dyld_info, clang, bounded SMT and private replay only.
O(B+F+R+V) time/space; a finite source-hook cap applies to each replay.
No native target, endpoint, file, environment or synchronization operation.
"""
import base64
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import zlib
from adid_reader import Adid,ROOT,CS,sha,SOURCE,FIXUPS,THIN_SHA
from probe_adid_startup import unpack_records
from probe_adid_requests import Request


def read(name):return json.loads((ROOT/name).read_text())


def main():
    checks=[]
    def check(condition,description):
        assert condition,description
        checks.append(description)
    s=Adid();p=read('adid_request_profiles.json');c=read('adid_request_contracts.json');rows={r['fixture']['label']:r for r in p['profiles']};events={k:unpack_records(v) for k,v in rows.items()}
    check(p['thin_sha256']==c['thin_sha256']==THIN_SHA,'fresh original provider identity')
    check(p['generator_sha256']==sha((ROOT/'probe_adid_requests.py').read_bytes()) and c['generator_sha256']==sha((ROOT/'recover_adid_requests.py').read_bytes()),'producer/static source pins')
    for source in (p,c):
        for name,digest in source['dependencies'].items():check(sha((ROOT/name).read_bytes())==digest,'dependency '+name)
    run=subprocess.run(['/usr/bin/dyld_info','-arch','arm64e','-fixups',str(SOURCE)],capture_output=True,check=True);check(run.stdout==FIXUPS.read_bytes(),'fresh independent pointer-tool output')
    instruction_bytes={}
    for ins in p['original_instruction_records']:
        pc=int(ins['ea'],16);raw=s.read(pc,4);actual=next(CS.disasm(raw,pc));instruction_bytes[pc]=raw
        check(raw.hex()==ins['bytes'] and actual.mnemonic==ins['mnemonic'] and actual.op_str==ins['operands'],'fresh source instruction '+ins['ea'])
    for f in p['original_functions']:
        a,z=int(f['start'],16),int(f['end'],16);check(s.bounds(a)==(a,z) and sha(s.read(a,z-a))==f['sha256'],'compiler range '+f['start'])
    for w in c['original_windows']:
        a=int(w['start'],16);raw=s.read(a,int(w['end'],16)-a);check(raw.hex()==w['bytes'] and sha(raw)==w['sha256'],'static predicate window '+w['start'])
    for ptr in c['source_import_pointers']+[b['pointer'] for b in c['mode_branch_pointers']]:check(s.decoded[int(ptr['address'],16)]==ptr,'fresh chained pointer '+ptr['address'])
    for proof in c['proofs']:
        path=ROOT/proof['path'];check(sha(path.read_bytes())==proof['sha256'],'proof pin '+proof['path']);run=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True)
        check(run.stdout.strip()=='unsat' and not run.stderr,'fresh full-domain local proof '+proof['path'])
    reference=c['filesystem_reference'];a=int(reference['reference_address'],16);check(s.read(a,16).hex()==reference['source_bytes'] and bytes(v^4 for v in s.read(a,4))==b'nfs\0','original encoded nfs reference')
    total=0;api_count=0
    symbols={im['name']:0x7c000000+im['ordinal']*256 for im in s.imports}
    for label,row in rows.items():
        raw=zlib.decompress(base64.b64decode(row['visited_original_instructions_zlib_base64']));check(len(raw)==row['visited_original_instruction_count']*8,'packed visit extent '+label);h=hashlib.sha256()
        for (pc,) in struct.iter_unpack('<Q',raw):
            h.update(struct.pack('<Q',pc));h.update(instruction_bytes[pc])
        total+=row['visited_original_instruction_count'];check(h.hexdigest()==row['ordered_original_instruction_sha256'],'complete ordered source bytes '+label)
        check(row['steps']<=row['fixture']['instruction_budget']+1,'finite hook cap '+label)
        payload=bytes.fromhex(row['fixture']['payload_hex']);check(struct.unpack('>IIIqQ',payload)==(1,0x632b8d6e,1,row['fixture']['selector_signed64'],row['fixture']['argument_u64']),'exact BE request fields '+label)
        edge=None
        for e in events[label]:
            if e['kind']=='PAC_bypassed_edge':edge=e
            if e.get('name') in symbols and 'API' in e['kind']:
                api_count+=1;check(not e['native_API_executed'],'explicit private API scope '+label+' '+e['name'])
                if 'callsite' in e:
                    check(edge is not None and edge['pc']==e['callsite'] and int(edge['target'],16)==symbols[e['name']],'source call target,site and symbol '+label+' '+e['name'])
            if e['kind']=='original_filesystem_reference':check(s.read(int(e['reference_address'],16),16).hex()==e['source_bytes'],'fresh loop reference bytes '+label)
    def ev(label,name=None,kind=None):return [e for e in events[label] if (name is None or e.get('name')==name) and (kind is None or e['kind']==kind)]
    prefixes=ev('statfs_selector_-8',kind='original_persistence_predicate')
    check(c['mode_prefix'] in prefixes and int(c['mode_prefix']['registers']['w9'],16)==0x1b6,'captured mode-mask prefix matches proof constant')
    fr=c['type_fold_prefix']['registers'];check(c['type_fold_prefix'] in prefixes and (int(fr['w22'],16)-0x1ac9)&31==c['type_fold_shift_low5']==1 and int(fr['w9'],16)==0xfbf9d5cf and int(fr['w11'],16)==0xf7f3ab9e,'captured full32 fold constants and source-derived shift match local proof')
    bag='/var/db/fpsd/adi/adi-gb';lock=bag+'.lck';selectors=(-8,-6,-5,-4,-3,-2)
    for selector in selectors:
        for value in (0,265,0x7b000100):
            label=f'selector_{selector}_argument_{value:016x}';last=events[label][-1]
            check(rows[label]['stop_reason']=='startup_unknown_stat_path_guard' and last['path']==bag and last['callsite']=='0x100110474','common first persistence boundary '+label)
        label='locked_selector_'+str(selector);opens=ev(label,'_open');lc=ev(label,'_lockf')[0];stat=ev(label,'_statfs')[0];gp=ev(label,'_fcntl')[0]
        check(opens[0]['path']==lock and opens[0]['flags_u32']==0x1000201 and int(opens[0]['first_variadic_stack_u64'],16)&0xffffffff==0o666,'original lock open and stack mode '+label)
        check(ev(label,'_fstat')[0]['callsite']=='0x10010cd5c' and ev(label,'_fchmod')[0]['mode_u32']==0o666,'lock descriptor metadata and normalization '+label)
        check(gp['command_u32']==50 and bytes.fromhex(gp['returned_path_bytes'])==lock.encode()+b'\0' and stat['path']==lock,'F_GETPATH output feeds statfs '+label)
        check(lc['command_u32']==1 and lc['extent_u64']==0 and lc['callsite']=='0x10010d3ec' and rows[label]['lock_model_final']['73']['locked'],'source exclusive lock request under explicit success model '+label)
        check(events[label][-1]['path']=='/Users/Shared/adi/adi-00000000.pb','common subsequent record path '+label)
        label=f'setup_selector_{selector}_status_0';core=ev(label,kind='original_core_record_return')[0];payload=ev(label,'_xpc_dictionary_set_data')[0]
        check(rows[label]['stop_reason']=='returned_to_private_fixture' and core['status_u32']==0 and core['output_length_u64']==4 and payload['payload_bytes']=='ffff501f','wrapper success and BE payload error remain distinct '+label)
        check(ev(label,'_xpc_dictionary_send_reply')[0]['callsite']=='0x1000aaa70','source reply emission '+label)
        unlocks=ev(label,'_lockf');check([(e['command_u32'],e['callsite']) for e in unlocks]==[(1,'0x10010d3ec'),(0,'0x1001239e8')] and ev(label,'_close')[0]['callsite']=='0x100123ac4','observed lock/unlock/close sites '+label)
        check(not rows[label]['open_descriptors_final'] and not rows[label]['lock_model_final'] and rows[label]['umask_model_final']==0x12,'finite completed request retires private lock descriptor and restores mask '+label)
        for status in (0,-1):
            label=f'setup_fallback_selector_{selector}_status_{status}'
            check(ev(label,'_lstat')[-2]['path']=='/var/setup/.AppleSetupUser' and ev(label,'_xpc_dictionary_set_data')[0]['payload_bytes']=='ffff501f' and rows[label]['stop_reason']=='returned_to_private_fixture','both fallback marker outcomes reach same finite payload error '+label)
        label='setup_no_markers_errno_zero_'+str(selector)
        check(rows[label]['stop_reason']=='returned_to_private_fixture' and ev(label,'_xpc_dictionary_set_data')[0]['payload_bytes']=='ffff501f','absent markers with zero initial errno still reach recorded error '+label)
    for label in ('counterfactual_selector_-9','counterfactual_selector_-7','counterfactual_selector_-1','counterfactual_selector_0','counterfactual_selector_1','counterfactual_selector_4294967288'):
        check(events[label][-1]['path']==bag,'counterfactual selector only shares retained prefix '+label)
    for value in (265,0xffffffff,0x100000000,0x7b000100):
        label='locked_argument_'+hex(value);check(events[label][-1]['path']=='/Users/Shared/adi/adi-00000000.pb','opaque u64 variant does not change observed record path '+label)
    check(not ev('statfs_type_nfs','_lockf') and ev('statfs_type_nfs','_statfs')[0]['filesystem_type']=='nfs','NFS match bypasses observed acquisition call')
    for label in ('statfs_selector_-8','statfs_type_hfs','statfs_type_smbfs'):check(ev(label,'_lockf')[0]['callsite']=='0x10010d3ec','nonmatching type reaches lock acquisition boundary '+label)
    for mode in (0o100666,0o100777):check(not ev('lock_mode_'+oct(mode),'_fchmod'),'mode containing requested bits skips normalization '+oct(mode))
    check(ev('lock_mode_0o100640','_fchmod')[0]['mode_u32']==0o666,'mode missing requested bits reaches normalization')
    check(ev('lock_open_fd_zero','_fstat')[0]['fd_signed32']==0 and ev('lock_open_fd_zero','_lockf')[0]['fd_signed32']==0,'descriptor zero remains a valid private lock descriptor')
    check(not ev('lock_open_failure','_fstat') and not ev('lock_open_failure','_lockf') and not rows['lock_open_failure']['open_descriptors_final'],'failed open avoids descriptor-dependent calls')
    check(not ev('getpath_failure','_statfs') and not ev('getpath_failure','_lockf'),'failed getpath avoids filesystem query and lock in retained continuation')
    check(not ev('statfs_failure','_lockf'),'failed statfs avoids observed lock acquisition')
    calls=ev('lockf_EINTR_then_success','_lockf');check([(e['callsite'],e['result']) for e in calls]==[('0x10010d3ec','-0x1'),('0x10010e480','0x0')],'EINTR fixture retries at distinct original site')
    check(len(ev('lockf_EACCES','_lockf'))==1 and not rows['lockf_EACCES']['lock_model_final'],'EACCES fixture does not acquire or take EINTR retry')
    check(rows['initial_errno_zero']['steps']==rows['initial_errno_EACCES']['steps'] and rows['initial_errno_zero']['steps']!=rows['locked_selector_-8']['steps'],'persistent errno value changes observed common continuation')
    # Independent source replay plus exact event and mutable-model readback.
    replay_steps=0
    for label in ('setup_selector_-8_status_0','statfs_type_nfs','lockf_EINTR_then_success'):
        fixture=json.loads(json.dumps(rows[label]['fixture']));fixture['label']='independent_'+label;probe=Request(s,fixture,read('adid_peer_checkpoint.json'));actual=probe.run_continuation();replay_steps+=actual['steps']
        check(actual['ordered_original_instruction_sha256']==rows[label]['ordered_original_instruction_sha256'] and actual['stop_reason']==rows[label]['stop_reason'] and actual['result_u32']==rows[label]['result_u32'],'independent complete instruction stream/result '+label)
        check(unpack_records(actual)==events[label] and actual['filesystem_model_final']==rows[label]['filesystem_model_final'] and json.loads(json.dumps(actual['open_descriptors_final']))==rows[label]['open_descriptors_final'] and json.loads(json.dumps(probe.lock_models))==rows[label]['lock_model_final'] and probe.umask_value==rows[label]['umask_model_final'],'independent events and mutable models '+label)
    counts={'private_cases':len(rows),'original_instruction_records':len(instruction_bytes),'original_compiler_ranges':len(p['original_functions']),'retained_original_visits':total,'source_API_boundaries':api_count,'SMT_unsat':len(c['proofs'])}
    layout=c['SDK_compile'];check(sha((ROOT/'adid_request_layouts.c').read_bytes())==layout['source_sha256'] and sha((ROOT/'adid_request_layouts.s').read_bytes())==layout['assembly_sha256'],'SDK analyst source/assembly pins')
    with tempfile.TemporaryDirectory() as directory:
        out=Path(directory)/'layout.s';run=subprocess.run(layout['command'][:-1]+[str(out)],capture_output=True,text=True)
        check(run.returncode==0 and not run.stderr and out.read_bytes()==(ROOT/'adid_request_layouts.s').read_bytes(),'fresh arm64e SDK structure,flags,lock and variadic compile')
    for header in c['SDK_headers']:check(sha(Path(header['path']).read_bytes())==header['sha256'],'SDK primary source '+header['path'])
    for row in read('interface_manifest.json')['inputs_preserved']:
        path=ROOT.parent/row['path'];check(path.stat().st_size==row['size_bytes'] and sha(path.read_bytes())==row['sha256'],'original supplied input preserved '+row['path'])
    counts.update({'independent_private_replay_steps':replay_steps,'independent_private_replays':3,'SDK_compile_exit':run.returncode,'assertions':len(checks)})
    (ROOT/'adid_request_checks.json').write_text(json.dumps({'scope':__doc__,'verified_counts':counts,'checks':checks,'all_checks_pass':True,'native_target_executed':False,'full_goal_complete':False},indent=2)+'\n')
    quality={'scope':'Shared request persistence,filesystem-type/permission predicates,lock/retry/release,setup-marker control and emitted payload errors only. Broad goal active.','verified_counts':counts,'native_target_executed':False,'full_goal_complete':False}
    for n,evidence in [(1,'Descriptive technical findings.'),(2,'Report R1-R7 retain assumptions,dependent results and falsification probes.'),(3,'Concrete external filesystem,IPC response and source-control progress;full goal incomplete.'),
        (4,'Byte extents,integer widths,BE payload,variadic stack ABI,SDK layouts and four local full-domain proofs explicit.'),(5,'Errno persistence,descriptor zero,permission superset,NFS versus other fixtures,retry versus nonretry,wrapper versus payload status and native ownership are distinct.'),
        (6,'Fresh original instruction/function/chain/reference/SDK readback and three source replays agree.'),(7,'Impact-labeled selector,opaque-field,record/provider,errno,filesystem identity and concurrency continuation.')]:quality['QG'+str(n)]={'status':'pass_for_stated_increment','evidence':evidence}
    (ROOT/'adid_request_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps(counts))


if __name__=='__main__':main()
