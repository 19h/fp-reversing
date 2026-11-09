#!/usr/bin/env python3
"""Independent readback of context, setup identity, status and state-sequence evidence.

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
from probe_adid_context import Context
from probe_adid_receiver import DONE,HEAP
from unicorn import arm64_const as A


def read(name):return json.loads((ROOT/name).read_text())


def main():
    checks=[]
    def check(condition,description):
        assert condition,description
        checks.append(description)
    s=Adid();p=read('adid_context_profiles.json');c=read('adid_context_contracts.json');rows={r['fixture']['label']:r for r in p['profiles']};events={k:unpack_records(v) for k,v in rows.items()}
    check(p['thin_sha256']==c['thin_sha256']==THIN_SHA,'fresh original provider identity')
    check(p['generator_sha256']==sha((ROOT/'probe_adid_context.py').read_bytes()) and c['generator_sha256']==sha((ROOT/'recover_adid_context.py').read_bytes()),'producer/static source pins')
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
    for ptr in c['source_import_pointers']+[b['pointer'] for b in c['cleanup_branch_pointers']]:check(s.decoded[int(ptr['address'],16)]==ptr,'fresh chained pointer '+ptr['address'])
    for proof in c['proofs']:
        path=ROOT/proof['path'];check(sha(path.read_bytes())==proof['sha256'],'proof pin '+proof['path']);run=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True)
        check(run.stdout.strip()=='unsat' and not run.stderr,'fresh full-domain local proof '+proof['path'])
    total=0;api_count=0
    symbols={im['name']:0x7c000000+im['ordinal']*256 for im in s.imports}
    for label,row in rows.items():
        raw=zlib.decompress(base64.b64decode(row['visited_original_instructions_zlib_base64']));check(len(raw)==row['visited_original_instruction_count']*8,'packed visit extent '+label);h=hashlib.sha256()
        for (pc,) in struct.iter_unpack('<Q',raw):
            h.update(struct.pack('<Q',pc));h.update(instruction_bytes[pc])
        total+=row['visited_original_instruction_count'];check(h.hexdigest()==row['ordered_original_instruction_sha256'],'complete ordered source bytes '+label)
        check(not str(row['stop_reason']).startswith('private_guest_exception:'),'no diagnostic/emulator exception in retained final case '+label)
        check(row['steps']<=row['fixture']['instruction_budget']+1,'finite hook cap '+label)
        payload=bytes.fromhex(row['fixture']['payload_hex']);check(struct.unpack('>IIIqQ',payload)[3:]==(row['fixture']['selector_signed64'],row['fixture']['argument_u64']),'exact BE request fields '+label)
        edge=None
        for e in events[label]:
            if e['kind']=='PAC_bypassed_edge':edge=e
            if e.get('name') in symbols and 'native_API_executed' in e:
                api_count+=1;check(not e['native_API_executed'],'explicit private API scope '+label+' '+e['name'])
                if 'callsite' in e:
                    check(edge is not None and edge['pc']==e['callsite'] and int(edge['target'],16)==symbols[e['name']],'source call target,site and symbol '+label+' '+e['name'])
            if e['kind']=='original_filesystem_reference':check(s.read(int(e['reference_address'],16),16).hex()==e['source_bytes'],'fresh loop reference bytes '+label)
    def ev(label,name=None,kind=None):return [e for e in events[label] if (name is None or e.get('name')==name) and (kind is None or e['kind']==kind)]
    def boundary(label,pc):return [e for e in ev(label,kind='original_context_boundary') if e['pc']==hex(pc)]
    for prefix,key in [('header_prefix',0x10016a800),('serializer_prefix',0x10021b8d0),('selector_prefix',0x1001ca3fc),('cleanup_prefix',0x10021abe8)]:
        check(c[prefix] in boundary('context_error_producer',key),'captured proof prefix '+prefix)
    for row in rows.values():
        label=row['fixture']['label'];payload=bytes.fromhex(row['fixture']['payload_hex'])
        for index,e in enumerate(boundary(label,0x10016a800)):
            r=e['registers'];check([int(r[k],16) for k in ('x7','x19','x20')]==[0xf577f73e,0xeaefee7c,0xacedfe8] and int(r['x9'],16)==struct.unpack_from('>I',payload,index*4)[0],'BE32 source operand and prefix '+label+' '+str(index))
        for index,e in enumerate(boundary(label,0x1001af170)):
            r=e['registers'];raw=struct.unpack_from('>Q',payload,12+8*index)[0];actual=(int(r['x9'],16)-int(r['x13'],16))&((1<<64)-1)
            check(actual==(raw^0xda8ca8cae5dfbd2d),'BE64 original argument fold '+label+' '+str(index))
    for prefix,expected,count in [('header_word0_', 'ffff5026',4),('header_word2_', 'ffff5024',12)]:
        for label in rows:
            if not label.startswith(prefix) or label.startswith('header_word0_1_'):continue
            check(ev(label,'_xpc_dictionary_set_data')[0]['payload_bytes']==expected and len(ev(label,kind='original_payload_read'))==count and not ev(label,'_lstat'),'specific early header rejection '+label)
    for label in ('header_word0_1_magic_00000000','header_word0_1_magic_632b8d6f'):
        check(ev(label,'_xpc_dictionary_set_data')[0]['payload_bytes']=='ffff5025' and not ev(label,'_lstat'),'magic rejection '+label)
    for uid in (265,501):
        label=f'nonroot_{uid}_markers_-1_-1';last=events[label][-1]
        check(last['path']==f'/Users/Shared/adi/adi-{uid:08X}.pb','audit EUID feeds hexadecimal record path '+str(uid))
        token=ev(label,'_xpc_dictionary_get_audit_token')[0]['audit_words'];check(token[1]==uid and rows[label]['fixture']['audit_euid_result']==uid,'consistent explicit audit identity '+str(uid))
        label='nonroot_ready_record_'+str(uid);check(ev(label,'_xpc_dictionary_set_data')[0]['payload_bytes']=='ffff501f','ready per-user record still reaches finite error '+str(uid))
    for base,path in [('db','/var/db'),('setup','/var/setup')]:
        label='nonroot_setup_parent_'+base+'_empty_dictionary';data=ev(label,'_CFDataCreateWithBytesNoCopy')[0];parse=ev(label,'_CFPropertyListCreateWithData')[0];lookup=ev(label,'_CFDictionaryGetValue')[0]
        check(data['callsite']=='0x1001061ac' and parse['callsite']=='0x100106248' and parse['args_x0_x7'][2:5]==['0x0','0x0','0x0'] and parse['analyst_parser_value']=={},'original immutable property-list interface '+base)
        check(lookup['callsite']=='0x1001063ac' and lookup['key_string']=='kBuddingRunningForUID' and events[label][-1]['path']=='/Users/Shared/adi/adi-000000F8.pb','missing key retains setup UID path '+base)
        import plistlib
        raw=bytes.fromhex(rows[label]['fixture']['extra_filesystem'][path+'/.AppleSetupUser']['contents_hex']);check(bytes.fromhex(data['data_bytes'])==raw and plistlib.loads(raw)=={},'analyst fixture bytes reach original data wrapper '+base)
    for value,expected in [(265,265),(501,501),(-1,0xffffffff),(0,248)]:
        label='setup_uid_modeled_'+str(value);number=ev(label,'_CFNumberGetValue')[-1]
        check(number['callsite']=='0x100106510' and number['args_x0_x7'][1]=='0x3' and number['initial_output_u32']==248,'SInt32 setup conversion and default '+str(value))
        check(events[label][-1]['path']==f'/Users/Shared/adi/adi-{expected:08X}.pb','setup numeric result selects record path '+str(value))
    for label in ('setup_uid_501_str','setup_uid_True_bool'):
        check(events[label][-1]['path']=='/Users/Shared/adi/adi-000000F8.pb' and len(ev(label,'_CFNumberGetValue'))==1,'wrong type avoids setup numeric conversion '+label)
    check(events['setup_uid_conversion_false_unchanged_output'][-1]['path'].endswith('adi-000000F8.pb') and events['setup_uid_conversion_false_written_output'][-1]['path'].endswith('adi-000001F5.pb'),'explicit false-Boolean cases discriminate output-cell consumption')
    labels=[k for k in rows if k.startswith('full_context_entitlement_')];check(len(labels)==50,'all listed numeric entitlement patterns tested through full context')
    for label in labels:check(ev(label,'_xpc_dictionary_set_data')[0]['payload_bytes']=='ffff501f','listed entitlement final finite result '+label)
    base='context_error_producer';stores=ev(base,kind='original_context_store');status=[e for e in stores if e['pc']=='0x10019c0b4'];check(status and int(status[0]['value'],16)==0x5874ae,'encoded final error cell producer')
    sourcebytes=[e for e in stores if e['pc'] in ('0x1002028a8','0x1002028bc','0x1002028c4','0x1002028d0')];check(len(sourcebytes)==4 and bytes(int(e['value'],16) for e in sorted(sourcebytes,key=lambda e:int(e['address'],16)))==bytes.fromhex('ffff501f'),'original BE serialization stores')
    copies=[e for e in stores if e['pc']=='0x1001fcca8'];check(len(copies)==4 and bytes(int(e['value'],16) for e in sorted(copies,key=lambda e:int(e['address'],16)))==bytes.fromhex('ffff501f'),'original final copy preserves error bytes')
    raw=bytes.fromhex(boundary(base,0x100104e90)[0]['context_record']['bytes64']);addr=int(boundary(base,0x100104e90)[0]['context_record']['address'],16);key=(((addr&0xffffffff)^0x075d910d)*0xd756578d)&0xffffffff
    check(struct.unpack_from('<I',raw,4)[0]^key==0xcf8 and (raw[8]+key)&255==0x62 and (raw[9]+key)&255==0x38,'original address-keyed context prefix decode; remaining fields untyped')
    for index in range(3):check(ev('retained_state_request_'+str(index),'_xpc_dictionary_set_data')[0]['payload_bytes']=='ffff501f','retained-state finite reply '+str(index))
    check(len({rows['retained_state_request_'+str(i)]['ordered_original_instruction_sha256'] for i in range(3)})==3,'three retained requests use different source streams')
    k=c['literal_setup_key'];a=int(k['object_address'],16);chars=int(k['characters_address'],16)
    check(s.read(a,32).hex()==k['object32_bytes'] and s.qword(a+16)==chars and s.read(chars,len(k['characters'])+1).hex()==k['characters_bytes'] and s.cstring(chars)=='kBuddingRunningForUID','fresh original CFString key object and characters')
    account=c['setup_account_declaration'];raw=Path(account['path']).read_bytes();check(sha(raw)==account['sha256'] and account['literal_record'] in raw.decode().splitlines() and account['uid']==248 and account['name']=='_mbsetupuser','installed setup-account declaration,not live identity')
    # Fresh one-case replays and a separate retained-state sequence.
    replay_steps=0
    for label in ('context_error_producer','setup_uid_modeled_501','setup_uid_conversion_false_written_output'):
        probe=Context(s,json.loads(json.dumps(rows[label]['fixture'])),read('adid_peer_checkpoint.json'));actual=probe.run_continuation();replay_steps+=actual['steps']
        check(actual['ordered_original_instruction_sha256']==rows[label]['ordered_original_instruction_sha256'] and unpack_records(actual)==events[label] and actual['stop_reason']==rows[label]['stop_reason'],'independent source/events replay '+label)
    probe=Context(s,json.loads(json.dumps(rows['retained_state_request_0']['fixture'])),read('adid_peer_checkpoint.json'))
    for index in range(3):
        label='retained_state_request_'+str(index)
        if index:
            probe.fixture=json.loads(json.dumps(rows[label]['fixture']));probe.steps=0;probe.reason=None;probe.records=[];probe.visited=[];probe.last_edge=None;probe.context_record=None;probe.bridge_record=None
            probe.u.reg_write(A.UC_ARM64_REG_SP,probe.sp);probe.u.reg_write(A.UC_ARM64_REG_LR,DONE);probe.u.reg_write(A.UC_ARM64_REG_PC,0x100029fc8)
            for j in range(8):probe.u.reg_write(getattr(A,'UC_ARM64_REG_X'+str(j)),[HEAP+0x300,HEAP+0xd100][j] if j<2 else 0)
            probe.previous_status_register=probe.reg('w5');probe.previous_pc=None
        actual=probe.run_continuation();replay_steps+=actual['steps']
        check(actual['ordered_original_instruction_sha256']==rows[label]['ordered_original_instruction_sha256'] and unpack_records(actual)==events[label] and actual['filesystem_model_final']==rows[label]['filesystem_model_final'] and json.loads(json.dumps(actual['open_descriptors_final']))==rows[label]['open_descriptors_final'],'independent retained-state source and mutable-model replay '+str(index))
    layout=c['SDK_compile'];check(sha((ROOT/'adid_context_layouts.c').read_bytes())==layout['source_sha256'] and sha((ROOT/'adid_context_layouts.s').read_bytes())==layout['assembly_sha256'],'SDK declaration and compiler-output pins')
    with tempfile.TemporaryDirectory() as directory:
        out=Path(directory)/'layout.s';run=subprocess.run(layout['command'][:-1]+[str(out)],capture_output=True,text=True);check(run.returncode==0 and not run.stderr and out.read_bytes()==(ROOT/'adid_context_layouts.s').read_bytes(),'fresh arm64e CF ABI compile')
    for h in c['SDK_headers']:check(sha(Path(h['path']).read_bytes())==h['sha256'],'SDK primary declaration '+h['path'])
    for r in read('interface_manifest.json')['inputs_preserved']:
        path=ROOT.parent/r['path'];check(path.stat().st_size==r['size_bytes'] and sha(path.read_bytes())==r['sha256'],'original supplied input preserved '+r['path'])
    counts={'private_cases':len(rows),'original_instruction_records':len(instruction_bytes),'original_compiler_ranges':len(p['original_functions']),'retained_original_visits':total,'source_API_boundaries':api_count,'SMT_unsat':len(c['proofs']),'listed_entitlement_full_context_cases':len(labels),'independent_replay_runs':6,'independent_replay_steps':replay_steps,'SDK_compile_exit':run.returncode,'assertions':len(checks)}
    (ROOT/'adid_context_checks.json').write_text(json.dumps({'scope':__doc__,'verified_counts':counts,'all_checks_pass':True,'checks':checks,'native_target_executed':False,'full_goal_complete':False},indent=2)+'\n')
    quality={'scope':'Header/argument/selector/status codecs,context prefix,setup-marker identity and finite retained-request sequence only; broad goal active.','verified_counts':counts,'native_target_executed':False,'full_goal_complete':False}
    for n,evidence in [(1,'Descriptive technical analysis.'),(2,'Report C1-C8 state assumptions,dependencies and falsification probes.'),(3,'Concrete record/identity/control/data/IPC progress;full objective incomplete.'),(4,'Exact byte widths,five full-domain local obligations,BE reply stores and CF SDK compile.'),(5,'Cleanup byte,error producer,wrapper/payload status,untyped fields,diagnostic failure,native parser/conversion behavior and state sequences separated.'),(6,'Fresh original bytes/chains/literals/SDK/account and six source replays agree.'),(7,'Impact-labeled remaining native pairing,success paths,record schemas,CF ownership,UID/errno/type/concurrency and IOKit continuation.')]:quality['QG'+str(n)]={'status':'pass_for_stated_increment','evidence':evidence}
    (ROOT/'adid_context_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps(counts))


if __name__=='__main__':main()
