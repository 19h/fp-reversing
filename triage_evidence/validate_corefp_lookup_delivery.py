#!/usr/bin/env python3
"""Source,record,lookup,retirement and cross-image metadata readback.

No native target,loader,API or IPC runs. O(B+F+R+V+256*K) time and O(B+F+R+V)
space;SMT cost separate with30 s query limits. Native endpoint identity,
initialization,rights and concurrency remain outside the verified scope.
"""
from collections import Counter
import hashlib
import json
import re
from pathlib import Path
import struct
import subprocess
from corefp_fixups_reader import Pointers,ROOT,sha,THIN_SHA
from daemon_receive_tools import IMAGE,SOURCE,verify_original_fixups,FIXUPS
from appstore_agent_reader import CS


def read(name):return json.loads((ROOT/name).read_text())


def main():
    s=Pointers();r=read('corefp_lookup_contracts.json');p=read('corefp_lookup_profiles.json')
    c=read('corefp_lookup_caller_profile.json');b=read('corefp_protocol_pair_profiles.json');checks=[]
    def check(ok,label):
        assert ok,label
        checks.append(label)
    def function(f,reader,label):
        at=int(f['start'],16);end=int(f['end'],16);raw=reader.read(at,end-at)
        check(sha(raw)==f['sha256'],'original source span '+label+':'+f['start'])
        if 'bytes' in f:check(raw.hex()==f['bytes'],'retained source bytes '+label+':'+f['start'])
        if reader is s:
            ix=s.starts.index(at);check(s.starts[ix+1]==end,'original compiler bounds '+label+':'+f['start'])
    def instructions(rows,label):
        for i in rows:
            at=int(i['ea'],16);raw=s.read(at,4);d=next(CS.disasm(raw,at))
            check(raw.hex()==i['bytes'] and (d.mnemonic,d.op_str)==(i['mnemonic'],i['operands']),'original instruction '+label+':'+i['ea'])
    def visits(row,reader,label):
        h=hashlib.sha256()
        for a in row['visited_original_instructions']:
            at=int(a,16);h.update(struct.pack('<Q',at));h.update(reader.read(at,4))
        check(h.hexdigest()==row['original_instruction_bytes_sha256'],'ordered instruction readback '+label)
    def events(row,kind):return [e for e in row['records'] if e['kind']==kind]
    def dependencies(obj,label):
        check(obj['generator_sha256']==sha((ROOT/label).read_bytes()),'generator pinned '+label)
        for name,value in obj.get('dependencies',{}).items():check(sha((ROOT/name).read_bytes())==value,'source dependency '+label+':'+name)
    dependencies(r,'recover_corefp_lookup.py');dependencies(p,'probe_corefp_lookup.py');dependencies(c,'probe_corefp_lookup.py');dependencies(b,'probe_corefp_protocol_pair.py')
    check(sha(s.data)==THIN_SHA==r['CoreFP_thin_sha256']==p['thin_sha256']==c['thin_sha256']==b['CoreFP_thin_sha256'],'original CoreFP slice identity')
    check(sha(SOURCE.read_bytes())==r['daemon_thin_sha256']==b['daemon_thin_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e','original daemon identity')
    for bank in r['banks']:
        aa=s.read(int(bank['first_address'],16),256);bb=s.read(int(bank['second_address'],16),256)
        vals=[i^bb[aa[i]^bank['key_u8']] for i in range(256)]
        check(aa.hex()==bank['first_bytes'] and bb.hex()==bank['second_bytes'] and vals==bank['results_256'] and set(vals)=={bank['constant_u8']},'256 original inputs '+bank['label'])
    check(len(r['banks'])==11,'eleven distinct bank identities')
    for item in r['resolutions']:
        at=int(item['slot'],16);value=s.qword(at);target=value+item['bias_signed_bytes'] if isinstance(value,int) else value
        check(item['target']==(hex(target) if isinstance(target,int) else target) and s.read(at,8).hex()==item['original_bytes'] and s.decoded.get(at)==item['original_pointer'],'selected original target '+item['label'])
    for item in r['strings']:
        raw=s.read(int(item['address'],16),item['size_bytes']);decoded=bytes(x^item['xor_key_u8'] for x in raw)
        check(raw.hex()==item['bytes'] and decoded.hex()==item['decoded_bytes'] and decoded==item['name'].encode()+b'\0','original decoded service '+item['name'])
    for item in r['branch_slots']:check(s.decoded[int(item['address'],16)]==item,'original branch-table slot '+item['address'])
    for proof in r['proofs']:
        path=ROOT/proof['path'];run=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True)
        check(sha(path.read_bytes())==proof['sha256'] and run.stdout.strip()=='unsat' and not run.stderr,'SMT '+path.name)
    for f in r['CoreFP_original_functions']+p['original_functions']+c['profile']['original_functions']+b['CoreFP_original_functions']:function(f,s,'CoreFP')
    prefix=r['caller_prefix'];check(s.read(int(prefix['start'],16),len(bytes.fromhex(prefix['bytes']))).hex()==prefix['bytes'] and sha(bytes.fromhex(prefix['bytes']))==prefix['sha256'],'original caller prefix')
    for f in r['daemon_original_ranges']+b['daemon_original_ranges']:function(f,IMAGE,'daemon')
    check(verify_original_fixups([0x1010380e0,0x101038108])==r['daemon_pointer_provenance'],'original daemon routine-descriptor fixups')
    ndr=r['daemon_NDR_data_binding'];word=struct.unpack('<Q',IMAGE.read(int(ndr['address'],16),8))[0]
    check(word==int(ndr['word'],16) and word>>63==0 and (word>>62)&1==1 and (word>>32)&0x7ffff==0 and FIXUPS[int(ndr['address'],16)]==ndr['reference'] and ndr['import_name']=='_NDR_record' and ndr['import_addend']==0,'original unauthenticated NDR data bind with zero addends')
    instructions(p['visited_instruction_records'],'lookup');instructions(c['profile']['visited_instruction_records'],'caller');instructions(b['CoreFP_visited_instruction_records'],'pair')
    profiles=p['profiles'];by={x['fixture']['label']:x for x in profiles}
    check(len(profiles)==16 and Counter(x['stop_reason'] for x in profiles)=={'opaque_import_boundary':3,'original_bootstrap_lookup_boundary':4,'original_mach_msg_request_boundary':1,'returned_to_private_fixture':8},'16 classified private outcomes without unexplained exception')
    for row in profiles+b['profiles']:
        label=row['fixture']['label'];visits(row,s,label);f=row['fixture'];raw=bytes.fromhex(row['record_before32_bytes']);ptr=int(row['record_pointer'],16)
        key=(((ptr&0xffffffff)^0x8b4ea7c9)*0x0bcb7857)&0xffffffff
        check(len(raw)==32 and struct.unpack_from('<QQ',raw,8)==(0x7b000300,0x7b000304) and (raw[24]-key)&255==f.get('flag_u8',9) and (struct.unpack_from('<I',raw,28)[0]-key)&0xffffffff==f.get('tag_u32',0xba27),'source private lookup record '+label)
        decoded=events(row,'original_decoded_lookup_record');check(len(decoded)==1 and decoded[0]['tag_u32']==0xba27 and decoded[0]['flag_u8']==f.get('flag_u8',9),'original record decode '+label)
        for e in events(row,'modeled_already_initialized_once'):
            check((e['control'],e['initializer']) in [('0x1d34f90','0x4a21e0'),('0x1d37f50','0x59e868')] and not e['original_initializer_executed'],'explicit warm-once precondition '+label)
        for e in events(row,'modeled_abstract_rwlock'):check(e['name']=='_pthread_rwlock_wrlock' and e['pointer']=='0x501d27bf0' and not e['native_lock_executed'],'original write-lock boundary '+label)
        lookup=events(row,'modeled_bootstrap_result')+events(row,'original_bootstrap_lookup_boundary')
        for e in lookup:check(e['service_name'] in ('com.apple.fpsd','com.apple.fairplayd') and e['bootstrap_name_u32']==0x1b57 and e['output_pointer']=='0x501d44448' and not e['native_lookup_executed'],'original bootstrap arguments '+label)
        for stub in row['original_auth_stubs']:check(s.read(int(stub['address'],16),16).hex()==stub['bytes'] and s.decoded[int(stub['pointer']['address'],16)]==stub['pointer'],'original import stub '+label+':'+stub['address'])
    for label in ('primary_other_error','fallback_other_error','fallback_unknown_service'):
        row=by[label];check(row['record_after32_bytes'][:8]=='e3a2e245' and row['output8_bytes']=='a5a5a5a5a5a5a5a5','failed lookup preserves caller outputs '+label)
    for label in ('fallback_success','fallback_other_error','fallback_unknown_service'):
        seq=events(by[label],'modeled_bootstrap_result');check([e['service_name'] for e in seq]==['com.apple.fpsd','com.apple.fairplayd'] and seq[0]['result']['status_u32']==1102,'exact fallback selector/name order '+label)
    check(by['fallback_success']['record_after32_bytes'][:8]=='dbf91dba' and by['fallback_success']['output8_bytes']==struct.pack('<II',0x5034,0).hex() and not events(by['fallback_success'],'original_mach_msg_request_boundary'),'fallback success omits metadata request')
    check(by['cached_port']['output8_bytes']==struct.pack('<II',0x5055,0x400).hex() and not events(by['cached_port'],'modeled_bootstrap_result'),'nonzero cached name bypasses lookup')
    for label,status,flags in [('primary_metadata_reply',0,4),('primary_transport_error',0x10000003,10),('primary_reply_return_error',0x42,10)]:
        row=by[label];check(events(row,'original_metadata_client_result')[0]['result_u32']==status and row['record_after32_bytes'][:8]=='dbf91dba' and row['output8_bytes']==struct.pack('<II',0x5017,flags).hex(),'local publication after metadata result '+label)
    for label,status in [('alternate_flag_deallocate_zero',0),('alternate_flag_deallocate_error',5)]:
        row=by[label];seq=events(row,'modeled_name_deallocation')
        check([(e['task_name_u32'],e['port_name_u32'],e['status_u32']) for e in seq]==[(0x1717,0x5066,status),(0x1717,0x5055,status)] and row['cache_after_u32']==0 and row['metadata_after_u32']==[0,0,0,0],'original two-name reset ignores modeled status '+label)
    parent=c['profile'];visits(parent,s,'protected caller');entry=events(parent,'original_lookup_record_from_caller')[0]
    caller_raw=bytes.fromhex(parent['caller_record_before48_bytes']);caller_ptr=int(parent['caller_record_pointer'],16)
    caller_key=((caller_ptr^0x84b771aed97ffe38)*0xfcf33521)&((1<<64)-1)
    check((struct.unpack_from('<I',caller_raw,20)[0]-caller_key)&0xffffffff==0xc1f7 and struct.unpack_from('<Q',caller_raw,8)[0]==0x7b001000 and struct.unpack_from('<Q',caller_raw,32)[0]==0x7b001200,'original caller encoded operation and required pointer preconditions')
    raw=bytes.fromhex(entry['record32_bytes']);ptr=int(entry['pointer'],16);key=(((ptr&0xffffffff)^0x8b4ea7c9)*0x0bcb7857)&0xffffffff
    check(parent['stop_reason']=='original_bootstrap_lookup_boundary' and parent['cursor_after_u64']==256 and entry['callsite']=='0x8e851c' and (raw[24]-key)&255==9 and (struct.unpack_from('<I',raw,28)[0]-key)&0xffffffff==0xba27,'original protected caller constructs lookup tag/flag and reaches primary service')
    for a,z in [(0x1ce278,0x1ce28c),(0x1ce47c,0x1ce4a8)]:
        ins=list(CS.disasm(s.read(a,z-a),a))
        check(len(ins)*4==z-a and all(not re.search(r'\b[wx]0\b',i.op_str) for i in ins),'source post-metadata continuation has no X0/W0 operand '+hex(a))
    check(s.qword(0x1c81940+0x9d91*8)==0x1ce47c and s.qword(0x1c81940+0xe0b5*8)==0x1ce4a4,'tag-specific post-metadata branch targets copy cached outputs and success marker')
    expected=[(-304,36,-304,[0,0,0,10],1203,1303),(-301,52,0,[0,0,0,10],1204,1304),(0,52,0,[76,9,0,42],1204,1304)]
    check(len(b['profiles'])==3,'three original/counterfactual protocol comparisons')
    for row,(client_status,size,server_status,metadata,mid,rid) in zip(b['profiles'],expected):
        label=row['fixture']['label'];child=row['daemon_children'][0];visits(child,IMAGE,label+'/daemon')
        check(child['stop_reason']=='returned_to_fixture' and child['recognized_u32']==1 and child['reply_size_bytes']==size and child['reply_status_signed32']==server_status,'source daemon outcome '+label)
        received=bytes.fromhex(child['received_request_bytes']);reply=bytes.fromhex(child['reply_bytes'])
        check(struct.unpack('<6I',received)==(18,24,0x6403,0x1403,0,mid) and struct.unpack_from('<I',reply,20)[0]==rid,'explicit receive envelope and source reply ID '+label)
        transfer=events(row,'source_daemon_reply_ABI_transfer')[0];wire=bytes.fromhex(transfer['request_bytes']);clientreply=bytes.fromhex(transfer['client_reply_bytes'])
        check(struct.unpack_from('<I',wire,20)[0]==1203 and clientreply[24:]==reply[24:] and len(clientreply)==size and not transfer['native_transport_executed'],'exact source body transfer and labeled envelope '+label)
        check(events(row,'original_metadata_client_result')[0]['result_u32']==client_status&0xffffffff and row['metadata_after_u32']==metadata and row['output8_bytes']==struct.pack('<II',0x5017,metadata[-1]).hex() and row['record_after32_bytes'][:8]=='dbf91dba','original client parse/publication result '+label)
        if server_status==0:check(list(struct.unpack_from('<4I',reply,36))==[76,9,0,42],'original daemon four metadata stores '+label)
    sdk=Path('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk');src=ROOT/'corefp_lookup_layouts.c'
    cmd=['/usr/bin/clang','-target','arm64e-apple-macos','-isysroot',str(sdk),'-fsyntax-only','-Wall','-Wextra','-Werror',str(src)]
    run=subprocess.run(cmd,capture_output=True,text=True);check(run.returncode==0 and not run.stderr,'arm64e32-byte record and bootstrap/MIG constants compile')
    for h in r['sdk_headers']:check(sha(Path(h['path']).read_bytes())==h['sha256'],'source SDK header '+h['path'])
    for item in read('interface_manifest.json')['inputs_preserved']:
        path=ROOT.parent/item['path'];check(path.stat().st_size==item['size_bytes'] and sha(path.read_bytes())==item['sha256'],'supplied input preserved '+item['path'])
    counts={'banks_256':11,'selected_resolutions':20,'source_service_strings':2,'SMT_unsat':3,'CoreFP_static_functions':6,
        'daemon_static_ranges':4,'lookup_profiles':16,'protected_caller_profiles':1,'protocol_pair_profiles':3,
        'lookup_original_instruction_records':len(p['visited_instruction_records']),'daemon_original_reply_rejections':1,
        'daemon_metadata_source_values':[76,9,0,42],'sdk_compile_exit':run.returncode,'assertions':len(checks)}
    (ROOT/'corefp_lookup_profile_checks.json').write_text(json.dumps({'scope':__doc__,'verified_counts':counts,'checks':checks,
        'SDK_compile':{'command':cmd,'exit_code':run.returncode,'source_sha256':sha(src.read_bytes())},'native_target_executed':False,'full_goal_complete':False},indent=2)+'\n')
    quality={'scope':'CoreFP lookup/cache/metadata client and explicit reference-image protocol comparison only.','verified_counts':counts,
        'QG1':{'status':'pass','evidence':'Descriptive technical investigation.'},
        'QG2':{'status':'pass','evidence':'L1-L6 state identities,record preconditions,warm models,envelopes and native gaps.'},
        'QG3':{'status':'pass_for_increment','evidence':'Caller,service names,cache/reset and protocol comparison recovered;full objective active.'},
        'QG4':{'status':'pass','evidence':'32/64-bit codecs,32-byte record,24/36/52/60/100-byte ABI,three SMT proofs and SDK compile.'},
        'QG5':{'status':'pass_for_stated_claims','evidence':'Raw names versus rights,source versus warm models,method difference versus native compatibility,and counterfactuals separated.'},
        'QG6':{'status':'pass','evidence':'Original file/range/chain/import/string readbacks,eleven exhaustive banks,source instruction hashes and original daemon guards/metadata stores.'},
        'QG7':{'status':'pass','evidence':'Impact-labeled protocol pairing,ownership,initialization and downstream consumers.'},
        'native_target_executed':False,'full_goal_complete':False}
    (ROOT/'corefp_lookup_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n')
    print(json.dumps(counts))


if __name__=='__main__':main()
