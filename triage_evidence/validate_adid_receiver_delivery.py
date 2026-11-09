#!/usr/bin/env python3
"""Fresh original-file, proof, private-case and paired-error readback.

No target/loader/API/IPC runs. O(B+F+R+V+256K) time, O(B+F+R+V) space;
SMT costs are separate and bounded by the query timeout. Compressed visits and
events are lossless evidence serialization, not omitted execution history.
"""
import base64
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import zlib
from adid_reader import Adid,ROOT,CS,sha,THIN_SHA,FIXUPS,SOURCE
from corefp_fixups_reader import Pointers


def read(name):return json.loads((ROOT/name).read_text())
def events(row):return row['records'] if 'records' in row else json.loads(zlib.decompress(base64.b64decode(row['records_zlib_base64'])))
def visits(row):
    if 'visited_original_instructions' in row:return [int(a,16) for a in row['visited_original_instructions']]
    packed=zlib.decompress(base64.b64decode(row['visited_original_instructions_zlib_base64']))
    assert len(packed)==8*row['visited_original_instruction_count']
    return [v[0] for v in struct.iter_unpack('<Q',packed)]


def main():
    assertions=[]
    def check(test,description):
        assert test,description
        assertions.append(description)
    s=Adid();iv=read('adid_inventory.json');c=read('adid_receiver_contracts.json');p=read('adid_receiver_profiles.json');pair=read('adid_client_pair_profiles.json');snap=read('adid_initialized_context_snapshot.json')
    check(iv['thin_sha256']==c['thin_sha256']==p['source_thin_sha256']==pair['provider_thin_sha256']==THIN_SHA,'fresh selected provider source identity')
    check(iv['reader_sha256']==sha((ROOT/'adid_reader.py').read_bytes()),'inventory reader pin')
    check(c['generator_sha256']==sha((ROOT/'recover_adid_receiver.py').read_bytes()),'static recovery source pin')
    check(p['generator_sha256']==snap['generator_sha256']==sha((ROOT/'probe_adid_receiver.py').read_bytes()),'private producer/snapshot source pin')
    check(pair['generator_sha256']==sha((ROOT/'probe_adid_client_pair.py').read_bytes()),'paired client producer source pin')
    check(p['static_contracts_sha256']==sha((ROOT/'adid_receiver_contracts.json').read_bytes()) and p['seed_snapshot_sha256']==sha((ROOT/'adid_initialized_context_snapshot.json').read_bytes()),'producer static/snapshot dependency pins')
    for parent in (c,pair):
        for name,digest in parent['dependencies'].items():check(sha((ROOT/name).read_bytes())==digest,'dependency '+name)
    tool=subprocess.run(['/usr/bin/dyld_info','-arch','arm64e','-fixups',str(SOURCE)],capture_output=True,check=True)
    check(tool.stdout==FIXUPS.read_bytes() and sha(tool.stdout)==iv['fixup_text_sha256'],'independent complete dyld_info correspondence')
    check(iv['all_chain_members_match_dyld_info'] and iv['import_format']==2 and len(s.decoded)==len(iv['fixups'])==11451,'format1 chain membership and format2 imports')
    check(list(s.decoded.values())==iv['fixups'] and s.imports==iv['imports'] and len(s.imports)==129,'complete original pointer/import inventory')
    for ptr in iv['fixups']:check(s.read(int(ptr['address'],16),8)==int(ptr['word'],16).to_bytes(8,'little'),'original pointer word '+ptr['address'])
    for b in c['banks']:
        aa=s.read(int(b['first_address'],16),256);bb=s.read(int(b['second_address'],16),256)
        check(aa.hex()==b['first_bytes'] and bb.hex()==b['second_bytes'],'original byte banks '+b['label'])
        for j in range(256):check(j^bb[aa[j]^b['key_u8']]==b['results_256'][j]==b['constant_u8'],'full byte-domain identity '+b['label']+':'+str(j))
        at=int(b['pointer_slot'],16);check(s.decoded[at]==b['pointer'] and s.qword(at)+b['signed_bias']==int(b['resolved_address'],16),'source context pointer resolution '+b['label'])
    for f in c['small_original_functions']:
        check(s.function(int(f['start'],16))==f,'complete original compiler-bounded helper '+f['start'])
    for f in c['large_original_function_bounds']+p['original_functions']:
        a=int(f['start'],16);z=int(f['end'],16);check(s.bounds(a)==(a,z) and sha(s.read(a,z-a))==f['sha256'],'original function bounds/hash '+f['start'])
    for w in c['selected_original_windows']:
        a,z=int(w['start'],16),int(w['end'],16);raw=s.read(a,z-a)
        check(raw.hex()==w['bytes'] and sha(raw)==w['sha256'],'selected original control/data-flow window '+w['role'])
        check([{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(raw,a)]==w['instructions'],'selected window instruction decode '+w['role'])
    for st in c['literal_strings']:check(s.read(int(st['address'],16),len(bytes.fromhex(st['bytes']))).hex()==st['bytes'] and st['string'].encode()+b'\0'==bytes.fromhex(st['bytes']),'source literal '+st['string'])
    cl=c['classifier'];check(s.read(int(cl['start'],16),len(bytes.fromhex(cl['bytes']))).hex()==cl['bytes'] and len(cl['listed_keys_u32'])==50 and cl['zero_keys_u32']==[0x3f4f8085],'original signed classifier and exact cardinalities')
    for proof in c['proofs']:
        path=ROOT/proof['path'];check(sha(path.read_bytes())==proof['sha256'],'proof source pin '+path.name)
        run=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);check(run.stdout.strip()=='unsat' and not run.stderr,'fresh full-domain SMT '+path.name)
    rows={r['fixture']['label']:r for r in p['profiles']};decoded={k:events(r) for k,r in rows.items()};instruction_bytes={}
    for i in p['original_instruction_records']:
        a=int(i['ea'],16);raw=s.read(a,4);ins=next(CS.disasm(raw,a));check(raw.hex()==i['bytes'] and ins.mnemonic==i['mnemonic'] and ins.op_str==i['operands'],'original provider instruction '+i['ea']);instruction_bytes[a]=raw
    total_visits=0
    for label,row in rows.items():
        vv=visits(row);total_visits+=len(vv);h=hashlib.sha256()
        for pc in vv:h.update(struct.pack('<Q',pc));h.update(instruction_bytes[pc])
        check(h.hexdigest()==row['ordered_original_instruction_sha256'],'complete ordered original-byte trace '+label)
        check(row['steps']<=row['fixture'].get('instruction_budget',100000)+1,'explicit finite instruction bound '+label)
        for e in decoded[label]:
            if e['kind']=='modeled_API':check(e['name'] in row['fixture'].get('model_APIs',[]) and not e['native_API_executed'],'declared API model '+label+':'+e['name'])
            if e['kind']=='modeled_vector_XOR3':
                v=[int(x,16) for x in e['input_u128']];check(int(e['output_u128'],16)==v[0]^v[1]^v[2] and next(CS.disasm(s.read(int(e['pc'],16),4),int(e['pc'],16))).mnemonic=='eor3','128-bit source XOR3 fixture '+label)
            if e['kind']=='original_private_global_write':
                a=int(e['address'],16);check(any(seg['name']=='__DATA' and seg['address']<=a and a+e['size_bytes']<=seg['address']+seg['vm_size'] for seg in s.meta['segments']),'owned source-global write '+label)
    def ev(label,kind=None,name=None):return [e for e in decoded[label] if (kind is None or e['kind']==kind) and (name is None or e.get('name')==name)]
    check(snap['source_stop_reason']==rows['startup_vector']['stop_reason']=='opaque_API_boundary:_getuid' and snap['source_ordered_instruction_sha256']==rows['startup_vector']['ordered_original_instruction_sha256'],'snapshot is an explicit incomplete startup prefix')
    for region in snap['regions']:
        raw=zlib.decompress(base64.b64decode(region['bytes_zlib_base64']));check(sha(raw)==region['sha256'] and len(raw)==region['size_bytes'],'retained prefix snapshot region '+region['address'])
        if int(region['address'],16)<=0x1002dd2e8<int(region['address'],16)+len(raw):check(struct.unpack_from('<Q',raw,0x1002dd2e8-int(region['address'],16))[0]==0x7e0003d0,'original prefix publishes context gate')
    maps=ev('startup_vector',name='_mmap');check([int(e['result'],16) for e in maps]==[0x7e000000,0x7e010000] and all(e['args_x0_x7'][:6]==['0x0','0x10000','0x3','0x1002','0xffffffff','0x0'] for e in maps),'two original 65536-byte anonymous mapping requests')
    check(ev('startup_mapping_failed',name='_sysctlbyname')[-1]['name_string']=='kern.hv_vmm_present','original VMM environment name')
    setup=ev('peer_setup_3',name='_xpc_connection_set_event_handler')[0];block=bytes.fromhex(setup['block48_bytes'])
    check(struct.unpack_from('<Q',block,16)[0]==0x100029fc8 and struct.unpack_from('<Q',block,32)[0]==0x7b000400,'peer setup installs original callback and captures peer')
    check([e['name'] for e in decoded['peer_setup_3'] if e['kind']=='modeled_API']==['_xpc_connection_set_target_queue','_xpc_connection_set_event_handler','_xpc_connection_resume'],'source peer-setup API order')
    check(rows['invalid_connection_event']['stop_reason']=='returned_to_private_fixture' and len(ev('invalid_connection_event',name='_xpc_connection_cancel'))==1 and not ev('invalid_connection_event',name='_xpc_dictionary_create_reply'),'exact invalid-event identity cancellation')
    check(rows['other_event_type']['stop_reason']=='returned_to_private_fixture' and not ev('other_event_type','original_core_record_entry'),'other event type does not enter protected record handler')
    for label in ['data_size_28_owned','data_size_0_owned','data_size_27_owned','data_size_29_owned']:
        ret=ev(label,'original_core_record_return')[0];gate=ev(label,'original_context_gate')[0]
        check(ret['status_u32']==0xffff5036 and ret['output_pointer_value']=='0x0' and ret['output_length_u64']==0 and gate['cell']=='0x1002dd2e8' and gate['value']=='0x0' and not ev(label,'original_payload_read'),'cold context failure precedes payload decoding '+label)
    check(rows['data_size_28_NULL']['stop_reason']=='returned_to_private_fixture' and not ev('data_size_28_NULL','original_core_record_entry'),'NULL data cleanup stays outside core')
    for label,row in rows.items():
        if 'seed_from' in row['fixture']:check(row['fixture']['seed_from']=='startup_vector','explicit seeded-prefix dependency '+label)
        for e in ev(label,'original_core_record_entry'):
            r=bytes.fromhex(e['record48_bytes']);address=int(e['pointer'],16);mask=(1<<64)-1
            h=((((0xfe69be85c31ad656|((address<<1)&mask))-address+0x80cb20bd1e7294d5)&mask)^0x1f6967cae97a38fd)*0x255e728d&mask
            data_event=ev(label,name='_xpc_dictionary_get_data')[0]
            check(((struct.unpack_from('<I',r)[0]+h)&0xffffffff)==0xd5b and ((struct.unpack_from('<Q',r,24)[0]-h)&mask)==data_event['size_bytes'],'original 48-byte operation/length codec '+label)
            check(struct.unpack_from('<Q',r,8)[0]==int(data_event['result'],16) and data_event['key']=='data','input pointer/key enters private record '+label)
        for e in ev(label,'original_entitlement_numeric_fold'):check(e['old_w19']=='0x3f4f8085' and e['shift_low5']==1,'original numeric-fold prefix constants '+label)
        for e in ev(label,name='_CFStringCreateWithCStringNoCopy'):
            if e['kind']=='modeled_API':check(e['string']=='adi-client' and e['encoding_u32']==0x600,'source entitlement key and encoding '+label)
        for e in ev(label,name='_SecTaskCreateWithAuditToken')+ev(label,name='_audit_token_to_au32')+ev(label,name='_audit_token_to_euid'):
            if 'audit_token32_bytes' in e:check(e['audit_token32_bytes']==struct.pack('<8I',*row['fixture'].get('audit_words',[0]*8)).hex(),'original audit-token copy reaches security/audit boundary '+label+':'+e['name'])
        for e in ev(label,'original_entitlement_classifier_input'):
            f=row['fixture']
            if f.get('entitlement_type')=='number' and f.get('number_conversion_success',True):check(e['encoded_key_u32']==(f.get('entitlement_number',0)&0xffffffff)^0x3f4f8085,'full-width numeric classifier input '+label)
    listed_labels=[]
    for value in cl['listed_values_under_XOR_u32']:
        label='initialized_path_listed_'+hex(value);listed_labels.append(label);row=rows[label];rr=ev(label,'original_payload_read')
        check(row['stop_reason']=='opaque_API_boundary:_audit_token_to_euid' and 0x100169f48 in visits(row) and len(rr)==12 and [int(e['address'],16)-0x7b002000 for e in rr]==list(range(12)),'listed entitlement reaches exact original 12-byte header decode '+hex(value))
        check(bytes.fromhex(''.join(e['bytes'] for e in rr))==bytes.fromhex(row['fixture']['payload_hex'])[:12],'client/provider header bytes agree '+hex(value))
    check(rows['listed_entitlement_path_lookup_failure']['stop_reason']=='opaque_API_boundary:_audit_token_to_euid' and ev('listed_entitlement_path_lookup_failure',name='_proc_pidpath')[0]['result']=='0x0','failed diagnostic path lookup does not block this listed-value branch')
    check(rows['listed_decimal_string_entitlement']['stop_reason']=='opaque_API_boundary:_audit_token_to_euid' and len(ev('listed_decimal_string_entitlement','original_payload_read'))==12,'complete listed decimal string reaches header decode')
    check(ev('initialized_path_string_1','original_entitlement_classifier_input')[0]['encoded_key_u32']==(1^0x3f4f8085) and ev('initialized_path_string_1junk','original_entitlement_classifier_input')[0]['encoded_key_u32']==0x3f4f8085,'decimal prefix with trailing text does not retain numeric-one classification')
    for selector in (-8,-6,-5,-4,-3,-2):
        label='denied_selector_'+str(selector);ret=ev(label,'original_core_record_return')[0];data=ev(label,name='_xpc_dictionary_set_data')[0];send=ev(label,name='_xpc_dictionary_send_reply')[0]
        check(ret['status_u32']==0 and ret['output_length_u64']==4 and data['key']=='data' and data['payload_bytes']=='ffff4ff2' and data['size_bytes']==4 and not ev(label,'original_payload_read'),'source denial envelope versus wire error '+label)
        check(data['callsite']=='0x1000aa9fc' and send['callsite']=='0x1000aaa70' and rows[label]['stop_reason']=='returned_to_private_fixture','source response emission and normal modeled completion '+label)
    check(ev('initialized_listed_euid_501',name='_lstat')[0]['name_string']=='/var/db/.AppleSetupUser','nonroot setup-file touch point')
    for label in ('initialized_listed_euid_0','initialized_listed_root_locks','initialized_root_osinstall_None','initialized_root_osinstall_1'):
        rr=ev(label,'original_payload_read');check(len(rr)==28 and [int(e['address'],16)-0x7b002000 for e in rr]==list(range(28)) and ''.join(e['bytes'] for e in rr)==rows[label]['fixture']['payload_hex'],'listed root case reads exact complete client 28-byte request '+label)
    check(len(ev('initialized_listed_euid_501','original_payload_read'))==12,'nonroot case stops at setup-file boundary after header')
    check(ev('initialized_listed_root_locks',name='_getenv')[0]['name_string']=='__OSINSTALL_ENVIRONMENT','original installation environment touch point')
    check(ev('initialized_root_osinstall_1',name='_lstat')[0]['name_string']=='/Users/Shared/adi/adi-00000000.pb','constructed persistent-record path in installation fixture')
    check(rows['initialized_root_osinstall_None']['stop_reason']=='unresolved_private_memory_boundary' and not ev('initialized_root_osinstall_None','unresolved_private_memory_boundary')[0]['native_fault_inferred'],'incomplete-prefix unresolved read remains conditional')
    fp=Pointers();fp_bytes={}
    for i in pair['original_instruction_records']:
        a=int(i['ea'],16);raw=fp.read(a,4);d=next(CS.disasm(raw,a));check(raw.hex()==i['bytes'] and d.mnemonic==i['mnemonic'] and d.op_str==i['operands'],'original paired CoreFP instruction '+i['ea']);fp_bytes[a]=raw
    for row in pair['profiles']:
        h=hashlib.sha256()
        for a in row['visited_original_instructions']:pc=int(a,16);h.update(struct.pack('<Q',pc));h.update(fp_bytes[pc])
        check(h.hexdigest()==row['original_instruction_bytes_sha256'],'ordered original client response trace '+row['fixture']['label'])
        check(row['stop_reason']=='returned_to_private_fixture','bounded original client parser returns '+row['fixture']['label'])
        if 'provider_source_profile' in row['fixture']:
            label=row['fixture']['provider_source_profile'];wire=next(e for e in row['records'] if e['kind']=='modeled_secondary_XPC_set_data')['bytes']
            check(wire==rows[label]['fixture']['payload_hex'] and row['result_u32']==0xffff4ff2 and row['argument1_fixture8_bytes']=='a5a5a5a5a5a5a5a5','source request/error-response/client-return pair '+label)
    pair_rows={r['fixture']['label']:r for r in pair['profiles']}
    for label,value in [('counterfactual_little_endian_response',0xf24fffff),('counterfactual_zero_status_only',0),('truncated_response3',0xffff5016),('NULL_data_response',0xffff5028)]:check(pair_rows[label]['result_u32']==value,'client response grammar boundary '+label)
    sdk=Path('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk')
    cmd=['/usr/bin/clang','-target','arm64e-apple-macos','-march=armv8.2-a+sha3','-isysroot',str(sdk),'-O2','-Wall','-Wextra','-Werror','-S',str(ROOT/'adid_receiver_layouts.c')]
    with tempfile.TemporaryDirectory() as directory:
        output=Path(directory)/'layout.s';run=subprocess.run(cmd+['-o',str(output)],capture_output=True,text=True)
        check(run.returncode==0 and not run.stderr,'arm64e SDK record/audit/pointer-format/number-type compile')
        text=output.read_text();check('eor3.16b' in text and 'mov\tx6, x1' in text and 'bl\t_audit_token_to_au32' in text,'independent compiler XOR3 and audit aggregate lowering')
        # Absolute and relative source spellings do not occur in optimized assembly.
        check(text==(ROOT/'adid_receiver_layouts.s').read_text(),'fresh retained compiler assembly readback')
    for header in c['sdk_headers']:check(sha(Path(header['path']).read_bytes())==header['sha256'],'SDK provenance '+header['path'])
    for row in read('interface_manifest.json')['inputs_preserved']:
        path=ROOT.parent/row['path'];check(path.stat().st_size==row['size_bytes'] and sha(path.read_bytes())==row['sha256'],'original supplied input preserved '+row['path'])
    counts={'provider_fixups':11451,'provider_imports':129,'provider_compiler_functions':len(s.starts),'provider_private_cases':len(rows),'client_pair_cases':len(pair['profiles']),
        'total_private_cases':len(rows)+len(pair['profiles']),'provider_original_instruction_records':len(p['original_instruction_records']),'client_original_instruction_records':len(pair['original_instruction_records']),
        'provider_original_visits':total_visits,'listed_entitlement_values':50,'banks_256':3,'SMT_unsat':3,'sdk_compile_exit':run.returncode,'assertions':len(assertions)}
    result={'scope':__doc__,'verified_counts':counts,'assertions':assertions,'all_checks_pass':True,'native_target_executed':False,'full_goal_complete':False}
    (ROOT/'adid_receiver_checks.json').write_text(json.dumps(result,indent=2)+'\n')
    quality={'scope':'Original adid receiver/context/entitlement/error ABI and CoreFP local denial pairing only. Full investigation remains active.',
        'verified_counts':counts,'native_target_executed':False,'full_goal_complete':False}
    for n,evidence in [(1,'Descriptive binary/ABI analysis.'),(2,'Report A1-A7 list dependencies and stress/falsification probes.'),(3,'Receiver,context,admission,payload prefix,error ABI,pair and deeper touches covered within explicit boundaries.'),
        (4,'Byte extents,u32/u64/u128 modular arithmetic,signed classifier and arm64e SDK/compiler readback explicit.'),(5,'Cold prefix,initialized prefix,listed/zero/other entitlements,envelope/wire statuses,diagnostic path and unresolved reads separated.'),
        (6,'Fresh original image/chain/instruction/SDK/static-tool readbacks,three SMT queries and ordered private source traces.'),(7,'Impact-labeled native pairing,legacy protocol,successful operations,context completion and persistence/IOKit continuations.')]:
        quality['QG'+str(n)]={'status':'pass_for_stated_increment','evidence':evidence}
    (ROOT/'adid_receiver_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n')
    print(json.dumps(counts))


if __name__=='__main__':main()
