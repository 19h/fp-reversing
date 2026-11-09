#!/usr/bin/env python3
"""Original main/secondary client byte,packet,certificate and context readback.

No native target/loader/API/IPC runs. Original files,finite private cases,
full-domain local predicates and offline certificate metadata remain distinct.
O(B+F+R+V+256*K) time,O(B+F+R+V) space;solver cost separate with30 s caps.
"""
from collections import Counter
import hashlib
import json
from pathlib import Path
import plistlib
import struct
import subprocess
from corefp_fixups_reader import Pointers,ROOT,sha,THIN_SHA
from appstore_agent_reader import CS
from resolve_kernel_collection_interfaces import macho
from probe_corefp_exports import BASE,STACK,HEAP


def read(name):return json.loads((ROOT/name).read_text())


def main():
    s=Pointers();r=read('corefp_client_paths_contracts.json');p=read('corefp_client_flow_profiles.json');q=read('corefp_secondary_client_profiles.json')
    cm=read('corefp_fppineboard_certificate.json');environment=read('corefp_adid_environment.json');checks=[]
    def check(ok,label):
        assert ok,label
        checks.append(label)
    def events(row,kind):return [e for e in row['records'] if e['kind']==kind]
    def visits(row,label):
        h=hashlib.sha256()
        for value in row['visited_original_instructions']:
            a=int(value,16);h.update(struct.pack('<Q',a));h.update(s.read(a,4))
        check(h.hexdigest()==row['original_instruction_bytes_sha256'],'ordered original visits '+label)
    def source_functions(rows,label):
        for f in rows:
            a=int(f['start'],16);z=int(f['end'],16);raw=s.read(a,z-a);ix=s.starts.index(a)
            check(s.starts[ix+1]==z and sha(raw)==f['sha256'],'original function bounds/hash '+label+':'+f['start'])
            if 'bytes' in f:check(raw.hex()==f['bytes'],'original function bytes '+label+':'+f['start'])
    for obj,name in [(r,'recover_corefp_client_paths.py'),(p,'probe_corefp_client_flow.py'),(q,'probe_corefp_secondary_client.py')]:
        check(obj['generator_sha256']==sha((ROOT/name).read_bytes()),'generator pinned '+name)
        for path,digest in obj.get('dependencies',{}).items():check(sha((ROOT/path).read_bytes())==digest,'dependency pinned '+name+':'+path)
    check(sha(s.data)==THIN_SHA==r['CoreFP_thin_sha256']==p['thin_sha256']==q['thin_sha256'],'original selected CoreFP identity')
    for b in r['banks']:
        aa=s.read(int(b['first_address'],16),256);bb=s.read(int(b['second_address'],16),256);vals=[i^bb[aa[i]^b['key_u8']] for i in range(256)]
        check(aa.hex()==b['first_bytes'] and bb.hex()==b['second_bytes'] and vals==b['results_256'] and set(vals)=={b['constant_u8']},'exhaustive256 bank '+b['label'])
    for ptr in r['pointers']+r['cache_pointer_references']:
        a=int(ptr['address'],16);check(s.decoded[a]==ptr and int.from_bytes(s.read(a,8),'little')==int(ptr['word'],16),'original pointer member '+ptr['address'])
    seg=r['cache_storage']['segment'];cache=0x1d49068
    check(seg in s.meta['segments'] and seg['address']+seg['file_size']<=cache and cache+4<=seg['address']+seg['vm_size'],'legacy cache is in original zero-fill extent')
    source_functions(r['original_functions'],'static');source_functions(p['original_functions'],'main');source_functions(q['original_functions'],'secondary');source_functions([r['main_caller']],'main bound')
    for pool,label in [(p['visited_instruction_records'],'main'),(q['visited_instruction_records'],'secondary')]:
        for row in pool:
            a=int(row['ea'],16);raw=s.read(a,4);i=next(CS.disasm(raw,a))
            check(raw.hex()==row['bytes'] and (i.mnemonic,i.op_str)==(row['mnemonic'],row['operands']),'original instruction '+label+':'+row['ea'])
    for proof in r['proofs']:
        path=ROOT/proof['path'];result=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True)
        check(sha(path.read_bytes())==proof['sha256'] and result.stdout.strip()=='unsat' and not result.stderr,'full-domain proof '+path.name)
    encoded=s.read(int(cm['encoded_source_address'],16),cm['encoded_size_bytes']);decoded=bytes(v^cm['xor_byte'] for v in encoded)
    der=(ROOT/'corefp_fppineboard_certificate.der').read_bytes()
    check(encoded.hex()==cm['encoded_bytes'] and len(encoded)==760 and decoded[:4].hex()=='01000007' and decoded[4:]==der and len(der)==756 and int.from_bytes(der[2:4],'big')+4==756 and sha(der)==cm['DER_sha256'],'original XOR container and complete DER extent')
    result=subprocess.run(cm['parser_command'],capture_output=True,text=True,check=True)
    check(result.stdout==cm['parser_output'] and result.stderr==cm['parser_stderr'] and not cm['certificate_authentication_executed'],'reproducible offline certificate metadata without authentication')
    main=p['profiles'];by={v['fixture']['label']:v for v in main}
    check(len(main)==15 and Counter(x['stop_reason'] for x in main)=={'opaque_import_boundary':12,'original_larger_request_boundary':2,'returned_to_private_fixture':1},'15 classified main caller outcomes')
    for row in main:
        label=row['fixture']['label'];visits(row,label);out=events(row,'original_lookup_outputs_in_parent')
        check(len(out)==1 and out[0]['port_name_u32']==0x5017 and out[0]['flags_u32']==row['fixture'].get('flags_u32',10),'source lookup output reaches parent '+label)
        for allocation in events(row,'modeled_private_allocation'):check(allocation['size_bytes']==760 and allocation['callsite']=='0x249368' and not allocation['native_allocator_executed'],'original760-byte allocation '+label)
        for stub in row['original_auth_stubs']:check(s.read(int(stub['address'],16),16).hex()==stub['bytes'],'main original import stub '+label+':'+stub['address'])
    check(by['cached_allocator_null']['caller_record_after48_bytes'][:8]=='0fa2e245' and by['cached_allocator_null']['stop_reason']=='returned_to_private_fixture','original allocation-null record marker')
    for label in ('cached_owned_cleanup','fresh_lookup_to_request1200'):
        row=by[label];message=events(row,'original_larger_request_boundary')[0];raw=bytes.fromhex(message['message_bytes']);payload=bytes.fromhex(message['OOL_bytes'])
        check(struct.unpack_from('<I',raw,8)[0]==0x5017 and struct.unpack_from('<I',raw,20)[0]==1200 and len(raw)==64 and message['args_x0_x6'][1:]==['0x3','0x40','0xdc','0x5173','0x0','0x0'],'source main request1200 destination and call arguments '+label)
        check(struct.unpack_from('<I',raw,24)[0]==1 and struct.unpack_from('<II',raw,36)==(0x01000100,756) and struct.unpack_from('<III',raw,52)==(2,2,756),'main OOL descriptor and scalar fields '+label)
        ptr=int(message['OOL_source_pointer'],16);check(STACK<=ptr and ptr+756<=STACK+0x40000 and payload==der,'main payload equals original decoded DER in private stack '+label)
        free=events(row,'modeled_private_free')[0];blob=bytes.fromhex(free['before_bytes'])
        check(free['callsite']=='0x8e9fa8' and int(free['pointer'],16)!=ptr and len(blob)==760 and blob[:756]==der and blob[-4:]==der[-4:],'temporary freed after DER rearrangement and before stack-backed message '+label)
        copy=events(row,'original_certificate_XOR_copy')[0]
        check(copy['source_pointer']=='0x185c226' and copy['xor_byte']==0xba and (copy['min_index'],copy['max_index'],copy['iterations'])==(0,759,760),'original760-byte XOR loop coverage '+label)
        edge=next(e for e in row['records'] if e['kind']=='PAC_bypassed_edge' and e['pc']=='0x8ea14c')
        check(edge['target']=='0x8ae0' and edge['modifier']=='0x563e','actual protected caller selects main MIG builder '+label)
    row=by['fresh_lookup_to_request1200'];lookup=events(row,'modeled_bootstrap_result');check(len(lookup)==1 and lookup[0]['service_name']=='com.apple.fpsd' and events(row,'original_metadata_client_result')[0]['result_u32']==0x10000003,'fresh primary acquisition and metadata error precede larger request')
    secondary=q['profiles'];sb={v['fixture']['label']:v for v in secondary}
    expected={'returned_to_private_fixture':13,'opaque_import_boundary':10,'original_mach_msg_request_boundary':5,'original_secondary_XPC_send_boundary':4,'original_secondary_XPC_get_data_boundary':2,'original_secondary_XPC_service_boundary':1,'original_secondary_lookup_boundary':1}
    check(len(secondary)==36 and Counter(x['stop_reason'] for x in secondary)==expected,'36 classified secondary outcomes')
    accepted={-8,-6,-5,-4,-3,-2};mask=(1<<64)-1
    for row in secondary:
        f=row['fixture'];label=f['label'];visits(row,label)
        if not f.get('entry_override'):
            state=events(row,'original_secondary_state_prelude')[0];g1,g2=state['before_u64'];sp=int(state['entry_sp'],16)
            mixed=g1^(sp-0x88)^g2;C=0xa90ac839;K=0x5f0913a0d6d70483
            check(state['after_u64']==[((mixed+K)*C)&mask,((mixed^K)*C)&mask],'source shared-state prelude before selector gate '+label)
            if f['selector_signed64'] not in accepted:check(row['result_u32']==0xffff5037 and row['argument1_fixture8_bytes']=='a5a5a5a5a5a5a5a5','rejected64-bit selector leaves argument fixture memory unchanged '+label)
        for e in events(row,'modeled_secondary_allocation'):check(e['size_bytes'] in (24,4096) and not e['native_allocator_executed'],'bounded constructor allocation '+label)
        for e in events(row,'modeled_secondary_XPC_set_data'):
            raw=bytes.fromhex(e['bytes']);expected=struct.pack('>IIIqQ',1,0x632b8d6e,1,f['selector_signed64'],HEAP+0x100+f.get('argument1_delta',0))
            check(e['callsite']=='0x15cea8c' and e['key']=='data' and e['size_bytes']==28 and raw==expected and not e['native_XPC_executed'],'source28-byte network-order payload '+label)
        for e in events(row,'original_secondary_XPC_service_boundary')+events(row,'modeled_secondary_connection'):
            check(e['service']=='com.apple.adid' and e['flags']=='0x0' and e['queue']=='0x7b00e100' and e['callsite']=='0x15ceb94','exact secondary XPC endpoint '+label)
        for e in events(row,'original_secondary_lookup_boundary')+events(row,'modeled_secondary_lookup'):
            check(e['service_name']=='com.apple.adid' and e['bootstrap_name_u32']==0x1b57 and e['output_pointer']=='0x501d49068' and e['callsite']=='0x15d0174','exact secondary bootstrap endpoint/cache '+label)
        for stub in row['original_auth_stubs']:check(s.read(int(stub['address'],16),16).hex()==stub['bytes'],'secondary original import stub '+label+':'+stub['address'])
    for label in ('first_allocator_null','second_allocator_null','connection_null'):
        check(sb[label]['result_u32']==0xffff5035 and sb[label]['argument1_fixture8_bytes']=='a5a5a5a5a5a5a5a5','constructor modeled failure result '+label)
    check([e['pointer'] for e in events(sb['second_allocator_null'],'modeled_secondary_cleanup') if e['name']=='_free']==['0x7b001000'],'second allocation failure releases first24-byte object')
    for label,name in [('reply_error',0),('reply_interrupted',0),('legacy_lookup_success_retry',0x6ad1),('legacy_cached_name_request',0x6a90),('legacy_cached_name_retry',0x6ad1)]:
        row=sb[label];e=row['records'][-1];raw=bytes.fromhex(e['message_bytes']);data=events(row,'modeled_secondary_XPC_set_data')[0]
        check(e['callsite']=='0x15908c8' and len(raw)==56 and struct.unpack_from('<I',raw,8)[0]==name and struct.unpack_from('<I',raw,20)[0]==1200 and struct.unpack_from('<I',raw,40)[0]==28 and struct.unpack_from('<I',raw,52)[0]==28,'source separate legacy1200 layout/destination '+label)
        allocation=next(a for a in row['private_allocations'] if a['address']=='0x7b001020')
        check(struct.unpack_from('<Q',raw,28)[0]==int(allocation['address'],16) and bytes.fromhex(allocation['first32_bytes'])[:28]==bytes.fromhex(data['bytes']),'same allocated28-byte payload backs XPC field and legacy OOL '+label)
        prior=events(row,'modeled_secondary_mach_failure')
        if prior:check(prior[0]['result_u32']==0x10000003 and prior[0]['OOL_bytes']==data['bytes'],'same XPC payload in modeled legacy first attempt '+label)
    check(sb['legacy_lookup_error']['result_u32']==0xffff5027 and sb['legacy_other_transport_error']['result_u32']==0xffff5028 and not events(sb['legacy_other_transport_error'],'modeled_secondary_lookup'),'lookup failure and other transport error remain distinct')
    interrupted=events(sb['reply_interrupted'],'modeled_secondary_XPC_reply')
    check([e['callsite'] for e in interrupted]==['0x15ced04','0x15ceecc','0x15cf02c','0x15cf14c','0x15cf28c'] and all(e['result']=='0x7c0006b0' for e in interrupted),'five source synchronous attempts for exact interrupted-object identity before Mach fallback')
    i=next(CS.disasm(s.read(0x15cee24,4),0x15cee24))
    check(s.decoded[0x1d1c028]['pointer_addend']==4 and i.mnemonic=='sub' and i.op_str=='x24, x9, #4','source compensates interrupted-object import addend before identity comparison')
    callback=sb['event_description_cleanup'];description=events(callback,'modeled_secondary_event_description')[0];cleanup=events(callback,'modeled_secondary_cleanup')[0]
    check(description['event_object']=='0x7b00e400' and description['callsite']=='0x15a4d8c' and cleanup['name']=='_free' and cleanup['pointer']==description['result'] and cleanup['tail_call'] and cleanup['callsite']=='0x15a4df4','original event description followed by exact free tail edge')
    block=next(e for e in sb['connection_success']['records'] if e['kind']=='modeled_secondary_connection_setup' and 'block32_bytes' in e)
    check(struct.unpack_from('<Q',bytes.fromhex(block['block32_bytes']),16)[0]==BASE+0x15a4c14,'configured block points to recovered event handler')
    launch=Path(environment['launchd_path']);raw=launch.read_bytes();plist=plistlib.loads(raw)
    check(sha(raw)==environment['launchd_sha256'] and plist==environment['launchd_plist'] and plist['MachServices']=={'com.apple.adid':True} and plist['UserName']==plist['GroupName']=='_fpsd','original launchd service/principal declaration')
    provider=Path(environment['provider_path']);raw=provider.read_bytes();sel=environment['selected_slice'];data=raw[sel['offset']:sel['offset']+sel['size_bytes']]
    check(sha(raw)==environment['provider_sha256'] and sha(data)==sel['sha256'] and json.loads(json.dumps(macho(data,0,'CoreADI adid selected arm64e')))==environment['macho'],'original CoreADI executable/slice/UUID metadata')
    fixups=ROOT/environment['dyld_info_fixups_path'];run=subprocess.run(['/usr/bin/dyld_info','-arch','arm64e','-fixups',str(provider)],capture_output=True,check=True)
    check(run.stdout==fixups.read_bytes() and sha(run.stdout)==environment['dyld_info_fixups_sha256'],'independent adid static-tool readback without running provider')
    sdk=Path('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk');src=ROOT/'corefp_client_paths_layouts.c'
    cmd=['/usr/bin/clang','-target','arm64e-apple-macos','-isysroot',str(sdk),'-fsyntax-only','-Wall','-Wextra','-Werror',str(src)]
    run=subprocess.run(cmd,capture_output=True,text=True);check(run.returncode==0 and not run.stderr,'arm64e packed28-byte wire and invalid-destination constant compile')
    for h in r['sdk_headers']:check(sha(Path(h['path']).read_bytes())==h['sha256'],'original SDK header '+h['path'])
    for row in read('interface_manifest.json')['inputs_preserved']:
        path=ROOT.parent/row['path'];check(path.stat().st_size==row['size_bytes'] and sha(path.read_bytes())==row['sha256'],'original supplied input preserved '+row['path'])
    counts={'main_profiles':15,'secondary_profiles':36,'total_private_profiles':51,'original_instruction_records':len(p['visited_instruction_records'])+len(q['visited_instruction_records']),
        'banks_256':3,'selected_pointers':len(r['pointers']),'SMT_unsat':2,'certificate_container_bytes':760,'certificate_DER_bytes':756,
        'main_send_bytes':64,'secondary_send_bytes':56,'secondary_XPC_payload_bytes':28,'adid_slices':len(environment['slices']),
        'sdk_compile_exit':run.returncode,'assertions':len(checks)}
    (ROOT/'corefp_client_paths_checks.json').write_text(json.dumps({'scope':__doc__,'verified_counts':counts,'checks':checks,
        'SDK_compile':{'command':cmd,'exit_code':run.returncode,'source_sha256':sha(src.read_bytes())},
        'native_target_executed':False,'full_goal_complete':False},indent=2)+'\n')
    quality={'scope':'Two CoreFP request1200 paths,certificate staging,adid XPC/legacy recovery,event handler and provider declaration only.',
        'verified_counts':counts,
        'QG1':{'status':'pass','evidence':'Descriptive interface analysis.'},
        'QG2':{'status':'pass','evidence':'P1-P7 identify image,private initialization,opaque APIs,selector/state,certificate and receiver limits.'},
        'QG3':{'status':'pass_for_increment','evidence':'Concrete main/secondary acquisition-to-emission progress;full objective active.'},
        'QG4':{'status':'pass','evidence':'u32/u64 selectors,modular state,28-byte big-endian payload,760/756 extents and two domain proofs.'},
        'QG5':{'status':'pass_for_stated_claims','evidence':'Separate endpoint schemas,freed temporary versus stack staging,conditional failures,callback tails and declared/live providers distinguished.'},
        'QG6':{'status':'pass','evidence':'Original image/range/instruction/chain/string/encoded certificate readbacks,offline parser,plist/provider metadata,static-tool comparison and SDK compile.'},
        'QG7':{'status':'pass','evidence':'Impact-labeled server parsing,rights,retry,metadata,callback/concurrency and payload-field continuations.'},
        'native_target_executed':False,'full_goal_complete':False}
    (ROOT/'corefp_client_paths_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n')
    print(json.dumps(counts))


if __name__=='__main__':main()
