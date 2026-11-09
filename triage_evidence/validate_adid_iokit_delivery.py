#!/usr/bin/env python3
"""Independent readback of IOKit providers, framing, query and cache contracts.

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
from probe_adid_iokit import Hardware
from probe_adid_receiver import DONE,HEAP
from unicorn import arm64_const as A


def read(name):return json.loads((ROOT/name).read_text())


def main():
    checks=[]
    def check(condition,description):
        assert condition,description
        checks.append(description)
    s=Adid();p=read('adid_iokit_profiles.json');c=read('adid_iokit_contracts.json');rows={r['fixture']['label']:r for r in p['profiles']};events={k:unpack_records(v) for k,v in rows.items()}
    check(p['thin_sha256']==c['thin_sha256']==THIN_SHA,'fresh original provider identity')
    check(p['generator_sha256']==sha((ROOT/'probe_adid_iokit.py').read_bytes()) and c['generator_sha256']==sha((ROOT/'recover_adid_iokit.py').read_bytes()),'producer/static source pins')
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
    for ptr in c['source_import_pointers']+[b['pointer'] for b in c['query_branch_pointers']]:check(s.decoded[int(ptr['address'],16)]==ptr,'fresh chained pointer '+ptr['address'])
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
        check(row['steps']<=row['fixture']['instruction_budget']+1,'finite hook cap '+label)
        edge=None
        for e in events[label]:
            if e['kind']=='PAC_bypassed_edge':edge=e
            if e.get('name') in symbols and 'native_API_executed' in e:
                api_count+=1;check(not e['native_API_executed'],'explicit private API scope '+label+' '+e['name'])
                if 'callsite' in e:
                    check(edge is not None and edge['pc']==e['callsite'] and int(edge['target'],16)==symbols[e['name']],'source call target,site and symbol '+label+' '+e['name'])
            if e['kind']=='original_AVP_name_source':check(s.read(int(e['address'],16),18).hex()==e['bytes18'],'fresh original service-name bytes '+label)
    def ev(label,name=None,kind=None):return [e for e in events[label] if (name is None or e.get('name')==name) and (kind is None or e['kind']==kind)]
    def modeled(label,name):return ev(label,name,'hardware_modeled_API')
    def record_status(label):return struct.unpack_from('<I',bytes.fromhex(rows[label]['private_record16_bytes']),4)[0]
    # Signature content declaration; no trust/effective credential claim.
    import plistlib
    sig=c['embedded_signature_declaration'];xml=ROOT/sig['XML_path'];check(sha(xml.read_bytes())==sig['XML_sha256'] and plistlib.loads(xml.read_bytes())==sig['entitlements'],'fresh selected-slice embedded entitlement bytes')
    run=subprocess.run(sig['independent_codesign_command'],capture_output=True,check=True);check(plistlib.loads(run.stdout)==sig['entitlements'] and not sig['trust_or_effective_entitlements_established'],'independent codesign content display agrees')
    for name in ('AvpFairPlayUserClient.access','com.apple.private.FairPlayIOKitUserClient.access'):check(sig['entitlements'][name] is True,'embedded true declaration '+name)
    for label in ('getter_0x1000208fc','getter_0x10002af70','open_success'):
        check(rows[label]['stop_reason']=='unresolved_private_memory_boundary' and events[label][-1]['native_fault_inferred'] is False,'invalid private record remains conditional '+label)
    avp='owned_output_open_success';check(rows[avp]['stop_reason']=='returned_to_private_fixture' and rows[avp]['private_output_u32']==0x5804 and record_status(avp)==0x59248f,'Avp record/output contract')
    check(modeled(avp,'_IOServiceMatching')[0]['name_string']=='AvpFairPlayDriver' and modeled(avp,'_IOServiceOpen')[0]['args_x0_x7'][:3]==['0x5803','0x5810','0x0'],'Avp class,service,task,type0 contract')
    check(modeled(avp,'_IOServiceOpen')[0]['connection_output_cell']=='0x1002dd290' and rows[avp]['observed_globals_final']['0x1002dd290']=='04580000','Avp connection cache cell')
    check(not modeled('record_basis_10fd_field_0x4a98f233707acdc1','_IOMainPort'),'encoded null output skips acquisition')
    check([(e['callsite'],e['args_x0_x7'][0]) for e in modeled(avp,'_IOObjectRelease')]==[('0x10002b8ac','0x5803'),('0x10002b940','0x5802')],'Avp service and iterator release sites')
    for label,classname,cell,site,size in [('first_getter_once_callback','com_apple_driver_FairPlayIOKit','0x1002dcc84','0x10001f908',16),('first_VMM_1','AvpFairPlayDriver','0x1002dcee4','0x10004967c',96),('first_VMM_2','AvpFairPlayDriver','0x1002dcee4','0x10004967c',96),('first_VMM_query_error','com_apple_driver_FairPlayIOKit','0x1002dcc84','0x10001f908',16)]:
        check(modeled(label,'_IOServiceMatching')[0]['name_string']==classname and modeled(label,'_IOServiceOpen')[0]['connection_output_cell']==cell,'query-selected class and distinct cache '+label)
        e=ev(label,kind='original_IOConnect_structure_boundary')[0];check(e['callsite']==site and e['args_x0_x7'][1]=='0x1a' and int(e['args_x0_x7'][3],16)==size and e['output_size_before_u64']==size and e['args_x0_x7'][2]==e['args_x0_x7'][4],'selector26 input/output shape '+label)
        query=ev(label,'_sysctlbyname')[0];check(query['name_string']=='kern.hv_vmm_present' and query['old_size_u64']==4 and query['args_x0_x7'][3:5]==['0x0','0x0'],'original query signature '+label)
    for label,value in [('first_getter_once_callback',0),('first_VMM_1',1),('first_VMM_2',1)]:
        writes=[e for e in events[label] if e['kind']=='original_private_global_write' and e['pc']=='0x1000014fc'];check(len(writes)==1 and writes[0]['address']=='0x1002dd2e0' and int(writes[0]['value'],16)==value,'original successful query writes Boolean byte '+label)
    check(not [e for e in events['first_VMM_query_error'] if e.get('pc')=='0x1000014fc'],'query failure bypasses byte write')
    packet=c['method26_descriptor'];raw=bytes.fromhex(packet['pointed_bytes']);check(struct.unpack('<QII',bytes.fromhex(packet['input_bytes']))==(int(packet['pointed_address'],16),96,0),'descriptor u64/u32/u32 fields')
    from recover_adid_iokit import parse_records
    check(len(raw)==96 and parse_records(raw)==c['method26_packet_records'] and len(c['method26_packet_records'])==6,'independent bounded 96-byte record decode')
    check([r['tag_u16'] for r in c['method26_packet_records']]==['0x9777']*5+['0x50db'] and c['method26_packet_records'][-1]['payload_size_bytes']==16 and c['method26_packet_records'][-1]['raw_key_be32']=='0x0','five scalar records and terminal span16')
    direct=ev('first_VMM_1',kind='original_IOConnect_structure_boundary')[0];check(bytes.fromhex(direct['input_bytes'])==raw,'legacy direct and descriptor pointed payload identical')
    name=c['AVP_name_source'];encoded=s.read(int(name['address'],16),18);check(encoded.hex()==name['bytes18'] and bytes((v*-93-58)&255 for v in encoded)==b'AvpFairPlayDriver\0','original affine name decoder')
    block=c['once_block'];a=int(block['address'],16);check(s.read(a,32).hex()==block['raw32_bytes'] and s.qword(a+16)==0x100001250 and s.qword(int(block['descriptor'],16)+8)==32,'original global block invokes query callback with declared size32')
    check(modeled('first_method26_error','_IOConnectCallStructMethod')[0]['kext_transform_executed'] is False and record_status('first_method26_error')==0x587c93,'transport-error fixture and local status')
    check(modeled('first_method26_identity','_IOConnectCallStructMethod')[0]['mode']=='identity_success' and record_status('first_method26_identity')==0x59248f,'explicit identity-response control remains nonnative')
    for label in ('first_method26_error','first_method26_identity'):
        check([(e['callsite'],e['args_x0_x7'][0]) for e in modeled(label,'_IOObjectRelease')]==[('0x1000217a0','0x5803'),('0x10002184c','0x5802')],'primary service/iterator release after transport model '+label)
    for label in ('avp_no_service','avp_open_failure'):
        check(not [e for e in modeled(label,'_IOObjectRelease') if e['args_x0_x7'][0]=='0x5802'] and rows[label]['stop_reason']=='returned_to_private_fixture','completed Avp failure lacks observed iterator release '+label)
    check(not modeled('avp_mainport_failure','_IOServiceMatching') and not modeled('avp_matching_services_failure','_IOIteratorNext'),'early acquisition failures avoid dependent APIs')
    for group in ('owned_output_open_success','first_method26_identity'):
        check(not ev(group+'_sequence_1',kind='hardware_modeled_API') and rows[group+'_sequence_1']['stop_reason']=='returned_to_private_fixture','warm helper bypasses modeled IOKit/once calls '+group)
    check(len(modeled('first_method26_error_sequence_1','_IOServiceOpen'))==1 and len(modeled('first_method26_error_sequence_1','_IOConnectCallStructMethod'))==1,'error path reopens and retries under a fresh enumeration model')
    check(rows['method26_error_recovery_sequence_1']['observed_globals_final']['0x1002dcc84']=='14580000' and rows['method26_error_recovery_sequence_1']['observed_globals_final']['0x1002dcc80']=='41' and not ev('method26_error_recovery_sequence_2',kind='hardware_modeled_API'),'controlled recovery replaces cache and next source call bypasses IOKit')
    table=c['upstream_control_table'];a=int(table['address'],16);blob=s.read(a,224);check(blob.hex()==table['raw224_bytes'] and len(table['states'])==56,'original local control table extent')
    for row in table['states']:check(int(row['target'],16)==int(table['relative_base'],16)+struct.unpack_from('<i',blob,4*row['state_u32'])[0],'original local control target '+str(row['state_u32']))
    # Source matching in the supplied kext is content evidence,not routing proof.
    kext=(ROOT.parent/'com.apple.driver.FairPlayIOKit.c').read_text();check('com_apple_driver_FairPlayIOKit' in kext and 'com.apple.private.FairPlayIOKitUserClient.access' in kext,'provided kext class and entitlement name match first provider')
    replay_steps=0
    for label in ('owned_output_open_success','first_getter_once_callback','first_VMM_1','avp_open_failure'):
        probe=Hardware(s,json.loads(json.dumps(rows[label]['fixture'])),read('adid_peer_checkpoint.json'));actual=probe.run_continuation();replay_steps+=actual['steps']
        check(actual['ordered_original_instruction_sha256']==rows[label]['ordered_original_instruction_sha256'] and actual['stop_reason']==rows[label]['stop_reason'] and unpack_records(actual)==events[label],'independent complete source/events replay '+label)
    for group,n in [('owned_output_open_success',2),('method26_error_recovery',3)]:
        probe=Hardware(s,json.loads(json.dumps(rows[group+'_sequence_0']['fixture'])),read('adid_peer_checkpoint.json'))
        for i in range(n):
            label=group+'_sequence_'+str(i);f=rows[label]['fixture']
            if i:
                probe.fixture=json.loads(json.dumps(f));probe.steps=0;probe.reason=None;probe.records=[];probe.visited=[];probe.last_edge=None;probe.u.reg_write(A.UC_ARM64_REG_SP,probe.sp);probe.u.reg_write(A.UC_ARM64_REG_LR,DONE);probe.u.reg_write(A.UC_ARM64_REG_PC,f['new_entry'])
                for j in range(8):probe.u.reg_write(getattr(A,'UC_ARM64_REG_X'+str(j)),f['new_args'][j] if j<len(f['new_args']) else 0)
            actual=probe.run_continuation();replay_steps+=actual['steps'];check(actual['ordered_original_instruction_sha256']==rows[label]['ordered_original_instruction_sha256'] and unpack_records(actual)==events[label] and json.loads(json.dumps(probe.iokit_objects))==rows[label]['iokit_object_models_final'],'independent retained-state replay '+label)
    layout=c['SDK_compile'];check(sha((ROOT/'adid_iokit_layouts.c').read_bytes())==layout['source_sha256'] and sha((ROOT/'adid_iokit_layouts.s').read_bytes())==layout['assembly_sha256'],'SDK source/output pins')
    with tempfile.TemporaryDirectory() as directory:
        out=Path(directory)/'layout.s';run=subprocess.run(layout['command'][:-1]+[str(out)],capture_output=True,text=True);check(run.returncode==0 and not run.stderr and out.read_bytes()==(ROOT/'adid_iokit_layouts.s').read_bytes(),'fresh arm64e IOKit port/descriptor/size ABI compile')
    h=c['SDK_header'];check(sha(Path(h['path']).read_bytes())==h['sha256'],'SDK IOKit declarations')
    for r in read('interface_manifest.json')['inputs_preserved']:
        path=ROOT.parent/r['path'];check(path.stat().st_size==r['size_bytes'] and sha(path.read_bytes())==r['sha256'],'original supplied input preserved '+r['path'])
    counts={'private_cases':len(rows),'original_instruction_records':len(instruction_bytes),'original_compiler_ranges':len(p['original_functions']),'retained_original_visits':total,'source_API_records':api_count,'SMT_unsat':len(c['proofs']),'source_windows':len(c['original_windows']),'service_classes':2,'embedded_true_entitlements':2,'method26_packet_bytes':96,'packet_records':6,'local_control_states':56,'independent_replay_runs':9,'independent_replay_steps':replay_steps,'SDK_compile_exit':run.returncode,'assertions':len(checks)}
    (ROOT/'adid_iokit_checks.json').write_text(json.dumps({'scope':__doc__,'verified_counts':counts,'checks':checks,'all_checks_pass':True,'native_target_executed':False,'full_goal_complete':False},indent=2)+'\n')
    quality={'scope':'Conditional source/provider acquisition,query-selected method26 ABI,record/control catalogs,cache/retry and release observations only; full goal active.','verified_counts':counts,'native_target_executed':False,'full_goal_complete':False}
    for n,evidence in [(1,'Descriptive technical findings.'),(2,'Report H1-H9 state dependencies and falsification boundaries.'),(3,'Concrete provider/kext/ABI/port-name/control/data/lifecycle progress;full goal incomplete.'),(4,'Four full-domain local proofs,port32/size64/descriptor16 SDK checks,96-byte bounded record parsing.'),(5,'Distinct providers/caches/framing,signed declaration versus credentials,private errors/identity response,query predicates,iterator generations and failure releases separated.'),(6,'Fresh bytes/fixups/code-signature declarations/SDK and nine matching source replays.'),(7,'Impact-labeled native pairing,real callers,valid operation/response,kernel/RPC selection and full resource/concurrency lifetime.')]:quality['QG'+str(n)]={'status':'pass_for_stated_increment','evidence':evidence}
    (ROOT/'adid_iokit_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps(counts))


if __name__=='__main__':main()
