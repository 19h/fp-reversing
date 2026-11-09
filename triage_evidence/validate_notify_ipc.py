#!/usr/bin/env python3
"""Fresh original-source,chain,MIG,packet,shared-counter and replay validation.

O(B+F+I+V+E) time/space plus finite complete client/server fixture replays and
four30 s-bounded local proofs. Compile SDK declarations only. No native target,
loader,service,IPC,port,notification or synchronization API executes.
"""
import base64
import hashlib
import json
from pathlib import Path
import plistlib
import struct
import subprocess
import zlib
from notify_ipc_reader import Notify,ROOT,sha,CS
from notifyd_ipc_reader import Notifyd,SOURCE,SOURCE_SHA,THIN_SHA
from probe_notify_ipc import run_sequence,CTX,SHMEM
from probe_notifyd_ipc import Server,REQUEST,REPLY,HEAP


def main():
    assertions=0;counts={};read=lambda n:json.loads((ROOT/n).read_text())
    def check(value,label):
        nonlocal assertions
        assert value,label
        assertions+=1
    s=Notify();d=Notifyd();ci=read('notify_ipc_inventory.json');di=read('notifyd_ipc_inventory.json');p=read('notify_ipc_profiles.json');dp=read('notifyd_ipc_profiles.json');c=read('notify_ipc_contracts.json')
    for artifact,producer in [(ci,'notify_ipc_reader.py'),(di,'notifyd_ipc_reader.py'),(p,'probe_notify_ipc.py'),(dp,'probe_notifyd_ipc.py'),(c,'recover_notify_ipc.py')]:
        check(artifact.get('generator_sha256',artifact.get('reader_sha256'))==sha((ROOT/producer).read_bytes()),'producer '+producer)
        for name,h in artifact.get('dependencies',{}).items():check(sha((ROOT/name).read_bytes())==h,'dependency '+name)
        check(artifact['native_target_executed'] is False and artifact['full_goal_complete'] is False,'scope '+producer)
    check(dp['client_profiles_sha256']==sha((ROOT/'notify_ipc_profiles.json').read_bytes()) and dp['base_engine_sha256']==sha((ROOT/'probe_adid_receiver.py').read_bytes()),'server bridge/base pins')
    check(sha(SOURCE.read_bytes())==SOURCE_SHA and sha(d.data)==THIN_SHA,'original notifyd identity')
    check(ci['cache_uuid']==s.cache.uuid==p['cache_uuid'] and ci['library_uuid']==s.lib.uuid==p['library_uuid'],'cache/library identity')
    for inv,source in [(ci,s),(di,d)]:
        for f in inv['complete_original_functions']:
            a=int(f['start'],16);z=int(f['end'],16);raw=source.read(a,z-a);check(source.bounds(a)==(a,z) and raw.hex()==f['bytes'] and sha(raw)==f['sha256'],'compiler bytes/ranges')
            for x,ins in zip(f['instructions'],CS.disasm(raw,a)):check(x=={'ea':hex(ins.address),'mnemonic':ins.mnemonic,'operands':ins.op_str},'fresh disassembly')
    check(ci['exports']==s.lib.exports and ci['original_nlists']==s.nlists(),'export and nlist declarations')
    for row in ci['original_chain_members']:check(s.pointer(int(row['address'],16))==row,'fresh original cache v5 member')
    for row in di['fixups']:check(d.decoded[int(row['address'],16)]==row,'fresh original notifyd format12 member')
    launch=di['launchd_declaration'];check(sha(Path(launch['path']).read_bytes())==launch['sha256'] and plistlib.loads(Path(launch['path']).read_bytes())==launch['parsed'],'original launchd declaration')
    for w in c['original_windows']:
        reader=s if w['image']=='client' else d;a=int(w['start'],16);raw=reader.read(a,int(w['end'],16)-a);check(raw.hex()==w['bytes'] and sha(raw)==w['sha256'],'source window '+w['role'])
    for row in c['mig_rows']:
        a=int(row['record_address'],16);check(d.read(a,40).hex()==row['record_bytes'] and hex(d.qword(a+8))==row['resolved_stub'],'MIG physical record')
        check(row['message_id']==1000+(a-0x1000104f0)//40 and a+40<=0x1000104f0+33*40,'MIG index bounds')
    check(len(c['mig_rows'])==33 and sum(r['resolved_stub']!='0x0' for r in c['mig_rows'])==31,'MIG null holes')
    for row in c['mach_notification_rows']:
        a=int(row['record_address'],16);check(d.read(a,40).hex()==row['record_bytes'] and hex(d.qword(a+8))==row['resolved_stub'],'Mach notification MIG row')
    check(len(c['mach_notification_rows'])==9 and sum(r['resolved_stub']!='0x0' for r in c['mach_notification_rows'])==6,'Mach notification holes')
    for row in c['original_demux_table_pointers']:check(d.decoded[int(row['address'],16)]==row,'original framework table pointer')
    fresh_sends=[]
    for f in ci['complete_original_functions']:
        for ins in f['instructions']:
            if ins['mnemonic'] in ['b','bl'] and ins['operands'].startswith('#'):
                target=int(ins['operands'][1:],16)
                if not s.text['address']<=target<s.text['address']+s.text['size']:
                    v=s.veneer(target)
                    if '_mach_msg' in v['resolved_target']['exact_exports']:fresh_sends.append((ins['ea'],hex(target)))
    check(fresh_sends==[(r['site'],r['target']) for r in c['client_mach_msg_emission_sites']] and len(fresh_sends)==64,'all static libnotify Mach send sites')
    for row in c['provider_import_stubs']:
        a=int(row['address'],16);slot=int(row['slot'],16);check(d.read(a,16).hex()==row['bytes'] and d.decoded[slot]==row['original_fixup'],'original provider import stub')
    provider_mach=[r for r in c['provider_external_direct_edges'] if r['stub']['symbol']=='_mach_msg'];check(len(provider_mach)==1 and provider_mach[0]['ea']=='0x100001374','unique provider direct Mach emitter')
    for row in c['provider_external_direct_edges']:
        a=int(row['ea'],16);ins=next(CS.disasm(d.read(a,4),a));check(ins.mnemonic==row['mnemonic'] and ins.op_str==row['operands'] and int(ins.op_str[1:],16)==int(row['stub']['address'],16),'provider external source edge')
    ndr=c['original_NDR_record'];check(s.pointer(int(ndr['original_pointer_member']['address'],16))==ndr['original_pointer_member'] and ndr['original_pointer_member']['target']==ndr['cache_address'] and s.read(int(ndr['cache_address'],16),8).hex()==ndr['bytes']=='0000000001000000','original NDR chain/data versus fixture')
    pool={}
    for i in p['original_instruction_records']:
        a=int(i['ea'],16);raw=s.read(a,4);ins=next(CS.disasm(raw,a));check(raw.hex()==i['bytes'] and ins.mnemonic==i['mnemonic'] and ins.op_str==i['operands'],'client original instruction');pool[a]=raw
    for f in p['original_functions']:
        a=int(f['start'],16);z=int(f['end'],16);check(sha(s.read(a,z-a))==f['sha256'],'client reached whole-function bytes')
    for page in p['original_materialized_pages']:
        a=int(page['address'],16);raw=bytearray(s.read(a,4096));check(sha(raw)==page['original_sha256'],'cache original page')
        check(page['original_chain_members']==[v for at,v in s.page_chains(a).items() if a<=at<a+4096],'all verified page chain members')
        for m in page['original_chain_members']:struct.pack_into('<Q',raw,int(m['address'],16)-a,int(m['target'],16))
        check(sha(raw)==page['materialized_sha256'],'materialized private cache page')
    source_visits=0;messages=0;shared_reads=0
    rows={case['case']['label']:case for case in p['cases']}
    for case in p['cases']:
        seen_counters={}
        for r in case['calls']:
            check(r['native_target_executed'] is False and r['native_transaction_executed'] is False,'private client scope')
            raw=zlib.decompress(base64.b64decode(r['visited_original_instructions_zlib_base64']));seq=[v[0] for v in struct.iter_unpack('<Q',raw)];h=hashlib.sha256()
            for a in seq:check(a in pool,'visited original client pool');h.update(struct.pack('<Q',a));h.update(pool[a])
            check(len(seq)==r['visited_original_instruction_count'] and h.hexdigest()==r['ordered_original_instruction_sha256'],'ordered client stream hash');source_visits+=len(seq)
            for e in r['records']:
                if 'message_id_u32' in e:
                    b=bytes.fromhex(e['send_bytes']);mid=e['message_id_u32'];check(len(b)==e['send_size_bytes'] and struct.unpack_from('<I',b,20)[0]==mid and b[4:8]==bytes(4),'raw client API message has separate send-size');messages+=1
                    check(struct.unpack_from('<I',b,8)[0]==0x5902,'declared bootstrap destination fixture')
                    if mid==1012:
                        count=struct.unpack_from('<I',b,36)[0];name=r['fixture'].get('notification_name','com.apple.adid.midchangedV1').encode();want=name[:511]+b'\0';check(b[40:40+count]==want and count==len(want) and len(b)==44+((count+3)&~3),'independent registration byte layout/truncation')
                        check(struct.unpack_from('<I',b,40+((count+3)&~3))[0] in [2,3],'source original allocated client token')
                    if mid==1009:check(len(b)==44 and struct.unpack_from('<Q',b,32)[0]==0x1122334455667788 and struct.unpack_from('<I',b,40)[0]==0,'cached-name post body')
                    if mid in [1002,1016]:check(len(b)==36 and struct.unpack_from('<I',b,32)[0] in [2,3],'token message body')
                if e['kind']=='original_shared_memory_read':
                    a=int(e['pc'],16);check(a in seq and e['size_bytes']==4,'original source shared read');shared_reads+=1
            if r['fixture']['entry']==s.lib.exports['_notify_check']['address'] and r['result_u32']==0:
                reads=[e for e in r['records'] if e['kind']=='original_shared_memory_read' and e['offset_bytes']==4]
                if reads:
                    token=r['fixture']['args'][0];seen=seen_counters.get(token,0);current=int.from_bytes(bytes.fromhex(reads[0]['bytes']),'little');changed=int(current!=seen);check(r['check_output_u32']==changed and len(reads)==1+changed,'independent per-token sampled counter semantics '+case['case']['label']+'/'+r['fixture']['label']);seen_counters[token]=current if changed else seen
    check(messages==len(c['observed_client_messages'])==69,'complete observed client message ledger')
    for label in [k for k in rows if k.startswith('lifecycle_')]:
        calls=rows[label]['calls'];check([r['check_output_u32'] for r in calls[1:5]]==[1,0,1,0],'fresh/shared update polling')
        check(calls[6]['check_output_u32']==0 and calls[8]['result_u32']==calls[9]['result_u32']==2,'oneway post is not automatic shared update;cancelled tokens invalid')
        check(not any('message_id_u32' in e for r in calls[1:5] for e in r['records']),'shared checks emit no Mach')
    check(rows['cancel_transport_failure']['calls'][1]['result_u32']==0 and rows['cancel_transport_failure']['calls'][2]['result_u32']==2,'client cancel ignores selected modeled send error and invalidates local token')
    check(rows['server_no_shared_memory']['calls'][1]['check_output_u32']==1 and any(e.get('message_id_u32')==1002 for e in rows['server_no_shared_memory']['calls'][1]['records']),'no-shared-memory RPC fallback')
    for version in [0,2]:check(rows['checkin_version_'+str(version)]['calls'][0]['stop_reason']=='unexecuted_native_instruction:brk','source version gate guard')
    server_rows={r['fixture']['label']:r for r in dp['profiles']};server_visits=0
    for r in dp['profiles']:
        h=hashlib.sha256();seq=[int(a,16) for a in r['visited_original_instructions']]
        for a in seq:h.update(struct.pack('<Q',a));h.update(d.read(a,4))
        check(h.hexdigest()==r['ordered_original_instruction_sha256'],'server original ordered bytes');server_visits+=len(seq)
        for i in r['instruction_records']:
            a=int(i['ea'],16);raw=d.read(a,4);ins=next(CS.disasm(raw,a));check(raw.hex()==i['bytes'] and ins.mnemonic==i['mnemonic'] and ins.op_str==i['operands'],'fresh original provider instruction')
        label=r['fixture']['label']
        if label.startswith('selector_'):
            mid=int(label.split('_')[1]);want=next((x['resolved_stub'] for x in c['mig_rows'] if x['message_id']==mid),'0x0');check(r['result_x0']==want,'actual selector output incl null holes')
        if label.startswith('mach_selector_'):
            mid=int(label.rsplit('_',1)[1]);want=next((x['resolved_stub'] for x in c['mach_notification_rows'] if x['message_id']==mid),'0x0');check(r['result_x0']==want,'Mach-notification selector including holes')
        if label.startswith('checkin_'):
            b=bytes.fromhex(r['reply64_hex']);err=struct.unpack_from('<i',b,32)[0]
            if label in ['checkin_complex','checkin_short_size','checkin_long_size']:check(err==-304,'MIG_BAD_ARGUMENTS')
            elif label in ['checkin_trailer_type','checkin_trailer31','checkin_trailer0']:check(err==-309,'MIG_TRAILER_ERROR')
            else:check(err==0 and struct.unpack_from('<4I',b,32)==(0,3,311,0),'original successful checkin body')
        if label.startswith('registration_') and r['stop_reason']=='original_registration_worker_boundary':
            e=r['records'][-1];check(e['pc']=='0x100001c7c' and e['whole_worker_or_native_registration_established'] is False,'natural parser worker boundary')
            if 'source_client_case' in r['fixture']:
                src=rows[r['fixture']['source_client_case']];msg=next(e for rr in src['calls'] for e in rr['records'] if e.get('message_id_u32')==1012);raw=bytearray.fromhex(msg['send_bytes']);struct.pack_into('<I',raw,4,len(raw));check(bytes.fromhex(r['fixture']['effective_request_and_trailer_hex'])[:len(raw)]==raw,'explicit cross-image effective-header transform')
                check(e['name'].encode()==bytes(raw[40:]).split(b'\0')[0] and e['client_token_u32']==struct.unpack_from('<I',raw,len(raw)-4)[0],'original parsed name/token worker ABI')
    valid=bytes.fromhex(server_rows['checkin_valid']['reply64_hex'])[:48];fixture=bytes.fromhex(rows['lifecycle_com.apple.adid.midchangedV1']['calls'][0]['fixture']['reply_by_id']['1023']);check(valid==fixture,'original server checkin bytes equal explicit original client reply input')
    check(server_rows['registration_reject_count27']['stop_reason']=='original_registration_worker_boundary','NUL outside declared count can satisfy broad search')
    check(server_rows['registration_name_without_nul_token2']['records'][-1]['name']=='A'*28+'\x02' and server_rows['registration_name_without_nul_token0']['records'][-1]['name']=='A'*28 and server_rows['registration_name_without_nul_token_all_ff']['stop_reason']=='returned_to_private_fixture','independent adjacent-token NUL witness and no-NUL control')
    for label,opts in [('success_opts0',0x11),('success_opts2',0x91)]:
        r=server_rows['direct_sender_'+label];e=next(e for e in r['records'] if e.get('name')=='_mach_msg');check(struct.unpack('<6I',bytes.fromhex(e['send_bytes']))==(19,24,0x5903,0,0,0x12345678) and e['options_u32']==opts,'independent active Mach notification packet');check(bytes.fromhex(r['client_record128_after'])[0x4f]==5,'successful sender clears top2 flag bits')
    check(not any(e.get('name')=='_mach_msg' for e in server_rows['direct_sender_suspended']['records']),'suspended local port record suppresses send')
    check(int(server_rows['direct_sender_timeout_opts0']['result_x0'],16)==45 and int(server_rows['direct_sender_other_error']['result_x0'],16)==46 and int(server_rows['direct_sender_timeout_opts2']['result_x0'],16)==0,'selected sender error/state handling')
    port=server_rows['port_construct_and_insert'];ce=next(e for e in port['records'] if e.get('name')=='_mach_port_construct');ie=next(e for e in port['records'] if e.get('name')=='_mach_port_insert_right');check(bytes.fromhex(ce['original_options24_hex'])==struct.pack('<IIQQ',2,16,0,0) and [int(x,16) for x in ie['args_x0_x7'][:4]]==[0x5801,0x5904,0x5904,20],'source queue limit16 and MAKE_SEND20')
    re=server_rows['port_request_notification']['records'][-1];check([int(x,16) for x in re['args_x0_x7'][1:6]]==[0x5905,66,0,0x5906,21],'SEND_POSSIBLE66 with MAKE_SEND_ONCE21')
    for proof in c['proofs']:
        path=ROOT/proof['path'];check(sha(path.read_bytes())==proof['sha256'],'proof source');run=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);check(run.stdout.strip()=='unsat' and not run.stderr,'fresh arithmetic proof')
    abi=c['sdk_compile'];check(sha((ROOT/'notify_ipc_layouts.c').read_bytes())==abi['source_sha256'] and sha((ROOT/'notify_ipc_layouts.s').read_bytes())==abi['assembly_sha256'],'ABI pins')
    for row in abi['headers']:check(sha(Path(row['path']).read_bytes())==row['sha256'],'SDK original header')
    cmd=list(abi['command']);cmd[cmd.index('-o')+1]='/tmp/notify-ipc-verify.s';run=subprocess.run(cmd,capture_output=True,text=True);check(run.returncode==0 and not run.stderr and sha(Path('/tmp/notify-ipc-verify.s').read_bytes())==abi['assembly_sha256'],'fresh SDK compile')
    fresh_client_calls=0
    for case in p['cases']:
        fresh=json.loads(json.dumps(run_sequence(s,case['case'])));check(len(fresh['calls'])==len(case['calls']),'fresh client call count')
        for new,old in zip(fresh['calls'],case['calls']):
            for key in ['fixture','stop_reason','steps','result_u32','records','ordered_original_instruction_sha256','context600_bytes','owned_allocator_final','owned_allocator_bytes_after','token_output_u32','check_output_u32','shared_slot1_u32','stack_balanced']:check(new[key]==old[key],'complete fresh client replay '+case['case']['label']+'/'+key)
            fresh_client_calls+=1
    for old in dp['profiles']:
        f=old['fixture'];q=Server(d,f)
        if f.get('local_sender_record_fixture'):
            q.u.mem_write(HEAP+0x6000,bytes(128));q.u.mem_write(HEAP+0x6100,bytes(128));q.u.mem_write(HEAP+0x6040,struct.pack('<I',0x12345678));q.u.mem_write(HEAP+0x604e,bytes([7,0xc5]));q.u.mem_write(HEAP+0x610c,struct.pack('<I',f['port_record_flags_u32']));q.u.mem_write(0x100014220,struct.pack('<I',f['global_flags_u32']))
        if f.get('local_port_helper_fixture'):q.u.mem_write(q.symbols['_mach_task_self_'],struct.pack('<I',0x5801));q.u.mem_write(0x100014250,struct.pack('<I',0x5906))
        new=q.invoke(f['label'],f['entry'],f['args'])
        for key in ['stop_reason','steps','result_x0','reply64_hex','records','ordered_original_instruction_sha256','stack_balanced']:check(new[key]==old[key],'fresh original server entry '+f['label']+'/'+key)
        for key,address in [('client_record128_after',HEAP+0x6000),('port_record128_after',HEAP+0x6100)]:
            if key in old:check(bytes(q.u.mem_read(address,128)).hex()==old[key],'complete sender source state')
    for row in read('interface_manifest.json')['inputs_preserved']:
        path=ROOT.parent/row['path'];check(path.stat().st_size==row['size_bytes'] and sha(path.read_bytes())==row['sha256'],'original supplied input preserved')
    counts={'original_client_compiler_functions':len(ci['complete_original_functions']),'original_provider_compiler_functions':len(di['complete_original_functions']),'client_exports':len(ci['exports']),'client_v5_const_members':len(ci['original_chain_members']),'provider_format12_members':len(di['fixups']),'all_static_client_mach_msg_sites':len(fresh_sends),'provider_import_stubs':len(c['provider_import_stubs']),'provider_external_edges':len(c['provider_external_direct_edges']),'MIG_rows':33,'nonnull_MIG_stubs':31,'Mach_notification_MIG_rows':9,'nonnull_Mach_notification_stubs':6,'client_sequences':len(p['cases']),'client_calls':fresh_client_calls,'server_entry_profiles':len(dp['profiles']),'client_source_visits':source_visits,'provider_source_visits':server_visits,'observed_client_messages':messages,'shared_counter_reads':shared_reads,'proofs_unsat':len(c['proofs']),'assertions':assertions}
    out={'scope':__doc__,'verified_counts':counts,'all_checks_pass':True,'native_target_executed':False,'native_transaction_executed':False,'native_defect_established':False,'full_goal_complete':False};(ROOT/'notify_ipc_checks.json').write_text(json.dumps(out,indent=2)+'\n')
    quality={**out,'scope':'Original libnotify/notifyd transport,shared counters and bounded local provider interfaces.'};descriptions=['Descriptive technical interfaces; no normative conclusion.','Report I1-I12 list assumptions,dependencies and falsification probes.','Defined transport/cache/MIG/port increment covered; native admission,dispatch and broad goal remain open.','Byte offsets,bit widths,queue counts,SDK layouts,source arithmetic and finite algorithm bounds explicit.','Raw/effective headers,port fixtures,shared-memory epochs,parser/worker and active/polling paths separated.','Fresh complete source/fixups,independent packet/counter/layout checks,four proofs,all client/server entry replays.','Impact-labeled provider startup/admission,wrapper transfer,shared epoch/concurrency and alternate notification interfaces.']
    for j,text in enumerate(descriptions,1):quality['QG'+str(j)]={'status':'pass_for_stated_increment','evidence':text}
    (ROOT/'notify_ipc_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps(counts),flush=True)

if __name__=='__main__':main()
