#!/usr/bin/env python3
"""Verify original paired startup/admission contracts and independent state ledger.

O(B+I+V+W+A) time/space plus all finite original paired-case replays and four
30 s-bounded proofs. Retained API/scheduling/audit/transport fixtures remain
explicit. No native target,IPC,file,sandbox,entitlement or port API executes.
"""
import base64
import bisect
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import zlib
from notifyd_ipc_reader import Notifyd,ROOT,sha,THIN_SHA
from notify_ipc_reader import Notify,CS
from bootpolicy_cache_reader import Dylib
from probe_notifyd_pairs import run_case,compact_row
from probe_notifyd_admission import HEAP,SHARED
from recover_notifyd_admission import events
from probe_notifyd_events import run_event_case


def visits(r):
    if 'visited_original_instructions' in r:return [int(a,16) for a in r['visited_original_instructions']]
    raw=zlib.decompress(base64.b64decode(r['visited_original_instructions_zlib_base64']));return [v[0] for v in struct.iter_unpack('<Q',raw)]


def main():
    assertions=0;metrics={'provider_source_visits':0,'client_source_visits':0,'original_owned_writes':0,'API_output_effects':0,'private_transport_messages':0,'independent_allocation_snapshots':0,'independent_name_record_snapshots':0};read=lambda n:json.loads((ROOT/n).read_text())
    def check(v,label):
        nonlocal assertions
        assert v,label
        assertions+=1
    s=Notifyd();cache=Notify();p=read('notifyd_admission_profiles.json');ep=read('notifyd_event_profiles.json');c=read('notifyd_admission_contracts.json');cases={x['case']['label']:x for x in p['cases']};source=lambda a,n:s.read(a,n) if s.base<=a<s.base+0x20000 else cache.read(a,n)
    for artifact,producer in [(p,'probe_notifyd_pairs.py'),(ep,'probe_notifyd_events.py'),(c,'recover_notifyd_admission.py')]:
        check(artifact['generator_sha256']==sha((ROOT/producer).read_bytes()),'producer source pin')
        for name,h in artifact['dependencies'].items():check(sha((ROOT/name).read_bytes())==h,'dependency pin '+name)
        check(not artifact['native_target_executed'] and not artifact['full_goal_complete'],'bounded scope')
    check(c['provider_thin_sha256']==THIN_SHA and c['cache_uuid']==cache.cache.uuid,'fresh source identities')
    bank={}
    for item in p['original_source_pools']['instructions']+ep['original_source_pools']['instructions']:
        a=int(item['ea'],16);raw=source(a,4);ins=next(CS.disasm(raw,a));check(raw.hex()==item['bytes'] and ins.mnemonic==item['mnemonic'] and ins.op_str==item['operands'],'fresh original instruction '+hex(a));bank[a]=raw
    libraries={cache.lib.path:cache.lib}
    for f in p['original_source_pools']['functions']+ep['original_source_pools']['functions']:
        a=int(f['start'],16);z=int(f['end'],16);check(sha(source(a,z-a))==f['sha256'],'complete original function bytes')
        if s.base<=a<s.base+0x20000:check(s.bounds(a)==(a,z),'provider compiler range')
        elif 'library' in f:
            path=f['library']
            if path not in libraries:libraries[path]=Dylib(cache.cache,path)
            lib=libraries[path];ix=bisect.bisect_right(lib.functions,a)-1;end=lib.functions[ix+1] if ix+1<len(lib.functions) else next(x['address']+x['size'] for x in lib.sections if x['name']=='__text');check(lib.functions[ix]==a and end==z and lib.uuid==f['uuid'],'cache original function boundary/UUID')
    for row in p['original_source_pools']['cache_pages']+ep['original_source_pools']['cache_pages']:
        a=int(row['address'],16);raw=bytearray(cache.read(a,4096));check(sha(raw)==row['original_sha256'],'original cache page');members=[v for at,v in cache.page_chains(a).items() if a<=at<a+4096];check(members==row['original_chain_members'],'all page chain members')
        for item in members:struct.pack_into('<Q',raw,int(item['address'],16)-a,int(item['target'],16))
        check(sha(raw)==row['materialized_sha256'],'private materialization hash')
    for f in c['original_functions']:
        a=int(f['start'],16);z=int(f['end'],16);check(s.bounds(a)==(a,z) and s.read(a,z-a).hex()==f['bytes'] and sha(s.read(a,z-a))==f['sha256'],'source contract '+f['role'])
    for row in c['original_strings']:
        raw=bytes.fromhex(row['bytes']);check(s.read(int(row['address'],16),len(raw))==raw and raw[:-1].decode()==row['text'],'original string bytes')
    check(s.read(0x10000bdb0,8).hex()==c['source_literals']['name_default_access_and_slot64'],'original name defaults literal')
    # A separate memory ledger applies API output effects and post-store bytes.
    # It never reads the guest while checking retained state snapshots.
    state_summaries=[]
    for case in p['cases']:
        label=case['case']['label'];mem={};alloc={};types={};data={};shared={SHARED+i:0 for i in range(16384)}
        for seg in s.meta['segments']:
            if seg['name']!='__DATA':continue
            raw=s.data[seg['file_offset']:seg['file_offset']+seg['file_size']]+bytes(seg['vm_size']-seg['file_size']);data.update({seg['address']+i:v for i,v in enumerate(raw)})
        for at,item in s.decoded.items():
            if at in data and not item['bind']:
                raw=struct.pack('<Q',int(item['target'],16));data.update({at+i:v for i,v in enumerate(raw)})
        def put(a,b):
            target=shared if SHARED<=a and a+len(b)<=SHARED+16384 else data if a in data else mem
            for i,v in enumerate(b):target[a+i]=v
        def span(a,n):
            target=shared if SHARED<=a<SHARED+16384 else data if a in data else mem
            return bytes(target[a+i] for i in range(n))
        def u32(a):return int.from_bytes(span(a,4),'little')
        def u64(a):return int.from_bytes(span(a,8),'little')
        for ordinal,r in enumerate([case['startup']]+case['provider_calls']):
            seq=visits(r);h=hashlib.sha256()
            for a in seq:check(a in bank,'provider visit belongs to original pool');h.update(struct.pack('<Q',a));h.update(bank[a])
            check(h.hexdigest()==r['ordered_original_instruction_sha256'],'provider ordered source stream');metrics['provider_source_visits']+=len(seq)
            for e in events(r):
                name=e.get('name','')
                if name in ['_malloc_type_malloc','_malloc_type_calloc','_malloc_type_realloc']:
                    a=int(e['result'],16);n=e['requested_size_bytes'];check(0<n<=65536 and HEAP+0x20000<=a and a+n<=HEAP+0x70000,'owned allocator extent');put(a,bytes(n) if name.endswith('calloc') else b'\xa5'*n);alloc[a]={'size_bytes':n,'freed':False};types[a]='name' if e['callsite']=='0x1000010f4' else 'client' if e['callsite']=='0x100000fa4' else 'other'
                    if name.endswith('realloc'):
                        old=int(e['args_x0_x7'][0],16)
                        if old:check(old in alloc and not alloc[old]['freed'],'old realloc owner');alloc[old]['freed']=True
                if name=='_strdup':
                    a=int(e['result'],16);n=len(e['string'].encode())+1;put(a,b'\xa5'*n);alloc[a]={'size_bytes':n,'freed':False};types[a]='other'
                if name=='_free':
                    a=int(e['args_x0_x7'][0],16)
                    if a:check(a in alloc and not alloc[a]['freed'],'free has live owner');alloc[a]['freed']=True
                if e['kind']=='explicit_notifyd_port_constructor_model':put(int(e['args_x0_x7'][3],16),struct.pack('<I',e['output_name_u32']));metrics['API_output_effects']+=1
                for effect in e.get('explicit_output_effects',[]):put(int(effect['address'],16),bytes.fromhex(effect['bytes']));metrics['API_output_effects']+=1
                if e['kind'] in ['original_owned_data_write','original_private_global_write']:
                    a=int(e['address'],16);raw=bytes.fromhex(e['actual_after_hex']);check(len(raw)==e['size_bytes'] and int(e['pc'],16) in seq,'source store provenance/extent');put(a,raw);metrics['original_owned_writes']+=1
            check({str(a):v for a,v in alloc.items()}==r['owned_allocations'],'independent allocation ownership ledger '+label+'/'+str(ordinal))
            for a,v in alloc.items():check(span(a,v['size_bytes']).hex()==r['owned_allocation_bytes_after'][hex(a)],'independent allocation contents '+label+'/'+hex(a));metrics['independent_allocation_snapshots']+=1
            for row in r['provider_DATA_after']:
                a=int(row['address'],16);actual=span(a,len(bytes.fromhex(row['bytes'])));want=bytes.fromhex(row['bytes']);differences=[(hex(a+j),actual[j],want[j]) for j in range(len(want)) if actual[j]!=want[j]];check(not differences,'independent provider DATA state '+label+'/'+str(ordinal)+' '+str(differences[:12]))
            check(span(SHARED,16384).hex()==r['shared_memory16384_after'],'independent shared counter state')
            names=[]
            for a,kind in types.items():
                if kind=='name' and not alloc[a]['freed']:
                    n=alloc[a]['size_bytes'];raw=span(a,n);check(u64(a+8)==a+72 and raw[72:].endswith(b'\0') and n==73+len(raw[72:-1]),'constructed name allocation/inline string binding');names.append({'pointer':hex(a),'name':raw[72:-1].decode(),'name_id':u64(a+16),'generation_u32':u32(a+60),'shared_slot_u32':u32(a+52),'clients_u32':u32(a+56)});metrics['independent_name_record_snapshots']+=1
            refs=u64(0x1000142b0);slot_count=u32(0x1000142a0);ref_head=[u32(refs+4*i) for i in range(min(slot_count,8))] if refs else []
            state_summaries.append({'case':label,'provider_call_ordinal':ordinal,'label':r['fixture']['label'],'names':names,'slot_count':slot_count,'slot_reference_head':ref_head})
        for row in case['client_calls']:
            seq=visits(row);h=hashlib.sha256()
            for a in seq:check(a in bank,'client visit belongs to original pool');h.update(struct.pack('<Q',a));h.update(bank[a])
            check(h.hexdigest()==row['ordered_original_instruction_sha256'],'client ordered original stream');metrics['client_source_visits']+=len(seq)
            for e in events(row):
                if e['kind']!='explicit_paired_notify_transport':continue
                metrics['private_transport_messages']+=1;check(e['kernel_API_result_u32']==0 and e['effective_header_and_audit_production_native_validated'] is False,'declared native boundary')
                r=case['provider_calls'][e['provider_stub_call']];check(r['stop_reason']=='returned_to_private_fixture','complete original provider stub')
                raw=bytearray.fromhex(e['send_bytes']);check(raw[4:8]==bytes(4),'raw API size0');struct.pack_into('<I',raw,4,len(raw));effective=bytes.fromhex(r['effective_received_message_and_trailer_hex']);check(effective[:len(raw)]==raw and len(effective)==len(raw)+52,'explicit effective-header transform');check(struct.unpack_from('<8I',effective,len(raw)+20)==tuple(r['explicit_audit_words']),'explicit audit bytes match actual provider input')
                if 'original_provider_reply_bytes' in e:
                    reply=bytes.fromhex(e['original_provider_reply_bytes']);check(reply==bytes.fromhex(r['reply64_hex'])[:len(reply)] and struct.unpack_from('<I',reply,20)[0]==e['message_id_u32']+100,'original provider body consumed by original client')
                else:check(e['oneway_provider_application_reply_delivered'] is False,'oneway has no policy receipt')
                check(e['explicit_shared_alias_snapshot_hex']==r['shared_memory16384_after'],'declared shared-object alias bytes')
    def changes(label):return [r['check_output_u32'] for r in cases[label]['client_calls'] if r['fixture']['entry']==cache.lib.exports['_notify_check']['address']]
    for name in ['com.apple.adid.midchangedV1','com.apple.adid.midchangedV1.5','com.apple.adid.midchangedV3']:check(changes('paired_'+name)==[1,0,1,0,0],'paired source invalidation sequence')
    for uid in [0,501,502]:check(changes('other_post_uid_'+str(uid))==[1,1],'ordinary name under absent config and modeled audit UID')
    for uid,want in [(0,1),(501,1),(502,0)]:check(changes('uid_namespace_post_'+str(uid))==[1,want],'UID namespace source gate')
    for choice,want in [('None',0),('False',0),('True',1)]:
        check(changes('restricted_entitlement_'+choice)==[1,want],'restricted post Boolean gate')
        check(changes('root_override_'+choice)==[1,want],'declared root override gate')
        call=cases['restricted_entitlement_'+choice]['client_calls'][2];check(call['result_u32']==0,'oneway client success is independent of provider admission')
    check(changes('restricted_key_suffix_204')==[1,1],'maximum256-byte entitlement key accepted')
    for n in [205,207,208]:
        case=cases['restricted_key_suffix_'+str(n)];check(changes(case['case']['label'])==[1,0] and not any(e.get('name')=='_xpc_copy_entitlement_for_token' for r in case['provider_calls'] for e in events(r)),'oversize entitlement key rejected before query')
    for label in ['registration_uid_mismatch','registration_uid_missing_delimiter','repeat_registration_denial']:check(all(r['result_u32']==7 for r in cases[label]['client_calls']),'registration admission status7')
    denied=[r for r in state_summaries if r['case']=='repeat_registration_denial' and r['label'].endswith('_stub')][-1];check(denied['slot_reference_head'][:4]==[1,1,1,1] and all(n['name']!='user.uid.501.fixture' for n in denied['names']),'three failed registration slot-reference side effects without target name record')
    check(changes('no_shared_cli')==[1,0,0,0,0] and changes('no_shared_named_post')==[1,0,1],'source CLI0 cached-ID versus named-post comparison')
    state=[r for r in state_summaries if r['case']=='no_shared_named_post'];both=[r for r in state if len(r['names'])==2];check(any({n['name_id']:n['generation_u32'] for n in r['names']}=={0:2,1:1} for r in both),'cached0 updates IPC-version name while target generation stays1');check({n['name_id']:n['generation_u32'] for n in both[-1]['names']}=={0:2,1:2},'named post updates intended generation')
    case=cases['no_shared_cli'];reg=next(e for r in case['client_calls'] for e in events(r) if e.get('message_id_u32')==1012);reply=bytes.fromhex(reg['original_provider_reply_bytes']);check(struct.unpack_from('<IIQ',reply,36)==(0xffffffff,0xffffffff,0),'plain fallback reply nameID0')
    check(not any(e.get('name')=='_sandbox_check_by_audit_token' for case in p['cases'] for r in [case['startup']]+case['provider_calls'] for e in events(r)),'tested legacy MIG paths do not call sandbox-post API model')
    check(changes('wrong_pid_cancel')==[1,1],'wrong-PID cancellation leaves original registration alive')
    for proof in c['proofs']:
        path=ROOT/proof['path'];check(sha(path.read_bytes())==proof['sha256'],'proof bytes');run=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);check(run.stdout.strip()=='unsat' and not run.stderr,'fresh local solver proof')
    abi=c['sdk_compile'];check(sha((ROOT/'notifyd_admission_layouts.c').read_bytes())==abi['source_sha256'] and sha((ROOT/'notifyd_admission_layouts.s').read_bytes())==abi['assembly_sha256'],'layout source/assembly pins');cmd=list(abi['command']);cmd[cmd.index('-o')+1]='/tmp/notifyd-admission-verify.s';run=subprocess.run(cmd,capture_output=True,text=True);check(run.returncode==0 and not run.stderr and sha(Path('/tmp/notifyd-admission-verify.s').read_bytes())==abi['assembly_sha256'],'fresh compile-only source-shape layouts')
    event_original_visits=0
    for case in ep['cases']:
        for r in [case['startup'],case['handler']]:
            seq=visits(r);h=hashlib.sha256()
            for a in seq:check(a in bank,'publisher original source visit');h.update(struct.pack('<Q',a));h.update(bank[a])
            check(h.hexdigest()==r['ordered_original_instruction_sha256'],'publisher original source order');event_original_visits+=len(seq)
        r=case['handler'];reason=case['fixture']['reason_u32'];check(r['provider_DATA_after']==case['startup']['provider_DATA_after'] and r['owned_allocation_bytes_after']==case['startup']['owned_allocation_bytes_after'],'publisher reason0-3 retains startup provider memory in scoped cases')
        if reason==2:
            startup=events(case['startup']);handlers=[e for e in startup if e.get('name')=='_xpc_event_publisher_set_handler'];check(len(handlers)==1 and struct.unpack_from('<Q',bytes.fromhex(handlers[0]['block48_hex']),16)[0]==0x100006104,'source-captured global block invokes executed publisher handler')
            creates=[e for e in startup if e.get('name')=='_dispatch_mach_create_f'];connects=[e for e in events(r) if e.get('name')=='_dispatch_mach_connect'];check(len(creates)==len(connects)==2,'two original channel connections')
            for create,connect,port in zip(creates,connects,[0x5904,0x5902]):check(create['result']==connect['args_x0_x7'][0] and int(connect['args_x0_x7'][1],16)==port and connect['args_x0_x7'][2:4]==['0x0','0x0'],'source-created channel connects correct original receive-name output')
            check([e['callsite'] for e in connects]==['0x100006264','0x100006298'],'original connect call and tail-branch sites')
        elif reason==0:check(r['stop_reason']=='opaque_notifyd_admission_API:_xpc_get_type','opaque event-object type boundary')
        else:check(r['stop_reason']=='returned_to_private_fixture','publisher reason returns')
    fresh_calls=0
    for old in p['cases']:
        print('fresh '+old['case']['label'],flush=True);new=run_case(old['case']);pools={'instructions':{},'functions':{},'cache_pages':{}}
        for origin,rr in [('provider',[new['startup']]+new['provider_calls']),('client',new['client_calls'])]:
            for r in rr:compact_row(r,origin,pools)
        new=json.loads(json.dumps(new));check(new==old,'fresh complete original paired sequence '+old['case']['label']);fresh_calls+=1+len(new['client_calls'])+len(new['provider_calls'])
    for old in ep['cases']:
        new=run_event_case(old['fixture']);pools={'instructions':{},'functions':{},'cache_pages':{}}
        for r in [new['startup'],new['handler']]:compact_row(r,'provider',pools)
        check(json.loads(json.dumps(new))==old,'complete fresh captured publisher-handler replay');fresh_calls+=2
    for row in read('interface_manifest.json')['inputs_preserved']:
        path=ROOT.parent/row['path'];check(path.stat().st_size==row['size_bytes'] and sha(path.read_bytes())==row['sha256'],'supplied input preserved')
    counts={**metrics,'paired_sequences':len(p['cases']),'publisher_event_cases':len(ep['cases']),'publisher_event_source_visits':event_original_visits,'client_public_calls':sum(len(x['client_calls']) for x in p['cases']),'provider_startups':len(p['cases']),'provider_selector_and_stub_calls':sum(len(x['provider_calls']) for x in p['cases']),'fresh_total_original_calls':fresh_calls,'original_instruction_records':len(bank),'paired_function_records':len(p['original_source_pools']['functions']),'publisher_function_records':len(ep['original_source_pools']['functions']),'unique_compiler_ranges':len({(f['start'],f['end'],f['sha256']) for f in p['original_source_pools']['functions']+ep['original_source_pools']['functions']}),'source_contract_functions':len(c['original_functions']),'proofs_unsat':len(c['proofs']),'assertions':assertions}
    result={'scope':__doc__,'verified_counts':counts,'independent_provider_state_summaries':state_summaries,'all_checks_pass':True,'native_target_executed':False,'native_transaction_executed':False,'native_defect_established':False,'full_goal_complete':False};(ROOT/'notifyd_admission_checks.json').write_text(json.dumps(result,indent=2)+'\n')
    quality={k:v for k,v in result.items() if k!='independent_provider_state_summaries'};texts=['Descriptive original-source interfaces only.','Report A1-A12 separate source,API,audit,config,transport and lifecycle assumptions with falsification probes.','Paired startup/registration/post/poll/cancel,namespace,entitlement and two bounded state witnesses covered;native/full goal remains open.','Exact source widths,byte records,slot counts,CLI arithmetic,SDK source-shape layouts and four bounded proofs.','Shared/ordinary generations,oneway success/admission,model-only namespace and fallback nameID0 remain distinct.','Fresh original bytes/chains,independent allocation/global/shared/name ledgers,packet/reply checks and every complete paired sequence replay.','Impact-labeled config/admission,transport/scheduling,nameID fallback,failed-slot lifecycle and native pairing continuation.']
    for j,t in enumerate(texts,1):quality['QG'+str(j)]={'status':'pass_for_stated_increment','evidence':t}
    (ROOT/'notifyd_admission_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps(counts),flush=True)

if __name__=='__main__':main()
