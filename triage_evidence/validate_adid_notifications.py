#!/usr/bin/env python3
"""Fresh original-source,allocation/byte ledger,ABI and event verification.

O(B+F+V+W+R) time/space plus bounded original-code sequence/fragment replays
and seven local solver queries. No target/loader/IPC/notify/time/file API.
Nominal allocator and synthetic reply witnesses are not native defects.
"""
import base64
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import zlib
from akd_client_reader import Akd,ROOT,THIN_SHA as CLIENT_SHA,sha,CS
from adid_reader import Adid,THIN_SHA as PROVIDER_SHA
from probe_adid_notifications import run_case,NAMES,CACHE_START,CACHE_SIZE
from probe_adid_notification_posts import run_one as post_run
from probe_adid_startup import unpack_records

MASK=(1<<32)-1


def visits(r):
    if 'visited_original_instructions' in r:return [int(v,16) for v in r['visited_original_instructions']]
    raw=zlib.decompress(base64.b64decode(r['visited_original_instructions_zlib_base64']));assert len(raw)%8==0;out=[v[0] for v in struct.iter_unpack('<Q',raw)];assert len(out)==r['visited_original_instruction_count'];return out


def trunc30(n):return (abs(n)//30)*(-1 if n<0 else 1)


def notification(dsid):
    if dsid in {x&((1<<64)-1) for x in [-8,-6,-5,-4,-3,-2]}:return NAMES[2]
    return NAMES[1] if dsid==(1<<64)-1 else NAMES[0]


def main():
    checks=[]
    def check(value,label):
        assert value,label
        checks.append(label)
    read=lambda n:json.loads((ROOT/n).read_text());s=Akd();server=Adid();p=read('adid_notification_profiles.json');pp=read('adid_notification_post_profiles.json');c=read('adid_notification_contracts.json');rows={r['case']['label']:r for r in p['cases']};post_rows={r['fixture']['label']:r for r in pp['profiles']}
    check(p['thin_sha256']==c['client_thin_sha256']==CLIENT_SHA and pp['thin_sha256']==c['provider_thin_sha256']==PROVIDER_SHA,'fresh original client/provider identities and chain readers')
    for name,generator in [('adid_notification_profiles.json','probe_adid_notifications.py'),('adid_notification_post_profiles.json','probe_adid_notification_posts.py'),('adid_notification_contracts.json','recover_adid_notifications.py')]:
        d=read(name);check(d['generator_sha256']==sha((ROOT/generator).read_bytes()),'generator source pin '+name)
        for path,h in d['dependencies'].items():check(sha((ROOT/path).read_bytes())==h,'dependency pin '+name+'/'+path)
        check(not d['native_target_executed'] and not d['full_goal_complete'],'bounded scope '+name)
    pools={};ranges=0
    for label,source,artifact in [('client',s,p),('provider',server,pp)]:
        bank={}
        for i in artifact['original_instruction_records']:
            a=int(i['ea'],16);raw=source.read(a,4);ins=next(CS.disasm(raw,a));check(raw.hex()==i['bytes'] and ins.mnemonic==i['mnemonic'] and ins.op_str==i['operands'],'fresh original instruction '+label+'/'+hex(a));bank[a]=raw
        pools[label]=bank
        for f in artifact['original_functions']:
            a=int(f['start'],16);z=int(f['end'],16);check(source.bounds(a)==(a,z) and sha(source.read(a,z-a))==f['sha256'],'complete original compiler range '+label+'/'+hex(a));ranges+=1
    for f in c['complete_client_functions']:
        a=int(f['start'],16);z=int(f['end'],16);raw=s.read(a,z-a);check(s.bounds(a)==(a,z) and raw.hex()==f['bytes'] and sha(raw)==f['sha256'],'complete client source '+hex(a));ranges+=1
    for w in c['original_windows']:
        source=s if w['image']=='client' else server;a=int(w['start'],16);z=int(w['end'],16);raw=source.read(a,z-a);check(raw.hex()==w['bytes'] and sha(raw)==w['sha256'],'original source window '+w['role'])
    for n in c['original_names']:
        source=s if n['image']=='client' else server;check(source.read(int(n['address'],16),len(n['name'])+1).hex()==n['bytes']==(n['name'].encode()+b'\0').hex(),'exact original notification string '+n['image']+'/'+n['name'])
    for b in c['provider_byte_banks']:
        first=server.read(int(b['first_address'],16),256);second=server.read(int(b['second_address'],16),256);check(first.hex()==b['first_bytes'] and second.hex()==b['second_bytes'],'original bank bytes '+b['role'])
        for i in range(256):check(i^second[first[i]^b['input_XOR_u8']]==b['low_byte_result']==b['all256_original_reductions'][i],'independent byte bank '+b['role']+'/'+str(i))
    for r in c['provider_chain_members']:check(server.decoded[int(r['address'],16)]==r,'independently walked provider chain '+r['address'])
    for n in c['provider_name_pointer_reductions']:check((int(server.decoded[int(n['slot'],16)]['target'],16)+int(n['addend_u64'],16))&((1<<64)-1)==int(n['decoded_name_address'],16),'source pointer/name modular reduction '+n['slot'])
    sdk=c['SDK_compile'];run=subprocess.run(sdk['command'],capture_output=True,text=True);check(run.returncode==0 and not run.stderr and sha((ROOT/'adid_notification_layouts.c').read_bytes())==sdk['source_sha256'] and sha((ROOT/'adid_notification_layouts.s').read_bytes())==sdk['assembly_sha256'],'fresh arm64e SDK ABI compile and deterministic assembly')
    for h in c['SDK_headers']:check(sha(Path(h['path']).read_bytes())==h['sha256'],'original SDK header pin '+h['path'])
    header=Path(c['SDK_headers'][0]['path']).read_text();check('no active notifications will be delivered' in header and 'true the first time notify_check' in header and 'False positives' in header,'SDK check-token baseline and no-active-delivery scope')
    for proof in c['proofs']:
        path=ROOT/proof['path'];check(sha(path.read_bytes())==proof['sha256'],'original query pin '+proof['path']);run=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);check(run.stdout.strip()=='unsat' and not run.stderr,'fresh solver unsat '+proof['path'])
    totals={'source_visits':0,'heap_write_effects':0,'heap_read_observations':0,'cache_read_observations':0,'API_output_effects':0,'cache_gate_observations':0};capacity=[]
    def stream(source,r,space,label):
        seq=visits(r);bank=pools[space];check(all(a in bank and source.read(a,4)==bank[a] for a in seq),'full retained visit membership '+label);h=hashlib.sha256()
        for a in seq:h.update(struct.pack('<Q',a));h.update(bank[a])
        check(h.hexdigest()==r['ordered_original_instruction_sha256'],'ordered original source digest '+label);totals['source_visits']+=len(seq);return seq
    for label,case in rows.items():
        heap={};alloc={};previous_cache=None;previous_tokens={};previous_callbacks=[]
        for ordinal,r in enumerate(case['calls']):
            tag=label+'/'+str(ordinal);seq=stream(s,r,'client',tag);ev=unpack_records(r);f=r['fixture'];cache=bytearray.fromhex(r['cache_region_before']);check(len(cache)==CACHE_SIZE,'cache observation extent '+tag)
            check(not r['call_boundary_internal_frame_or_instruction_overrides'] and r['call_boundary_LR']=='0x7d000000','fresh ABI entry without internal intervention '+tag)
            if previous_cache is not None:check(r['cache_region_before']==previous_cache and r['registered_tokens_before']==previous_tokens and r['exit_callbacks_before']==previous_callbacks,'global/token/exit state preserved across original calls '+tag)
            # Independent byte/lifetime replay: source memory events versus API
            # allocation/free events ordered by original instruction ordinal.
            ordered=[]
            for kind,key in [('read','original_heap_reads'),('write','original_heap_writes')]:
                for j,e in enumerate(r[key]):ordered.append((e['source_visit_index'],0 if kind=='read' else 1,j,kind,e))
            for j,e in enumerate(ev):
                if e['kind'] in ['explicit_client_allocation','explicit_client_free']:ordered.append((e['source_visit_index'],2,j,'API',e))
            for index,phase,j,kind,e in sorted(ordered,key=lambda x:x[:3]):
                check(0<=index<len(seq),'event source ordinal '+tag+'/'+kind+'/'+str(j))
                if kind=='API':
                    if e['kind']=='explicit_client_allocation':
                        a=int(e['result'],16);n=e['size_bytes'];check(0<n<=8192 and a not in alloc,'owned bounded monotonic allocation '+tag+'/'+hex(a));alloc[a]={'size_bytes':n,'freed':False}
                        for k in range(n):heap[a+k]=0xa5
                    else:
                        a=int(e['pointer'],16);check(not a or a in alloc,'modeled free has known allocation '+tag+'/'+hex(a))
                        if a:alloc[a]['freed']=True
                    continue
                a=int(e['address'],16);n=e['size_bytes'];check(seq[index]==int(e['pc'],16),'heap effect bound to exact original instruction '+tag+'/'+kind+'/'+str(j));owners=[hex(base) for base,m in alloc.items() if not m['freed'] and base<=a and a+n<=base+m['size_bytes']];check(owners==e['nominal_live_allocation_owners'],'independent live nominal owners '+tag+'/'+kind+'/'+str(j))
                expected=bytes(heap.get(a+k,0xa5) for k in range(n));check(expected.hex()==e['bytes' if kind=='read' else 'before'],'independent before/read bytes '+tag+'/'+kind+'/'+str(j))
                if kind=='write':
                    raw=int(e['value'],16).to_bytes(n,'little')
                    for k,v in enumerate(raw):heap[a+k]=v
                    if 'copy_destination_requested_bytes' in e:
                        dest=int(e['copy_destination_base'],16);check(dest in alloc and alloc[dest]['size_bytes']==e['copy_destination_requested_bytes'] and (dest<=a and a+n<=dest+alloc[dest]['size_bytes'])==e['write_within_destination_request'],'independent intended copy-object extent '+tag+'/'+str(j))
                totals['heap_write_effects' if kind=='write' else 'heap_read_observations']+=1
            for m in r['allocation_model_final']:
                a=m['pointer'];check(alloc[a]=={'size_bytes':m['size_bytes'],'freed':m['freed']},'independent allocation lifetime final '+tag+'/'+hex(a));check(bytes(heap[a+k] for k in range(m['size_bytes'])).hex()==r['allocation_observation_bytes_after'][hex(a)],'independent final nominal allocation bytes '+tag+'/'+hex(a))
            # Source global writes and explicit API writes are different epochs.
            for e in ev:
                if e['kind']=='original_private_global_write':
                    a=int(e['address'],16);n=e['size_bytes']
                    if CACHE_START<=a and a+n<=CACHE_START+CACHE_SIZE:cache[a-CACHE_START:a-CACHE_START+n]=int(e['value'],16).to_bytes(n,'little')
                if e['kind']=='explicit_notification_API':
                    check(seq[e['source_visit_index']]==int(e['callsite'],16),'source API branch attribution including tail cancellation '+tag+'/'+e['name'])
                    for w in r['explicit_API_write_effects']:
                        if w['callsite']!=e['callsite']:continue
                        a=int(w['address'],16);raw=bytes.fromhex(w['after'])
                        if CACHE_START<=a and a+len(raw)<=CACHE_START+CACHE_SIZE:check(cache[a-CACHE_START:a-CACHE_START+len(raw)].hex()==w['before'],'API global token before bytes '+tag);cache[a-CACHE_START:a-CACHE_START+len(raw)]=raw
                    if e['name']=='_notify_check' and e['result_u32']==0 and e['initial_check']:check(e['changed_u32']==f.get('initial_check_value',1),'SDK initial true check modeled explicitly '+tag)
            check(cache.hex()==r['cache_region_after'],'independent full cache-region source/API mutation ledger '+tag)
            previous_cache=r['cache_region_after'];previous_tokens=r['registered_tokens_after'];previous_callbacks=r['exit_callbacks_after'];totals['cache_read_observations']+=len(r['original_cache_reads']);totals['API_output_effects']+=len(r['explicit_API_write_effects'])
            for g in [e for e in ev if e['kind']=='original_notification_cache_gate']:
                regs={k:int(v,16) for k,v in g['registers'].items()};totals['cache_gate_observations']+=1
                if g['pc']=='0x100308b40':check(regs['x11']==300,'original bucket delta threshold300 '+tag)
                if g['pc']=='0x100308b44':
                    prior=next(e for e in ev if e['kind']=='original_notification_cache_gate' and e['pc']=='0x100308b3c');rr={k:int(v,16) for k,v in prior['registers'].items()};accept=rr['x10']&MASK>=rr['x8']&MASK and ((rr['x10']-rr['x8'])&MASK)<300;C=int(g['NZCV'],16)>>29&1;check((not C)==accept,'independent SUBS/CCMP carry/LO predicate '+tag)
                if g['pc']=='0x10030a094':check(regs['x9']==0 and regs['x25']==0x391,'publication CCMP comparator is original zero '+tag)
            sends=[e for e in ev if e.get('name')=='_xpc_connection_send_message_with_reply_sync'];warm_checks=[e for e in ev if e.get('name')=='_notify_check' and not e['initial_check']]
            for e in warm_checks:check(e['notification_name']==notification(f['args'][2]),'independent full64 DSID notification class '+tag)
            for e in [e for e in ev if e['kind']=='original_private_global_write' and e['address'] in ['0x100450574','0x10045059c']]:check(int(e['value'],16)==(f['clock_seconds']&MASK)//30,'unsigned32 cache bucket publication '+tag)
            if ordinal==0:check(len(sends)==1,'cold original OTP source request '+tag)
            if r['stop_reason']=='returned_to_private_fixture' and f['entry']!=0x1002dcbec:
                raw=bytes.fromhex(f['reply_hex']);n=int.from_bytes(raw[4:8],'big');m=int.from_bytes(raw[8+n:12+n],'big');expected=[raw[8:8+n],raw[12+n:12+n+m]]
                for pointer_off,count_off,want in [(0x1100,0x1200,expected[0]),(0x1300,0x1400,expected[1])]:
                    ptr=int.from_bytes(bytes.fromhex(r['output_observation_windows_after'][hex(0x7b000000+pointer_off)]),'little');count=int.from_bytes(bytes.fromhex(r['output_observation_windows_after'][hex(0x7b000000+count_off)]),'little');check(count==len(want) and bytes(heap.get(ptr+k,0xa5) for k in range(count))==want,'independent caller span contents/count '+tag+'/'+hex(pointer_off))
            bad=[e for e in r['original_heap_writes'] if e.get('write_within_destination_request') is False]
            if bad:
                request=next(e for e in ev if e['kind']=='explicit_client_allocation' and e['size_bytes']==24);cell=int(request['result'],16);after=bytes(heap[cell+k] for k in range(8));unowned=[e for e in ev if e['kind']=='notification_free_argument_observation' and not e['allocation_known']]
                if unowned:check(len(unowned)==1 and int(unowned[0]['pointer'],16)==int.from_bytes(after,'little'),'independent overwritten live request cell equals emitted free argument '+tag)
                capacity.append({'case':label,'call':ordinal,'source_writes_outside_intended_request':len(bad),'source_store_sites':sorted({e['pc'] for e in bad}),'destination_requested_extents':sorted({(e['copy_destination_base'],e['copy_destination_requested_bytes']) for e in bad}),'live_request_pointer_cell':hex(cell),'request_pointer_cell_after':after.hex(),'stop_reason':r['stop_reason'],'unowned_free_arguments':unowned})
    def events(label,n=1):return unpack_records(rows[label]['calls'][n])
    def sends(label,n=1):return sum(e.get('name')=='_xpc_connection_send_message_with_reply_sync' for e in events(label,n))
    for key in [-17,-16,-9,-8,-7,-6,-5,-4,-3,-2,-1,1,0x1122334455667788,0x1000000000000001]:check(sends('dsid_'+str(key))==0,'same DSID warm cache bypasses XPC '+str(key))
    check(sends('dsid_0')==1 and not any(e.get('name')=='_notify_check' for e in events('dsid_0')),'zero DSID is not a warm cache hit in retained sequence')
    for label,case in rows.items():
        if label.startswith('clock_delta_'):
            now=case['case']['calls'][1]['clock_seconds'];cached=1700000000//30;current=trunc30(now)&MASK;hit=cached>=current and cached-current<300;check(sends(label)==int(not hit),'independent clock bucket/rollback boundary '+label)
        if label.startswith('absolute_clock_'):
            sec=case['case']['calls'][0]['clock_seconds'];cached=(sec&MASK)//30;current=trunc30(sec)&MASK;hit=cached>=current and cached-current<300;check(sends(label)==int(not hit),'distinct publication/lookup arithmetic '+label)
        if label.startswith('changed_'):
            f=case['case']['calls'][1];expected=f.get('changed',{}).get(notification(f['args'][2]),0);check(sends(label)==int(expected!=0),'only selected notification class controls refresh '+label)
        if label.startswith('check_failure_'):check(sends(label)==1,'check failure falls through to XPC '+label)
        if label.startswith('register_failure_'):
            for ordinal,r in enumerate(case['calls']):
                ev=unpack_records(r);registers=[e for e in ev if e.get('name')=='_notify_register_check'];target=next(name for name,status in r['fixture']['register_status'].items() if status);check([e['notification_name'] for e in registers]==NAMES[:NAMES.index(target)+1] and not any(e.get('name') in ['_notify_cancel','_atexit'] for e in ev) and bytes.fromhex(r['cache_region_after'])[0xa8]==0,'registration failure retries prefix without local cancel/ready publication '+label+'/'+str(ordinal))
    check(sends('atexit_failure')==0 and bytes.fromhex(rows['atexit_failure']['calls'][0]['cache_region_after'])[0xa8]==1 and rows['atexit_failure']['calls'][0]['exit_callbacks_after']==[],'atexit failure leaves ready byte set without a registered model callback')
    check(sends('clock_failure')==1 and sends('microseconds_only')==0,'clock failure refreshes;microseconds do not change tested bucket')
    check([sends('two_cache_keys',i) for i in range(3)]==[1,1,0],'two original records retain first and second DSIDs')
    check([sends('three_cache_keys',i) for i in range(4)]==[1,1,1,0],'third DSID replaces record1 while first DSID stays cached')
    check([sends('invalidation_two_keys',i) for i in range(4)]==[1,1,1,0],'one selected changed flag refreshes matching record without clearing other record')
    for label in ['cleanup_success','cleanup_cancel_failure']:
        r=rows[label]['calls'][2];ev=unpack_records(r);cancel=[e for e in ev if e.get('name')=='_notify_cancel'];check([e['notification_name'] for e in cancel]==NAMES and r['fixture']['entry']==0x1002dcbec and r['stop_reason']=='returned_to_private_fixture','original registered exit callback cancels three names '+label);check(r['cache_region_before']==r['cache_region_after'] and not any(e.get('name')=='_free' for e in ev),'exit callback leaves cache bytes and buffer disposal outside observed callback '+label)
    cap={x['case']:x for x in capacity}
    check(cap['refresh_larger_spans']['source_writes_outside_intended_request']==9 and cap['refresh_capacity_17']['source_writes_outside_intended_request']==27 and cap['refresh_capacity_33']['source_writes_outside_intended_request']==59,'independent intended-object overflow byte counts9/27/59')
    later=rows['refresh_larger_spans']['calls'][2];check(sum(not r['nominal_live_allocation_owners'] for r in later['original_heap_reads'])==9 and sends('refresh_larger_spans',2)==0,'later source cache hit reads nine bytes beyond original nominal requests')
    for label,want in [('refresh_capacity_17','0x7b008071'),('refresh_capacity_33','0x7877767574737271')]:
        bad=cap[label];check(bad['stop_reason']=='client_unowned_free_guard' and bad['unowned_free_arguments']==[{'kind':'notification_free_argument_observation','name':'_free','callsite':'0x10030ec68','pointer':want,'allocation_known':False,'native_API_executed':False,'source_visit_index':bad['unowned_free_arguments'][0]['source_visit_index']}],'source crossed live model request pointer and stopped before unowned free '+label)
    for label,r in post_rows.items():
        seq=stream(server,r,'provider','post/'+label);ev=unpack_records(r);posts=[e for e in ev if e.get('name')=='_notify_post'];f=r['fixture'];check(f['local_fragment_and_frame_overrides'] and ev[0]['whole_request_or_native_reachability_established'] is False and r['resume_pc']=='0x100218fbc','explicit local provider frame/record scope '+label)
        if f['encoded_status_u32']==0x59248f:check(len(posts)==1 and posts[0]['callsite']=='0x100219198' and posts[0]['notification_name']==notification(f['DSID_u64']),'independent status and DSID class reach original post '+label)
        else:check(not posts and r['stop_reason']=='notification_after_local_post_or_status_rejection','nonmatching encoded status bypasses post '+label)
        if 'post_result_u32' in f:check(r['stop_reason']=='notification_after_local_post_or_status_rejection' and seq[-1]==0x1002191a4,'modeled post result reaches same immediate continuation '+label)
    for bridge in c['conditional_event_bridges']:
        pr=post_rows[bridge['provider_fragment_label']];pe=next(e for e in unpack_records(pr) if e.get('name')=='_notify_post');ce=next(e for e in events(bridge['client_case_label']) if e.get('name')=='_notify_check' and not e['initial_check']);check(pe['notification_name']==ce['notification_name']==bridge['exact_original_name'] and ce['changed_u32']==1 and sends(bridge['client_case_label'])==1 and not bridge['notification_delivery_and_native_pairing_established'],'conditional exact-name provider/client event bridge '+str(bridge['DSID_signed64']))
    fresh_labels=['dsid_-8','dsid_-1','dsid_1','clock_delta_-8990','clock_delta_-8991','clock_delta_10','register_failure_midchangedV3','atexit_failure','cleanup_success','three_cache_keys','invalidation_two_keys','refresh_larger_spans','refresh_capacity_17','refresh_capacity_33','absolute_clock_1099511627776'];fresh_calls=0;fresh_steps=0
    for label in fresh_labels:
        q,fresh=run_case(s,rows[label]['case']);old=rows[label];check(len(fresh['calls'])==len(old['calls']),'fresh complete call count '+label)
        for ordinal,(new,retained) in enumerate(zip(fresh['calls'],old['calls'])):
            for key in ['ordered_original_instruction_sha256','stop_reason','output_observation_windows_after','cache_region_before','cache_region_after','allocation_model_final','allocation_observation_bytes_after','registered_tokens_after','exit_callbacks_after','explicit_API_write_effects','original_heap_writes','original_heap_reads','original_cache_reads']:check(new[key]==retained[key],'fresh original sequence '+label+'/'+str(ordinal)+'/'+key)
            check(unpack_records(new)==unpack_records(retained),'fresh complete source/API event order '+label+'/'+str(ordinal));fresh_calls+=1;fresh_steps+=new['steps']
    checkpoint=read('adid_driver_dispatch_frame.json');post_replays=['DSID_-8','DSID_-1','DSID_1','encoded_status_0x0','post_result_0xffffffff'];post_steps=0
    for label in post_replays:
        q,new=post_run(server,post_rows[label]['fixture'],checkpoint);old=post_rows[label];check(new['ordered_original_instruction_sha256']==old['ordered_original_instruction_sha256'] and new['stop_reason']==old['stop_reason'] and unpack_records(new)==unpack_records(old),'fresh original local provider source/event replay '+label);post_steps+=new['steps']
    for row in read('interface_manifest.json')['inputs_preserved']:
        path=ROOT.parent/row['path'];check(path.stat().st_size==row['size_bytes'] and sha(path.read_bytes())==row['sha256'],'original supplied input preserved '+row['path'])
    verified={**totals,'client_sequences':len(rows),'client_original_calls':sum(len(r['calls']) for r in rows.values()),'local_provider_fragments':len(post_rows),'original_client_instructions':len(pools['client']),'original_provider_instructions':len(pools['provider']),'complete_compiler_range_records':ranges,'original_names':len(c['original_names']),'original_source_windows':len(c['original_windows']),'byte_bank_inputs':256*len(c['provider_byte_banks']),'new_proofs_unsat':len(c['proofs']),'conditional_name_event_bridges':len(c['conditional_event_bridges']),'capacity_witnesses':len(capacity),'fresh_client_sequences':len(fresh_labels),'fresh_client_calls':fresh_calls,'fresh_client_steps':fresh_steps,'fresh_provider_fragments':len(post_replays),'fresh_provider_steps':post_steps,'assertions':len(checks)}
    result={'scope':__doc__,'verified_counts':verified,'checks':checks,'conditional_nominal_capacity_witnesses':capacity,'all_checks_pass':True,'native_target_executed':False,'native_defect_established':False,'full_goal_complete':False};(ROOT/'adid_notification_checks.json').write_text(json.dumps(result,indent=2)+'\n')
    descriptions=['Descriptive original-binary interface analysis.','Report N1-N13 enumerate assumptions,dependent results and falsification probes.','Three-name notification,cache/time/lifetime and conditional capacity increment covered;broader native architecture remains incomplete.','Source widths,byte extents,seconds/microseconds,SDK layouts,seven solver scopes and bounded algorithms explicit.','Provider fragments versus whole requests,check-token polling versus active delivery,distinct clock arithmetic,nominal allocation versus native capacity and synthetic replies separated.','Fresh original identities/instructions/ranges/fixups,banks,independent byte/lifetime/cache ledgers,SDK compile,seven proofs and complete source/event replays.','Impact-labeled native accepted lengths,provider post predecessors,libnotify IPC/admission,partial-registration/exit behavior and multi-record/event lifecycle continuation.'];quality={'scope':'Local original notification/cache/post and conditional nominal-capacity interfaces.','verified_counts':verified,'native_target_executed':False,'native_defect_established':False,'full_goal_complete':False}
    for i,t in enumerate(descriptions,1):quality['QG'+str(i)]={'status':'pass_for_stated_increment','evidence':t}
    (ROOT/'adid_notification_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps(verified),flush=True)


if __name__=='__main__':main()
