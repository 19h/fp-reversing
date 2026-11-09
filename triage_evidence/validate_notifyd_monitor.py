#!/usr/bin/env python3
"""Independent original monitor byte/ownership/FD/Block/dispatch/polling checks.

Re-read original binary/cache,independently replay recorded effects into byte and
ownership ledgers,compile source-shape SDK layouts,rerun four local formulas and
all private source cases,including the declared NULL boundary. Byte-ledger time
O(B+P+V+W*V+A+D),space O(B+P+V+W+A+D);the W*V term covers linear membership
checks against each source-visit list. A includes all snapshot bytes.
No native daemon,watch,filesystem,credential,dispatch or Mach operation.
"""
import bisect,hashlib,json,struct,subprocess
from pathlib import Path
from notifyd_ipc_reader import Notifyd,ROOT,THIN_SHA,sha
from notify_ipc_reader import Notify,CS
from bootpolicy_cache_reader import Dylib
from recover_notifyd_admission import events
from validate_notifyd_admission import visits
from probe_notifyd_admission import HEAP,SHARED
from probe_notifyd_monitor_cases import run_case,compact_row


def main():
    assertions=0;totals={k:0 for k in ['provider_source_visits','client_source_visits','source_stores','API_output_effects','allocation_snapshots','source_record_snapshots','FD_state_snapshots','copied_Block_snapshots','dispatch_source_snapshots','paired_messages','callback_deliveries','source_bound_global_stores']}
    def check(v,label):
        nonlocal assertions
        assert v,label
        assertions+=1
    read=lambda n:json.loads((ROOT/n).read_text());d=Notifyd();cache=Notify();p=read('notifyd_monitor_profiles.json');c=read('notifyd_monitor_contracts.json');cases={x['case']['label']:x for x in p['cases']};source=lambda a,n:d.read(a,n) if d.base<=a<d.base+0x20000 else cache.read(a,n);libraries={};bank={}
    for data,name in [(p,'probe_notifyd_monitor_cases.py'),(c,'recover_notifyd_monitor.py')]:
        check(data['generator_sha256']==sha((ROOT/name).read_bytes()),'producer pin '+name)
        for n,h in data['dependencies'].items():check(sha((ROOT/n).read_bytes())==h,'dependency '+n)
        check(not data['native_target_executed'] and not data['full_goal_complete'],'explicit scope')
    check(c['provider_thin_sha256']==THIN_SHA and c['cache_uuid']==cache.cache.uuid and c['client_uuid']==cache.lib.uuid,'original identities')
    for row in p['original_source_pools']['instructions']:
        a=int(row['ea'],16);raw=source(a,4);ins=next(CS.disasm(raw,a));check(raw.hex()==row['bytes'] and ins.mnemonic==row['mnemonic'] and ins.op_str==row['operands'],'fresh original instruction');bank[a]=raw
    for row in p['original_source_pools']['functions']:
        a=int(row['start'],16);z=int(row['end'],16);check(sha(source(a,z-a))==row['sha256'],'whole original compiler body')
        if d.base<=a<d.base+0x20000:check(d.bounds(a)==(a,z),'provider compiler boundary')
        elif 'library'in row:
            if row['library']not in libraries:libraries[row['library']]=Dylib(cache.cache,row['library'])
            lib=libraries[row['library']];ix=bisect.bisect_right(lib.functions,a)-1;end=lib.functions[ix+1]if ix+1<len(lib.functions)else next(s['address']+s['size']for s in lib.sections if s['name']=='__text');check(lib.functions[ix]==a and end==z and lib.uuid==row['uuid'],'cache compiler boundary and UUID')
    for row in p['original_source_pools']['cache_pages']:
        a=int(row['address'],16);raw=bytearray(cache.read(a,4096));check(sha(raw)==row['original_sha256'],'original cache page');members=[v for at,v in cache.page_chains(a).items()if a<=at<a+4096];check(members==row['original_chain_members'],'independent cache v5 chain')
        for m in members:struct.pack_into('<Q',raw,int(m['address'],16)-a,int(m['target'],16))
        check(sha(raw)==row['materialized_sha256'],'materialized original cache page')
    for row in c['original_functions']:
        a=int(row['start'],16);check(d.function(a)=={k:v for k,v in row.items()if k!='role'},'whole source contract function')
    for row in c['original_strings']:check(d.read(int(row['address'],16),len(bytes.fromhex(row['bytes']))).hex()==row['bytes'],'source string')
    roles={int(r['start'],16)for r in c['original_functions']};incoming=[];outgoing=[]
    for a in d.starts:
        for i in d.function(a)['instructions']:
            if i['mnemonic']not in ['b','bl'] or not i['operands'].startswith('#0x'):continue
            target=int(i['operands'][1:],16);row={'caller':hex(a),'site':i['ea'],'mnemonic':i['mnemonic'],'target':hex(target)}
            if target in roles:incoming.append(row)
            if a in roles:outgoing.append(row)
    check(incoming==c['complete_direct_callers_of_selected_functions'],'all source direct incoming edges')
    check(outgoing==[{k:v for k,v in r.items()if k!='import'}for r in c['selected_direct_outgoing_edges']],'all selected direct outgoing edges')
    for row in c['selected_direct_outgoing_edges']:
        if 'import'not in row:continue
        im=row['import'];a=int(im['stub'],16);ins=list(CS.disasm(d.read(a,16),a));slot=int(ins[0].op_str.split('#')[1],16)+int(ins[1].op_str.split('#')[1],16);check(d.read(a,16).hex()==im['bytes'] and hex(slot)==im['slot'] and d.decoded[slot]==im['original_format12_bind'] and d.decoded[slot]['symbol']==im['symbol'],'fresh original stub and format12 import')
    for row in c['original_data_bindings']:
        lib=Dylib(cache.cache,row['library']);a=lib.exports[row['symbol']]['address'];check(lib.uuid==row['uuid'] and hex(a)==row['address'] and cache.read(a,4).hex()==row['bytes4'],'original imported data bytes');check([v for v in d.decoded.values()if v.get('symbol')==row['symbol']]==row['bind_slots'],'original data import slots')
    descriptors={r['address']:r for r in c['source_Block_descriptors']}
    for row in descriptors.values():check(d.read(int(row['address'],16),16).hex()==row['original_bytes16'] and int.from_bytes(d.read(int(row['address'],16)+8,8),'little')==row['declared_block_size_bytes'],'source Block descriptor')
    summaries=[]
    def order(row,origin):
        seq=visits(row);h=hashlib.sha256()
        for a in seq:check(a in bank,'visited original address');h.update(struct.pack('<Q',a));h.update(bank[a])
        check(h.hexdigest()==row['ordered_original_instruction_sha256'],'ordered source-byte stream');totals[origin+'_source_visits']+=len(seq);return seq
    symbols={0x7c000000+im['ordinal']*256:im['name']for im in d.imports}
    for case in p['cases']:
        label=case['case']['label'];cfg=case['case'];fixture=cfg.get('server_fixture',{});mem={};data={};shared={SHARED+i:0 for i in range(16384)};alloc={};record_types={};blocks=[];fds={};objects={};fs=fixture.get('fs',{'/':{'mode':0o040755},'/model':{'mode':0o040755},'/model/file':{'mode':0o100644}});fs=json.loads(json.dumps(fs));before={};post={};last=0
        for action in case['actions']:
            if 'provider_journal_index'in action:last=action['provider_journal_index']
            elif action.get('provider_journal_indexes'):last=max(action['provider_journal_indexes'])
            if action['op']in ['declare_source_cancelled','explicit_consume_dataor']:before.setdefault(last+1,[]).append(action)
            if action['op']=='vnode_event':before.setdefault(action['provider_journal_index'],[]).append(action)
        for seg in d.meta['segments']:
            if seg['name']=='__DATA':
                raw=d.data[seg['file_offset']:seg['file_offset']+seg['file_size']]+bytes(seg['vm_size']-seg['file_size']);data.update({seg['address']+i:v for i,v in enumerate(raw)})
        for a,item in d.decoded.items():
            if a in data and not item['bind']:data.update({a+i:v for i,v in enumerate(struct.pack('<Q',int(item['target'],16)))})
        def put(a,b):
            target=shared if SHARED<=a and a+len(b)<=SHARED+16384 else data if a in data else mem
            target.update({a+i:v for i,v in enumerate(b)})
        def span(a,n):
            target=shared if SHARED<=a<SHARED+16384 else data if a in data else mem
            return bytes(target[a+i]for i in range(n))
        def u32(a):return int.from_bytes(span(a,4),'little')
        def u64(a):return int.from_bytes(span(a,8),'little')
        for row in case['provider_journal'][0]['reference_data_bindings']:
            source_binding=next(v for v in c['original_data_bindings']if v['symbol']==row['symbol']);check(row['original_bytes']==source_binding['bytes4'] and row['original_cache_address']==source_binding['address'] and row['uuid']==source_binding['uuid'],'imported reference data identity');expected=fixture.get('initial_L1_u32',int.from_bytes(bytes.fromhex(row['original_bytes']),'little'))if row['symbol']=='_gL1CacheEnabled'else 0x40000000;check(row['declared_guest_initial_u32']==expected and not row['runtime_native_value_established'],'declared data initialization');put(int(row['guest_bound_address'],16),struct.pack('<I',expected))
        l1=int(next(v for v in case['provider_journal'][0]['reference_data_bindings']if v['symbol']=='_gL1CacheEnabled')['guest_bound_address'],16)
        source_summaries=[]
        for j,r in enumerate(case['provider_journal']):
            for action in before.get(j,[]):
                op=action['op']
                if op=='declare_source_cancelled':objects[action['source_pointer']]['cancel_requested']=True
                elif op=='explicit_consume_dataor':check(objects[action['source_pointer']]['pending_data_u64']==action['consumed_u64'],'declared DataOR consumption');objects[action['source_pointer']]['pending_data_u64']=0
                elif op=='vnode_event':
                    for path,changes in action['event'].get('fs_updates',{}).items():fs.setdefault(path,{}).update(changes)
            check(r['provider_invocation_index']==j,'chronological provider journal')
            check(r['stop_reason']in ['returned_to_private_fixture','original_startup_dispatch_main_boundary']or label=='config_dataor_create_NULL'and r['stop_reason']=='explicit_NULL_dispatch_source_boundary','complete path or declared NULL boundary '+label);seq=order(r,'provider')
            for e in events(r):
                name=e.get('name','');x=[int(v,16)for v in e.get('args_x0_x7',[])];site=e.get('callsite')
                if name in ['_malloc_type_malloc','_malloc_type_calloc','_malloc_type_realloc','_reallocf']:
                    a=int(e['result'],16);n=e['requested_size_bytes'];check(0<n<=65536 and HEAP+0x20000<=a and a+n<=HEAP+0x70000,'owned allocator extent');put(a,bytes(n)if name.endswith('calloc')else b'\xa5'*n);alloc[a]={'size_bytes':n,'freed':False}
                    if name.endswith('realloc')or name=='_reallocf':
                        if x[0]:check(x[0]in alloc and not alloc[x[0]]['freed'],'reallocation prior owner');alloc[x[0]]['freed']=True
                    if site in ['0x100007430','0x10000828c']:record_types[a]='monitor'if site=='0x100007430'else'watcher';check(n==(112 if record_types[a]=='monitor'else 72),'source allocation shape')
                if name=='_strdup':a=int(e['result'],16);n=len(e['string'].encode())+1;alloc[a]={'size_bytes':n,'freed':False};put(a,b'\xa5'*n)
                if name=='_free'and x[0]:check(x[0]in alloc and not alloc[x[0]]['freed'],'free live source owner');alloc[x[0]]['freed']=True
                if e['kind']=='explicit_notifyd_port_constructor_model':put(x[3],struct.pack('<I',e['output_name_u32']));totals['API_output_effects']+=1
                for effect in e.get('explicit_output_effects',[]):put(int(effect['address'],16),bytes.fromhex(effect['bytes']));totals['API_output_effects']+=1
                if e['kind']in ['original_owned_data_write','original_private_global_write','original_bound_global_write']:
                    raw=bytes.fromhex(e['actual_after_hex']);check(len(raw)==e['size_bytes']and int(e['pc'],16)in seq,'actual source store and instruction provenance');put(int(e['address'],16),raw);totals['source_stores']+=1
                    if e['kind']=='original_bound_global_write':check(int(e['address'],16)==l1 and e['size_bytes']==4,'source L1-bound store');totals['source_bound_global_stores']+=1
                if 'explicit_Block_copy'in e:
                    b=e['explicit_Block_copy'];raw=bytes.fromhex(b['bytes']);check(len(raw)==b['size_bytes']==descriptors[b['descriptor_pointer']]['declared_block_size_bytes'],'copied Block extent');check(raw[16:24]==int(b['invoke_pointer'],16).to_bytes(8,'little')and raw[24:32]==int(b['descriptor_pointer'],16).to_bytes(8,'little')and int(b['invoke_pointer'],16)in d.starts,'source-built Block callback and descriptor');check(span(int(b['copy_pointer'],16),len(raw))==raw,'Block explicit output bytes');blocks.append(b)
                    if name in ['_dispatch_source_set_event_handler','_dispatch_source_set_cancel_handler']:objects[hex(x[0])]['cancel_block'if'cancel'in name else'event_block']=b['copy_pointer']
                if name=='_dispatch_source_create'and'result'in e and e['result']!='NULL fixture':objects[e['result']]={'type_symbol':symbols[x[0]],'handle_u64':x[1],'mask_u64':x[2],'queue_pointer':hex(x[3]),'merge_requests':[],'pending_data_u64':0,'cancel_requested':False}
                if name=='_dispatch_source_merge_data':o=objects[hex(x[0])];o['merge_requests'].append(x[1]);o['pending_data_u64']|=x[1];check(o['pending_data_u64']==e['modeled_pending_data_u64'],'DataOR declared OR arithmetic')
                if name in ['_dispatch_suspend','_dispatch_resume','_dispatch_activate','_dispatch_source_cancel','_dispatch_release']and hex(x[0])in objects:
                    o=objects[hex(x[0])];o.setdefault('requests',[]).append(name)
                    if name=='_dispatch_source_cancel':o['cancel_requested']=True
                if name in ['_open','_open$NOCANCEL']and e.get('result_fd_signed32',-1)>=0:fds[str(e['result_fd_signed32'])]={'path':e['path'],'closed':False};check(e['flags_u32']in [0x8000,0x208000],'original event-only open flags')
                if name in ['_close','_close$NOCANCEL','___close_nocancel']and str(x[0])in fds:check(not fds[str(x[0])]['closed'],'close a live declared FD');fds[str(x[0])]['closed']=True
                if name=='_dispatch_time'and site=='0x1000078c8':check(x[:2]==[0,100000000],'source delay100000000 ns =100 ms')
                if name=='_sandbox_check_by_audit_token':check(e['filter_u32']==0x40000001 and e['operation']=='file-read-metadata'and len(bytes.fromhex(e['audit_token32_hex']))==32,'sandbox operation/filter/audit extent')
                if name=='_syscall':check(e['syscall_number']==243 and e['variadic_groups_u32']==fixture.get('group_list',[20,80]) and e['variadic_uid_u64']==0,'source arm64 variadic initgroups restore request')
            check({str(a):v for a,v in alloc.items()}==r['owned_allocations'],'independent lifetime ledger '+label)
            for a,v in alloc.items():check(span(a,v['size_bytes']).hex()==r['owned_allocation_bytes_after'][hex(a)],'independent allocation bytes');totals['allocation_snapshots']+=1
            for row in r['provider_DATA_after']:check(span(int(row['address'],16),len(bytes.fromhex(row['bytes']))).hex()==row['bytes'],'independent provider DATA bytes')
            check(span(SHARED,16384).hex()==r['shared_memory16384_after'],'independent shared bytes');check(u32(l1)==r['bound_L1_u32_after'],'independent bound L1 data bytes');check(fds==r['declared_FD_state_after'],'independent FD lifetime requests');totals['FD_state_snapshots']+=1;check(fs==r['declared_fs_after'],'declared filesystem update chronology');check(blocks==r['explicit_copied_blocks_after'],'independent copied Block chronology');totals['copied_Block_snapshots']+=len(blocks)
            for a,o in objects.items():
                actual=r['external_objects_after'][str(int(a,16))];check(o=={k:actual[k]for k in o},'independent dispatch declaration/request state');totals['dispatch_source_snapshots']+=1
            for row in r['source_owned_record_snapshots']:
                a=int(row['pointer'],16);check(record_types[a]==row['kind']and alloc[a]['freed']==row['freed']and span(a,row['size_bytes']).hex()==row['bytes'],'source record ownership/bytes');totals['source_record_snapshots']+=1
                if not row['freed']:
                    pathptr=u64(a);check(span(pathptr,alloc[pathptr]['size_bytes']).split(b'\0')[0].decode()==row['path'],'source record path binding')
                    if row['kind']=='monitor':
                        check([u32(a+64),u32(a+68),u64(a+72),u64(a+96),u32(a+104)]==[row['status_u32'],row['flags_u32'],int(row['source_pointer'],16),row['client_key_u64'],row['refcount_u32']],'monitor field widths/offsets');audit=bytes(32)if cfg.get('mode','config')=='config'else struct.pack('<8I',*cfg.get('audit_words',[0,501,20,501,20,2117,7,3]));check(span(a+16,32)==audit,'source monitor audit capture')
                    else:check(u32(a+8)==row['follow_u32']and u32(a+12)==row['fd_signed32']and [hex(u64(u64(a+64)+8*k))for k in range(u32(a+56))]==row['monitor_pointers'],'watcher field/list offsets')
            source_summaries.append({'index':j,'label':r['fixture']['label'],'L1_u32':r['bound_L1_u32_after'],'watcher_count_u32':u32(0x100014400),'monitor_records':[v for v in r['source_owned_record_snapshots']if v['kind']=='monitor'],'declared_open_FDs':[int(fd)for fd,v in fds.items()if not v['closed']]})
        for action in case['actions']:
            if 'block_copy_pointer'not in action:continue
            totals['callback_deliveries']+=1;r=case['provider_journal'][action['provider_journal_index']];b=next(b for b in r['explicit_copied_blocks_after']if b['copy_pointer']==action['block_copy_pointer']);check(b['invoke_pointer']==action['source_built_invoke']==hex(r['fixture']['entry'])and r['fixture']['args']==[int(b['copy_pointer'],16)],'captured original callback entry/frame')
            if action['op']=='dataor_delivery':
                seq=visits(r);check((0x1000051dc in seq)==(cfg.get('mode','config')=='config'),'configuration named-post versus client-key callback')
                check(any(e['kind']=='original_owned_data_write'and SHARED<=int(e['address'],16)<SHARED+16384 for e in events(r)),'original callback counter store')
                check(not any(e.get('message_id_u32')in [1009,1010]for e in events(r)),'internal callback publication has no injected post request')
        last_counter=None;checks=[]
        for r in case['client_calls']:
            order(r,'client');check(r['stop_reason']=='returned_to_private_fixture'and r['result_u32']==0,'complete original public client call');op=r['fixture']['label'].split('_')[0]
            if op=='check':
                reads=[e for e in events(r)if e['kind']=='original_shared_memory_read'];check(reads,'check original shared read');first=reads[0];alias=bytes.fromhex(r['explicit_shared_alias_before_hex']);value=int.from_bytes(bytes.fromhex(first['bytes']),'little');off=first['offset_bytes'];check(alias[off:off+first['size_bytes']].hex()==first['bytes'],'client reads declared provider alias bytes');expected=1 if last_counter is None or last_counter!=value else 0;check(r['check_output_u32']==expected,'independent counter delta -> public check');last_counter=value;checks.append(r['check_output_u32'])
            for e in events(r):
                if e['kind']!='explicit_paired_notify_transport':continue
                totals['paired_messages']+=1;local=r['provider_call_indexes'].index(e['provider_stub_call']);pr=case['provider_journal'][r['provider_journal_indexes'][local]];raw=bytearray.fromhex(e['send_bytes']);check(raw[4:8]==bytes(4),'raw client size0');struct.pack_into('<I',raw,4,len(raw));effective=bytes.fromhex(pr['effective_received_message_and_trailer_hex']);check(effective[:len(raw)]==raw and len(effective)==len(raw)+52 and struct.unpack_from('<8I',effective,len(raw)+20)==tuple(pr['explicit_audit_words']),'declared exact effective header/audit trailer')
                if 'original_provider_reply_bytes'in e:reply=bytes.fromhex(e['original_provider_reply_bytes']);check(reply==bytes.fromhex(pr['reply64_hex'])[:len(reply)],'original provider body consumed by original parser')
        summary={'case':label,'checks':checks,'provider_states':source_summaries,'merges':[(a,o['merge_requests'])for a,o in objects.items()if o['type_symbol']=='__dispatch_source_type_data_or'],'final_FDs':fds,'callback_deliveries':sum('block_copy_pointer'in a for a in case['actions'])};summaries.append(summary)
    # Independent,explicit source-path controls: these are finite witnesses.
    summary={v['case']:v for v in summaries}
    def checkseq(label,seq):check(summary[label]['checks']==seq,'finite observable check sequence '+label)
    for label in ['config_write','config_mtime_only','config_ctime_only','config_both_metadata_pairs','config_write_and_mtime','config_initial_sandbox_denial_then_flag_bypass','client_normal','client_getgroups_failure','client_passwd_missing','client_initgroups_failure','client_timezone_prefix_bypass','client_timezone_lexical_prefix_no_separator','client_restore_groups_failure']:checkseq(label,[1,1,0])
    for label in ['config_no_data_no_metadata_change','config_cancelled_vnode_boundary','client_sandbox_denied','client_user_stat_EACCES']:checkseq(label,[1,0,0])
    for label in ['config_symlink','client_mask_write_only','client_mask_metadata_only']:checkseq(label,[1,0,0,1,0])
    check(summary['config_write_and_mtime']['merges'][0][1]==[0x102],'raw write2 plus changed mtime100')
    check(summary['config_two_events_one_delay']['merges'][0][1]==[2,8],'separate merge requests preserved')
    for label,count in [('config_two_events_one_delay',1),('config_two_batches',2)]:
        ev=[e for r in cases[label]['provider_journal']for e in events(r)];check(sum(e.get('name')=='_dispatch_after'for e in ev)==count,'source coalesced delay scheduling request count');final=cases[label]['provider_journal'][-1];dataor=next(v for v in final['external_objects_after'].values()if v.get('type_symbol')=='__dispatch_source_type_data_or');check(dataor['requests'].count('_dispatch_suspend')==count and dataor['requests'].count('_dispatch_resume')==count,'source coalesced suspend/resume request counts')
    for label in ['config_pending_delay_release','client_pending_delay_cancel']:
        states=summary[label]['provider_states'];live=[v['monitor_records'][0]for v in states if v['label']in ['vnode_event_6','vnode_event_5','explicit_monitor_release','message_4_stub','delayed_resume_8']and v['monitor_records']];check([r.get('refcount_u32')for r in live]==[2,1,None]and live[-1]['freed'],'source pending timer reference delays monitor retirement')
    for label in ['client_getgroups_failure','client_getgroups_failure_initial_L1_zero']:check(summary[label]['provider_states'][-1]['L1_u32']==0,'source getgroups-failure L1 zero continuation')
    for label in ['client_passwd_missing','client_initgroups_failure','client_normal']:check(summary[label]['provider_states'][-1]['L1_u32']==1,'source alternative L1 restoration')
    for label in ['client_timezone_prefix_bypass','client_timezone_lexical_prefix_no_separator','client_root_skips_credential_stat']:check(not any(e.get('name')=='_getgroups'for r in cases[label]['provider_journal']for e in events(r)),'source credential-helper bypass control')
    for label in ['config_release_cleanup','client_cancel_cleanup','client_pending_delay_cancel']:check(summary[label]['provider_states'][-1]['watcher_count_u32']==0 and len(summary[label]['provider_states'][-1]['declared_open_FDs'])==3,'last monitor zero-global-count/open declared FDs control')
    multi=summary['config_release_with_second_monitor_alive'];check(len(multi['provider_states'][-1]['declared_open_FDs'])==3 and sum(v['closed']for v in multi['final_FDs'].values())==2,'surviving monitor per-watcher cancellation/close control')
    check(any(a['op']=='cancel_FD_close'for a in cases['config_release_with_second_monitor_alive']['actions']),'captured close callback exercised')
    for proof in c['proofs']:
        path=ROOT/proof['path'];check(sha(path.read_bytes())==proof['sha256'],'proof source');run=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);check(run.stdout.strip()=='unsat'and not run.stderr,'fresh local formula')
    abi=c['sdk_compile'];check(sha((ROOT/'notifyd_monitor_layouts.c').read_bytes())==abi['source_sha256']and sha((ROOT/'notifyd_monitor_layouts.s').read_bytes())==abi['assembly_sha256'],'ABI source/assembly pins')
    for row in abi['headers']:check(sha(Path(row['path']).read_bytes())==row['sha256'],'SDK header pin')
    cmd=list(abi['command']);cmd[cmd.index('-o')+1]='/tmp/notifyd-monitor-verify.s';run=subprocess.run(cmd,capture_output=True,text=True);check(run.returncode==0 and not run.stderr and sha(Path('/tmp/notifyd-monitor-verify.s').read_bytes())==abi['assembly_sha256'],'fresh SDK compile')
    fresh_calls=0;freshpools={'instructions':{},'functions':{},'cache_pages':{}}
    for old in p['cases']:
        print('fresh '+old['case']['label'],flush=True);new=run_case(old['case'])
        for origin,rows in [('provider',new['provider_journal']),('client',new['client_calls'])]:
            for row in rows:compact_row(row,origin,freshpools)
        check(json.loads(json.dumps(new))==old,'complete fresh original replay '+old['case']['label']);fresh_calls+=len(new['provider_journal'])+len(new['client_calls'])
    check({k:list(v.values())for k,v in freshpools.items()}==p['original_source_pools'],'full fresh source pool readback')
    for row in read('interface_manifest.json')['inputs_preserved']:
        path=ROOT.parent/row['path'];check(path.stat().st_size==row['size_bytes']and sha(path.read_bytes())==row['sha256'],'original input preserved')
    counts={**totals,'monitor_sequences':len(p['cases']),'provider_original_calls':sum(len(v['provider_journal'])for v in p['cases']),'client_public_calls':sum(len(v['client_calls'])for v in p['cases']),'fresh_original_calls':fresh_calls,'original_instruction_records':len(bank),'original_compiler_records':len(p['original_source_pools']['functions']),'source_contract_functions':len(c['original_functions']),'source_Block_descriptors':len(descriptors),'source_incoming_edges':len(incoming),'source_outgoing_edges':len(outgoing),'proofs_unsat':len(c['proofs']),'assertions':assertions};result={'scope':__doc__,'verified_counts':counts,'independent_summaries':summaries,'all_checks_pass':True,'native_target_executed':False,'native_transaction_executed':False,'native_defect_established':False,'full_goal_complete':False};(ROOT/'notifyd_monitor_checks.json').write_text(json.dumps(result,indent=2)+'\n');quality={k:v for k,v in result.items()if k!='independent_summaries'}
    texts=['Factual source/interface analysis.','Report M1-M12 state assumptions,dependent results and falsification probes.','Monitor construction,callback/publication,credentials,masking/coalescing and cancellation covered for this increment;full goal remains active.','Byte/bit widths,record extents,stat timespec layout,100000000 ns delay,source arithmetic and bounded complexity explicit.','Source requests versus native effects,last-monitor versus surviving-monitor cleanup,and general-error versus EACCES returns separated.','Original bytes/import chains/data,independent allocation/DATA/shared/L1/Block/FD/dispatch ledgers,all original-case replays,SDK compile and local formulas.','Impact-labeled callback provenance,credential/cache state,watcher ownership and protected-provider continuation included.']
    for j,t in enumerate(texts,1):quality['QG'+str(j)]={'status':'pass_for_stated_increment','evidence':t}
    (ROOT/'notifyd_monitor_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps(counts),flush=True)

if __name__=='__main__':main()
