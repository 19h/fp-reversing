#!/usr/bin/env python3
"""Finite original notifyd monitor callbacks and original libnotify polling.

Callback entry/capture comes from source-built copied Blocks; scheduler and VFS
inputs are declared, synchronous and private. Original main, selector, stubs,
workers, audit helpers and collections execute. O(C*(B+P+V+W+A)) bounded time
and space. No native daemon,IPC,filesystem watch,credential or dispatch API.
"""
import copy,json,struct
from pathlib import Path
from probe_notifyd_monitor import Monitor,HEAP
from probe_notifyd_policy_pairs import PolicyPair,CLIENT_HEAP,Notify,audit_words,compact_row
from notifyd_ipc_reader import Notifyd,ROOT,sha


def run_case(case):
    config=(('monitor fixture.path '+case.get('path','/model/file')+'\n'+''.join('monitor '+line+'\n' for line in case.get('additional_monitors',[]))).encode() if case.get('mode','config')=='config' else b'\n')
    f={'model_port_constructor':True,'model_port_request_notification':True,'config_hex':config.hex(),**case.get('server_fixture',{})};q=Monitor(Notifyd(),f);actions=[];client_rows=[];q.invoke('startup',q.provider.entry,[q.argc,HEAP+0x1800]);s=Notify();name=case.get('name','fixture.path' if case.get('mode','config')=='config' else 'com.apple.system.notify.service.path:'+case.get('path','/model/file'));client=PolicyPair(s,{'entry':0,'args':[],'notification_name':name,'execute_original_collections':True,'execute_original_mig_string':True,'reply_by_id':{},'oneway_result_by_id':{},'audit_words':case.get('audit_words',audit_words()),'instruction_budget':200000},q)
    delivered=set()
    def call(op):
        args={'register':[CLIENT_HEAP+0x1000,CLIENT_HEAP+0x2000],'check':[2,CLIENT_HEAP+0x2010],'cancel':[2]}[op];r=client.invoke(op+'_'+str(len(client_rows)),s.lib.exports[{'register':'_notify_register_check','check':'_notify_check','cancel':'_notify_cancel'}[op]]['address'],args);r['provider_journal_indexes']=[client.provider_calls[j]['provider_invocation_index'] for j in r['provider_call_indexes']];client_rows.append(r);actions.append({'op':op,'client_index':len(client_rows)-1,'provider_journal_indexes':r['provider_journal_indexes']});return r
    def block_delivery(block,op,extra=None):
        p=int(block['copy_pointer'],16);r=q.invoke(op+'_'+str(len(q.history)),int(block['invoke_pointer'],16),[p]);actions.append({'op':op,'block_copy_pointer':hex(p),'source_built_invoke':block['invoke_pointer'],'provider_journal_index':r['provider_invocation_index'],**(extra or {})});return r
    def findblock(p):return next(b for b in q.blocks if b['copy_pointer']==p)
    def source(kind,path=None,allow_cancel=False):
        rows=[(p,o) for p,o in q.objects.items() if o.get('type_symbol')=='__dispatch_source_type_'+kind and (allow_cancel or not o.get('cancel_requested')) and (path is None or q.fds[o['handle_u64']]['path']==path)]
        return rows[-1] if rows else (None,None)
    def finish():
        return {'case':case,'declared_config_hex':config.hex(),'notification_name':name,'actions':actions,'provider_journal':q.history,'client_calls':client_rows,'native_transaction_executed':False,'full_goal_complete':False}
    call('register');call('check')
    if case.get('mode','config')=='config':
        for b in [b for b in q.blocks if b['invoke_pointer']=='0x10000712c']:
            r=block_delivery(b,'deferred_config')
            if r['stop_reason']!='returned_to_private_fixture':return finish()
    # Deliberately declared source cancellation control,not a native cancel event.
    if case.get('declare_source_cancelled'):
        p,o=source('vnode','/model/file');o['cancel_requested']=True;actions.append({'op':'declare_source_cancelled','source_pointer':hex(p)})
    for event in case.get('events',[]):
        for path,changes in event.get('fs_updates',{}).items():q.fs.setdefault(path,{}).update(changes)
        p,o=source('vnode',event.get('watch_path','/model/file'),case.get('declare_source_cancelled',False))
        if p is None:actions.append({'op':'no_matching_owned_vnode','event':event});continue
        q.event_data[p]=event.get('data',0);r=block_delivery(findblock(o['event_block']),'vnode_event',{'source_pointer':hex(p),'event':event})
        if r['stop_reason']!='returned_to_private_fixture':return finish()
        if event.get('batch_end',False):
            for b in list(q.blocks):
                if b['kind']=='after' and b['copy_pointer'] not in delivered:delivered.add(b['copy_pointer']);block_delivery(b,'delayed_resume')
            p,o=source('data_or')
            if p and o['pending_data_u64'] and not case.get('suppress_dataor_delivery'):
                value=o['pending_data_u64'];block_delivery(findblock(o['event_block']),'dataor_delivery',{'source_pointer':hex(p),'declared_coalesced_data_u64':value});o['pending_data_u64']=0;actions.append({'op':'explicit_consume_dataor','source_pointer':hex(p),'consumed_u64':value,'native_scheduler_validated':False})
            call('check');call('check')
    if case.get('cleanup'):
        if case.get('mode','config')=='client':call('cancel')
        else:
            live=[p for p,k in q.source_records.items() if k=='monitor' and not q.allocations[p]['freed']]
            if live:r=q.invoke('explicit_monitor_release',0x1000072f0,[live[0]]);actions.append({'op':'explicit_helper_release','provider_journal_index':r['provider_invocation_index'],'original_predecessor_established':False})
        for b in list(q.blocks):
            if b['kind']=='after' and b['copy_pointer'] not in delivered:delivered.add(b['copy_pointer']);block_delivery(b,'delayed_resume')
        for b in list(q.blocks):
            if b['invoke_pointer']=='0x100007f98':block_delivery(b,'watcher_dispose')
        for p,o in list(q.objects.items()):
            if o.get('type_symbol')=='__dispatch_source_type_vnode' and o.get('cancel_requested') and 'cancel_block' in o:block_delivery(findblock(o['cancel_block']),'cancel_FD_close',{'source_pointer':hex(p)})
    return finish()


def cases():
    out=[]
    def add(label,**kw):out.append({'label':label,**kw})
    def ev(data=2,updates=None,**kw):return {'data':data,'fs_updates':updates or {},'batch_end':True,**kw}
    for label,data,updates in [('write',2,{}),('no_data_no_metadata_change',0,{}),('mtime_only',0,{'mtime_seconds':11}),('ctime_only',0,{'ctime_nanoseconds':1}),('both_metadata_pairs',0,{'mtime_nanoseconds':1,'ctime_seconds':21})]+[('raw_'+hex(v),v,{}) for v in [1,4,8,16,32,64]]:
        add('config_'+label,events=[ev(data,{'/model/file':updates})])
    add('config_write_and_mtime',events=[ev(2,{'/model/file':{'mtime_seconds':11}})])
    add('config_two_events_one_delay',events=[{'data':2,'batch_end':False},ev(8)])
    add('config_two_batches',events=[ev(2),ev(8)])
    add('config_relative_path',path='model/file',events=[])
    add('config_repeated_slashes',path='//model///file/',events=[ev(2)])
    add('config_missing_target',server_fixture={'fs':{'/':{'mode':0o040755},'/model':{'mode':0o040755}}},events=[ev(2,{'/model/file':{'mode':0o100644}},watch_path='/model')])
    add('config_symlink',server_fixture={'fs':{'/':{'mode':0o040755},'/model':{'mode':0o040755},'/model/file':{'mode':0o120777},'/target':{'mode':0o100644}},'realpaths':{'/model/file':'/target'}},events=[ev(2,watch_path='/target'),ev(2)])
    add('config_initial_sandbox_denial_then_flag_bypass',server_fixture={'sandbox_monitor_result':1},events=[ev(2)])
    add('config_vnode_create_NULL',server_fixture={'source_create_NULL_type':'__dispatch_source_type_vnode'},events=[])
    add('config_dataor_create_NULL',server_fixture={'source_create_NULL_type':'__dispatch_source_type_data_or'},events=[])
    add('config_cancelled_vnode_boundary',declare_source_cancelled=True,events=[ev(2)])
    add('config_release_cleanup',cleanup=True,events=[])
    add('config_release_with_second_monitor_alive',additional_monitors=['fixture.other /other/file'],server_fixture={'fs':{'/':{'mode':0o040755},'/model':{'mode':0o040755},'/model/file':{'mode':0o100644},'/other':{'mode':0o040755},'/other/file':{'mode':0o100644}}},cleanup=True,events=[])
    add('config_pending_delay_release',cleanup=True,suppress_dataor_delivery=True,events=[{'data':2,'batch_end':False}])
    for label,fixture in [('normal',{}),('sandbox_denied',{'sandbox_monitor_result':1}),('getgroups_failure',{'getgroups_failure':True}),('getgroups_failure_initial_L1_zero',{'getgroups_failure':True,'initial_L1_u32':0}),('passwd_missing',{'passwd_missing':True}),('initgroups_failure',{'initgroups_result':-1}),('user_stat_EACCES',{'user_stat_denied_paths':['/model/file']}),('timezone_prefix_bypass',{'realpaths':{'/model/file':'/var/db/timezone/zoneinfo/fixture'}}),('restore_groups_failure',{'restore_groups_result':-1})]:
        add('client_'+label,mode='client',server_fixture=fixture,events=[ev(2)])
    add('client_mask_write_only',mode='client',name='com.apple.system.notify.service.path:0x2:/model/file',events=[ev(8),ev(2)])
    add('client_mask_metadata_only',mode='client',name='com.apple.system.notify.service.path:0x100:/model/file',events=[ev(2),ev(0,{'/model/file':{'mtime_seconds':11}})])
    add('client_timezone_lexical_prefix_no_separator',mode='client',server_fixture={'realpaths':{'/model/file':'/VAR/DB/TIMEZONE/ZONEINFOx/fixture'}},events=[ev(2)])
    add('client_root_skips_credential_stat',mode='client',audit_words=audit_words(uid=0),events=[ev(2)])
    add('client_cancel_cleanup',mode='client',events=[ev(2)],cleanup=True)
    add('client_pending_delay_cancel',mode='client',events=[{'data':2,'batch_end':False}],cleanup=True,suppress_dataor_delivery=True)
    return out


def main():
    rows=[];pools={'instructions':{},'functions':{},'cache_pages':{}}
    for case in cases():
        r=run_case(case);print(json.dumps({'case':case['label'],'stops':[(v['fixture']['label'],v['stop_reason']) for v in r['provider_journal'] if v['stop_reason'] not in ['returned_to_private_fixture','original_startup_dispatch_main_boundary']],'checks':[v['check_output_u32'] for v in r['client_calls'] if v['fixture']['label'].startswith('check')],'L1':r['provider_journal'][-1]['bound_L1_u32_after'],'calls':len(r['provider_journal'])}),flush=True)
        for origin,seq in [('provider',r['provider_journal']),('client',r['client_calls'])]:
            for row in seq:compact_row(row,origin,pools)
        rows.append(r)
    out={'scope':__doc__,'generator_sha256':sha(Path(__file__).read_bytes()),'dependencies':{n:sha((ROOT/n).read_bytes()) for n in ['probe_notifyd_monitor.py','probe_notifyd_policy.py','probe_notifyd_policy_pairs.py','probe_notifyd_pairs.py','probe_notifyd_admission.py','notifyd_ipc_reader.py','notify_ipc_reader.py']},'original_source_pools':{k:list(v.values()) for k,v in pools.items()},'cases':rows,'native_target_executed':False,'native_transaction_executed':False,'full_goal_complete':False};(ROOT/'notifyd_monitor_profiles.json').write_text(json.dumps(out,indent=2)+'\n')

if __name__=='__main__':main()
