#!/usr/bin/env python3
"""Paired original libnotify/notifyd under parsed reference/config fixtures.

Frozen original-code engines plus bounded configuration API models. Original
parser constructs controlled-name state before complete selector/stub workers.
No native daemon/IPC/file/policy/scheduler API. O(C*(B+P+V+W+A)) time/space.
"""
import base64
import copy
import json
from pathlib import Path
import struct
import zlib
from probe_notifyd_pairs import Paired,process,audit_words,NDR,CLIENT_HEAP,Notify,compact_row
from probe_notifyd_policy import Policy,HEAP
from notifyd_ipc_reader import Notifyd,ROOT,sha

class PolicyPair(Paired):
    def api(self,meta):
        if '_mach_absolute_time' in meta['exact_exports']:
            value=self.fixture.get('client_tick_u64',0x123456789);self.records.append({'kind':'explicit_client_tick_model','name':'_mach_absolute_time','callsite':hex(getattr(self,'last_client_branch',self.reg('lr')-4)),'opaque_ticks_u64':value,'native_API_executed':False});return self.finish(value)
        return super().api(meta)


def run_policy_case(case):
    server=Policy(Notifyd(),{'model_port_constructor':True,'model_port_request_notification':True,**case.get('server_fixture',{})});startup=server.invoke('startup',server.provider.entry,[server.argc,HEAP+0x1800]);f={'entry':0,'args':[],'notification_name':case.get('name','com.apple.adid.midchangedV1'),'execute_original_collections':True,'execute_original_mig_string':True,'reply_by_id':{},'oneway_result_by_id':{},'audit_words':case.get('audit_words',audit_words()),'instruction_budget':200000};s=Notify();f.update(case.get('client_fixture',{}));client=PolicyPair(s,f,server);calls=[]
    for step in case['steps']:
        if step['op']=='external_state_get':
            raw=struct.pack('<6I',0x1513,40,0x5902,0x5901,0,1017)+NDR+struct.pack('<Q',step.get('name_id_u64',1));pcalls=process(server,'external_state_'+str(len(client.provider_calls)),raw,step.get('audit_words',audit_words()));client.provider_calls.extend(pcalls)
            if pcalls[-1]['stop_reason']!='returned_to_private_fixture':break
            continue
        if step['op'] in ['external_name_post','external_cancel']:
            if step['op']=='external_name_post':
                name=case.get('name','com.apple.adid.midchangedV1').encode()+b'\0';count=len(name);body=NDR+struct.pack('<II',0,count)+name+bytes((-count)%4)+struct.pack('<I',step.get('flags',0));raw=struct.pack('<6I',19,24+len(body),0x5902,0,0,1010)+body
            else:raw=struct.pack('<6I',19,36,0x5902,0,0,1016)+NDR+struct.pack('<I',step.get('token',2))
            pcalls=process(server,'external_'+str(len(client.provider_calls)),raw,step.get('audit_words',audit_words()));client.provider_calls.extend(pcalls)
            if pcalls[-1]['stop_reason']!='returned_to_private_fixture':break
            continue
        if step['op']=='external_post':
            reg=next(e for r in calls for e in r['records'] if e.get('message_id_u32')==1012);nameid=struct.unpack_from('<Q',bytes.fromhex(reg['original_provider_reply_bytes']),44)[0];raw=struct.pack('<6I',19,44,0x5902,0,0,1009)+NDR+struct.pack('<QI',nameid,step.get('flags',0));pcalls=process(server,'external_post_'+str(len(client.provider_calls)),raw,step.get('audit_words',audit_words()));client.provider_calls.extend(pcalls)
            if pcalls[-1]['stop_reason']!='returned_to_private_fixture':break
            continue
        if 'client_tick_u64' in step:client.fixture={**client.fixture,'client_tick_u64':step['client_tick_u64']}
        export={'register':'_notify_register_check','check':'_notify_check','post':'_notify_post','cancel':'_notify_cancel','get_state':'_notify_get_state','set_state':'_notify_set_state'}[step['op']];args={'register':[CLIENT_HEAP+0x1000,CLIENT_HEAP+0x2000],'check':[step.get('token',2),CLIENT_HEAP+0x2010],'post':[CLIENT_HEAP+0x1000],'cancel':[step.get('token',2)],'get_state':[step.get('token',2),CLIENT_HEAP+0x2100],'set_state':[step.get('token',2),step.get('state_u64',0)]}[step['op']];r=client.invoke(step['op']+'_'+str(len(calls)),s.lib.exports[export]['address'],args);r['state_output_u64']=int.from_bytes(client.u.mem_read(CLIENT_HEAP+0x2100,8),'little');calls.append(r)
        if r['stop_reason']!='returned_to_private_fixture':break
    return {'case':case,'startup':startup,'client_calls':calls,'provider_calls':client.provider_calls,'native_transaction_executed':False,'full_goal_complete':False}


def reserve(name,uid=0,gid=0,access='rwr-r-'):
    return ('reserve '+name+' '+str(uid)+' '+str(gid)+' '+access+'\n').encode()


def main():
    reference=(ROOT/'notifyd_policy_reference.conf').read_bytes();cases=[]
    life=[{'op':v} for v in ['register','check','post','check','cancel','check']]
    def add(label,raw,name='com.apple.adid.midchangedV1',steps=None,audit=None,**fixture):
        cases.append({'label':label,'name':name,'server_fixture':{'config_hex':raw.hex(),**fixture},'audit_words':audit or audit_words(),'steps':steps if steps is not None else life})
    for name in ['com.apple.adid.midchangedV1','com.apple.adid.midchangedV1.5','com.apple.adid.midchangedV3']:add('reference_'+name,reference,name)
    for name,gid in [('com.apple.system.fixture',20),('com.apple.system.clock_set',20),('com.apple.system.clock_set',266),('com.apple.system.clock_set.extra',266),('com.apple.system.clock_setx',266),('com.apple.system2.clock_set',20)]:add('reference_prefix_'+name+'_gid_'+str(gid),reference,name,audit=audit_words(gid=gid))
    for uid in [0,501,1000]:
        for gid in [20,21]:add('owner_group_'+str(uid)+'_'+str(gid),reserve('fixture.',501,20,'rwr---'),'fixture.value',audit=audit_words(uid=uid,gid=gid))
    add('owner_read_falls_through_to_other',reserve('fixture.',501,20,'-w--r-'),'fixture.value')
    add('group_write_falls_through_to_other',reserve('fixture.',501,20,'--r--w'),'fixture.value',audit=audit_words(uid=502,gid=20))
    for label,fixture in [('nonroot_owner',{'config_uid':501}),('world_writable',{'config_mode_u16':0o100666}),('group_writable',{'config_mode_u16':0o100664}),('open_failure',{'config_open_success':False}),('absent',{'config_present':False})]:add('config_gate_'+label,reserve('fixture.',0,0,'------'),'fixture.value',**fixture)
    parent=reserve('fixture.',0,0,'r-r-r-');child=reserve('fixture.child',0,20,'rwrwrw')
    for label,raw in [('parent_then_child',parent+child),('child_then_parent',child+parent),('duplicate_child_last_denies',child+reserve('fixture.child',0,0,'------')),('duplicate_child_last_allows',reserve('fixture.child',0,0,'------')+child)]:add('ordering_'+label,raw,'fixture.child.value')
    for label,raw in [('leading_space',b' '+reserve('fixture.',0,0,'------')),('double_space',reserve('fixture.',0,0,'------').replace(b'reserve ',b'reserve  ')),('tab_separators',reserve('fixture.',0,0,'------').replace(b' ',b'\t')),('uppercase_command',reserve('fixture.',0,0,'------').replace(b'reserve',b'RESERVE')),('CRLF',reserve('fixture.',0,0,'rwrwrw').replace(b'\n',b'\r\n')),('no_final_newline',reserve('fixture.',0,0,'rwrwrw').rstrip(b'\n')),('inline_comment',reserve('fixture.',0,0,'------').rstrip(b'\n')+b' # comment\n'),('comment_first_byte',b'#'+reserve('fixture.',0,0,'------')),('quit_before_rule',b'quit\n'+reserve('fixture.',0,0,'------')),('empty_line',b'\n'+reserve('fixture.',0,0,'------'))]:add('grammar_'+label,raw,'fixture.value')
    add('own_uid_namespace_precedes_config',reserve('user.uid.501.',0,0,'------'),'user.uid.501.value')
    add('other_uid_namespace_precedes_config',reserve('user.uid.501.',0,0,'rwrwrw'),'user.uid.501.value',audit=audit_words(uid=502))
    for value in ['0','1','-1','9223372036854775807','12junk']:add('set_state_'+value,('set fixture.state '+value+'\n').encode(),'fixture.state',steps=[])
    add('set_state_without_value',b'set fixture.state\n','fixture.state',steps=[])
    add('monitor_declaration',b'monitor fixture.path /tmp/model-only-path\n','fixture.path',steps=[])
    add('reserve_defaults_no_control',b'reserve fixture.\n','fixture.value')
    add('short_access_string_denies',reserve('fixture.',0,0,'rw'),'fixture.value')
    add('unknown_access_letters',reserve('fixture.',0,0,'xxxxxx'),'fixture.value')
    for value in ['0','1','-1','9223372036854775807']:
        add('state_get_initial_'+value,('set fixture.state '+value+'\n').encode(),'fixture.state',steps=[{'op':'register'},{'op':'get_state'},{'op':'cancel'}])
    state_steps=[{'op':'register'},{'op':'get_state'},{'op':'check'},{'op':'set_state','state_u64':0x1122334455667788},{'op':'get_state'},{'op':'check'},{'op':'post'},{'op':'check'},{'op':'cancel'}]
    add('state_set_allowed',b'set fixture.state 17\n','fixture.state',steps=state_steps)
    add('state_set_denied',b'set fixture.state 17\n'+reserve('fixture.state',0,0,'rwr-r-'),'fixture.state',steps=state_steps)
    add('state_set_root',b'set fixture.state 17\n'+reserve('fixture.state',0,0,'------'),'fixture.state',steps=state_steps,audit=audit_words(uid=0))
    add('state_set_group',b'set fixture.state 17\n'+reserve('fixture.state',0,266,'rwrwr-'),'fixture.state',steps=state_steps,audit=audit_words(gid=266))
    add('state_get_known_id_after_registration_denial',b'set fixture.state 17\n'+reserve('fixture.state',0,0,'------'),'fixture.state',steps=[{'op':'register'},{'op':'external_state_get','name_id_u64':1}])
    add('state_get_missing_id',b'set fixture.state 17\n','fixture.state',steps=[{'op':'external_state_get','name_id_u64':0xffffffffffffffff}])
    rows=[];pools={'instructions':{},'functions':{},'cache_pages':{}}
    for case in cases:
        r=run_policy_case(case);print(json.dumps({'label':case['label'],'startup':r['startup']['stop_reason'],'tokens':[e['tokens'] for e in r['startup']['records'] if e['kind']=='original_config_token_vector'],'controlled':[(e['name'],e['uid_u32'],e['gid_u32'],e['access_u32']) for e in r['startup']['controlled_names_after']],'client':[(x['result_u32'],x['check_output_u32'],x['stop_reason']) for x in r['client_calls']]}),flush=True)
        for origin,records in [('provider',[r['startup']]+r['provider_calls']),('client',r['client_calls'])]:
            for row in records:compact_row(row,origin,pools)
        rows.append(r)
    out={'scope':__doc__,'generator_sha256':sha(Path(__file__).read_bytes()),'dependencies':{n:sha((ROOT/n).read_bytes()) for n in ['probe_notifyd_policy.py','probe_notifyd_pairs.py','probe_notifyd_admission.py','notifyd_ipc_reader.py','notifyd_policy_reference.conf','notifyd_policy_reference.json']},'cases':rows,'original_source_pools':{k:list(v.values()) for k,v in pools.items()},'native_target_executed':False,'native_transaction_executed':False,'full_goal_complete':False};(ROOT/'notifyd_policy_profiles.json').write_text(json.dumps(out,indent=2)+'\n')

if __name__=='__main__':main()
