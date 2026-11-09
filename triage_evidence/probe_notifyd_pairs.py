#!/usr/bin/env python3
"""Paired original libnotify public calls and initialized original notifyd.

Explicit transport supplies effective headers,audit trailers,framework reply
headers,API result0 and cross-guest shared-byte aliasing. Original selector,
stub,worker,collections and client parsers execute. Native admission/rights/
transport/scheduling remain unknown. O(C*(B+P+V+W)) time/space,bounded fixtures.
"""
import copy
import base64
import zlib
import json
from pathlib import Path
import struct
from probe_notify_ipc import IPC,HEAP as CLIENT_HEAP,SHMEM
from probe_notifyd_admission import Session,SHARED,HEAP,REQUEST,REPLY,request
from notifyd_ipc_reader import Notifyd,ROOT,sha,THIN_SHA
from notify_ipc_reader import Notify

NDR=bytes.fromhex('0000000001000000')


def audit_words(uid=501,pid=2117,gid=20):return [0,uid,gid,uid,gid,pid,7,3]


def process(q,label,raw,audit):
    raw=bytearray(raw);size=len(raw);assert 24<=size<=4096-52;struct.pack_into('<I',raw,4,size);mid=struct.unpack_from('<I',raw,20)[0];trailer=bytearray(52);struct.pack_into('<5I',trailer,0,0,52,0,0,0);struct.pack_into('<8I',trailer,20,*audit);effective=bytes(raw)+trailer;q.fixture={**q.fixture,'effective_request_and_trailer_hex':effective.hex()};q.u.mem_write(REQUEST,bytes(4096));q.u.mem_write(REQUEST,bytes(effective));q.u.mem_write(REPLY,bytes(4096));q.u.mem_write(REPLY,struct.pack('<6I',0,36,0,0x5901,0,mid+100));selector=q.invoke(label+'_selector',0x100008dfc,[REQUEST]);target=int(selector['result_x0'],16);assert target
    r=q.invoke(label+'_stub',target,[REQUEST,REPLY]);r.update(raw_client_send_hex=bytes(raw[:4]+bytes(4)+raw[8:]).hex(),effective_received_message_and_trailer_hex=effective.hex(),explicit_audit_words=audit);return [selector,r]


class Paired(IPC):
    def __init__(self,s,f,provider):super().__init__(s,f);self.provider=provider;self.provider_calls=[];self.transfers=[]
    def api(self,meta):
        if '_mach_msg' not in meta['exact_exports']:return super().api(meta)
        x=[self.reg('x'+str(j)) for j in range(8)];raw=bytes(self.u.mem_read(x[0],x[2]));mid=struct.unpack_from('<I',raw,20)[0];e={'kind':'explicit_paired_notify_transport','name':'_mach_msg','callsite':hex(getattr(self,'last_client_branch',self.reg('lr')-4)),'args_x0_x7':[hex(v) for v in x],'message_id_u32':mid,'send_size_bytes':x[2],'send_bytes':raw.hex(),'native_API_executed':False,'effective_header_and_audit_production_native_validated':False};self.records.append(e)
        calls=process(self.provider,'message_'+str(len(self.provider_calls)),raw,self.fixture.get('audit_words',audit_words()));self.provider_calls.extend(calls);r=calls[-1];e.update(provider_selector_call=len(self.provider_calls)-2,provider_stub_call=len(self.provider_calls)-1,provider_stop_reason=r['stop_reason'])
        if r['stop_reason']!='returned_to_private_fixture':return self.stop('paired_provider_boundary:'+r['stop_reason'])
        # Distinct private guests represent one shared object only by declared byte transfer.
        shared=bytes(self.provider.u.mem_read(SHARED,16384));self.u.mem_write(SHMEM,shared);e['explicit_shared_alias_snapshot_hex']=shared.hex()
        if x[3]:
            reply=bytes.fromhex(r['reply64_hex']);size=struct.unpack_from('<I',reply,4)[0];assert 36<=size<=len(reply) and size<=x[3];reply=reply[:size];self.u.mem_write(x[0],reply);e['original_provider_reply_bytes']=reply.hex()
        else:e['oneway_provider_application_reply_delivered']=False
        e['kernel_API_result_u32']=0;return self.finish(0)
    def invoke(self,label,entry,args,shared_counter=None):
        assert shared_counter is None;before=bytes(self.provider.u.mem_read(SHARED,16384));self.u.mem_write(SHMEM,before);start=len(self.provider_calls);r=super().invoke(label,entry,args);r.update(provider_call_indexes=list(range(start,len(self.provider_calls))),explicit_shared_alias_before_hex=before.hex(),explicit_shared_alias_after_hex=bytes(self.u.mem_read(SHMEM,16384)).hex());return r


def run_case(case):
    server=Session(Notifyd(),{'model_port_constructor':True,'model_port_request_notification':True,**case.get('server_fixture',{})});startup=server.invoke('startup',server.provider.entry,[server.argc,HEAP+0x1800]);f={'entry':0,'args':[],'notification_name':case.get('name','com.apple.adid.midchangedV1'),'execute_original_collections':True,'execute_original_mig_string':True,'reply_by_id':{},'oneway_result_by_id':{},'audit_words':case.get('audit_words',audit_words()),'instruction_budget':200000};s=Notify();client=Paired(s,f,server);calls=[]
    for step in case['steps']:
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
        export={'register':'_notify_register_check','check':'_notify_check','post':'_notify_post','cancel':'_notify_cancel'}[step['op']];args={'register':[CLIENT_HEAP+0x1000,CLIENT_HEAP+0x2000],'check':[step.get('token',2),CLIENT_HEAP+0x2010],'post':[CLIENT_HEAP+0x1000],'cancel':[step.get('token',2)]}[step['op']];r=client.invoke(step['op']+'_'+str(len(calls)),s.lib.exports[export]['address'],args);calls.append(r)
        if r['stop_reason']!='returned_to_private_fixture':break
    return {'case':case,'startup':startup,'client_calls':calls,'provider_calls':client.provider_calls,'native_transaction_executed':False,'full_goal_complete':False}


def compact_row(r,origin,pools):
    for key in ['original_instruction_records','instruction_records']:
        for item in r.pop(key,[]):
            a=item['ea'];old=pools['instructions'].get(a);assert old is None or old==item;pools['instructions'][a]=item
    for key in ['original_functions','original_cache_functions']:
        for item in r.pop(key,[]):
            a=item['start'];tag=origin+':'+a;old=pools['functions'].get(tag);assert old is None or old==item;pools['functions'][tag]=item
    for key in ['original_materialized_pages','original_materialized_cache_pages']:
        for item in r.pop(key,[]):
            a=item['address'];old=pools['cache_pages'].get(a);assert old is None or old==item;pools['cache_pages'][a]=item
    if 'records' in r:
        r['records_zlib_base64']=base64.b64encode(zlib.compress(json.dumps(r.pop('records'),separators=(',',':')).encode())).decode();r['records_encoding']='zlib compressed UTF-8 JSON array then base64'


def main():
    cases=[];life=[{'op':v} for v in ['register','check','check','post','check','check','cancel','check']]
    for name in ['com.apple.adid.midchangedV1','com.apple.adid.midchangedV1.5','com.apple.adid.midchangedV3']:cases.append({'label':'paired_'+name,'name':name,'steps':life})
    for uid in [0,501,502]:cases.append({'label':'other_post_uid_'+str(uid),'steps':[{'op':'register'},{'op':'check'},{'op':'external_post','audit_words':audit_words(uid=uid,pid=2222)},{'op':'check'}]})
    for uid in [0,501,502]:cases.append({'label':'uid_namespace_post_'+str(uid),'name':'user.uid.501.fixture','steps':[{'op':'register'},{'op':'check'},{'op':'external_post','audit_words':audit_words(uid=uid,pid=2222)},{'op':'check'}]})
    for choice in [None,False,True]:
        key='com.apple.private.darwin-notification.restrict-post.fixture';cases.append({'label':'restricted_entitlement_'+str(choice),'name':'com.apple.private.restrict-post.fixture','server_fixture':{'entitlements':{key:choice}},'steps':[{'op':'register'},{'op':'check'},{'op':'post'},{'op':'check'}]})
    for choice in [None,False,True]:
        cases.append({'label':'root_override_'+str(choice),'name':'user.uid.501.fixture','server_fixture':{'entitlements':{'com.apple.notify.root_access':choice}},'steps':[{'op':'register'},{'op':'check'},{'op':'external_post','flags':1,'audit_words':audit_words(uid=502,pid=2222)},{'op':'check'}]})
    cases.append({'label':'no_shared_cli','server_fixture':{'argv':['-shm_pages','0']},'steps':life})
    cases.append({'label':'no_shared_named_post','server_fixture':{'argv':['-shm_pages','0']},'steps':[{'op':'register'},{'op':'check'},{'op':'post'},{'op':'check'},{'op':'external_name_post'},{'op':'check'}]})
    for decision in [0,1]:cases.append({'label':'named_post_sandbox_'+str(decision),'server_fixture':{'sandbox_post_result':decision},'steps':[{'op':'register'},{'op':'check'},{'op':'external_name_post'},{'op':'check'}]})
    for label,name,uid in [('registration_uid_mismatch','user.uid.501.fixture',502),('registration_uid_missing_delimiter','user.uid.501x',501)]:cases.append({'label':label,'name':name,'audit_words':audit_words(uid=uid),'steps':[{'op':'register'}]})
    for size in [204,205,207,208]:
        suffix='a'*size;key='com.apple.private.darwin-notification.restrict-post.'+suffix;cases.append({'label':'restricted_key_suffix_'+str(size),'name':'com.apple.private.restrict-post.'+suffix,'server_fixture':{'entitlements':{key:True}},'steps':[{'op':'register'},{'op':'check'},{'op':'post'},{'op':'check'}]})
    cases.append({'label':'repeat_registration_denial','name':'user.uid.501.fixture','audit_words':audit_words(uid=502),'steps':[{'op':'register'} for _ in range(3)]})
    cases.append({'label':'wrong_pid_cancel','steps':[{'op':'register'},{'op':'check'},{'op':'external_cancel','audit_words':audit_words(pid=2222)},{'op':'post'},{'op':'check'},{'op':'cancel'}]})
    rows=[]
    for case in cases:
        r=run_case(case);rows.append(r);print(json.dumps({'label':case['label'],'startup':r['startup']['stop_reason'],'client':[(c['stop_reason'],c['result_u32'],c['check_output_u32']) for c in r['client_calls']],'provider':[(p['fixture']['label'],p['stop_reason']) for p in r['provider_calls']]}),flush=True)
    pools={'instructions':{},'functions':{},'cache_pages':{}}
    for case in rows:
        for origin,records in [('provider',[case['startup']]+case['provider_calls']),('client',case['client_calls'])]:
            for r in records:compact_row(r,origin,pools)
    out={'scope':__doc__,'original_source_pools':{k:list(v.values()) for k,v in pools.items()},'generator_sha256':sha(Path(__file__).read_bytes()),'dependencies':{n:sha((ROOT/n).read_bytes()) for n in ['probe_notifyd_admission.py','probe_notifyd_ipc.py','probe_notify_ipc.py','notifyd_ipc_reader.py','notify_ipc_reader.py']},'cases':rows,'native_target_executed':False,'native_transaction_executed':False,'full_goal_complete':False};(ROOT/'notifyd_admission_profiles.json').write_text(json.dumps(out,indent=2)+'\n')

if __name__=='__main__':main()
