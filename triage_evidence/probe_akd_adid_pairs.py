#!/usr/bin/env python3
"""Pass original client request bytes through original ADID and resume its API.

Client stops at the synchronous API binding. The provider runs in a separate
private guest; its exact reply bytes complete that pending modeled API at the
same PC/SP/LR. No internal control/frame patches or native IPC. O(C*(B+F+K))
time/space; finite original-hook caps and <=8192-byte modeled data.
"""
import base64
import hashlib
import json
from pathlib import Path
import struct
import zlib
from akd_client_reader import Akd,THIN_SHA as CLIENT_SHA
from adid_reader import Adid,ROOT,sha,THIN_SHA as PROVIDER_SHA
from probe_akd_clients import run_one as client_run,OUTPUTS
from probe_adid_command_dispatch import Commands
from probe_adid_startup import unpack_records
from probe_adid_receiver import DONE

def declared_credential(f):
    actual=json.loads((ROOT/'akd_client_inventory.json').read_text())['embedded_entitlements']['adi-client']
    assert isinstance(actual,str) and actual=='347420559'
    f={**f,'entitlement_result':'String','entitlement_type':'string','entitlement_string':actual}
    f.pop('entitlement_number',None)
    return f


LABELS=['get','set','otp','is_provisioned','start','end','destroy','sync','erase','login_core','unnamed720','vmtohost']


def resume_reply(q,prefix,reply):
    assert q.reason=='original_client_sync_send' and q.binds[q.reg('pc')]['name']=='_xpc_connection_send_message_with_reply_sync'
    before={r:q.reg(r) for r in ['pc','sp','lr']};q.fixture={**q.fixture,'reply_hex':reply,'provider_reply_resume':True};q.reason=None
    try:q.u.emu_start(before['pc'],DONE+4,count=q.fixture['instruction_budget']-q.steps+1)
    except Exception as e:
        if q.reason is None:q.reason='private_guest_exception:'+str(e)
    h=hashlib.sha256()
    for pc in q.visited:h.update(struct.pack('<Q',pc));h.update(q.s.read(pc,4))
    row={'fixture':q.fixture,'entry_sp':hex(q.sp),'stop_reason':q.reason,'steps':q.steps,'result_u32':q.reg('w0'),'records':q.records,'ordered_original_instruction_sha256':h.hexdigest(),'original_functions':list(q.functions.values()),'instruction_records':list(q.instructions.values()),'output_observation_windows_before':prefix['output_observation_windows_before'],'output_observation_windows_after':{hex(a):bytes(q.u.mem_read(a,n)).hex() for a,n in OUTPUTS},'allocation_model_final':q.allocations,'allocation_observation_bytes_after':{hex(a['pointer']):bytes(q.u.mem_read(a['pointer'],a['size_bytes'])).hex() for a in q.allocations}}
    row['visited_original_instructions_zlib_base64']=base64.b64encode(zlib.compress(b''.join(struct.pack('<Q',pc) for pc in q.visited))).decode();row['visited_original_instruction_count']=len(q.visited)
    if len(row['records'])>256:row['records_zlib_base64']=base64.b64encode(zlib.compress(json.dumps(row.pop('records'),separators=(',',':')).encode())).decode()
    return row,{'pending_API_PC':hex(before['pc']),'pending_stack_pointer':hex(before['sp']),'pending_return_address':hex(before['lr']),'source_instruction_PC_overridden':False,'resume_mechanism':'emu_start at unchanged pending modeled API binding; exact provider reply supplied as external API data'}


def run_pair(client,provider,fixture,server_base,checkpoint):
    q,prefix=client_run(client,fixture);prefix=json.loads(json.dumps(prefix));requests=[e for e in unpack_records(prefix) if e['kind']=='original_client_data_emission'];assert len(requests)==1;wire=requests[0]['payload_hex'];f={**declared_credential(server_base),'label':'akd_'+fixture['label'],'mode':'command','payload_hex':wire,'instruction_budget':800000,'instruction_or_frame_overrides':False};server=Commands(provider,f,checkpoint);pr=server.result();replies=[e for e in unpack_records(pr) if e.get('name')=='_xpc_dictionary_set_data'];assert pr['stop_reason']=='returned_to_private_fixture' and len(replies)==1;reply=replies[0]['payload_bytes'];final,resume=resume_reply(q,prefix,reply)
    return {'label':fixture['label'],'client_initial_fixture':fixture,'source_request_bytes':wire,'source_reply_bytes':reply,'client_prefix':prefix,'provider_profile':pr,'client_completed':final,'resume_contract':resume,'native_transaction_executed':False}


def main():
    client=Akd();provider=Adid();source=json.loads((ROOT/'akd_client_profiles.json').read_text());rows={r['fixture']['label']:r for r in source['profiles']};server_base=next(r['fixture'] for r in json.loads((ROOT/'adid_context_profiles.json').read_text())['profiles'] if r['fixture']['label']=='context_error_producer');checkpoint=json.loads((ROOT/'adid_peer_checkpoint.json').read_text());out=[];functions={'client':{},'provider':{}};instructions={'client':{},'provider':{}}
    for label in LABELS:
        pair=run_pair(client,provider,rows[label]['fixture'],server_base,checkpoint)
        for key,space in [('client_prefix','client'),('client_completed','client'),('provider_profile','provider')]:
            r=pair[key]
            for f in r.pop('original_functions'):functions[space][f['start']]=f
            for i in r.pop('instruction_records'):instructions[space][i['ea']]=i
        out.append(pair);print(json.dumps({'label':label,'request':pair['source_request_bytes'],'reply':pair['source_reply_bytes'],'provider_stop':pair['provider_profile']['stop_reason'],'client_stop':pair['client_completed']['stop_reason'],'client_result_u32':hex(pair['client_completed']['result_u32'])}),flush=True)
    q,cp=client_run(client,rows['vmtohost']['fixture']);cp=json.loads(json.dumps(cp));wire=next(e['payload_hex'] for e in unpack_records(cp) if e['kind']=='original_client_data_emission');environment=next(r['fixture'] for r in json.loads((ROOT/'adid_command_dispatch_profiles.json').read_text())['profiles'] if r['fixture']['label']=='environment_iokit_opaque');f={**declared_credential(environment),'label':'akd_vmtohost_to_Avp100','payload_hex':wire};server=Commands(provider,f,checkpoint);pr=server.result();assert pr['stop_reason']=='original_method100_opaque_boundary'
    for r,space in [(cp,'client'),(pr,'provider')]:
        for v in r.pop('original_functions'):functions[space][v['start']]=v
        for v in r.pop('instruction_records'):instructions[space][v['ea']]=v
    bridge={'scope':'Original complete unreferenced client C entry -> original XPC request bytes -> full provider callback -> opaque Avp method100 under explicit VMM/time/random/IOKit models;native caller and actual transaction unknown.','source_request_bytes':wire,'client_prefix':cp,'provider_profile':pr,'native_transaction_executed':False};print(json.dumps({'label':'akd_vmtohost_to_Avp100','request':wire,'provider_stop':pr['stop_reason']}),flush=True)
    deps=['akd_client_entitlements.xml','akd_client_entitlements.json','akd_client_inventory.json','akd_client_reader.py','akd_client_profiles.json','probe_akd_clients.py','probe_akd_adid_pairs.py','adid_reader.py','probe_adid_command_dispatch.py','adid_context_profiles.json','adid_command_dispatch_profiles.json','adid_peer_checkpoint.json'];result={'scope':__doc__,'provider_credential_fixture_source':'Original embedded akd adi-client string 347420559;not effective runtime entitlement attestation','client_thin_sha256':CLIENT_SHA,'provider_thin_sha256':PROVIDER_SHA,'pairs':out,'vmtohost_IOKit_bridge':bridge,'original_functions':{k:list(v.values()) for k,v in functions.items()},'original_instruction_records':{k:list(v.values()) for k,v in instructions.items()},'generator_sha256':sha(Path(__file__).read_bytes()),'dependencies':{n:sha((ROOT/n).read_bytes()) for n in deps},'native_target_executed':False,'native_transaction_executed':False,'full_goal_complete':False};(ROOT/'akd_adid_pair_profiles.json').write_text(json.dumps(result,indent=2)+'\n')


if __name__=='__main__':main()
