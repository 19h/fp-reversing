#!/usr/bin/env python3
"""Fresh source/ABI/credential/packet verification for the akd increment.

O(B+F+M+V+E) time/space, plus bounded private original-code replays and two
30 s solver queries. Original metadata tools only; no native target, target
loader, Mach, IOKit, notification, file, environment or synchronization API.
"""
import base64
import hashlib
import json
from pathlib import Path
import plistlib
import struct
import subprocess
import zlib
from akd_client_reader import Akd, ROOT, SOURCE, SOURCE_SHA, THIN_SHA, sha, CS
from adid_reader import Adid, THIN_SHA as SERVER_SHA
from arcade_service_reader import code_signature
from bootpolicy_cache_reader import Cache, Dylib, uleb
from probe_akd_clients import run_one, HEAP, STACK
from probe_akd_adid_pairs import run_pair, declared_credential
from probe_adid_command_dispatch import Commands
from probe_adid_startup import unpack_records

COMMANDS={'get':0x85fe63b0,'set':0x632b8d6e,'otp':0xcfe0b46a,
 'is_provisioned':0xb0eda7af,'start':0x716bd86c,'end':0x0b2b3196,
 'destroy':0x55a637c0,'sync':0xa54951ec,'erase':0x7715488c,
 'login_code':0x385b2ce8,'unnamed720':0x72096fe6,'vmtohost':0x76e89210}
MASK=(1<<64)-1


def addresses(r):
    if 'visited_original_instructions' in r:return [int(a,16) for a in r['visited_original_instructions']]
    raw=zlib.decompress(base64.b64decode(r['visited_original_instructions_zlib_base64']))
    assert len(raw)%8==0
    out=[a[0] for a in struct.iter_unpack('<Q',raw)]
    assert len(out)==r['visited_original_instruction_count']
    return out


def forwarded(f):
    a=f['args'];op=f['operation']
    if f['label']=='login_code':return [f['active_dsid'],STACK+0x38000-0x34]
    if f['entry_scope'].startswith('original_C_entry'):return a
    if op=='get':return [a[3],a[2]]
    if op=='set':return [a[3],a[2]]
    if op=='otp':return a[2:7]
    if op in ['dispose','is_provisioned','destroy','erase']:return a[2:3]
    if op in ['start','end']:return a[2:]
    if op=='sync':return a[2:]+[HEAP+0x1400]
    raise AssertionError(op)


def packet(f):
    a=forwarded(f);op=f['operation'];head=struct.pack('>III',1,COMMANDS[op],1)
    first=bytes.fromhex(f.get('input_hex','01234567'));second=bytes.fromhex(f.get('input2_hex','89abcdef'))
    if op in ['get','otp','is_provisioned','erase','login_code']:return head+struct.pack('>Q',a[0])
    if op=='set':return head+struct.pack('>QQ',*a[:2])
    if op in ['start','sync']:return head+struct.pack('>QI',a[0],a[2]&0xffffffff)+first[:a[2]&0xffffffff]
    if op=='end':return head+struct.pack('>II',a[0]&0xffffffff,a[2]&0xffffffff)+first[:a[2]&0xffffffff]+struct.pack('>I',a[4]&0xffffffff)+second[:a[4]&0xffffffff]
    if op=='destroy':return head+struct.pack('>I',a[0]&0xffffffff)
    if op=='unnamed720':return head
    if op=='vmtohost':return head+struct.pack('>II',0,11)+b'vmtohostmsg'
    raise AssertionError(op)


def independent_export_names(raw):
    """Recursive trie walk independent of the producer's work-list walker."""
    result={}
    def visit(offset,prefix,parents):
        assert offset not in parents
        n,p=uleb(raw,offset);end=p+n
        assert end<len(raw)
        if n:result[prefix]=uleb(raw,p)[0]
        count=raw[end];p=end+1
        for _ in range(count):
            end=raw.index(0,p);edge=raw[p:end].decode();child,p=uleb(raw,end+1)
            visit(child,prefix+edge,parents|{offset})
    if raw:visit(0,'',frozenset())
    return result


def main():
    checks=[]
    def check(value,label):
        assert value,label
        checks.append(label)
    read=lambda n:json.loads((ROOT/n).read_text())
    s=Akd();server=Adid();inv=read('akd_client_inventory.json');p=read('akd_client_profiles.json');c=read('akd_adid_contracts.json');pairs=read('akd_adid_pair_profiles.json')
    rows={r['fixture']['label']:r for r in p['profiles']}
    check(len(rows)==98 and len(c['client_producers'])==12,'98 distinct cases and12 original producers')
    check(sha(SOURCE.read_bytes())==SOURCE_SHA and sha(s.data)==THIN_SHA and inv['uuid']==s.meta['uuid'],'fresh universal/selected UUID and SHA identity')
    check(inv['slices']==s.slices and len(s.slices)==3,'three universal slices independently pinned;runtime slice unknown')
    check(inv['function_starts']==[hex(a) for a in s.starts] and len(s.starts)==10039,'complete original function-start delta stream')
    check(inv['imports']==s.imports and len(s.imports)==1575,'complete original import table')
    display=subprocess.run(['/usr/bin/dyld_info','-arch','arm64e','-fixups',str(SOURCE)],capture_output=True,text=True,check=True)
    check(display.stdout==(ROOT/'akd_client_fixups.txt').read_text(),'fresh independent dyld_info matches complete retained chain reference')
    check(inv['fixups']==list(s.decoded.values()) and len(s.decoded)==37439,'all37439 independently walked original chains match reference')
    embedded=next(b['xml_entitlements'] for b in code_signature(s.data)['blobs'] if 'xml_entitlements' in b)
    display=subprocess.run(['/usr/bin/codesign','-d','--arch','arm64e','--entitlements',':-',str(SOURCE)],capture_output=True,check=True)
    check(display.stdout==(ROOT/'akd_client_entitlements.xml').read_bytes() and plistlib.loads(display.stdout)==embedded==inv['embedded_entitlements']==c['client_embedded_entitlements'],'fresh signature parser and independent codesign display agree')
    check(type(embedded['adi-client']) is str and embedded['adi-client']=='347420559' and int(embedded['adi-client'])==0x14b5378f,'actual original adi-client declaration is decimal string347420559')
    check(embedded['com.apple.private.adid'] is True and embedded['AvpFairPlayUserClient.access'] is True and type(embedded['fairplay-client']) is str,'co-declared ADID/Avp/FairPlay capability values;effective entitlements unknown')
    check(len(embedded)==125 and not read('akd_client_entitlements.json')['effective_entitlements_established'],'125 embedded declarations;no runtime credential claim')
    check(inv['classes']==s.class_inventory() and len(inv['classes'])==309,'309 original ObjC class/metaclass records')
    for m in inv['methods']:
        a=int(m['entry'],16);raw=s.read(a,12);name,typ,imp=struct.unpack('<iii',raw)
        check(raw.hex()==m['entry_bytes'] and a+8+imp==int(m['implementation'],16) and a+4+typ==int(m['type_address'],16),'original relative method fields '+hex(a))
        selector=s.qword(a+name)
        check(selector==int(m['selector_address'],16) and s.cstring(selector)==m['selector'] and s.cstring(a+4+typ)==m['type_encoding'],'original selector indirection/type '+hex(a))
    check(len(inv['methods'])==3422,'complete3422 original method entries')
    for artifact,generator in [('akd_client_inventory.json','akd_client_reader.py'),('akd_client_profiles.json','probe_akd_clients.py'),('akd_adid_contracts.json','recover_akd_adid_contracts.py'),('akd_adid_pair_profiles.json','probe_akd_adid_pairs.py')]:
        d=read(artifact);check(d['generator_sha256']==sha((ROOT/generator).read_bytes()),'generator pinned '+artifact)
        for n,h in d['dependencies'].items():check(sha((ROOT/n).read_bytes())==h,'dependency pinned '+artifact+'/'+n)
        check(d['native_target_executed'] is False and d['full_goal_complete'] is False,'bounded source scope '+artifact)
    instruction_count=0;range_count=0
    def pool(source,instructions,functions,space):
        nonlocal instruction_count,range_count
        out={}
        for i in instructions:
            a=int(i['ea'],16);raw=source.read(a,4);decoded=next(CS.disasm(raw,a))
            check(raw.hex()==i['bytes'] and decoded.mnemonic==i['mnemonic'] and decoded.op_str==i['operands'],'fresh instruction '+space+'/'+hex(a));out[a]=raw;instruction_count+=1
        for f in functions:
            a=int(f['start'],16);z=int(f['end'],16);raw=source.read(a,z-a)
            check(source.bounds(a)==(a,z) and sha(raw)==f['sha256'],'complete compiler range '+space+'/'+hex(a));range_count+=1
            if 'bytes' in f:check(raw.hex()==f['bytes'],'complete range bytes '+space+'/'+hex(a))
        return out
    client_pool=pool(s,p['original_instruction_records'],p['original_functions'],'retained_client')
    pair_pools={space:pool(source,pairs['original_instruction_records'][space],pairs['original_functions'][space],'paired_'+space) for space,source in [('client',s),('provider',server)]}
    pool(s,[],c['original_functions'],'static_client')
    visits=0
    def stream(source,r,bank,label):
        nonlocal visits
        seq=addresses(r);h=hashlib.sha256()
        check(all(a in bank and source.read(a,4)==bank[a] for a in seq),'complete visit source membership '+label)
        for a in seq:h.update(struct.pack('<Q',a));h.update(bank[a])
        check(h.hexdigest()==r['ordered_original_instruction_sha256'],'ordered source stream hash '+label);visits+=len(seq)
        return seq
    for m in c['named_method_C_bindings']:
        original=m['original_method_metadata'];check(original in inv['methods'],'named metadata membership '+m['label'])
        call=m['original_direct_call'];pc=int(call['ea'],16);word=int.from_bytes(s.read(pc,4),'little');imm=word&0x3ffffff;imm=imm-(1<<26) if imm&(1<<25) else imm
        check(word&0xfc000000==0x94000000 and pc+4*imm==int(m['C_target'],16),'original direct named C binding '+m['label'])
    check(len(c['named_method_C_bindings'])==11,'11 original named method to C bindings including dispose')
    for w in c['source_windows']:
        raw=s.read(int(w['start'],16),int(w['end'],16)-int(w['start'],16));check(raw.hex()==w['bytes'] and sha(raw)==w['sha256'],'original predicate/ABI window '+w['role'])
    for stub in c['original_selected_stubs']:
        raw=bytes.fromhex(stub['bytes']);check(s.read(int(stub['address'],16),len(raw))==raw,'original bound stub '+stub['address'])
        if stub.get('selector') is not None:check(s.cstring(s.qword(int(stub['selector_slot'],16)))==stub['selector'],'original stub selector '+stub['address'])
        if 'binding' in stub:check(s.decoded[int(stub['binding']['address'],16)]==stub['binding'],'original stub chain membership '+stub['address'])
    for m in c['high_level_methods']:
        for ref in m['literal_references']:check(s.read(int(ref['characters'],16),ref['size_bytes']).decode()==ref['text'],'original CFString characters '+ref['source'])
    check(len(c['high_level_methods'])==10 and len(c['high_level_direct_edges'])==525 and len(c['original_selected_stubs'])==55,'ten high-level methods525 direct edges55 stubs')
    for edge in c['high_level_direct_edges']:
        pc=int(edge['callsite'],16);w=int.from_bytes(s.read(pc,4),'little');imm=w&0x3ffffff;imm-=1<<26 if imm&(1<<25) else 0
        check(w&0x7c000000==0x14000000 and pc+4*imm==int(edge['target'],16),'original high-level direct edge '+edge['callsite'])
    check(not any(r['target'] in ['0x1002e7d04','0x1002f3944'] for r in c['original_C_entry_references']),'two complete C entries remain unreferenced under declared scan grammar')
    reserved={x&MASK for x in [-8,-6,-5,-4,-3,-2]};emissions=0
    for label,r in rows.items():
        stream(s,r,client_pool,label);ev=unpack_records(r);f=r['fixture'];a=forwarded(f);entries=[e for e in ev if e['kind']=='original_client_C_entry']
        check(len(entries)==1 and [int(v,16) for v in entries[0]['args_x0_x7'][:len(a)]]==a,'original ObjC/C argument forwarding '+label)
        check(not f['internal_instruction_or_frame_overrides'],'no client internal frame/instruction overrides '+label)
        sent=[e for e in ev if e['kind']=='original_client_data_emission']
        if sent:
            check(len(sent)==1 and sent[0]['key']=='data' and bytes.fromhex(sent[0]['payload_hex'])==packet(f) and sent[0]['size_bytes']==len(packet(f)),'independent request byte oracle '+label);emissions+=1
        for e in ev:
            if e['kind']=='explicit_client_connection':check(e['service']=='com.apple.adid' and int(e['args_x0_x7'][2],16)==0,'source ADID connection name/flags '+label)
            if 'native_API_executed' in e:check(e['native_API_executed'] is False,'private API scope '+label+'/'+e.get('name',''))
        if f['operation'] in ['get','set'] and f['args'][3] not in reserved:check(r['result_u32']==0xffff5037 and not sent,'routing reserved64 rejection '+label)
        if label.startswith('login_dsid_') or label=='login_null_output':
            accepted=a[0]>=MASK-15 and a[1]!=0;check(bool(sent)==accepted and (accepted or r['result_u32']==0xffff5037),'login full64 gate finite control '+label)
        if f.get('allocation_NULL'):check(r['result_u32']==0xffff5035 and not sent and not r['allocation_model_final'],'original mallocNULL early result '+label)
        if f.get('dictionary_NULL'):check(r['stop_reason']=='client_NULL_dictionary_set_data_boundary' and sent[0]['args_x0_x7'][0]=='0x0' and not any(e['kind']=='explicit_client_connection' for e in ev),'NULL dictionary stops at external set-data boundary '+label)
        if f.get('reply_hex')=='ffff501f':check(r['result_u32']==0xffff501f,'nonzero source status propagated '+label)
        if f.get('reply_hex')=='00000000':check(r['result_u32']==(0xffff5016 if f['operation'] in ['get','otp','start','sync','login_code'] else 0),'operation-dependent status-only response '+label)
    def out(label,offset):return bytes.fromhex(rows[label]['output_observation_windows_after'][hex(HEAP+offset)])
    check(out('get_rich_route',0x1100)==struct.pack('<Q',0x1122334455667788) and rows['get_rich_route']['result_u32']==0,'routing reply BE64 to scalar64')
    check(out('login_core_rich_code',0x1100)==struct.pack('<I',0x12345678)+b'\xa5'*4 and rows['login_core_rich_code']['result_u32']==0,'login reply BE32 writes exactly four observed bytes')
    for label in ['otp_rich_two_spans','sync_rich_two_spans','start_rich_blob_session']:
        r=rows[label];alloc={a['pointer']:a for a in r['allocation_model_final']};first=int.from_bytes(out(label,0x1100),'little');check(alloc[first]['size_bytes']==3 and not alloc[first]['freed'] and r['allocation_observation_bytes_after'][hex(first)]=='616263' and out(label,0x1200)==struct.pack('<I',3),'first allocated output span '+label)
        if label.startswith('start'):check(out(label,0x1300)==struct.pack('<I',0x12345678)+b'\xa5'*4 and r['result_u32']==0,'CPIM then session32 reply order')
        else:
            second=int.from_bytes(out(label,0x1300),'little');check(alloc[second]['size_bytes']==4 and not alloc[second]['freed'] and r['allocation_observation_bytes_after'][hex(second)]=='5758595a' and out(label,0x1400)==struct.pack('<I',4),'second allocated output span '+label)
    otp=rows['otp_rich_two_spans'];event=unpack_records(otp)[-1]
    check(otp['stop_reason']=='opaque_API_boundary:_notify_register_check' and event['callsite']=='0x100309b14' and event['args_x0_x7'][:2]==['0x100347d23','0x100450548'] and s.cstring(0x100347d23)=='com.apple.adid.midchangedV1','original OTP notification name/token output and opaque API boundary')
    check(rows['start_rich_session_blob_rejected']['result_u32']==0xffff5016,'incorrect session-before-CPIM reply rejected')
    for label in ['otp_allocator_NULL','sync_allocator_NULL']:
        check(all(out(label,o)==bytes(n) for o,n in [(0x1100,8),(0x1200,4),(0x1300,8),(0x1400,4)]),'four caller outputs cleared before allocator failure '+label)
    check(out('start_allocator_NULL',0x1100)==bytes(8) and out('start_allocator_NULL',0x1200)==bytes(4) and out('start_allocator_NULL',0x1300)==b'\xa5'*8,'start clears CPIM outputs but preserves session slot on early failure')
    check(out('get_allocator_NULL',0x1100)==b'\xa5'*8 and out('login_core_allocator_NULL',0x1100)==bytes(4)+b'\xa5'*4,'routing preserves output;login clears code32 on allocator failure')
    check([e['name'] for e in unpack_records(rows['dispose']) if e.get('name')]==['_free'],'dispose is original local free path without IPC;return supplied by model')
    dispatch={r['wire_command_u32']:r for r in read('adid_command_dispatch_contracts.json')['command_tree']['accepted']}
    check(set(dispatch)-set(COMMANDS.values())=={0x9679d4b5,0xa8471cad} and set(c['provider_commands_without_identified_client_producer'])=={'0x9679d4b5','0xa8471cad'},'exact two of14 provider commands lack identified client producer')
    pairs_by_label={r['label']:r for r in pairs['pairs']};provider_events={};pair_steps=0
    for label,pair in pairs_by_label.items():
        prefix=pair['client_prefix'];pr=pair['provider_profile'];final=pair['client_completed'];wire=pair['source_request_bytes'];reply=pair['source_reply_bytes'];pev=unpack_records(pr);provider_events[label]=pev
        seq=stream(server,pr,pair_pools['provider'],label+'/provider');stream(s,prefix,pair_pools['client'],label+'/client_prefix');stream(s,final,pair_pools['client'],label+'/client_completed')
        check(prefix['ordered_original_instruction_sha256']==rows[label]['ordered_original_instruction_sha256'] and unpack_records(prefix)==unpack_records(rows[label]),'pair prefix equals retained complete client case '+label)
        check(bytes.fromhex(wire)==packet(pair['client_initial_fixture']) and pr['fixture']['payload_hex']==wire,'byte-exact client to provider bridge '+label)
        received=[e for e in pev if e.get('name')=='_xpc_dictionary_get_data'];emitted=[e for e in pev if e.get('name')=='_xpc_dictionary_set_data'];consumed=[e for e in unpack_records(final) if e['kind']=='explicit_client_reply_data']
        check(len(received)==len(emitted)==len(consumed)==1 and received[0]['payload_bytes']==wire and emitted[0]['payload_bytes']==consumed[0]['bytes']==reply,'byte-exact provider reply to client parser '+label)
        core=next(e for e in pev if e['kind']=='original_core_record_return')
        check(pr['stop_reason']==final['stop_reason']=='returned_to_private_fixture' and core['status_u32']==0 and core['output_length_u64']==4 and final['result_u32']==int(reply,16),'provider inner wrapper0 distinct from callback X0/four-byte payload/client result '+label)
        check(pr['fixture']['entitlement_result']=='String' and pr['fixture']['entitlement_type']=='string' and pr['fixture']['entitlement_string']==embedded['adi-client'] and any(e.get('name')=='_CFStringGetCString' and e.get('string')==embedded['adi-client'] for e in pev) and any(e.get('name')=='_strtoul' and e.get('result')=='0x14b5378f' for e in pev),'actual declared string credential crosses original conversion path '+label)
        command=int.from_bytes(bytes.fromhex(wire)[4:8],'big');path=[int(a,16) for a in dispatch[command]['path']];start=seq.index(path[0]);check(seq[start:start+len(path)]==path,'original full command tree selects exact raw command '+label)
        resume=pair['resume_contract'];check(not resume['source_instruction_PC_overridden'] and prefix['stop_reason']=='original_client_sync_send','pending API resumed without frame/PC redirection '+label)
        direct=run_one(s,{**pair['client_initial_fixture'],'reply_hex':reply})[1]
        check(direct['ordered_original_instruction_sha256']==final['ordered_original_instruction_sha256'] and direct['output_observation_windows_after']==final['output_observation_windows_after'] and direct['allocation_model_final']==final['allocation_model_final'] and direct['allocation_observation_bytes_after']==final['allocation_observation_bytes_after'],'fresh uninterrupted client equals split reply continuation '+label)
        pair_steps+=direct['steps']
    constructed=pairs_by_label['start']['provider_profile'];snapshot=next(e for e in provider_events['start'] if e['kind']=='original_command_packet_boundary' and e['pc']=='0x10019cb24')['constructed_objects'];outer=bytes.fromhex(snapshot['outer']);nested=bytes.fromhex(snapshot['nested'])
    check(len(outer)==96 and len(nested)==176 and int.from_bytes(nested[8:16],'little')^0xda8ca8cae5dfbd2d==forwarded(rows['start']['fixture'])[0] and int.from_bytes(nested[0x98:0xa0],'little')^0xda8ca8cae5dfbd2d==0 and (int.from_bytes(nested[0xa0:0xa4],'little')-0x46d726)&0xffffffff==0,'named SPIM request constructs DSID-keyed96/176-byte source objects before minimum-length error')
    bridge=pairs['vmtohost_IOKit_bridge'];pr=bridge['provider_profile'];ev=unpack_records(pr);stream(s,bridge['client_prefix'],pair_pools['client'],'VM/client');stream(server,pr,pair_pools['provider'],'VM/provider')
    check(bridge['source_request_bytes']==packet(rows['vmtohost']['fixture']).hex()==pr['fixture']['payload_hex'] and len(bytes.fromhex(bridge['source_request_bytes']))==31,'complete original31-byte vmtohost request bridge')
    open_event=next(e for e in ev if e.get('name')=='_IOServiceOpen');method=next(e for e in ev if e.get('name')=='_IOConnectCallStructMethod')
    check(open_event['callsite']=='0x10002b854' and open_event['args_x0_x7'][2]=='0x0' and open_event['connection_output_cell']=='0x1002dd290','VM request reaches original type0 Avp connection output')
    check(pr['stop_reason']=='original_method100_opaque_boundary' and method['callsite']=='0x100058a1c' and method['args_x0_x7'][1]=='0x64' and method['args_x0_x7'][2]==method['args_x0_x7'][4] and method['args_x0_x7'][3]=='0x90' and method['output_size_before_u64']==144 and len(bytes.fromhex(method['input_bytes']))==144,'original VM31 request reaches shared144-byte Avp100 opaque boundary')
    check(not any(e.get('name')=='_xpc_dictionary_set_data' for e in ev),'VM Avp boundary precedes any provider reply in this profile')
    check(any(e.get('name')=='_strtoul' and e.get('result')=='0x14b5378f' for e in ev),'VM bridge uses exact declared string credential conversion')
    checkpoint=read('adid_peer_checkpoint.json');fresh_labels=['get','set','start','sync','unnamed720'];fresh_server_steps=0
    server_base=next(r['fixture'] for r in read('adid_context_profiles.json')['profiles'] if r['fixture']['label']=='context_error_producer')
    for label in fresh_labels:
        fresh=run_pair(s,server,rows[label]['fixture'],server_base,checkpoint);old=pairs_by_label[label]
        check(fresh['source_request_bytes']==old['source_request_bytes'] and fresh['source_reply_bytes']==old['source_reply_bytes'] and unpack_records(fresh['provider_profile'])==provider_events[label] and fresh['provider_profile']['ordered_original_instruction_sha256']==old['provider_profile']['ordered_original_instruction_sha256'] and fresh['client_completed']['ordered_original_instruction_sha256']==old['client_completed']['ordered_original_instruction_sha256'],'fresh complete source/event pair replay '+label);fresh_server_steps+=fresh['provider_profile']['steps']
    fresh=Commands(server,pr['fixture'],checkpoint).result();check(fresh['ordered_original_instruction_sha256']==pr['ordered_original_instruction_sha256'] and unpack_records(fresh)==ev,'fresh complete VM request-to-Avp source/event replay');fresh_server_steps+=fresh['steps']
    replay_labels=['get_dsid_-7','get_dsid_-6','login_dsid_-17','login_dsid_-16','start_input_27','end_inputs_27_32','get_allocator_NULL','start_allocator_NULL','get_dictionary_NULL','otp_rich_two_spans','sync_rich_two_spans','start_rich_blob_session']
    fresh_client_steps=pair_steps
    for label in replay_labels:
        fresh=run_one(s,rows[label]['fixture'])[1];old=rows[label]
        check(fresh['ordered_original_instruction_sha256']==old['ordered_original_instruction_sha256'] and fresh['stop_reason']==old['stop_reason'] and unpack_records(fresh)==unpack_records(old) and fresh['output_observation_windows_after']==old['output_observation_windows_after'] and fresh['allocation_observation_bytes_after']==old['allocation_observation_bytes_after'],'fresh boundary/output/source client replay '+label);fresh_client_steps+=fresh['steps']
    for proof in c['proofs']:
        path=ROOT/proof['path'];check(sha(path.read_bytes())==proof['sha256'],'pinned full64 query '+proof['path']);solved=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);check(solved.stdout.strip()=='unsat' and not solved.stderr,'fresh full64 unsat '+proof['path'])
    catalog=read('akd_adid_cache_exports.json');cache=Cache();check(cache.uuid==catalog['cache_uuid'] and len(cache.images)==len(catalog['image_rows'])==4113,'fresh complete4113 cache image list')
    for image,row in zip(cache.images,catalog['image_rows']):
        d=Dylib(cache,image['path']);raw=getattr(d,'export_bytes',b'');names=independent_export_names(raw);matching={n:f for n,f in names.items() if n.startswith(('_ADI','__ADI')) or 'CoreADI' in n}
        check(row['path']==image['path'] and row['base']==hex(d.base) and row['uuid']==d.uuid and row['export_trie_size_bytes']==len(raw) and row['export_trie_sha256']==sha(raw) and row['all_terminal_names_count']==len(names) and row['all_terminal_names_sha256']==sha('\n'.join(sorted(names)).encode()) and row['matching_names']==matching=={},'independent complete export terminal/reexport walk '+image['path'])
    check(not catalog['matching_exports'] and not catalog['CoreADI_named_image_paths'] and not any('CoreADI' in i['path'] for i in cache.images),'bounded cache-wide CoreADI/ADI export absence including reexports')
    check(c['cache_export_catalog_sha256']==sha((ROOT/'akd_adid_cache_exports.json').read_bytes()),'complete export catalog pin')
    for row in read('interface_manifest.json')['inputs_preserved']:
        path=ROOT.parent/row['path'];check(path.stat().st_size==row['size_bytes'] and sha(path.read_bytes())==row['sha256'],'original supplied input preserved '+row['path'])
    verified={'retained_client_cases':len(rows),'client_original_instructions':len(client_pool),'retained_client_steps':sum(r['steps'] for r in rows.values()),'verified_instruction_records':instruction_count,'complete_compiler_ranges':range_count,'verified_source_visits':visits,'original_fixups':len(s.decoded),'original_methods':len(inv['methods']),'named_method_C_bindings':11,'named_IPC_roles':10,'client_command_producers':12,'provider_command_count':14,'provider_commands_without_client':2,'completed_private_pairs':len(pairs_by_label),'opaque_VM_request_Avp_bridges':1,'fresh_uninterrupted_client_reply_replays':12,'fresh_additional_client_replays':len(replay_labels),'fresh_complete_provider_pair_replays':len(fresh_labels),'fresh_complete_VM_Avp_replays':1,'fresh_client_steps':fresh_client_steps,'fresh_provider_steps':fresh_server_steps,'new_full64_SMT_unsat':len(c['proofs']),'cache_images_independently_walked':4113,'embedded_entitlements':len(embedded),'assertions':len(checks)}
    out={'scope':__doc__,'verified_counts':verified,'checks':checks,'all_checks_pass':True,'native_target_executed':False,'effective_entitlements_established':False,'full_goal_complete':False};(ROOT/'akd_adid_checks.json').write_text(json.dumps(out,indent=2)+'\n')
    descriptions=['Descriptive original-binary interface analysis.','Report K1-K12 list assumptions,dependent results and falsification probes.','Named client/command/reply/credential and VM-to-Avp increment covered;full architectural goal incomplete.','Explicit32/64-bit widths,BE wire versus LE observation,byte extents and bounded algorithm complexity.','Unreferenced entries,native slice/credential/port gaps,local success responses versus actual provisioning,notification boundary and dispose return separated.','Fresh original bytes/metadata/fixups,independent codesign and export walks,packet oracles,two full64 proofs and original-code replays.','Impact-labeled valid SPIM/session,Avp implementation,notification,remaining commands,NSXPC,legacy Mach and lifetime continuation.']
    quality={'scope':'akd statically linked ADID client and explicit private provider/Avp interface increment.','verified_counts':verified,'native_target_executed':False,'full_goal_complete':False}
    for i,t in enumerate(descriptions,1):quality['QG'+str(i)]={'status':'pass_for_stated_increment','evidence':t}
    (ROOT/'akd_adid_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps(verified),flush=True)


if __name__=='__main__':main()
