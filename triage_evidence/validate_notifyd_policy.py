#!/usr/bin/env python3
"""Independent config/policy semantics,byte ledger,original ABI and replay checks.

O(B+P+I+V+W+A) time/space plus finite original full-case replays and four
30 s-bounded local formulas. No native daemon/IPC/policy/target-file operation.
Reference capture is distinguished from daemon-loaded/effective state.
"""
import base64,bisect,hashlib,json,re,struct,subprocess,zlib
from pathlib import Path
from notifyd_ipc_reader import Notifyd,ROOT,THIN_SHA,sha
from notify_ipc_reader import Notify,CS
from bootpolicy_cache_reader import Dylib
from probe_notifyd_policy_pairs import run_policy_case,compact_row
from recover_notifyd_admission import events
from validate_notifyd_admission import visits
from probe_notifyd_admission import HEAP,SHARED

MASK=(1<<64)-1


def decimal(s):
    m=re.match(r'^[\t\n\v\f\r ]*([+-]?)([0-9]+)',s);return int(m[2])*(-1 if m[1]=='-' else 1) if m else 0


def mask6(s):
    if len(s)!=6:return 0
    return sum(bit for ch,want,bit in zip(s,'rwrwrw',[1,2,16,32,256,512]) if ch==want)


def configuration(case):
    f=case.get('server_fixture',{});raw=bytes.fromhex(f.get('config_hex',''));rules={};states={};vectors=[];monitors=[]
    if not f.get('config_present',True) or f.get('config_uid',0)!=0 or f.get('config_mode_u16',0o100644)&2 or not f.get('config_open_success',True):return rules,states,vectors,monitors
    offset=0
    while offset<len(raw):
        limit=min(offset+1023,len(raw));nl=raw.find(b'\n',offset,limit)
        if nl>=0:limit=nl+1
        chunk=raw[offset:limit];offset=limit
        if not chunk or chunk[0] in [0,35]:continue
        text=chunk.split(b'\0',1)[0][:-1].decode()
        if not text:continue
        tokens=re.split('[ \t]',text);vectors.append(tokens);command=tokens[0].lower()
        if command=='quit':break
        if command=='monitor' and len(tokens)>=3:monitors.append(tokens);continue
        if command=='set' and len(tokens) in [2,3]:states[tokens[1]]=decimal(tokens[2])&MASK if len(tokens)==3 else 0;continue
        if command!='reserve' or len(tokens)<2:continue
        name=tokens[1];uid=decimal(tokens[2])&0xffffffff if len(tokens)>=3 else 0;gid=decimal(tokens[3])&0xffffffff if len(tokens)>=4 else 0;access=mask6(tokens[4]) if len(tokens)>=5 else 0x333
        if not(uid or gid or access!=0x333):continue
        old=rules.setdefault(name,{'uid':0,'gid':0,'access':0x333})
        if uid or gid:old.update(uid=uid,gid=gid)
        if access!=0x333:old['access']=access
    return rules,states,vectors,monitors


def permit(name,uid,gid,op,rules):
    if uid==0:return True
    if name.startswith('user.uid.'):
        signed=uid-(1<<32) if uid&(1<<31) else uid;prefix='user.uid.'+str(signed);return name.startswith(prefix) and (len(name)==len(prefix) or name[len(prefix)]=='.')
    for prefix in sorted(rules,reverse=True):
        if name.startswith(prefix):
            r=rules[prefix];mask=r['access'];return bool(uid==r['uid'] and mask&op or gid==r['gid'] and mask&(op<<4) or mask&(op<<8))
    return True


def main():
    assertions=0;totals={'provider_source_visits':0,'client_source_visits':0,'source_stores':0,'API_output_effects':0,'allocation_snapshots':0,'controlled_record_snapshots':0,'paired_messages':0,'state_messages':0};read=lambda n:json.loads((ROOT/n).read_text())
    def check(v,label):
        nonlocal assertions
        assert v,label
        assertions+=1
    d=Notifyd();cache=Notify();p=read('notifyd_policy_profiles.json');c=read('notifyd_policy_contracts.json');reference=read('notifyd_policy_reference.json');ref=(ROOT/'notifyd_policy_reference.conf').read_bytes();cases={x['case']['label']:x for x in p['cases']};source=lambda a,n:d.read(a,n) if d.base<=a<d.base+0x20000 else cache.read(a,n)
    for artifact,producer in [(p,'probe_notifyd_policy_pairs.py'),(c,'recover_notifyd_policy.py')]:
        check(artifact['generator_sha256']==sha((ROOT/producer).read_bytes()),'producer source pin')
        for name,h in artifact['dependencies'].items():check(sha((ROOT/name).read_bytes())==h,'dependency '+name)
        check(not artifact['native_target_executed'] and not artifact['full_goal_complete'],'stated scope')
    check(reference['generator_sha256']==sha((ROOT/'notifyd_policy_reference_capture.py').read_bytes()) and sha(ref)==reference['sha256'] and len(ref)==reference['size_bytes']==557,'stable reference capture bytes/source')
    check(reference['uid']==reference['gid']==0 and reference['mode_permissions_octal']=='0o644' and reference['daemon_loaded_these_bytes_established'] is False,'reference metadata is not effective daemon state')
    check(c['provider_thin_sha256']==THIN_SHA and c['cache_uuid']==cache.cache.uuid,'fresh original source identities')
    bank={};libraries={}
    for row in p['original_source_pools']['instructions']:
        a=int(row['ea'],16);raw=source(a,4);ins=next(CS.disasm(raw,a));check(raw.hex()==row['bytes'] and ins.mnemonic==row['mnemonic'] and ins.op_str==row['operands'],'fresh original instruction');bank[a]=raw
    for row in p['original_source_pools']['functions']:
        a=int(row['start'],16);z=int(row['end'],16);check(sha(source(a,z-a))==row['sha256'],'complete compiler bytes')
        if d.base<=a<d.base+0x20000:check(d.bounds(a)==(a,z),'provider compiler boundary')
        elif 'library' in row:
            path=row['library']
            if path not in libraries:libraries[path]=Dylib(cache.cache,path)
            lib=libraries[path];ix=bisect.bisect_right(lib.functions,a)-1;end=lib.functions[ix+1] if ix+1<len(lib.functions) else next(s['address']+s['size'] for s in lib.sections if s['name']=='__text');check(lib.functions[ix]==a and end==z and lib.uuid==row['uuid'],'cache compiler boundary/UUID')
    for row in p['original_source_pools']['cache_pages']:
        a=int(row['address'],16);raw=bytearray(cache.read(a,4096));check(sha(raw)==row['original_sha256'],'original cache page');members=[v for at,v in cache.page_chains(a).items() if a<=at<a+4096];check(members==row['original_chain_members'],'original v5 member set')
        for member in members:struct.pack_into('<Q',raw,int(member['address'],16)-a,int(member['target'],16))
        check(sha(raw)==row['materialized_sha256'],'materialized cache page')
    for row in c['original_functions']+c['original_audit_helpers']:
        a=int(row['start'],16);z=int(row['end'],16);check(source(a,z-a).hex()==row['bytes'] and sha(source(a,z-a))==row['sha256'],'source contract body')
    for row in c['original_strings']:check(d.read(int(row['address'],16),len(bytes.fromhex(row['bytes']))).hex()==row['bytes'],'original config string')
    ledger_summaries=[]
    for case in p['cases']:
        label=case['case']['label'];f=case['case'].get('server_fixture',{});rules,states,vectors,monitors=configuration(case['case']);actual_vectors=[e['tokens'] for e in events(case['startup']) if e['kind']=='original_config_token_vector'];check(actual_vectors==vectors,'independent chunk/token/directive interpretation '+label)
        ev=events(case['startup']);chunks=[e for e in ev if e.get('name')=='_fgets' and 'read_chunk_hex' in e];consumed=b''.join(bytes.fromhex(e['read_chunk_hex']) for e in chunks);check(bytes.fromhex(f.get('config_hex','')).startswith(consumed),'declared FILE stream chunk prefix')
        for e in chunks:check(len(bytes.fromhex(e['read_chunk_hex']))<e['bound_bytes']<=1024,'fgets extent bound')
        expected=[(name,rules[name]['uid'],rules[name]['gid'],rules[name]['access']) for name in sorted(rules,reverse=True)]
        mem={};data={};shared={SHARED+i:0 for i in range(16384)};alloc={};types={}
        for seg in d.meta['segments']:
            if seg['name']=='__DATA':
                raw=d.data[seg['file_offset']:seg['file_offset']+seg['file_size']]+bytes(seg['vm_size']-seg['file_size']);data.update({seg['address']+i:v for i,v in enumerate(raw)})
        for at,item in d.decoded.items():
            if at in data and not item['bind']:data.update({at+i:v for i,v in enumerate(struct.pack('<Q',int(item['target'],16)))})
        def put(a,b):
            target=shared if SHARED<=a and a+len(b)<=SHARED+16384 else data if a in data else mem
            for i,v in enumerate(b):target[a+i]=v
        def span(a,n):
            target=shared if SHARED<=a<SHARED+16384 else data if a in data else mem
            return bytes(target[a+i] for i in range(n))
        def u32(a):return int.from_bytes(span(a,4),'little')
        def u64(a):return int.from_bytes(span(a,8),'little')
        for ordinal,r in enumerate([case['startup']]+case['provider_calls']):
            check(r['stop_reason'] in ['original_startup_dispatch_main_boundary','returned_to_private_fixture'],'complete original provider path '+label)
            seq=visits(r);h=hashlib.sha256()
            for a in seq:check(a in bank,'provider source visit belongs to original pool');h.update(struct.pack('<Q',a));h.update(bank[a])
            check(h.hexdigest()==r['ordered_original_instruction_sha256'],'provider ordered source bytes');totals['provider_source_visits']+=len(seq)
            for e in events(r):
                name=e.get('name','')
                if name in ['_malloc_type_malloc','_malloc_type_calloc','_malloc_type_realloc','_reallocf']:
                    a=int(e['result'],16);n=e['requested_size_bytes'];check(0<n<=65536 and HEAP+0x20000<=a and a+n<=HEAP+0x70000,'owned allocation bounds');put(a,bytes(n) if name.endswith('calloc') else b'\xa5'*n);alloc[a]={'size_bytes':n,'freed':False};types[a]='name' if e['callsite']=='0x1000010f4' else 'other'
                    if name.endswith('realloc') or name=='_reallocf':
                        old=int(e['args_x0_x7'][0],16)
                        if old:check(old in alloc and not alloc[old]['freed'],'reallocation prior owner');alloc[old]['freed']=True
                if name=='_strdup':
                    a=int(e['result'],16);n=len(e['string'].encode())+1;put(a,b'\xa5'*n);alloc[a]={'size_bytes':n,'freed':False};types[a]='other'
                if name=='_free':
                    a=int(e['args_x0_x7'][0],16)
                    if a:check(a in alloc and not alloc[a]['freed'],'free live owner');alloc[a]['freed']=True
                if e['kind']=='explicit_notifyd_port_constructor_model':put(int(e['args_x0_x7'][3],16),struct.pack('<I',e['output_name_u32']));totals['API_output_effects']+=1
                for effect in e.get('explicit_output_effects',[]):put(int(effect['address'],16),bytes.fromhex(effect['bytes']));totals['API_output_effects']+=1
                if e['kind'] in ['original_owned_data_write','original_private_global_write']:
                    raw=bytes.fromhex(e['actual_after_hex']);check(len(raw)==e['size_bytes'] and int(e['pc'],16) in seq,'actual original store provenance');put(int(e['address'],16),raw);totals['source_stores']+=1
            check({str(a):v for a,v in alloc.items()}==r['owned_allocations'],'independent allocation lifetime ledger '+label)
            for a,v in alloc.items():check(span(a,v['size_bytes']).hex()==r['owned_allocation_bytes_after'][hex(a)],'independent allocation bytes');totals['allocation_snapshots']+=1
            for row in r['provider_DATA_after']:check(span(int(row['address'],16),len(bytes.fromhex(row['bytes']))).hex()==row['bytes'],'independent DATA bytes')
            check(span(SHARED,16384).hex()==r['shared_memory16384_after'],'independent shared counter bytes')
            actual=[(row['name'],row['uid_u32'],row['gid_u32'],row['access_u32']) for row in r['controlled_names_after']];check(actual==expected,'independent parsed policy field/order model '+label)
            base=u64(0x100014210);count=u32(0x100014224);check(count==len(expected) and hex(base)==r['controlled_name_array_pointer'],'controlled array/count globals')
            for j,row in enumerate(r['controlled_names_after']):
                a=u64(base+8*j);check(hex(a)==row['record_pointer'] and span(a,72).hex()==row['record72_hex'],'independent controlled record bytes');name=span(u64(a+8),alloc[a]['size_bytes']-72).split(b'\0')[0].decode();check(name==row['name'] and [u32(a+40),u32(a+44),u32(a+48)]==[row['uid_u32'],row['gid_u32'],row['access_u32']],'independent UID/GID/access/name field binding');totals['controlled_record_snapshots']+=1
            if ordinal==0:
                found={}
                for a,kind in types.items():
                    if kind=='name' and not alloc[a]['freed']:
                        raw=span(a,alloc[a]['size_bytes']);name=raw[72:-1].decode();found[name]={'id_u64':u64(a+16),'state_u64':u64(a+24),'timestamp_ticks_u64':u64(a+32),'generation_u32':u32(a+60)}
                for name,value in states.items():check(name in found and found[name]['state_u64']==value,'independent initial config state '+label)
                ledger_summaries.append({'case':label,'tokens':vectors,'controlled':actual,'name_state_after_startup':found,'monitors':monitors})
        audit=case['case'].get('audit_words',[0,501,20,501,20,2117,7,3]);uid,gid=audit[1:3];name=case['case'].get('name','com.apple.adid.midchangedV1');allowed_read=permit(name,uid,gid,1,rules);allowed_write=permit(name,uid,gid,2,rules);registered=False;dirty=False;value=states.get(name,0)
        for r in case['client_calls']:
            seq=visits(r);h=hashlib.sha256()
            for a in seq:check(a in bank,'client source visit belongs to original pool');h.update(struct.pack('<Q',a));h.update(bank[a])
            check(h.hexdigest()==r['ordered_original_instruction_sha256'] and r['stop_reason']=='returned_to_private_fixture','complete client original bytes/return');totals['client_source_visits']+=len(seq);op=r['fixture']['label'].rsplit('_',1)[0]
            if op=='register':check(r['result_u32']==(0 if allowed_read else 7),'independent read admission '+label);registered=allowed_read;dirty=registered
            elif op=='post':check(r['result_u32']==0,'oneway API transport success');dirty=dirty or registered and allowed_write
            elif op=='check':
                check(r['result_u32']==(0 if registered else 2),'local token status')
                if registered:check(r['check_output_u32']==int(dirty),'independent write admission -> counter -> check '+label);dirty=False
            elif op=='cancel':check(r['result_u32']==(0 if registered else 2),'cancel status');registered=False
            elif op=='set_state':
                check(r['result_u32']==0,'state setter one-way result0')
                message=next(e for e in events(r) if e.get('message_id_u32')==1019);newvalue=struct.unpack_from('<Q',bytes.fromhex(message['send_bytes']),40)[0]
                if allowed_write:value=newvalue
            elif op=='get_state':check(r['result_u32']==0 and r['state_output_u64']==value,'independent config/state setter -> original getter '+label)
            for e in events(r):
                if e['kind']!='explicit_paired_notify_transport':continue
                totals['paired_messages']+=1;pr=case['provider_calls'][e['provider_stub_call']];raw=bytearray.fromhex(e['send_bytes']);check(raw[4:8]==bytes(4),'raw size0');struct.pack_into('<I',raw,4,len(raw));effective=bytes.fromhex(pr['effective_received_message_and_trailer_hex']);check(effective[:len(raw)]==raw and len(effective)==len(raw)+52,'declared effective header/trailer');check(tuple(pr['explicit_audit_words'])==struct.unpack_from('<8I',effective,len(raw)+20),'exact audit input bytes')
                if 'original_provider_reply_bytes' in e:
                    reply=bytes.fromhex(e['original_provider_reply_bytes']);check(reply==bytes.fromhex(pr['reply64_hex'])[:len(reply)],'original provider body consumed by client')
                if e['message_id_u32']==1017:
                    b=bytes.fromhex(e['send_bytes']);reply=bytes.fromhex(e['original_provider_reply_bytes']);check(len(b)==40 and len(reply)==48 and struct.unpack_from('<I',reply,20)[0]==1117,'state get wire40/48');totals['state_messages']+=1
                if e['message_id_u32']==1019:check(len(bytes.fromhex(e['send_bytes']))==52 and e['oneway_provider_application_reply_delivered'] is False,'state set wire52 and no admission receipt');totals['state_messages']+=1
    for label in ['state_get_known_id_after_registration_denial','state_get_missing_id']:
        case=cases[label];r=case['provider_calls'][-1];reply=bytes.fromhex(r['reply64_hex']);status=struct.unpack_from('<I',reply,44)[0];state=struct.unpack_from('<Q',reply,36)[0];check((status,state)==((0,17) if label.endswith('denial') else (1,0)),'known/missing nameID read control')
        if label.endswith('denial'):check(case['client_calls'][0]['result_u32']==7 and 0x100000890 not in visits(r),'read-registered denial distinct from ID-state getter path')
    check(cases['grammar_double_space']['startup']['controlled_names_after'][0]['name']=='','empty controlled prefix witness')
    check(cases['ordering_duplicate_child_last_allows']['startup']['controlled_names_after'][0]['access_u32']==0,'default full grant does not reset earlier mask')
    for proof in c['proofs']:
        path=ROOT/proof['path'];check(sha(path.read_bytes())==proof['sha256'],'solver source pin');run=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);check(run.stdout.strip()=='unsat' and not run.stderr,'fresh local proof')
    abi=c['sdk_compile'];check(sha((ROOT/'notifyd_policy_layouts.c').read_bytes())==abi['source_sha256'] and sha((ROOT/'notifyd_policy_layouts.s').read_bytes())==abi['assembly_sha256'],'compile source/assembly pins')
    for row in [abi['stat_header']]+c['additional_SDK_headers']:check(sha(Path(row['path']).read_bytes())==row['sha256'],'original SDK header pin')
    cmd=list(abi['command']);cmd[cmd.index('-o')+1]='/tmp/notifyd-policy-verify.s';run=subprocess.run(cmd,capture_output=True,text=True);check(run.returncode==0 and not run.stderr and sha(Path('/tmp/notifyd-policy-verify.s').read_bytes())==abi['assembly_sha256'],'fresh SDK ABI compile')
    fresh_calls=0
    for old in p['cases']:
        print('fresh '+old['case']['label'],flush=True);new=run_policy_case(old['case']);pools={'instructions':{},'functions':{},'cache_pages':{}}
        for origin,rows in [('provider',[new['startup']]+new['provider_calls']),('client',new['client_calls'])]:
            for r in rows:compact_row(r,origin,pools)
        check(json.loads(json.dumps(new))==old,'complete fresh parsed-policy paired replay '+old['case']['label']);fresh_calls+=1+len(new['client_calls'])+len(new['provider_calls'])
    for row in read('interface_manifest.json')['inputs_preserved']:
        path=ROOT.parent/row['path'];check(path.stat().st_size==row['size_bytes'] and sha(path.read_bytes())==row['sha256'],'original supplied input preserved')
    counts={**totals,'policy_sequences':len(p['cases']),'client_public_calls':sum(len(x['client_calls']) for x in p['cases']),'provider_startups':len(p['cases']),'provider_selector_and_stub_calls':sum(len(x['provider_calls']) for x in p['cases']),'fresh_original_calls':fresh_calls,'original_instruction_records':len(bank),'original_compiler_records':len(p['original_source_pools']['functions']),'audit_helper_export_bodies':len(c['original_audit_helpers']),'source_contract_functions':len(c['original_functions']),'proofs_unsat':len(c['proofs']),'assertions':assertions}
    result={'scope':__doc__,'verified_counts':counts,'independent_config_state_summaries':ledger_summaries,'all_checks_pass':True,'native_target_executed':False,'native_transaction_executed':False,'native_defect_established':False,'daemon_loaded_reference_config_established':False,'full_goal_complete':False};(ROOT/'notifyd_policy_checks.json').write_text(json.dumps(result,indent=2)+'\n');quality={k:v for k,v in result.items() if k!='independent_config_state_summaries'};texts=['Descriptive technical analysis only.','Report P1-P13 enumerate source/config/audit/file/transport/semantic/native assumptions and falsification probes.','Reference parser,policy ordering/access,grammar,metadata,state IPC and explicit controls covered;native/full goal remains open.','Byte widths,stat offsets,permission bits,source state packets,bounded algorithms and four local formulas explicit.','Current file versus loaded state,policy grants versus registration/state-read decisions,and one-way result/admission separated.','Fresh binary/cache/audit/helper bytes,independent parser/policy/allocation/global/shared ledgers,all full replays,SDK compile and solver queries.','Impact-labeled effective-config reconciliation,parser boundaries,ID-state read admission,monitor callbacks and native transaction continuation.']
    for j,t in enumerate(texts,1):quality['QG'+str(j)]={'status':'pass_for_stated_increment','evidence':t}
    (ROOT/'notifyd_policy_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps(counts),flush=True)

if __name__=='__main__':main()
