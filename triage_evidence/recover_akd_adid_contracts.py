#!/usr/bin/env python3
"""Original AKADIProxy names, client/daemon packets and bounded cache catalog.

O(B+F+M+T+E) time/space for binary bytes,chains,metadata,text and export tries;
two separate30 s full64-bit SMT queries. No target/loader/IPC/native API runs.
Names are original ObjC metadata; internal C labels are analyst role mappings.
"""
import json
from pathlib import Path
import struct
import subprocess
from akd_client_reader import Akd,ROOT,CS,sha,THIN_SHA,SOURCE_SHA
from adid_reader import THIN_SHA as PROVIDER_SHA
from bootpolicy_cache_reader import Cache,Dylib,uleb
from probe_adid_startup import unpack_records
from recover_appstore_agent import stub

METHODS={
 'get':('AKADIProxy','getIDMSRoutingInfo:forDSID:',0x1002f86d8),
 'set':('AKADIProxy','setIDMSRoutingInfo:forDSID:',0x10030f600),
 'otp':('AKADIProxy','requestOTPForDSID:outMID:outMIDSize:outOTP:outOTPSize:',0x100308278),
 'dispose':('AKADIProxy','dispose:',0x1003026f8),
 'is_provisioned':('AKADIProxy','isMachineProvisioned:',0x1002d8790),
 'start':('AKADIProxy','startProvisioningWithDSID:SPIM:SPIMLength:outCPIM:outCPIMLength:outSession:',0x1002e1b74),
 'end':('AKADIProxy','endProvisioningWithSession:PTM:PTMLength:TK:TKLength:',0x100302898),
 'destroy':('AKADIProxy','destroyProvisioningSession:',0x1002dd3a0),
 'sync':('AKADIProxy','synchronizeWithDSID:SIM:SIMLength:outMID:outMIDLength:outSRM:outSRMLength:',0x1002ed22c),
 'erase':('AKADIProxy','eraseProvisioningForDSID:',0x1002fd5c8),
 'login_code':('AKAppleIDCodeGenerator','generateLoginCode:',0x1002d3d84)}


def trie_names(data):
    out={};work=[(0,'',frozenset())]
    while work:
        at,prefix,parents=work.pop();assert at not in parents;n,cur=uleb(data,at);end=cur+n;assert end<len(data)
        if n:flags,_=uleb(data,cur);out[prefix]=flags
        count=data[end];cur=end+1
        for _ in range(count):
            term=data.index(0,cur);suffix=data[cur:term].decode();child,cur=uleb(data,term+1);work.append((child,prefix+suffix,parents|{at}))
    return out


def cache_catalog():
    cache=Cache();assert cache.uuid=='2bd06591-e751-3e84-963f-b08dab6af23a';rows=[];matches=[]
    for image in cache.images:
        d=Dylib(cache,image['path']);raw=getattr(d,'export_bytes',b'');names=trie_names(raw) if raw else {};selected={n:f for n,f in names.items() if n.startswith(('_ADI','__ADI')) or 'CoreADI' in n}
        if selected:matches.append({'path':image['path'],'names':selected})
        rows.append({'path':image['path'],'base':hex(d.base),'uuid':d.uuid,'export_trie_size_bytes':len(raw),'export_trie_sha256':sha(raw),'all_terminal_names_count':len(names),'all_terminal_names_sha256':sha('\n'.join(sorted(names)).encode()),'matching_names':selected})
    return {'scope':'All4113 listed original cache images;all export terminal names including reexports. This is neither a filesystem-wide search nor runtime-loaded-image attestation.','cache_uuid':cache.uuid,'image_count':len(rows),'image_rows':rows,'matching_exports':matches,'CoreADI_named_image_paths':[i['path'] for i in cache.images if 'CoreADI' in i['path']],'cache_file_catalog':list(cache.files.values()),'native_target_executed':False}


def source_refs(s,targets):
    sec=next(x for x in s.sections if x['section']=='__text');raw=s.read(sec['address'],sec['size']);words=[x[0] for x in struct.iter_unpack('<I',raw)];out=[]
    for j,w in enumerate(words):
        pc=sec['address']+4*j
        if w&0x7c000000==0x14000000:
            imm=w&0x3ffffff;imm=imm-0x4000000 if imm&0x2000000 else imm;t=pc+4*imm
            if t in targets:out.append({'kind':'original_direct_B_or_BL','source':hex(pc),'target':hex(t),'compiler_start':hex(s.bounds(pc)[0])})
        if w&0x9f000000 in (0x10000000,0x90000000):
            imm=((w>>5)&0x7ffff)<<2|((w>>29)&3);imm=imm-(1<<21) if imm&(1<<20) else imm;rd=w&31
            if w&0x9f000000==0x10000000:
                t=pc+imm
                if t in targets:out.append({'kind':'original_ADR','source':hex(pc),'target':hex(t)})
            elif j+1<len(words):
                nxt=words[j+1]
                if nxt&0xff800000==0x91000000 and (nxt>>5&31)==rd:
                    t=(pc&~4095)+(imm<<12)+(((nxt>>10)&4095)<<(12 if nxt>>22&1 else 0))
                    if t in targets:out.append({'kind':'original_adjacent_ADRP_ADD','source':hex(pc),'target':hex(t)})
    for a,r in s.decoded_fixups.items():
        if not r['bind'] and int(r['target'],16) in targets:out.append({'kind':'original_chained_pointer','source':hex(a),'target':r['target']})
    return out


def literal_refs(s,fn):
    rows=[];ins=fn['instructions'];cf=next((x for x in s.sections if x['section']=='__cfstring'),None)
    for a,b in zip(ins,ins[1:]):
        if a['mnemonic']!='adrp' or b['mnemonic']!='add':continue
        aa=a['operands'].split(', ');bb=b['operands'].split(', ')
        if len(bb)!=3 or bb[1]!=aa[0] or not bb[2].startswith('#'):continue
        try:p=int(aa[1][1:],16)+int(bb[2][1:],0)
        except ValueError:continue
        if cf and cf['address']<=p and p+32<=cf['address']+cf['size']:
            ptr=s.qword(p+16);n=struct.unpack('<Q',s.read(p+24,8))[0]
            if isinstance(ptr,int) and n<4096:
                raw=s.read(ptr,n)
                try:text=raw.decode('utf-8')
                except UnicodeDecodeError:continue
                rows.append({'source':a['ea'],'object':hex(p),'characters':hex(ptr),'size_bytes':n,'text':text})
    return rows


def main():
    s=Akd();inv=json.loads((ROOT/'akd_client_inventory.json').read_text());profiles=json.loads((ROOT/'akd_client_profiles.json').read_text());rows={r['fixture']['label']:r for r in profiles['profiles']};ms=inv['methods'];bound=[];functions={};edges=[]
    for label,(owner,selector,target) in METHODS.items():
        method=next(m for m in ms if m['class']==owner and m['selector']==selector);a=int(method['implementation'],16);fn=s.function(a);functions[a]=fn;functions[target]=s.function(target);calls=[x for x in fn['instructions'] if x['mnemonic']=='bl' and int(x['operands'][1:],16)==target];assert len(calls)==1;evs=unpack_records(rows[label]);request=next((e for e in evs if e['kind']=='original_client_data_emission'),None)
        bound.append({'label':label,'original_method_metadata':method,'original_direct_call':calls[0],'C_target':hex(target),'source_request':request,'semantic_scope':'Original named method -> direct C call -> original packet producer;not original C symbol or native runtime dispatch proof.'})
    for a in [0x1002e7d04,0x1002f3944]:functions[a]=s.function(a)
    high_names=['_tq_anisetteDataForDSID:withError:','_tq_processStartProvisioningResponse:error:completion:','_tq_processEndProvisioningResponse:error:cpimBytes:provisioningContext:completion:','_cleanUpCPIMBytes:provisioningContext:','_tq_syncAnisetteWithSIMData:completion:','_tq_eraseAnisetteWithCompletion:','_tq_anisetteDataWithRoutingInfoForLastKnownDSIDWithError:','_createProvisioningStartURLRequestWithPreviousTXID:completion:','_createProvisioningEndURLRequestWithCPIM:withPreviousTransactionID:completion:','_createSyncURLRequestWithMID:SRM:routingInfo:completion:']
    high=[];stubs={}
    for name in high_names:
        m=next(m for m in ms if m['class']=='AKNativeAnisetteService' and m['selector']==name);a=int(m['implementation'],16);f=s.function(a);functions[a]=f;high.append({'method':m,'literal_references':literal_refs(s,f)})
        for i in f['instructions']:
            if i['mnemonic'] not in ('bl','b'):continue
            target=int(i['operands'][1:],16);sec=next((x for x in s.sections if x['address']<=target<x['address']+x['size']),None);edge={'source_method':name,'callsite':i['ea'],'target':hex(target),'branch':i['mnemonic']}
            if sec and sec['section'] in ('__auth_stubs','__objc_stubs'):
                if target not in stubs:stubs[target]=stub(s,target)
                edge['stub']=stubs[target]
            edges.append(edge)
    queries={
      'akd_adid_reserved_dsid64.smt2':'''(declare-fun dsid () (_ BitVec 64))
(define-fun index () (_ BitVec 64) (bvadd dsid #x0000000000000008))
(define-fun bits () (_ BitVec 32) (bvlshr #x0000007d ((_ zero_extend 27) ((_ extract 4 0) index))))
(define-fun accept () Bool (and (bvule index #x0000000000000006) (= (bvand bits #x00000001) #x00000001)))
(assert (distinct accept (or (= dsid #xfffffffffffffff8) (= dsid #xfffffffffffffffa) (= dsid #xfffffffffffffffb) (= dsid #xfffffffffffffffc) (= dsid #xfffffffffffffffd) (= dsid #xfffffffffffffffe))))''',
      'akd_adid_login_dsid64.smt2':'''(declare-fun dsid () (_ BitVec 64))
(declare-fun output () (_ BitVec 64))
(define-fun sum () (_ BitVec 65) (bvadd ((_ zero_extend 1) dsid) #b00000000000000000000000000000000000000000000000000000000000010001))
(define-fun carry () Bool (= ((_ extract 64 64) sum) #b1))
(define-fun nonzero () Bool (distinct ((_ extract 63 0) sum) #x0000000000000000))
(define-fun cmn_hi () Bool (and carry nonzero))
(define-fun ccmp_ne () Bool (and cmn_hi (distinct output #x0000000000000000)))
(assert (distinct ccmp_ne (and (bvuge dsid #xfffffffffffffff0) (distinct output #x0000000000000000))))'''}
    proofs=[]
    for name,q in queries.items():
        path=ROOT/name;path.write_text('(set-logic QF_BV)\n(set-option :timeout 30000)\n'+q+'\n(check-sat)\n');r=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);assert r.stdout.strip()=='unsat' and not r.stderr,(name,r.stdout,r.stderr);proofs.append({'path':name,'sha256':sha(path.read_bytes()),'result':'unsat'})
    windows=[]
    for a,z,role in [(0x1002f87f8,0x1002f8814,'routing read reserved DSID gate'),(0x10030f724,0x10030f740,'routing write reserved DSID gate'),(0x1002d3e90,0x1002d3f14,'login CMN/CCMP identifier and output-pointer gate'),(0x10010dd08,0x10010dd6c,'sync method ninth ObjC argument to C X6')]:
        raw=s.read(a,z-a);windows.append({'start':hex(a),'end':hex(z),'role':role,'bytes':raw.hex(),'sha256':sha(raw),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(raw,a)]})
    targets={v[2] for v in METHODS.values()}|{0x1002e7d04,0x1002f3944};refs=source_refs(s,targets);server=json.loads((ROOT/'adid_command_dispatch_contracts.json').read_text());accepted={r['wire_command_u32'] for r in server['command_tree']['accepted']};producer=[]
    for label in ['get','set','otp','is_provisioned','start','end','destroy','sync','erase','login_code','unnamed720','vmtohost']:
        es=unpack_records(rows[label]);e=next(e for e in es if e['kind']=='original_client_data_emission');wire=bytes.fromhex(e['payload_hex']);command=int.from_bytes(wire[4:8],'big');assert command in accepted;producer.append({'label':label,'command_u32':command,'data_emission_site':e['callsite'],'wire_bytes':wire.hex(),'sync_send_site':next(e['callsite'] for e in es if e['kind']=='original_client_sync_send'),'connection_site':next(e['callsite'] for e in es if e['kind']=='explicit_client_connection')})
    catalog=cache_catalog();assert not catalog['matching_exports'] and not catalog['CoreADI_named_image_paths'];(ROOT/'akd_adid_cache_exports.json').write_text(json.dumps(catalog,indent=2)+'\n')
    out={'scope':__doc__,'client_source_sha256':SOURCE_SHA,'client_thin_sha256':THIN_SHA,'client_uuid':s.meta['uuid'],'client_embedded_entitlements':inv['embedded_entitlements'],'effective_client_entitlements_established':False,'provider_thin_sha256':PROVIDER_SHA,'named_method_C_bindings':bound,'original_functions':list(functions.values()),'high_level_methods':high,'high_level_direct_edges':edges,'original_selected_stubs':list(stubs.values()),'client_producers':producer,'provider_commands_without_identified_client_producer':[hex(x) for x in sorted(accepted-{r['command_u32'] for r in producer})],'original_C_entry_references':refs,'reference_scan_scope':'All text B/BL,ADR,adjacent ADRP+ADD and independently walked chain pointers;other computed/interprocedural references may remain.','proofs':proofs,'source_windows':windows,'cache_export_catalog_sha256':sha((ROOT/'akd_adid_cache_exports.json').read_bytes()),'generator_sha256':sha(Path(__file__).read_bytes()),'dependencies':{n:sha((ROOT/n).read_bytes()) for n in ['akd_client_entitlements.xml','akd_client_entitlements.json','akd_client_reader.py','akd_client_inventory.json','akd_client_profiles.json','probe_akd_clients.py','recover_appstore_agent.py','bootpolicy_cache_reader.py','adid_command_dispatch_contracts.json']},'native_target_executed':False,'full_goal_complete':False};(ROOT/'akd_adid_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'named_methods':len(bound),'RPC_producers':len(producer),'unmapped_provider_commands':out['provider_commands_without_identified_client_producer'],'source_functions':len(functions),'high_methods':len(high),'high_direct_edges':len(edges),'selected_stubs':len(stubs),'new_proofs_unsat':len(proofs),'cache_images':catalog['image_count']}))


if __name__=='__main__':main()
