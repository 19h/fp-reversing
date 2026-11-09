#!/usr/bin/env python3
"""Independent byte/chain/ABI/profile readback for the CoreFP export increment.

No native target/loader/IPC/API runs. O(B+F+V+R+256*K) verification time,
O(B+F+V+R) space; solver complexity separate, each query capped at30 s.
Original files, source-pinned instruction visits and explicit API models are
distinct evidence. The broad interface investigation remains active.
"""
import bisect
from collections import Counter
import hashlib
import json
from pathlib import Path
import plistlib
import re
import struct
import subprocess
import sys
from corefp_fixups_reader import Pointers,ROOT,sha,THIN_SHA,SHA,FIXUPS
from corefp_library_reader import SOURCE
from ams_core_reader import Core
from appstore_agent_reader import CS


def load(name):return json.loads((ROOT/name).read_text())


def main():
    s=Pointers();r=load('corefp_exports_contracts.json');p=load('corefp_exports_profiles.json')
    b=load('corefp_version_bridge_profiles.json');inv=load('corefp_fixups_inventory.json');calls=load('corefp_import_calls.json');m=load('corefp_mach_request_profiles.json');checks=[]
    def check(ok,label):
        assert ok,label
        checks.append(label)
    def pinned(obj,key,name):check(obj[key]==sha((ROOT/name).read_bytes()),'pinned '+name+' / '+key)
    check(sha(SOURCE.read_bytes())==SHA==r['source_sha256'] and sha(s.data)==THIN_SHA==r['thin_sha256']==p['thin_sha256']==calls['thin_sha256'],'original universal/thin image identity')
    check(s.meta['uuid']==r['uuid']==inv['uuid']==calls['uuid']=='9061ddc3-93b4-3824-914f-9cc97d708d58','original CoreFP UUID')
    check(len(s.decoded)==r['fixups_count']==79512 and len(s.imports)==r['imports_count']==196 and s.imports==inv['imports'],'complete chain/import membership and dyld_info correspondence')
    check(inv['dyld_info_text_sha256']==sha(FIXUPS.read_bytes()),'dyld_info text identity')
    pinned(inv,'reader_sha256','corefp_fixups_reader.py');pinned(r,'generator_sha256','recover_corefp_exports.py')
    for row in inv['fixups']:
        at=int(row['address'],16)
        auth_matches=True
        if row['authenticated']:
            fields=re.search(r'\(div=(0x[0-9a-fA-F]+) ad=([01]) key=(IA|IB|DA|DB)\)',s.fixups[at]['line'])
            auth_matches=bool(fields) and (int(fields[1],16),int(fields[2]),fields[3])==(int(row['diversity'],16),row['address_diversity'],row['key'])
        check(s.decoded[at]==row and struct.unpack('<Q',s.read(at,8))[0]==int(row['word'],16) and auth_matches,'original chain member '+row['address'])
    for row in r['pointers']:check(s.decoded[int(row['address'],16)]==row,'selected chain target '+row['address'])
    for row in r['ranges']+p['original_functions']+b['CoreFP_original_functions']+calls['original_ranges']+m['original_functions']:
        at=int(row['start'],16);end=int(row['end'],16);raw=s.read(at,end-at);ix=s.starts.index(at)
        expected=s.starts[ix+1] if ix+1<len(s.starts) else next(x['address']+x['size'] for x in s.meta['sections'] if x['section']=='__text')
        check(end==expected and sha(raw)==row['sha256'],'original function/hash extent '+row['start'])
        if 'bytes' in row:check(raw.hex()==row['bytes'],'retained original function bytes '+row['start'])
        if 'original_function' in row:check(raw.hex()==row['original_function']['bytes'],'original static function body '+row['start'])
    for row in p['visited_instruction_records']+m['visited_instruction_records']:
        at=int(row['ea'],16);raw=s.read(at,4);i=next(CS.disasm(raw,at))
        check(raw.hex()==row['bytes'] and (i.mnemonic,i.op_str)==(row['mnemonic'],row['operands']),'visited instruction '+row['ea'])
    for bank in r['banks']:
        aa=s.read(int(bank['first_address'],16),256);bb=s.read(int(bank['second_address'],16),256)
        values=[i^bb[aa[i]^bank['key_u8']] for i in range(256)]
        check(aa.hex()==bank['first_bytes'] and bb.hex()==bank['second_bytes'] and values==bank['results_256'] and set(values)=={bank['constant_u8']},'exhaustive bank '+bank['label'])
    check(len(r['banks'])==9 and r['distinct_bank_identities']==7 and len(r['proofs'])==4,'nine bank uses/seven identities/four proof obligations')
    for proof in r['proofs']:
        path=ROOT/proof['path'];result=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True)
        check(sha(path.read_bytes())==proof['sha256'] and result.stdout.strip()=='unsat' and not result.stderr,'SMT '+path.name)
    plist_path=Path(r['bundle']['path']);raw=plist_path.read_bytes();plist=plistlib.loads(raw)
    check(sha(raw)==r['bundle']['sha256'] and plist['CFBundleVersion']==plist['CFBundleShortVersionString']==r['bundle']['version']=='6.8.3','original version metadata')
    for obj in [r,p,b,calls,m]:pinned(obj,'fixup_inventory_sha256','corefp_fixups_inventory.json')
    pinned(p,'generator_sha256','probe_corefp_exports.py');pinned(p,'pointer_reader_sha256','corefp_fixups_reader.py')
    pinned(b,'generator_sha256','probe_corefp_version_bridge.py');pinned(b,'AMS_parent_sha256','probe_ams_core.py');pinned(b,'CoreFP_child_sha256','probe_corefp_exports.py')
    pinned(calls,'generator_sha256','recover_corefp_import_calls.py')
    pinned(r,'import_calls_sha256','corefp_import_calls.json');pinned(m,'import_calls_sha256','corefp_import_calls.json')
    pinned(m,'generator_sha256','probe_corefp_mach_requests.py');pinned(m,'engine_sha256','probe_corefp_exports.py')
    def visits(row,reader,label):
        h=hashlib.sha256()
        for a in row['visited_original_instructions']:
            at=int(a,16);h.update(struct.pack('<Q',at));h.update(reader.read(at,4))
        check(h.hexdigest()==row['original_instruction_bytes_sha256'],'ordered source instruction visits '+label)
    def version(row,label):
        visits(row,s,label);f=row['fixture'];mask=(1<<64)-1;g1,g2,g3=f['state64'];sp=int(row['entry_sp'],16)-0x30
        C=0x68001f0b;K=0x2a3c56842e5d49ec;v=((g1^g2)+sp)&mask
        g1=(v*C-K)&mask;g2=((v^K)*C)&mask;v=(g3-(sp-0x10+8)+g2)&mask
        g3=((v*C)^K)&mask;g2=((v^K)*C)&mask
        check(row['state_after']==[struct.pack('<Q',v).hex() for v in [g1,g2,g3]],'four original state stores '+label)
        null=f.get('null',False)
        check(row['stop_reason']=='returned_to_private_fixture' and row['result_u32']==(0xffff5bd9 if null else 0),'version pointer/status partition '+label)
        expected=b'\xa5'*16 if null else struct.pack('<III',6,8,3)+b'\xa5'*4
        check(row['output16_bytes']==expected.hex(),'exact12-byte output/sentinel '+label)
        event=next(e for e in row['records'] if e['kind']=='original_version_record_entry');record=bytes.fromhex(event['record16_bytes']);rp=int(event['record_pointer'],16)
        p32=rp&0xffffffff;encoded=((p32^0x302a1e77)*0xcae5b081&0xffffffff)^0x3231
        check(struct.unpack_from('<I',record,4)[0]==encoded and struct.unpack_from('<Q',record,8)[0]==(0 if null else 0x7b000100),'version original record inputs '+label)
        operation=next(e for e in row['records'] if e['kind']=='original_version_operation')
        check(operation['operation_u32']==0x3231,'original decoded version operation '+label)
        stores=[e for e in row['records'] if e['kind']=='original_private_global_write']
        check(len(stores)==4 and {e['address'] for e in stores}==set(r['version_query']['state_cells']),'version mutable side effects retained '+label)
    profiles=p['profiles'];by={x['fixture']['label']:x for x in profiles}
    check(len(profiles)==15 and Counter(x['stop_reason'] for x in profiles)=={'returned_to_private_fixture':7,'opaque_import_boundary':6,'atomic_instruction_boundary':1,'second_private_mapping_guard':1},'15 classified bounded outcomes without emulator exception')
    for row in profiles:
        label=row['fixture']['label']
        if row['fixture']['mode']=='version':version(row,label);continue
        visits(row,s,label)
        event=next(e for e in row['records'] if e['kind']=='original_packet_record_entry');record=bytes.fromhex(event['record_written_extent88_bytes']);ptr=int(event['record_pointer'],16)
        key=(((ptr&0xffffffff)^0x309487ae)*0x87cfdb29)&0xffffffff
        d32=lambda o:struct.unpack_from('<I',record,o)[0]
        d64=lambda o:struct.unpack_from('<Q',record,o)[0]
        check(len(record)==88 and d32(0)==(key+0x2472c1e1)&0xffffffff and d32(32)==(891-key)&0xffffffff and d32(64)==(7+key)&0xffffffff,'packet original encoded mode/length/operation '+label)
        check([d64(o) for o in [8,24,40,48,56,72]]==[0x7b000200,0x7b000500,0x7b001000,0x7b000400,0x7b002000,0x7b000300] and d64(80)==((ptr-24)^0xc43af69d4c49fa99),'packet original pointer slots '+label)
        edges=[e for e in row['records'] if e['kind']=='PAC_bypassed_edge' and e['pc']=='0xe40c']
        check(len(edges)==1 and edges[0]['target']=='0x27afd4' and edges[0]['modifier']=='0x17c6','packet exact authenticated target/modifier '+label)
        for e in row['records']:
            if e['kind']=='modeled_stack_probe':check(e['requested_size_x9']=='0x1c030' and e['import']['name']=='___chkstk_darwin','explicit stack model '+label)
            if e['kind']=='modeled_once':check(e['control']=='0x1d36080' and e['callback']=='0x28994','original once callback/control '+label)
            if e['kind']=='modeled_sequential_atomic_exchange':check(e['pc']=='0x28e4c' and e['before_bytes']=='00000000' and e['after_bytes']=='01000000' and not e['concurrent_ordering_validated'],'explicit sequential atomic model '+label)
            if e['kind']=='modeled_page_size_query':check(e['selector_u32']==29 and e['result_signed64']==row['fixture']['page_size_result'] and not e['native_query_executed'],'explicit sysconf result '+label)
            if e['kind']=='modeled_anonymous_mapping':check(e['callsite']=='0x29028' and e['args_x0_x5']==r['initialization']['mmap_args_x0_x5'] and not e['native_mapping_executed'],'explicit private mapping '+label)
        if 'page_size_result' in row['fixture'] and 'mapping_result' not in row['fixture']:
            e=row['records'][-1];check(e['import']['name']=='_mmap' and e['callsite']=='0x29028' and e['live_x0_x7'][:6]==r['initialization']['mmap_args_x0_x5'],'three conditional page-size paths request identical mapping '+label)
    failed=by['certificate_packet_mapping_failed']
    check(failed['result_u32']==0xffffffff and next(e for e in failed['records'] if e['kind']=='original_packet_status_load')['record_status_u32']==0xffffffff,'original public status from first modeled MAP_FAILED')
    success=by['certificate_packet_mapping_success'];check(success['stop_reason']=='second_private_mapping_guard' and len([e for e in success['records'] if e['kind']=='modeled_anonymous_mapping'])==1,'first successful private mapping stops before a second allocation')
    core=Core();cache=core.cache
    for f in b['AMS_original_functions']:
        at=int(f['start'],16);check(cache.read(at,len(bytes.fromhex(f['bytes']))).hex()==f['bytes'] and core.ams.function(at)['end']==f['end'],'original AMS bridge function '+f['start'])
    for page in b['AMS_original_pages']:
        at=int(page['address'],16);raw=cache.read(at,4096);material=bytearray(raw)
        check(sha(raw)==page['original_sha256'],'original AMS bridge page '+page['address'])
        for ptr in page['relocations']:
            a=int(ptr['address'],16);check(core.page_chains(a).get(a)==ptr,'AMS bridge pointer '+ptr['address']);struct.pack_into('<Q',material,a-at,int(ptr['target'],16))
        check(sha(material)==page['materialized_sha256'],'AMS bridge private materialization '+page['address'])
    check(len(b['profiles'])==2,'two independent source-output bridge cases')
    for row in b['profiles']:
        label=row['fixture']['label'];visits(row,cache,label)
        check(row['stop_reason']=='CoreFP_export_call_boundary' and len(row['source_version_children'])==1,'bridge call classified '+label)
        child=row['source_version_children'][0];version(child,label+'/child')
        e=next(e for e in row['records'] if e['kind']=='source_CoreFP_version_ABI_transfer')
        check(e['target_cell']=='0x1ebbfd6ec' and e['after12_bytes']==child['output16_bytes'][:24] and e['source_result_u32']==0,'exact source12-byte ABI transfer '+label)
        e=row['records'][-1];check(e['export']=='WIn9UJ86JKdV4dM' and e['callsite']=='0x19c20e690' and e['live_registers_x0_x8'][0]=='0x7' and e['live_registers_x0_x8'][3:5]==['0x19cb1a483','0x37b'],'original AMS reaches mode7 certificate call '+label)
    stubs={int(x['address'],16):x for x in calls['stubs']}
    for at,row in stubs.items():
        check(s.read(at,16).hex()==row['bytes'] and sha(s.read(at,16))==row['sha256'] and s.decoded[int(row['pointer']['address'],16)]==row['pointer'],'original authenticated stub '+hex(at))
        instructions=list(CS.disasm(s.read(at,16),at));cell=int(instructions[0].op_str.split('#')[1],16)+int(instructions[1].op_str.split('#')[1],16)
        check(cell==int(row['pointer']['address'],16) and [i.mnemonic for i in instructions]==['adrp','add','ldr','braa'],'original stub cell/address modifier '+hex(at))
    for edge in calls['direct_branch_candidates']:
        at=int(edge['callsite'],16);word=struct.unpack('<I',s.read(at,4))[0];delta=word&0x3ffffff
        if delta&0x2000000:delta-=0x4000000
        check(word&0x7c000000==0x14000000 and at+4*delta==int(edge['stub'],16) and s.read(at,4).hex()==edge['instruction_bytes'],'original direct import edge '+edge['callsite'])
        check(stubs[int(edge['stub'],16)]['pointer']['import']==edge['import'] and s.read(int(edge['window']['start'],16),len(bytes.fromhex(edge['window']['bytes']))).hex()==edge['window']['bytes'],'edge original window/import '+edge['callsite'])
    scanned=set()
    for sec in s.meta['sections']:
        if sec['section']!='__text':continue
        for ix,(word,) in enumerate(struct.iter_unpack('<I',s.read(sec['address'],sec['size']))):
            if word&0x7c000000!=0x14000000:continue
            at=sec['address']+ix*4;delta=word&0x3ffffff
            if delta&0x2000000:delta-=0x4000000
            if at+4*delta in stubs:scanned.add((at,at+4*delta))
    check(scanned=={(int(x['callsite'],16),int(x['stub'],16)) for x in calls['direct_branch_candidates']},'complete original __text B/BL encoding scan to authenticated import stubs')
    specs={int(x['entry'],16):x for x in r['mach_request_builders']}
    check(len(specs)==5 and len(m['profiles'])==7,'five request builders and seven independent private request cases')
    for spec in specs.values():
        lit=spec['header_voucher_and_id_literal'];raw=s.read(int(lit['address'],16),8)
        check(raw.hex()==lit['bytes'] and struct.unpack('<II',raw)==(0,spec['request_id']),'original voucher/ID literal '+spec['entry'])
        edge=next(x for x in calls['direct_branch_candidates'] if x['callsite']==spec['callsite'])
        check(edge['import']['name']=='_mach_msg' and edge['stub']=='0x15d18e4' and edge['compiler_function_start']==spec['entry'],'exact direct Mach emission call '+spec['entry'])
        f=s.function(int(spec['entry'],16))
        check(any(i['mnemonic']=='cmp' and i['operands']=='w8, #'+hex(spec['expected_reply_id']) for i in f['instructions']),'original expected reply ID comparison '+spec['entry'])
        reloads={0x8ae0:(0x8b84,'w4, [sp, #0x18]'),0x8d40:(0x8de0,'w4, [sp, #0x10]'),
            0x8ed4:(0x8f6c,'w4, [sp, #0x10]'),0x90c8:(0x9128,'w4, [sp, #0x10]'),
            0x1590824:(0x15908a4,'w4, [sp, #0xc]')}
        at,operand=reloads[int(spec['entry'],16)];ins=next(CS.disasm(s.read(at,4),at))
        check(ins.mnemonic=='ldr' and ins.op_str==operand,'original receive-name reload after voucher hook '+spec['entry'])
    for ref in r['mach_request_builder_pointer_references']:check(s.decoded[int(ref['address'],16)]==ref,'request builder pointer reference '+ref['address'])
    for row in m['profiles']:
        f=row['fixture'];label=f['label'];spec=specs[f['entry']];visits(row,s,label)
        check(row['stop_reason']=='original_mach_msg_request_boundary','private request stop '+label)
        e=row['records'][-1];args=[int(v,16) for v in e['args_x0_x6']];raw=bytes.fromhex(e['message_bytes']);head=struct.unpack_from('<6I',raw)
        check(args[1:]==[3,spec['send_bytes'],spec['receive_capacity_bytes'],f['reply_name_u32'],0,0] and len(raw)==spec['send_bytes'] and e['callsite']==spec['callsite'] and not e['native_message_emitted'],'original message call arguments '+label)
        bits=0x1513|(0x80000000 if spec['body_descriptors'] else 0)
        check(head==(bits,0xa5a5a5a5,0x3141,f['reply_name_u32'],0,spec['request_id']) and list(head)==e['header_u32'],'original request header,remote/reply names and untouched size '+label)
        check(len([v for v in row['records'] if v['kind']=='modeled_voucher_noop'])==int(f['voucher_present']),'explicit weak voucher model '+label)
        for stub in row['original_auth_stubs']:check(stubs[int(stub['address'],16)]==stub,'private original import stub '+label+':'+stub['address'])
        if spec['body_descriptors']:
            check(struct.unpack_from('<I',raw,24)[0]==1 and struct.unpack_from('<QII',raw,28)==(0x7b001000,0x01000100,8) and raw[44:52].hex()==row['NDR8_fixture_bytes'],'original OOL descriptor and modeled NDR byte flow '+label)
        if f['entry']==0x8ae0:check(struct.unpack_from('<III',raw,52)==(0x11223344,2,8),'original request1200 scalar fields '+label)
        if f['entry']==0x8d40:check(raw[24:32].hex()==row['NDR8_fixture_bytes'] and struct.unpack_from('<I',raw,32)[0]==0x11223344 and raw[36:]==bytes(range(128)),'original request1201 inline128-byte copy '+label)
        if f['entry']==0x8ed4:check(struct.unpack_from('<III',raw,52)==(0x11223344,0x55667788,0x99aabbcc) and raw[64:80]==bytes(range(16)) and struct.unpack_from('<I',raw,80)[0]==8,'original request1202 scalar and inline16-byte copy '+label)
        if f['entry']==0x1590824:check(struct.unpack_from('<I',raw,52)[0]==8,'separate request1200 length copy '+label)
    sdk='/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk';src=ROOT/'corefp_exports_layouts.c'
    command=['/usr/bin/clang','-target','arm64e-apple-macos','-isysroot',sdk,'-fsyntax-only','-Wall','-Wextra','-Werror',str(src)]
    result=subprocess.run(command,capture_output=True,text=True)
    check(result.returncode==0 and not result.stderr,'arm64e version record/output and sysconf/mmap constants compile')
    for h in r['sdk_headers']:check(sha(Path(h['path']).read_bytes())==h['sha256'],'original SDK header '+h['path'])
    for row in load('interface_manifest.json')['inputs_preserved']:
        path=ROOT.parent/row['path'];check(path.stat().st_size==row['size_bytes'] and sha(path.read_bytes())==row['sha256'],'original supplied input preserved '+row['path'])
    counts={'original_fixups':79512,'imports':196,'original_static_ranges':len(r['ranges']),
        'selected_pointer_members':len(r['pointers']),'banks_256':9,'distinct_bank_identities':7,'smt_unsat':4,
        'private_profiles':15,'source_version_bridge_profiles':2,'private_original_functions':len(p['original_functions']),
        'visited_original_instruction_records':len(p['visited_instruction_records']),
        'AMS_bridge_original_functions':len(b['AMS_original_functions']),'AMS_bridge_original_pages':len(b['AMS_original_pages']),
        'authenticated_import_stubs':len(stubs),'direct_import_branch_candidates':len(calls['direct_branch_candidates']),
        'direct_import_caller_ranges':len(calls['original_ranges']),'sdk_compile_exit':result.returncode,'assertions':len(checks)}
    counts.update({'CoreFP_direct_mach_msg_calls':5,'CoreFP_request_profiles':7,
        'CoreFP_request_builder_pointer_references':len(r['mach_request_builder_pointer_references'])})
    (ROOT/'corefp_exports_profile_checks.json').write_text(json.dumps({'scope':__doc__,'verified_counts':counts,'checks':checks,
        'sdk_compile':{'command':command,'exit_code':result.returncode,'source_sha256':sha(src.read_bytes())},
        'native_target_executed':False,'full_goal_complete':False},indent=2)+'\n')
    quality={'scope':'CoreFP version/export records, protected initialization prefix and static import edges only.',
        'verified_counts':counts,
        'QG1':{'status':'pass','evidence':'Descriptive binary/interface analysis.'},
        'QG2':{'status':'pass','evidence':'CF1-CF6 with dependencies, current status and falsification probes.'},
        'QG3':{'status':'pass_for_increment','evidence':'Version/record/caller/initializer/import evidence and five Mach emission sites advanced; full objective active.'},
        'QG4':{'status':'pass','evidence':'u32/u64 widths, modular algebra,12/16/88-byte extents,SDK constants and complexity explicit.'},
        'QG5':{'status':'pass_for_stated_claims','evidence':'Source/private/native,unknown schema,PAC,concurrency and static reachability separated.'},
        'QG6':{'status':'pass','evidence':'79512 original fixups and independent dyld_info fields;all profile instruction hashes;four SMT obligations;complete875-edge encoding scan;seven request cases;compile-only SDK checks.'},
        'QG7':{'status':'pass','evidence':'Impact-labeled import/port,allocation,concurrency and protocol continuations.'},
        'native_target_executed':False,'full_goal_complete':False}
    (ROOT/'corefp_exports_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n')
    print(json.dumps(counts))


if __name__=='__main__':main()
