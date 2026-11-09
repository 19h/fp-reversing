#!/usr/bin/env python3
"""Original AMS pointer/bank/record/CoreFP-file and private-profile readback.

No native target/loader/framework/IPC runs. Original bytes, two SMT queries,
offline certificate parsing and arm64e syntax/layout compile only. Scope is
the protected-core/dynamic ABI increment; the full investigation stays active.
"""
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
from ams_core_reader import Core,ROOT,sha
from bootpolicy_cache_reader import Dylib
from corefp_library_reader import Library,SHA as LIB_SHA,THIN_SHA as LIB_THIN_SHA,SOURCE as LIB_SOURCE


def read(name):return json.loads((ROOT/name).read_text())


def main():
    for name in ['ams_core_reader.py','corefp_library_reader.py','recover_ams_core.py']:
        subprocess.run([sys.executable,str(ROOT/name)],check=True,stdout=subprocess.DEVNULL)
    c=Core();cache=c.cache;inv=read('ams_core_pointer_inventory.json');r=read('ams_core_contracts.json');p=read('ams_core_profiles.json');li=read('corefp_library_inventory.json');library=Library();checks=[]
    def check(ok,label):
        assert ok,label
        checks.append(label)
    check(cache.uuid==r['cache_uuid']==p['cache_uuid']==inv['cache_uuid'] and c.ams.uuid==r['ams_uuid']==inv['ams_uuid'],'original reference cache/AMS identities')
    check(sha(LIB_SOURCE.read_bytes())==LIB_SHA==li['source_sha256'] and sha(library.data)==LIB_THIN_SHA==li['thin_sha256'],'original CoreFP universal and selected slice hashes')
    check(library.meta['uuid']==li['uuid']=='9061ddc3-93b4-3824-914f-9cc97d708d58' and library.base==0,'CoreFP selected UUID and preferred base')
    check(library.exports==li['exports'] and len(library.exports)==8 and len(library.starts)==1602,'original CoreFP complete export trie and function starts')
    for f in li['export_original_functions']:
        at=int(f['start'],16);raw=bytes.fromhex(f['bytes']);check(library.exports[f['export']]['address']==at and library.read(at,len(raw))==raw and sha(raw)==f['sha256'],f'original CoreFP export range {f["export"]}')
    members=inv['original_pointer_members'];check(len(members)==29034,'29034 selected original pointer members')
    rawpages={}
    for row in members:
        at=int(row['address'],16);page=at&~4095
        if page not in rawpages:rawpages[page]=cache.read(page,4096)
        word=struct.unpack_from('<Q',rawpages[page],at-page)[0];auth=bool(word>>63);target=int(row['value_add'],16)+(word&0x3ffffffff)
        if not auth:target|=((word>>34)&255)<<56
        check(word==int(row['raw_word'],16) and auth==row['authenticated'] and target==int(row['target'],16),f'original pointer word/target {row["address"]}')
    selected=r['pointers']+members[::max(1,len(members)//12)]
    for row in selected:check(cache.pointer(int(row['address'],16))==row,f'independent frozen-reader chain member {row["address"]}')
    check(len(inv['external_executable_targets'])==85 and len(inv['external_pointer_occurrences'])==713,'external mapped target and occurrence counts')
    libs={c.ams.path:c.ams}
    for row in inv['external_executable_targets']:
        path=row['library']
        if path not in libs:libs[path]=Dylib(cache,path)
        lib=libs[path];at=int(row['address'],16)
        check(lib.uuid==row['library_uuid'] and sorted(n for n,x in lib.exports.items() if x['address']==at)==sorted(row['exact_exports']) and bool(row['exact_exports']),f'exact external exported value {row["address"]}')
        check((at in lib.functions)==row['compiler_function_start'],f'external compiler-entry classification {row["address"]}')
    check(sum(x['compiler_function_start'] for x in inv['external_executable_targets'])==83,'83 external compiler function starts; stub/data kept distinct')
    for row in r['ranges']+[r['loader_original_function']]:
        at=int(row['start'],16);raw=bytes.fromhex(row['bytes']);check(cache.read(at,len(raw))==raw and c.ams.function(at)['end']==row['end'],f'original static AMS range {row["start"]}')
    for b in r['banks']:
        aa=cache.read(int(b['first_address'],16),256);bb=cache.read(int(b['second_address'],16),256)
        values=[i^bb[aa[i]^b['key_u8']] for i in range(256)]
        check(aa.hex()==b['first_bytes'] and bb.hex()==b['second_bytes'] and values==b['results_256'] and set(values)=={b['constant_u8']},f'exhaustive original bank {b["label"]}')
    check(len(r['banks'])==8 and len(r['proofs'])==2,'eight banks and two proofs')
    for proof in r['proofs']:
        path=ROOT/proof['path'];run=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True)
        check(sha(path.read_bytes())==proof['sha256'] and run.stdout.strip()=='unsat' and not run.stderr,f'full-width SMT {path.name}')
    free=r['free_binding'];malloc=libs.get(free['library']) or Dylib(cache,free['library'])
    check(malloc.uuid==free['uuid'] and malloc.exports[free['exact_export']]['address']==int(free['target'],16)==0x181e7a6f0,'disposal resolves exact malloc free')
    check(r['external_inventory_sha256']==sha((ROOT/'ams_core_pointer_inventory.json').read_bytes()) and r['CoreFP_library_inventory_sha256']==sha((ROOT/'corefp_library_inventory.json').read_bytes()),'static inventory dependencies pinned')
    check(p['generator_sha256']==sha((ROOT/'probe_ams_core.py').read_bytes()) and p['reader_sha256']==sha((ROOT/'ams_core_reader.py').read_bytes()) and p['source_contracts_sha256']==sha((ROOT/'ams_core_contracts.json').read_bytes()) and p['CoreFP_library_inventory_sha256']==sha((ROOT/'corefp_library_inventory.json').read_bytes()),'private model and source dependencies pinned')
    functions={x['start']:x for x in p['original_functions']};pages={x['address']:x for x in p['mapped_original_pages']}
    check(len(functions)==29 and len(pages)==63,'deduplicated 29 original functions and63 original pages')
    for row in functions.values():
        at=int(row['start'],16);raw=bytes.fromhex(row['bytes']);check(cache.read(at,len(raw))==raw and c.ams.function(at)['end']==row['end'],f'private original function pool {row["start"]}')
    for row in pages.values():
        at=int(row['address'],16);raw=cache.read(at,4096);rebased=bytearray(raw)
        check(sha(raw)==row['original_sha256'],f'original mapped page {row["address"]}')
        for ptr in row['relocations']:
            pa=int(ptr['address'],16);check(c.page_chains(pa).get(pa)==ptr,f'private page chain provenance {ptr["address"]}')
            struct.pack_into('<Q',rebased,pa-at,int(ptr['target'],16))
        check(sha(rebased)==row['materialized_sha256'],f'exact private pointer materialization {row["address"]}')
    profiles=p['profiles'];by={x['fixture']['label']:x for x in profiles}
    check(len(profiles)==29 and Counter(x['stop_reason'] for x in profiles)=={'returned_to_private_fixture':14,'external_API_boundary':11,'CoreFP_export_call_boundary':4},'29 private outcomes with no unexplained exception')
    for row in profiles:
        label=row['fixture']['label'];check(all(x in functions for x in row['original_function_starts']) and all(x in pages for x in row['mapped_original_page_addresses']),f'private source-pool references {label}')
        h=hashlib.sha256()
        for pc in row['visited_original_instructions']:
            pc=int(pc,16);h.update(struct.pack('<Q',pc));h.update(cache.read(pc,4))
        check(h.hexdigest()==row['original_instruction_bytes_sha256'],f'visited original instruction readback {label}')
        for stub in row['original_shared_stubs']:
            check(cache.read(int(stub['address'],16),16).hex()==stub['bytes'] and cache.pointer(int(stub['pointer']['address'],16))==stub['pointer'],f'original shared-cache stub {label}:{stub["address"]}')
    for row in profiles[:6]:
        f=row['fixture'];first,second=f['dispose_state'];sp=0x76000000+0x18000+f.get('stack_delta',0)-0x20
        value=(((second-first+sp+8)&((1<<64)-1))^0xa0fb9d7d32f316e4)*0x74b92847&((1<<64)-1)
        check(row['state_after']==[struct.pack('<Q',value).hex()]*2,f'original two-cell disposal side effect {f["label"]}')
        check(row['result_u32']==(0xffff5bd9 if f['null'] else 0) and row['private_object_freed']==(not f['null']),f'exact disposal return/free partition {f["label"]}')
    for row in profiles:
        f=row['fixture']
        if f['mode']=='create_wrapper':
            event=next(e for e in row['records'] if e['kind']=='modeled_create_backend')
            check(event['operation_u32']==0xc4b and row['result_u32']==f['backend_status_u32'],f'48-byte operation/status round trip {f["label"]}')
        for e in row['records']:
            if e['kind']=='original_decoded_create_operation':check(e['operation_u32']==0xc4b,f'original backend operation decode {f["label"]}')
    check(by['create_private_malloc_null']['result_u32']==0xffff5bd4,'original NULL200-byte allocation status')
    check(by['create_CoreFP_load_failure']['result_u32']==by['create_CoreFP_symbol_absent']['result_u32']==0xffff5a5c,'original load/symbol-null status')
    check(by['create_initial_CoreFP_return_error']['result_u32']==1,'original propagation of modeled first-export status1')
    names=r['dynamic_loader']['requested_names']
    for label in ('create_CoreFP_export_call','import_CoreFP_export_call'):
        row=by[label];lookups=[e['name'] for e in row['records'] if e['kind']=='modeled_dlsym']
        check(lookups==names and all('_'+name in library.exports for name in lookups),f'five exact CoreFP lookups {label}')
        event=row['records'][-1];check(event['kind']=='CoreFP_export_call_boundary' and event['export']=='lxpgvVMLd0S7uRl' and event['callsite']=='0x19c20e2f0',f'first CoreFP export call {label}')
    for label in ('create_initial_CoreFP_return_zero','import_initial_CoreFP_return_zero'):
        event=by[label]['records'][-1]
        check(event['kind']=='CoreFP_export_call_boundary' and event['export']=='WIn9UJ86JKdV4dM' and event['callsite']=='0x19c20e690' and event['live_registers_x0_x8'][0]=='0x7' and event['live_registers_x0_x8'][3:5]==['0x19cb1a483','0x37b'],f'conditional certificate-bearing public call {label}')
    cert=r['certificate'];raw=(ROOT/cert['path']).read_bytes();cm=read(cert['metadata_path'])
    check(cache.read(int(cert['source_address'],16),cert['size_bytes'])==raw and len(raw)==891 and sha(raw)==cert['sha256']==cm['sha256'] and int.from_bytes(raw[2:4],'big')+4==891,'exact original DER extent/hash and caller length')
    parsed=subprocess.run(cm['parser_command'],capture_output=True,text=True,check=True);check(parsed.stdout==cm['parser_output'] and not parsed.stderr and not cm['certificate_authentication_executed'],'reproducible offline certificate parse, no authentication')
    sdk=Path('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk');src=ROOT/'ams_core_layouts.c'
    cmd=['/usr/bin/clang','-target','arm64e-apple-macos','-isysroot',str(sdk),'-fsyntax-only','-Wall','-Wextra','-Werror',str(src)]
    run=subprocess.run(cmd,capture_output=True,text=True);check(run.returncode==0 and not run.stderr,'arm64e48-byte frame,200-byte rwlock and RTLD flags compile')
    counts={'original_pointer_members':29034,'external_targets_exact_bound':85,'external_pointer_occurrences':713,'compiler_function_targets':83,
        'original_static_core_ranges':5,'private_original_function_pool':29,'private_original_page_pool':63,'banks_256':8,'smt_unsat':2,
        'selected_pointer_chains':18,'private_profiles':29,'private_normal_returns':14,'private_API_boundaries':11,'private_CoreFP_boundaries':4,
        'CoreFP_exports':8,'CoreFP_functions':1602,'observed_symbol_lookups':5,'certificate_bytes':891,'sdk_compile_exit':run.returncode,'assertions':len(checks)}
    (ROOT/'ams_core_profile_checks.json').write_text(json.dumps({'scope':__doc__,'verified_counts':counts,'checks':checks,
        'sdk_compile':{'command':cmd,'exit_code':run.returncode,'source_sha256':sha(src.read_bytes())},
        'sdk_headers':[{'path':str(sdk/x),'sha256':sha((sdk/x).read_bytes())} for x in ['usr/include/dlfcn.h','usr/include/pthread.h']],
        'native_target_executed':False,'full_goal_complete':False},indent=2)+'\n')
    quality={'scope':'Protected AMS disposal/creation/shared initialization and dynamic CoreFP ABI increment only.','verified_counts':counts,
        'QG1':{'status':'pass','evidence':'Descriptive technical scope.'},
        'QG2':{'status':'pass','evidence':'AC1-AC6 with dependencies,probes and current boundaries.'},
        'QG3':{'status':'pass_for_increment','evidence':'Concrete protected-core and library ABI progress; full objective active.'},
        'QG4':{'status':'pass','evidence':'u32/u64 modular arithmetic,48/200-byte layouts,flags5,891-byte DER and bounded algorithms.'},
        'QG5':{'status':'pass_for_stated_claims','evidence':'Pointer/data/code,mutable side effects,private failures,export model outputs and native postconditions separated.'},
        'QG6':{'status':'pass','evidence':'Original cache/file/chain/export/range/page readbacks,eight banks,two SMT proofs,29 private profiles and offline parse.'},
        'QG7':{'status':'pass','evidence':'Impact-labeled CoreFP/IOKit/IPC,certificate,ownership and initialization continuation.'},
        'native_target_executed':False,'full_goal_complete':False}
    (ROOT/'ams_core_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n')
    subprocess.run([sys.executable,str(ROOT/'validate_rpc502_sidecar_delivery.py')],check=True)
    print(json.dumps(counts))


if __name__=='__main__':main()
