#!/usr/bin/env python3
"""Independent RPC502 parser source,codec,extent,path and ownership checks.

Read original bytes/fixups;reconstruct owner bytes,initialization and retirement;
check frame producers,readers,compact record oracle,source pathname writes and
local formulas;freshly replay every finite case. O(B+I+V+E+S) time/space for
bounded bytes,instructions,visits,events and snapshots. No native target API.
"""
import ast,base64,hashlib,json,struct,subprocess,zlib
from pathlib import Path
from daemon_receive_tools import IMAGE,SOURCE,ROOT,CS,FIXUPS,TABLE,qword,verify_original_fixups
from daemon_import_bindings import binding
from probe_rpc502_parser_cases import run_case

K=0x8b3dc651;BIAS=0xa30e544d;MASK=0xffffffff

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def unpack(row):return json.loads(zlib.decompress(base64.b64decode(row['payload_zlib_base64'])))
def visits(r):
    raw=zlib.decompress(base64.b64decode(r['original_visits_zlib_base64']));assert len(raw)%8==0;return struct.unpack('<'+'Q'*(len(raw)//8),raw)
def expected_record(raw):
    h=int.from_bytes(raw[:4],'big');t=int.from_bytes(raw[8:12],'big');out=bytearray(56);struct.pack_into('<I',out,0,h^K);out[4:8]=raw[4:8];struct.pack_into('<4I',out,8,t^K,K,K,K);out[24:56]=bytes([0x98])*32
    if t in [1,2]:
        out[24:56]=bytes(v^0x98 for v in raw[24:56])
        if t==2:
            for off in [12,16,20]:struct.pack_into('<I',out,off,int.from_bytes(raw[off:off+4],'big')^K)
    return bytes(out)


def main():
    assertions=0;counts={v:0 for v in ['original_source_visits','source_owner_stores','owner_bytes_checked','owner_snapshots','reader_completions','source_path_store_bytes','source_path_snapshots','source_frame_fields','original_fixup_read_observations','parser_record_oracles','next_file_boundaries','complete_worker_returns','logical_extent_boundaries','allocation_boundaries','fresh_original_calls','fresh_source_visits']}
    def check(value,label):
        nonlocal assertions
        assert value,label
        assertions+=1
    read=lambda n:json.loads((ROOT/n).read_text());p=read('rpc502_parser_profiles.json');c=read('rpc502_parser_contracts.json');bank={};summaries=[];dataset={};sha_source=sha(SOURCE)
    for data,generator in [(p,'probe_rpc502_parser_cases.py'),(c,'recover_rpc502_parser.py')]:
        check(data['generator_sha256']==sha(ROOT/generator),'producer source pin')
        for name,h in data['dependencies'].items():check(sha(ROOT/name)==h,'dependency '+name)
        check(data['source_sha256']==sha_source=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e','original source identity');check(not data['native_target_executed']and not data['full_goal_complete'],'explicit scope')
    for row in p['original_instruction_pool']:
        a=int(row['ea'],16);raw=IMAGE.read(a,4);i=next(CS.disasm(raw,a));check(raw.hex()==row['bytes']and i.mnemonic==row['mnemonic']and i.op_str==row['operands'],'fresh source instruction');bank[a]=raw
    for row in c['original_ranges']:
        a=int(row['start'],16);z=int(row['end'],16);raw=IMAGE.read(a,z-a);check(raw.hex()==row['bytes']and hashlib.sha256(raw).hexdigest()==row['sha256'],'original bounded range')
        check([{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(raw,a)]==row['instructions'],'range disassembly')
    for row in c['original_fixup_records']:
        if 'slot'in row:check(binding(int(row['slot'],16))==row,'independent import/addend/library decode')
        else:check(verify_original_fixups([int(row['address'],16)])['records'][0]==row,'independent format12 pointer decode')
    for row in c['header_guard_target_cells']:
        a=int(row['slot'],16);check(a==TABLE+8*int(row['index'],16)and IMAGE.read(a,8).hex()==row['original_word_hex']and FIXUPS[a]==row['original_fixup']and hex(qword(a))==row['target'],'length-guard original target cell')
    from recover_rpc502_parser_ownership import starts
    ownership=read('rpc502_parser_compiler_ownership.json');funcs,meta=starts();check(ownership['generator_sha256']==sha(ROOT/'recover_rpc502_parser_ownership.py')and ownership['source_sha256']==sha_source,'compiler ownership source pins');check([hex(v)for v in funcs]==ownership['all_compiler_starts']and meta==ownership['LC_FUNCTION_STARTS'],'fresh original compiler metadata')
    for row in ownership['selected_compiler_ranges']:
        a=int(row['start'],16);z=int(row['end'],16);i=funcs.index(a);check(funcs[i+1]==z and sha_source==ownership['source_sha256']and hashlib.sha256(IMAGE.read(a,z-a)).hexdigest()==row['sha256'],'whole metadata-delimited compiler range')
    for row in ownership['source_range_ownership']:
        cursor=int(row['source_start'],16)
        for part in row['compiler_segments']:
            a=int(part['start'],16);z=int(part['end'],16);start=int(part['compiler_range_start'],16);i=funcs.index(start);check(a==cursor and start<=a<z<=funcs[i+1],'complete compiler ownership partition');cursor=z
        check(cursor==int(row['source_end'],16),'full bounded source range partition')
    for row in c['byte_codec_exhaustive_256']:check(row['source_u8']==row['xor_u8']==row['input_u8']^0x98,'complete u8 codec domain')
    for wrapper in p['cases']:
        case=wrapper['case'];label=case['label'];r=unpack(wrapper);dataset[label]=r;raw=bytes.fromhex(case['file_hex']);n=len(raw);seq=visits(r);seqset=set(seq);digest=hashlib.sha256();check(len(seq)==r['original_visit_count']==wrapper['original_visit_count'],'source visit count')
        for a in seq:check(a in bank,'original instruction visit');digest.update(struct.pack('<Q',a));digest.update(bank[a])
        check(digest.hexdigest()==r['original_ordered_bytes_sha256']==wrapper['original_ordered_bytes_sha256'],'ordered original byte digest');counts['original_source_visits']+=len(seq)
        check(r['declared_file_bytes_hex']==case['file_hex']and r['fixture']==case['fixture'],'exact declared input');check(r['source_sha256']==sha_source and not r['native_target_executed']and not r['target_host_ipc_files_or_system_calls_executed']and not r['idb_mutated'],'model/native/IDB boundaries')
        check(r['scope']==ast.get_docstring(ast.parse((ROOT/'probe_rpc502_parser.py').read_text()),clean=False),'engine scope source pin')
        owners={};mapping_retired=False;copy_ptr=None;seen_stores=[]
        for e in r['records']:
            kind=e['kind'];name=e.get('name','')
            if kind=='import'and name=='libSystem/_malloc_type_malloc':
                a=int(e['private_address'],16);size=e['size_bytes'];check(0<size<=0x40000 and a not in owners,'typed owner bounds');owners[a]={'bytes':bytearray(b'\xa5'*size),'known':bytearray(size),'retired':False}
            if kind=='private_malloc_result_model'and int(e['return_bits'],16):
                a=int(e['return_bits'],16);size=e['requested_extent_bytes'];check(size==n and a not in owners,'exact copy allocation extent');copy_ptr=a;owners[a]={'bytes':bytearray(size),'known':bytearray(size),'retired':False}
            if kind=='explicit_parser_API_model'and name=='libSystem/_malloc':
                value=e['result']
                if value.startswith('0x')and int(value,16):a=int(value,16);size=e['requested_size_bytes'];check(size==56 and a not in owners,'source record allocation56');owners[a]={'bytes':bytearray(b'\xa5'*size),'known':bytearray(size),'retired':False}
            if kind=='source_owner_store':
                s=e['store'];a=int(s['owner'],16);off=s['offset_bytes'];value=bytes.fromhex(s['actual_after_hex']);check(a in owners and not owners[a]['retired']and 0<=off and off+len(value)<=len(owners[a]['bytes'])and len(value)==s['size_bytes']and int(s['pc'],16)in seqset,'source store provenance/live extent');owners[a]['bytes'][off:off+len(value)]=value;owners[a]['known'][off:off+len(value)]=bytes([1])*len(value);seen_stores.append(s);counts['source_owner_stores']+=1
            if kind=='explicit_parser_API_model'and name=='libSystem/_free':
                a=int(e['retired_pointer'],16)
                if a:check(a in owners and not owners[a]['retired']and owners[a]['bytes'].hex()==e['retired_bytes_hex'],'free exact live owner bytes');owners[a]['retired']=True
            if kind=='explicit_parser_API_model'and name=='libSystem/_munmap':mapping_retired=e['result_signed32']==0;check(e['logical_mapping_retired']==mapping_retired,'declared unmap result distinction')
        check(seen_stores==r['owner_stores'],'complete chronological source owner store journal');check(len(owners)==len(r['owner_snapshots']),'complete owner inventory')
        for item in r['owner_snapshots']:
            a=int(item['address'],16);o=owners[a];check(o['bytes'].hex()==item['bytes_hex']and o['known'].hex()==item['initialized_mask_hex']and o['retired']==item['retired']and len(o['bytes'])==item['size_bytes'],'independent owner bytes/initialized/lifetime');counts['owner_snapshots']+=1;counts['owner_bytes_checked']+=len(o['bytes'])
        check(copy_ptr is not None and owners[copy_ptr]['bytes']==raw and all(owners[copy_ptr]['known']),'exact original file copy')
        mapped=[e for e in r['file_read_events']if e['kind']=='mapping'];check([e['offset_bytes']for e in mapped]==list(reversed(range(n)))and all(e['size_bytes']==1 and bytes.fromhex(e['bytes_hex'])==raw[e['offset_bytes']:e['offset_bytes']+1]for e in mapped),'independent complete descending source read/copy')
        for e in r['file_read_events']:
            if e['kind']=='allocation':check(0<=e['offset_bytes']and e['offset_bytes']+e['size_bytes']<=n and raw[e['offset_bytes']:e['offset_bytes']+e['size_bytes']].hex()==e['bytes_hex'],'parser read within declared bytes')
        reader=None
        for point in r['parser_points']:
            pc=int(point['pc'],16);regs=[int(v,16)for v in point['registers_x0_x28']];frame=bytes.fromhex(point['frame_0x900_hex']);check(pc in seqset and len(frame)==0x900,'original checkpoint source')
            if pc==0x1009b7728:check((regs[23]&MASK)==0x928 and struct.unpack_from('<I',frame,0x234)[0]==n^K,'source length preparation inputs')
            if pc==0x1009b6eac:reader=regs[8]+((regs[9]+0xfe53bc45)&MASK)-copy_ptr
            if pc==0x1009b6f64:
                check(reader is not None and 0<=reader and reader+4<=n,'complete BE32 reader extent');word=int.from_bytes(raw[reader:reader+4],'big');check((regs[20]&MASK)==word^K and (regs[9]&MASK)==word^(K^0xec3e0ab8),'independent source BE32 output/intermediate');counts['reader_completions']+=1
            if pc==0x100a50508:check(struct.unpack_from('<I',frame,0x1d8)[0]==(n+BIAS)&MASK,'source additive size word')
            if pc==0x100972888:check(struct.unpack_from('<I',frame,0x1d0)[0]==(n-57)&MASK,'source minimum-size word')
            if pc==0x1009bb5c4:check((regs[9]+0x4da1)&31==1,'source variable shift is1 in retained byte-copy entry')
        for field in r['source_frame_field_stores']:
            check(int(field['pc'],16)in seqset and len(bytes.fromhex(field['actual_after_hex']))==field['size_bytes'],'source frame-field store provenance');counts['source_frame_fields']+=1
        for e in r['original_fixup_reads']:
            a=int(e['address'],16);check(int(e['pc'],16)in seqset and IMAGE.read(a,8).hex()==e['original_word_hex']and FIXUPS[a]==e['original_fixup'],'fresh recorded original pointer member');counts['original_fixup_read_observations']+=1
        for observation in r['source_open_observations']:
            a=int(observation['path_pointer'],16);length=len(bytes.fromhex(observation['path_hex']))+1;mem={}
            for store in r['source_path_stores']:
                if store['step_index']>observation['observed_at_step']:continue
                at=int(store['address'],16);value=bytes.fromhex(store['actual_after_hex']);check(int(store['pc'],16)in seqset and len(value)==store['size_bytes'],'source path store provenance');mem.update({at+i:v for i,v in enumerate(value)});counts['source_path_store_bytes']+=len(value)
            check(bytes(mem[a+i]for i in range(length))==bytes.fromhex(observation['path_hex'])+b'\0','independent source-built pathname including NUL');check(observation['site']=='0x100d94494'and observation['flags_u32']==0,'exact source open emission/flags');counts['source_path_snapshots']+=1
        extras=[v for v in r['owner_snapshots']if v.get('allocation_pc')=='0x100913590'];h=int.from_bytes(raw[:4],'big')if n>=4 else None;t=int.from_bytes(raw[8:12],'big')if n>=12 else None
        if extras:
            check(len(extras)==1 and n>=57 and h in [1,3,5]and bytes.fromhex(extras[0]['bytes_hex'])==expected_record(raw),'compact independent56-byte record oracle');counts['parser_record_oracles']+=1
        stop=r['stop_reason'];check(stop in ['returned_to_fixture','next_file_open_epoch','private_copy_allocation_extent_read','new_malloc_boundary'],'declared terminal boundary '+label)
        if stop=='next_file_open_epoch':
            counts['next_file_boundaries']+=1;check(h in [1,3,5]and t in [1,2]and n>=57 and len(r['source_open_observations'])==2,'inner discriminator/supplemental transition');first,second=r['source_open_observations'];a=bytes.fromhex(first['path_hex']);b=bytes.fromhex(second['path_hex']);check(a.endswith(b'.sinf')and b==a[:-5]+b'.v5.supf','exact original next-sidecar filename relation');check(not owners[copy_ptr]['retired']and not any(e['name']=='libSystem/_munmap'for e in r['explicit_parser_models'])and extras[0]['retired'],'record retirement precedes next open while copy/mapping cleanup is undeclared')
        elif stop=='returned_to_fixture':counts['complete_worker_returns']+=1;check(owners[copy_ptr]['retired']and any(e['name']=='libSystem/_munmap'for e in r['explicit_parser_models'])and any(e['name']=='libSystem/_close'for e in r['explicit_parser_models']),'rejection copy/map/FD cleanup requests')
        elif stop=='private_copy_allocation_extent_read':counts['logical_extent_boundaries']+=1;last=r['records'][-1];check(n<=4 and int(last['address'],16)==copy_ptr+n and last['size_bytes']==1,'exact first logical over-extent read')
        else:counts['allocation_boundaries']+=1;check(case['fixture'].get('extra_malloc_stop'),'intentional constructor allocation boundary')
        summaries.append({'case':label,'length_bytes':n,'header_u32':h,'selector_u32':t,'stop_reason':stop,'raw_worker_result':r['records'][-1].get('result'),'record56_hex':extras[0]['bytes_hex']if extras else None,'open_path_hex':[e['path_hex']for e in r['source_open_observations']],'mapping_retired_in_model':mapping_retired,'copy_retired_in_model':owners[copy_ptr]['retired'],'original_source_visits':len(seq)})
    for proof in c['proofs']:
        path=ROOT/proof['path'];check(sha(path)==proof['sha256'],'local solver source pin');run=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);check(run.stdout.strip()=='unsat'and not run.stderr,'fresh local formula '+proof['path'])
    abi=c['sdk_compile'];check(sha(ROOT/'rpc502_parser_layouts.c')==abi['source_sha256']and sha(ROOT/'rpc502_parser_layouts.s')==abi['assembly_sha256'],'SDK/source-shape pins');cmd=list(abi['command']);cmd[cmd.index('-o')+1]='/tmp/rpc502-parser-verify.s';run=subprocess.run(cmd,capture_output=True,text=True);check(run.returncode==0 and not run.stderr and sha(Path('/tmp/rpc502-parser-verify.s'))==abi['assembly_sha256'],'fresh compile-only ABI')
    data={v['case']:v for v in summaries}
    for n in [1,2,3,4]:check(data['extent_'+str(n)]['stop_reason']=='private_copy_allocation_extent_read','early logical-extent witness')
    for n in [5,7,8,9,11,12,16,40,55,56]:check(data['extent_'+str(n)]['raw_worker_result']=='0xffff5bd9','minimum-size rejection result')
    for n in [57,58,63,64]:check(data['extent_'+str(n)]['stop_reason']=='next_file_open_epoch','minimum-size acceptance control')
    check(data['allocation_NULL']['raw_worker_result']=='0xffff5bd4'and data['allocation_NULL']['record56_hex']is None,'constructor NULL follows original cleanup')
    check(data['unmap_error']['raw_worker_result']==data['close_error']['raw_worker_result']=='0xffff5bde','declared cleanup status does not change retained worker rejection')
    check(not data['unmap_error']['mapping_retired_in_model']and data['close_error']['mapping_retired_in_model'],'unmap failure distinct from declared successful unmap')
    for row in p['cases']:
        label=row['case']['label'];print('fresh '+label,flush=True);r,actualbank=run_case(row['case']);old=dataset[label];check(r==old,'complete fresh original worker sequence '+label);counts['fresh_original_calls']+=1;counts['fresh_source_visits']+=len(visits(r))
        for a,item in actualbank.items():check(item['bytes']==bank[a].hex(),'fresh replay original instruction pool')
    for row in read('interface_manifest.json')['inputs_preserved']:
        path=ROOT.parent/row['path'];check(path.stat().st_size==row['size_bytes']and sha(path)==row['sha256'],'original supplied input preserved')
    identity=read('rpc502_parser_ida_context.json');check(identity['live_IDB_bytes_verified']is False and identity['IDB_mutated']is False,'IDA unavailable distinct from current byte readback')
    totals={**counts,'parser_sequences':len(p['cases']),'original_instruction_records':len(bank),'original_source_ranges':len(c['original_ranges']),'metadata_compiler_ranges':len(ownership['selected_compiler_ranges']),'original_fixup_records':len(c['original_fixup_records']),'parser_API_sites':len(c['observed_parser_API_sites']),'proofs_unsat':len(c['proofs']),'codec_byte_inputs':len(c['byte_codec_exhaustive_256']),'assertions':assertions};out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in ['rpc502_parser_profiles.json','rpc502_parser_contracts.json','rpc502_parser_compiler_ownership.json','recover_rpc502_parser_ownership.py','probe_rpc502_parser.py','probe_rpc502_parser_cases.py','rpc502_parser_ida_context.json','rpc502_parser_source_identity.json']},'verified_counts':totals,'independent_summaries':summaries,'all_checks_pass':True,'native_target_executed':False,'native_defect_established':False,'native_file_acceptance_established':False,'live_IDB_bytes_verified':False,'full_goal_complete':False};(ROOT/'rpc502_parser_checks.json').write_text(json.dumps(out,indent=2)+'\n');quality={k:v for k,v in out.items()if k!='independent_summaries'}
    texts=['Descriptive source/interface analysis.','Report R1-R12 state source,environment,byte/owner,guard,scheduler/cleanup and native assumptions with falsification probes.','Original RPC502 parser/record/cleanup/supplemental-open transition covered for finite cases;full daemon/kext/deeper goal remains active.','u8/u32/BE/LE widths,56-byte record,57-byte size predicate,logical extents and bounded algorithms are explicit.','Record rejection/local supplemental continuation,logical/API/native extents,unmap failure and absent live IDA readback remain separated.','Fresh original instructions/ranges/imports,pointer decodes,owner/initialized/lifetime/path/frame/codec oracles,all case replays,SDK compile and seven local formulas.','Impact-labeled supplemental-file parsing,legacy branches,large-size views,original producer/native context and final ownership/IPC continuation.']
    for i,t in enumerate(texts,1):quality['QG'+str(i)]={'status':'pass_for_stated_increment','evidence':t}
    (ROOT/'rpc502_parser_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps(totals),flush=True)

if __name__=='__main__':main()
