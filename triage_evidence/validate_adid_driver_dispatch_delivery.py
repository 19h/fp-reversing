#!/usr/bin/env python3
"""Fresh source/frame/bank/proof/ABI readbacks and bounded local replays.

O(B+F+R+V) time/space for bytes,fixups,records and instruction visits. Explicit
finite hook caps; no native target,endpoint,file,environment or synchronization.
"""
import base64
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import zlib
from adid_reader import Adid,ROOT,CS,sha,THIN_SHA,SOURCE,FIXUPS
from probe_adid_driver_dispatch import Dispatch,SITES
from probe_adid_startup import unpack_records
from resolve_kernel_collection_interfaces import CACHE,commands,string


def read(name):return json.loads((ROOT/name).read_text())
def normalized(value):return json.loads(json.dumps(value))


def main():
    assertions=[]
    def check(condition,label):
        assert condition,label
        assertions.append(label)
    s=Adid();p=read('adid_driver_dispatch_profiles.json');c=read('adid_driver_dispatch_contracts.json');ck=read('adid_driver_dispatch_frame.json');rows={r['fixture']['label']:r for r in p['profiles']};events={label:unpack_records(row) for label,row in rows.items()}
    check(p['thin_sha256']==c['thin_sha256']==THIN_SHA,'fresh original provider identity')
    check(p['generator_sha256']==sha((ROOT/'probe_adid_driver_dispatch.py').read_bytes()) and c['generator_sha256']==sha((ROOT/'recover_adid_driver_dispatch.py').read_bytes()),'producer/recoverer source pins')
    for source in (p,c):
        for name,digest in source['dependencies'].items():check(sha((ROOT/name).read_bytes())==digest,'dependency '+name)
    run=subprocess.run(['/usr/bin/dyld_info','-arch','arm64e','-fixups',str(SOURCE)],capture_output=True,check=True);check(run.stdout==FIXUPS.read_bytes(),'independent original fixup display')
    instructions={}
    for i in p['original_instruction_records']:
        pc=int(i['ea'],16);raw=s.read(pc,4);d=next(CS.disasm(raw,pc));instructions[pc]=raw
        check(raw.hex()==i['bytes'] and d.mnemonic==i['mnemonic'] and d.op_str==i['operands'],'fresh original instruction '+i['ea'])
    for f in p['original_functions']:
        a,z=int(f['start'],16),int(f['end'],16);check(s.bounds(a)==(a,z) and sha(s.read(a,z-a))==f['sha256'],'complete compiler range '+f['start'])
    for w in c['original_windows']:
        a,z=int(w['start'],16),int(w['end'],16);raw=s.read(a,z-a);decoded=[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(raw,a)]
        check(raw.hex()==w['bytes'] and sha(raw)==w['sha256'] and decoded==w['instructions'],'original producer/constructor/consumer window '+w['start'])
    frame=events['original_request_frame'][-1];sp=int(frame['registers']['sp'],16);fp=int(frame['registers']['x29'],16);table=0x1002c40c0
    check(sp&15==0 and fp-sp==0x9ff0 and fp-0xa8==0x7a037b58,'observed original frame layout/alignment')
    check(int(frame['registers']['x27'],16)==int(frame['registers']['x24'],16)==table and int(frame['stack_slots']['0x1658'],16)==table,'original table frame bindings')
    prior=next(r for r in read('adid_context_profiles.json')['profiles'] if r['fixture']['label']=='context_error_producer')
    prefix=zlib.decompress(base64.b64decode(rows['original_request_frame']['visited_original_instructions_zlib_base64']));original=zlib.decompress(base64.b64decode(prior['visited_original_instructions_zlib_base64']))
    check(original.startswith(prefix),'original callback frame matches frozen request source prefix')
    writer_events=[e for e in events['original_frame_slot_writers'] if e['kind']=='original_frame_slot_store'];check(len(writer_events)==3,'three original output-pointer slot producers')
    offset_info={0x148:(0x1001664f8,0x2ede),0x150:(0x100166538,0x28e3),0x158:(0x100166528,0x16db)}
    for offset,(site,destination_offset) in offset_info.items():
        address=sp+offset;actual=int(frame['stack_slots'][hex(offset)],16);expected=(sp+destination_offset+0x7e1f59740c8f6451)&((1<<64)-1)
        e=next(e for e in writer_events if int(e['address'],16)==address);check(int(e['pc'],16)==site and e['size_bytes']==8 and int(e['value'],16)==actual==expected,'source-produced encoded output slot '+hex(offset))
    for bank,binding in zip(c['banks'],c['local_bindings']):
        aa=s.read(int(bank['first_address'],16),256);bb=s.read(int(bank['second_address'],16),256)
        check(aa.hex()==bank['first_bytes'] and bb.hex()==bank['second_bytes'],'fresh byte tables '+bank['label'])
        for n in range(256):check(n^bb[aa[n]^bank['key_u8']]==bank['results_256'][n]==bank['constant_u8'],'full byte-domain lookup '+bank['label']+' '+str(n))
        index=binding['base_index_u32']+bank['constant_u8'];ptr=binding['source_pointer'];check(index==binding['index_u32'] and table+index*8==int(ptr['address'],16) and s.decoded[int(ptr['address'],16)]==ptr,'original selected target '+binding['label'])
        a,z=int(binding['window_start'],16),int(binding['window_end'],16);raw=s.read(a,z-a);check(raw.hex()==binding['window_bytes'] and sha(raw)==binding['window_sha256'],'lookup instruction prefix '+binding['label'])
        check(int(frame['stack_slots'][hex(binding['first_frame_slot_offset'])],16)==int(bank['first_address'],16),'first table source frame '+binding['label'])
        second=binding['second_frame_slot_offset']
        if second is not None:check(int(frame['stack_slots'][hex(second)],16)==int(bank['second_address'],16),'second table source frame '+binding['label'])
        else:check(binding['second_register_assumption']['writer_or_reaching_binding_proven'] is False and int(frame['registers']['x15'],16)!=int(bank['second_address'],16),'extra X15 binding remains conditional,not current-frame fact')
    for proof in c['proofs']:
        path=ROOT/proof['path'];check(sha(path.read_bytes())==proof['sha256'],'proof pin '+proof['path']);run=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);check(run.stdout.strip()=='unsat' and not run.stderr,'fresh full-domain local proof '+proof['path'])
    total=0;upstream=0;comparisons=0;two_stage=0
    def kinds(label,kind):return [e for e in events[label] if e['kind']==kind]
    for label,row in rows.items():
        packed=zlib.decompress(base64.b64decode(row['visited_original_instructions_zlib_base64']));h=hashlib.sha256();check(len(packed)==row['visited_original_instruction_count']*8,'visit extent '+label)
        for (pc,) in struct.iter_unpack('<Q',packed):h.update(struct.pack('<Q',pc));h.update(instructions[pc])
        check(h.hexdigest()==row['ordered_original_instruction_sha256'],'complete ordered original source '+label);total+=len(packed)//8;check(row['steps']<=row['fixture']['instruction_budget']+1,'finite source-hook cap '+label)
        if 'fragment_entry' not in row['fixture']:
            check(not kinds(label,'analyst_fragment_entry') and not kinds(label,'analyst_fragment_jump'),'original frame has no fragment overrides '+label);continue
        f=row['fixture'];site=next(x for x in SITES if x['label']==f['site_label']);entry=kinds(label,'analyst_fragment_entry');jump=kinds(label,'analyst_fragment_jump')
        check(len(entry)==len(jump)==1 and entry[0]['whole_request_or_native_reachability_established'] is False and jump[0]['intervening_predecessors_validated'] is False,'all local control overrides explicit '+label)
        check(int(entry[0]['entry'],16)==site['prefix'] and int(jump[0]['to'],16)==site['entry'] and f['state_register']==site['state_register'] and f['state_value']==site['state_value'],'declared source prefix/state '+label)
        call=kinds(label,'original_upstream_caller_record');check(len(call)==1,'one original upstream caller edge '+label);upstream+=1;call=call[0];raw=bytes.fromhex(call['bytes16']);ptr=struct.unpack_from('<Q',raw)[0];key=(((fp-0xa8)^0x834674ac)*0x0a42990d)&0xffffffff
        check(call['address']==hex(fp-0xa8) and int(call['source_return'],16)=={'query_A':0x1001f4d8c,'query_B':0x1001f55dc,'query_C':0x1001f5994}[site['label']] and struct.unpack_from('<I',raw,8)[0]^key==0x237f,'original caller-built record codec and return '+label)
        check(ptr==int(frame['stack_slots'][hex(site['output_stack_offset'])],16),'original frame output-pointer field reused '+label)
        reads=[e for e in kinds(label,'original_selected_pointer_read') if e['address']=='0x1002d86c8'];check(len(reads)==1 and reads[0]['decoded_private_value_u64']=='0x1000590ac' and s.decoded[0x1002d86c8]==reads[0]['source_pointer'],'selected original caller pointer cell '+label)
        compare=kinds(label,'original_output_byte_comparison');check(len(compare)==1,'one immediate output comparison '+label);comparisons+=1;compare=compare[0];last=events[label][-1];returned=last['returned_caller_record'];status=struct.unpack_from('<I',bytes.fromhex(returned['bytes16']),12)[0]
        expected_status=0x587c93 if label.endswith('_primary_error') else 0x587c85 if label.endswith('_primary_identity') else 0x59248f;expected_byte=32 if label.endswith('_post_context_control') else 31
        check(status==expected_status and returned['output_byte_u8']==compare['loaded_u32']==expected_byte and compare['expected_u8']==31,'status and encoded output remain distinct '+label)
        check(returned['decoded_output_pointer']==compare['address'] and int(compare['address'],16)==sp+offset_info[site['output_stack_offset']][1],'source producer/caller/consumer byte alias '+label)
        reg='x8' if site['label']=='query_C' else 'x9';expected_predicate=int(expected_byte!=31) if site['label']=='query_C' else int(expected_byte==31)
        check(int(last['registers'][reg],16)==expected_predicate,'original immediate predicate polarity '+label)
        if label.endswith('_two_stage_identity'):
            direct=kinds(label,'original_direct26_boundary_and_model');primary=kinds(label,'original_IOConnect_structure_boundary');check(len(direct)==len(primary)==1 and direct[0]['args_x0_x7'][0]=='0x580a' and primary[0]['args_x0_x7'][0]=='0x5804','two-stage providers from original upstream record '+label);two_stage+=1
        check(row['stop_reason']=='original_dispatch_boundary','completed bounded source continuation '+label)
    corpus=c['kernel_corpus_search'];raw=CACHE.read_bytes();check(sha(raw)==corpus['sha256'] and len(raw)==corpus['size_bytes'],'fresh pinned kernel collection')
    names=[]
    for at,cmd,size in commands(raw,0):
        if cmd==0x80000035:names.append(string(raw,at+struct.unpack_from('<I',raw,at+24)[0]))
    check(names==corpus['fileset_names'] and len(names)==362,'fresh complete collection fileset names')
    for word,n in corpus['literal_counts'].items():check(raw.count(word.encode())==n,'exact whole-collection literal count '+word)
    check([x for x in names if any(k in x.lower() for k in ('avp','fairplay','virt'))]==corpus['name_filter_matches'],'bounded module-name filter')
    # Fresh executions reproduce original frame and the same declared local models.
    replays=0;replay_steps=0;peer=read('adid_peer_checkpoint.json')
    for label in ['original_request_frame','original_frame_slot_writers','query_A_primary_error','query_B_two_stage_identity','query_C_post_context_control']:
        f=normalized(rows[label]['fixture']);q=Dispatch(s,f,peer if 'fragment_entry' not in f else ck);actual=q.run_continuation();replays+=1;replay_steps+=actual['steps']
        check(actual['ordered_original_instruction_sha256']==rows[label]['ordered_original_instruction_sha256'] and actual['stop_reason']==rows[label]['stop_reason'] and unpack_records(actual)==events[label],'fresh complete source/event replay '+label)
        if label=='original_request_frame':
            fresh=q.checkpoint(actual);fresh.update(request_lock_models=q.lock_models,request_umask_value=q.umask_value,request_lockf_calls=q.lockf_calls)
            check(normalized(fresh)==ck,'all mutable original-frame regions/registers/model state replay')
    compile=c['SDK_compile'];check(sha((ROOT/'adid_driver_dispatch_layouts.c').read_bytes())==compile['source_sha256'] and sha((ROOT/'adid_driver_dispatch_layouts.s').read_bytes())==compile['assembly_sha256'],'analyst ABI source/output pins')
    with tempfile.TemporaryDirectory(prefix='adid-driver-dispatch-') as directory:
        cmd=compile['command'][:-1]+[str(Path(directory)/'layouts.s')];run=subprocess.run(cmd,capture_output=True,check=True);check(not run.stderr and (Path(directory)/'layouts.s').read_bytes()==(ROOT/'adid_driver_dispatch_layouts.s').read_bytes(),'fresh arm64e UUID/timeout/ftruncate SDK compile')
    for header in c['SDK_headers']:check(sha(Path(header['path']).read_bytes())==header['sha256'],'SDK header '+header['path'])
    for r in read('interface_manifest.json')['inputs_preserved']:
        path=ROOT.parent/r['path'];check(path.stat().st_size==r['size_bytes'] and sha(path.read_bytes())==r['sha256'],'original input preserved '+r['path'])
    counts={'private_cases':len(rows),'original_instruction_records':len(instructions),'original_compiler_ranges':len(p['original_functions']),'retained_original_visits':total,'upstream_call_record_observations':upstream,'immediate_byte_comparisons':comparisons,'two_stage_upstream_cases':two_stage,'original_frame_slot_producers':len(writer_events),'bank_bindings':len(c['banks']),'byte_domain_checks':len(c['banks'])*256,'SMT_unsat':len(c['proofs']),'source_windows':len(c['original_windows']),'collection_filesets':len(names),'independent_replay_runs':replays,'independent_replay_steps':replay_steps,'SDK_compile_exit':0,'assertions':len(assertions)}
    out={'scope':__doc__,'verified_counts':counts,'checks':assertions,'all_checks_pass':True,'native_target_executed':False,'full_goal_complete':False};(ROOT/'adid_driver_dispatch_checks.json').write_text(json.dumps(out,indent=2)+'\n')
    quality={'scope':'Original frame/slot provenance,conditional local upstream paths,bank bindings,consumer polarity and bounded collection search;full goal active.','verified_counts':counts,'native_target_executed':False,'full_goal_complete':False}
    texts=['Descriptive findings.','Report D1-D9 list dependent results and falsification probes.','Concrete upstream source edges,ABI/control/data/environment progress;whole goal incomplete.','Full byte-domain checks,four local proofs,alignment/alias/width/SI timeout units and SDK compile.','Entry/jump/state overrides explicit,extra X15 assumption unproved,consumer polarity and statuses distinct,bounded absence claims.','Fresh original bytes/fixups,whole-frame replay,retained request-prefix match,SDK and collection provenance.','Impact-labeled feasible request paths,Avp corpus,remaining callers,context/response/rights and deeper RPC selection.']
    for j,t in enumerate(texts,1):quality['QG'+str(j)]={'status':'pass_for_stated_increment','evidence':t}
    (ROOT/'adid_driver_dispatch_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps(counts))


if __name__=='__main__':main()
