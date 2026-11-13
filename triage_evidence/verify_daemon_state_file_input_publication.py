#!/usr/bin/env python3
"""Verify file-input receipts, source contracts and exact publication.

O(receipts+visits+owned bytes+manifest+query DAG) time/storage;30 s/query.
No native target operation executes; SDK/library and caller epochs are premises.
"""
import json
from hashlib import sha256
from collections import Counter
from compression import zstd
import z3
from daemon_receive_tools import SOURCE,IMAGE,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_daemon_payload_mix_publication import ROOT,BASE,git,hygiene,path_hygiene
from verify_daemon_second_mix_publication import canonical_expression,check_query_comparison
import recover_daemon_state_file_input as R
import audit_daemon_state_file_input as A

PREVIOUS='4217eea8b6aadfe612b28ef5e62bae244bceb6e3'
BASELINE_SHA='37c53d0182faee6ee90b945ef205b74d637a653f733045c99cf612ddadb5f7b9'
CHECKS_SHA='cdd60c06abc58fbb4b891ef851c6fa563ccff2fe671057d135a3633af379bd2b';AUDIT_SHA='03f9d598480d49ba7f28e9d31379c1892aae2ac366175811139ba42d5ee042bf'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'mach_ports_report.md','interface_abi_report.md','interface_investigation_status.md',
         'obfuscated_routines_report.md','foundational_triage_report.md','corefp_client_paths_report.md',
         'daemon_state_file_metadata_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_state_file_input_report.md','triage_evidence/recover_daemon_state_file_input.py',
       'triage_evidence/audit_daemon_state_file_input.py','triage_evidence/verify_daemon_state_file_input_publication.py',
       'triage_evidence/daemon_state_file_input_checks.json','triage_evidence/daemon_state_file_input_audit.json',
       'triage_evidence/daemon_state_file_input_abi.c'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_state_file_input_checks.json','triage_evidence/daemon_state_file_input_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'contexts': 256, 'NULL_allocations': 1536, 'nonnull_allocations': 768, 'read_cases': 1792, 'NULL_close_cases': 512, 'mismatch_free_cases': 256, 'mismatch_close_cases': 512, 'success_lock_cases': 512, 'timestamp_cases': 768, 'intervals': 9728, 'source_visits': 884480, 'reads': 217856, 'writes': 44800, 'logical_edges': 30464, 'source_calls': 2816}
INDEPENDENT={'register_values_checked': 28614656, 'NZCV_values_checked': 894208, 'vector_register_values_checked': 28614656, 'read_bytes_checked': 1376256, 'source_visits': 884480, 'original_authenticated_edges_checked': 22272, 'write_bytes_checked': 295680}
MODEL={'API_return_joins_checked': 8192, 'opaque_output_span_bytes_checked': 8634368, 'NULL_allocation_partitions_checked': 1536, 'initially_undefined_owner_bytes_checked': 1048832, 'fresh_owner_records_checked': 768, 'nonnull_read_requests_checked': 768, 'full64_read_return_joins_checked': 1792, 'read_exact_count_partitions_checked': 1792, 'exact_read_private_pointer_publications_checked': 256, 'raw_status_record_stores_checked': 4608, 'common_wrapper_requests_checked': 1024, 'declared_owner_retirements_checked': 256, 'source_paired_synchronization_requests_checked': 2048, 'supplied_output_word_bytes_checked': 12288, 'output_word_state_joins_checked': 1536, 'timestamp_pair_publications_checked': 768, 'first_file_byte_demands_checked': 768, 'unknown_payload_bytes_preserved_checked': 3145728, 'owner_and_generated_stream_preservation_intervals_checked': 9728}

def function_brackets():
    import struct,bisect
    from resolve_kernel_collection_interfaces import commands
    data=SOURCE.read_bytes();assert sha256(data).hexdigest()=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e';cmds=list(commands(data,0))
    text=next(o for o,c,n in cmds if c==0x19 and data[o+8:o+24].rstrip(b'\0')==b'__TEXT')
    base=struct.unpack_from('<Q',data,text+24)[0];assert base==0x100000000
    tables=[o for o,c,n in cmds if c==0x26];assert len(tables)==1
    table=tables[0];off,size=struct.unpack_from('<II',data,table+8);raw=data[off:off+size];assert len(raw)==size
    starts=[];cursor=0;address=base;terminated=False
    while cursor<len(raw):
        delta=shift=0
        while True:
            assert cursor<len(raw);b=raw[cursor];cursor+=1;delta|=(b&127)<<shift;shift+=7;assert shift<=70
            if not b&128:break
        if not delta:terminated=True;break
        address+=delta;starts.append(address)
    assert terminated and len(starts)==1005 and all(a<b for a,b in zip(starts,starts[1:]))
    assert (off,size,sha256(raw).hexdigest())==(17603576,1864,'ce02892286eaa20b5ad18e05d3a348a5c4b20ab49c668be14fd9e2eb119ccd54')
    expected=[(0x100d3d658,0x100d3d658,0x100d3e6d8),(0x100d3e6d8,0x100d3e6d8,0x100d3e968),
              (0x10043d044,0x10043d044,0x10043d36c),(0x10043e280,0x10043e280,0x10043e574),
              (0x1004423f8,0x1004423f8,0x100442688),(0x100ce1d3c,0x100ccf52c,0x100ce20c8),
              (0x100d69fc0,0x100d65598,0x100d7c6ec),(0x100be5f18,0x100ba8510,0x100c9e894),
              (0x1005b94fc,0x100559b7c,0x10061748c)]
    brackets=[]
    for pc,lo,hi in expected:
        j=bisect.bisect_right(starts,pc)-1;assert j>=0 and (starts[j],starts[j+1])==(lo,hi)
        brackets.append({'site':hex(pc),'preceding_advertised_start':hex(lo),'next_advertised_start':hex(hi)})
    syms=[o for o,c,n in cmds if c==2];assert len(syms)==1;so,ns,st,sz=struct.unpack_from('<IIII',data,syms[0]+8)
    exact=[];sites={a for a,_,_ in expected}
    for j in range(ns):
        ix,ty,se,de,va=struct.unpack_from('<IBBHQ',data,so+j*16)
        if ix and va in sites:
            assert ix<sz;end=data.index(0,st+ix,st+sz)
            exact.append({'value':hex(va),'name':data[st+ix:end].decode()})
    assert not exact
    return {'LC_FUNCTION_STARTS_file_offset':off,'LC_FUNCTION_STARTS_bytes':size,
            'LC_FUNCTION_STARTS_sha256':sha256(raw).hexdigest(),'advertised_starts_checked':len(starts),
            'site_brackets':brackets,'exact_site_symbols':exact,
            'scope':'Advertised start brackets; complete chunk/function ownership remains unknown.'}

def header_controls():
    from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM
    from unicorn import arm64_const as ar
    words=['00000000','ffffffff','01000000','00010000','00000100','00000001',
           '12345678','89abcdef','6703cce9','98fc3316'];out=[]
    code=IMAGE.read(R.BYTE,0x1005b9550-R.BYTE)
    for value in words:
        u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(R.BYTE&~4095,4096);u.mem_write(R.BYTE,code)
        u.mem_map(R.A,4096);u.mem_write(R.A,bytes.fromhex(value))
        for k,v in A.HEADER_SEEDS.items():u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(k)),v)
        u.reg_write(ar.UC_ARM64_REG_X28,R.A);u.emu_start(R.BYTE,0x1005b9550,count=21)
        result=u.reg_read(ar.UC_ARM64_REG_W19);expected=int(value,16)^0x6703cce9
        assert result==expected and u.reg_read(ar.UC_ARM64_REG_PC)==0x1005b9550
        out.append({'input_four_bytes_hex':value,'result32_hex':f'{result:08x}',
                    'source_instructions':21,'native_target_executed':False,
                    'scope':'Isolated original word construction; not a loader or native file observation.'})
    assert len(out)==10;return out

def receipts():
    assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
    e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
    assert e['generator_sha256']==a['generator_sha256']==sha(R.__file__) and a['auditor_sha256']==sha(A.__file__) and a['checks_sha256']==CHECKS_SHA
    assert e['dependencies']==a['dependencies']=={n:sha(ROOT/n) for n in R.DEPS} and a['auditor_dependencies']=={n:sha(ROOT/n) for n in A.AD}
    assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert e['verified_counts']==a['verified_counts']==COUNTS and a['independent_totals']==INDEPENDENT and a['model_checks']==MODEL and a['all_checks_pass']
    assert e['source_regions']==R.source() and e['SDK_checks']==R.sdk_checks() and e['SDK_checks']['source']==read(ROOT/'daemon_state_file_input_abi.c')
    assert 'ldr\tx2, [x2, #96]' in e['SDK_checks']['assembly'] and '_read' in e['SDK_checks']['assembly']
    assert a['symbolic_header_source']==A.header_source()
    parent=json.loads(read(ROOT/(R.Parent.P+'_checks.json')));h=Counter();counts=Counter();total=Counter();model=Counter();used=set();keys=set();n=0
    assert len(e['contexts'])==len(a['contexts'])==256
    for c,ac in zip(e['contexts'],a['contexts']):
        key=tuple(c[k] for k in ['parent_context_index','ABI_clobber_pattern']);assert key not in keys;keys.add(key)
        assert tuple(ac[k] for k in ['parent_context_index','ABI_clobber_pattern'])==key and ac['all_checks_pass']
        ct=A.contract(c,parent['contexts'][key[0]]);assert ct==ac['contract'];model.update(ct['model_checks'])
        rows=list(R.context_intervals(c));assert len(rows)==len(ac['independent_lifts'])==38;local=Counter()
        for row,lift in zip(rows,ac['independent_lifts']):
            n+=1;h.update(hygiene(row));counts.update(R.rc(row));local.update(lift['verified_counts'])
            assert not row['native_target_executed'] and lift['all_checks_pass'] and not lift['native_target_executed']
            assert len(row['source_visits'])==len(row['source_frames'])==lift['verified_counts'].get('source_visits',0) and row['boundary']['pc']==lift['boundary']
            for visit,frame in zip(row['source_visits'],row['source_frames']):
                assert visit['bytes_hex']==IMAGE.read(int(visit['pc'],16),4).hex() and visit['pc']==frame['pc'] and len(frame['Q_registers32'])==32
            used.update(int(x['address'],16) for x in row['source_reads'] if int(x['address'],16) in FIXUPS)
        assert dict(local)==ac['independent_totals'];total.update(local)
    assert keys=={(j,1-p['ABI_clobber_pattern']) for j,p in enumerate(parent['contexts'])} and n==9728
    assert dict(total)==INDEPENDENT and dict(model)==MODEL and dict(counts)=={k:COUNTS[k] for k in counts} and e['source_fixups']==R.Parent.Parent.Parent.fixups(used)
    check_query_comparison();fresh=A.obligations();assert len(fresh)==len(a['source_proofs'])==a['source_queries_unsat']==12
    for old,new in zip(a['source_proofs'],fresh):
        assert {k:v for k,v in old.items() if k!='query'}=={k:v for k,v in new.items() if k!='query'}
        oa,na=z3.parse_smt2_string(old['query']),z3.parse_smt2_string(new['query']);assert len(oa)==len(na)>0 and all(canonical_expression(x)==canonical_expression(y) for x,y in zip(oa,na))
        s=z3.Solver();s.set(timeout=30000);s.from_string(old['query']);assert s.check()==z3.unsat and old['premises_nonvacuous']
    for obj in [e,a]:
        h.update(hygiene(obj));assert all(not obj[k] for k in ['native_API_executed','native_daemon_kext_pairing_established','native_epoch_join_established','full_goal_complete'])
    controls=header_controls();h.update(hygiene(controls));h['isolated_header_unicorn_controls_checked']=len(controls);h['isolated_header_original_instructions_checked']=sum(x['source_instructions'] for x in controls)
    brackets=function_brackets();h.update(hygiene(brackets));h['MachO_advertised_starts_checked']=brackets['advertised_starts_checked'];h['MachO_site_brackets_checked']=len(brackets['site_brackets'])
    report=read(BASE/'daemon_state_file_input_report.md');assert CHECKS_SHA in report and AUDIT_SHA in report
    assert all(f'| SI{j} |' in report for j in range(1,7)) and all(f'| SI-A{j}:' in report for j in range(1,9)) and all(f'**QG{j}**' in report for j in range(1,8))
    return e,a,h,controls,brackets

def main():
    e,a,h,controls,brackets=receipts();raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==8816 and len(after)==8823 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256'] and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    for suffix,value in [('increment_checks',COUNTS),('replay_checks',INDEPENDENT),('model_checks',MODEL),('static_scope',e['scope']),('source_queries_unsat',12)]:assert new['validation'][R.P+'_'+suffix]==value
    assert new['validation'][R.P+'_isolated_header_controls']==controls and new['validation'][R.P+'_function_brackets']==brackets
    assert new['validation']['reports']==old['validation']['reports']+1==517 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        path_hygiene((BASE/p).read_bytes());path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
    print(json.dumps({'unchanged_manifest_entries':8808,'owned_physical_files':16,'original_inputs_preserved':3,'reports':517,'independent_lifts':9728,'source_visits':COUNTS['source_visits'],'source_queries_unsat':12,**h,'native_API_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
