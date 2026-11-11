#!/usr/bin/env python3
"""Verify owned publication, pinned fresh-replay receipt and independent data joins.

This command does not replay instructions. Use the separate auditor for a fresh
source replay. O(owned bytes + manifest entries + decoded profiles) time and
O(largest profile + manifest) space, excluding bounded integer operations.
"""
import base64
from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess
import zlib
from compression import zstd
from verify_daemon_reader_record_payloads_publication import read, sha, size
from verify_lskd_vector_origin_publication import path_hygiene

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='16ea6d23a509b4476d327b156113d725ecea05ef'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'fpsd1200_context_report.md','daemon_receive_interface_report.md','mach_ports_report.md',
 'foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md',
 'obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'fpsd1200_certificate_report.md','triage_evidence/recover_fpsd1200_certificate.py',
 'triage_evidence/audit_fpsd1200_certificate.py','triage_evidence/verify_fpsd1200_certificate_publication.py',
 'triage_evidence/fpsd1200_certificate_checks.json','triage_evidence/fpsd1200_certificate_ida_readback.json',
 'triage_evidence/fpsd1200_certificate_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/fpsd1200_certificate_checks.json',
 'triage_evidence/fpsd1200_certificate_ida_readback.json','triage_evidence/fpsd1200_certificate_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles':4,'daemon_visits':30103530,'library_visits':76,'import_events':141,
 'certificate_allocations':8,'certificate_retirements':6,'certificate_store_events':15532,
 'certificate_read_events':25507,'montgomery_calls':251,'complete_montgomery_calls':251,
 'new_atomic_guards':1,'new_atomic_fixtures':6,'returned_replies':1,'OOL_read_events':9252,
 'source_spans':832,'source_instructions_including_guards':39379,'format12_rebases':1113,
 'format12_bindings':28,'bank_identities':17,'bank_inputs':4352,'bank_pair_uses':13112,
 'unpaired_byte_bank_reads':138}
FINITE={'profiles':4,'original_instruction_visits':30103606,'import_events':141,
 'admission_checkpoints':72,'source_IDA_spans':832,'constructor_store_bytes_checked':15532,
 'full_Montgomery_outputs_checked':251,'active_arithmetic_bytes_checked':240784,
 'public_exponent_outputs_checked':6,'public_signature_relations':2,'bank_inputs':4352,
 'all_checks_pass':True}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def integer(v):
    cap,raw,_=struct.unpack('<IIQ',bytes.fromhex(v['header16_hex']))
    n=(raw-0x693be708)&0xffffffff
    if n>>31:n-=1<<32
    assert 0<=n<=cap and v['header_known_mask_hex']=='01'*16
    b=bytes.fromhex(v['active_limbs_hex']);assert len(b)==4*n and v['active_known_mask_hex']=='01'*len(b)
    return sum((int.from_bytes(b[j:j+4],'little')^0xada56e3c)<<(8*j)for j in range(0,len(b),4))


def tlvs(b,start=0,end=None):
    """Walk constructed DER only; yield tag, content start/end. O(DER bytes)."""
    end=len(b)if end is None else end;p=start
    while p<end:
        tag=b[p];n=b[p+1];p+=2
        if n&0x80:
            k=n&0x7f;assert 0<k<=4;n=int.from_bytes(b[p:p+k],'big');p+=k
        z=p+n;assert p<=z<=end;yield tag,p,z
        if tag&0x20:yield from tlvs(b,p,z)
        p=z
    assert p==end


def data_joins(e):
    total=extension_reads=0
    expected_cases=['reference_atomic_guard','reference_task_data_guard','reference_Mach_boundary','first_certificate_NULL']
    assert [p['label']for p in e['profiles']]==expected_cases
    extra_offsets=list(range(589,597))+list(range(601,609))
    extra_pcs=[0x1003f47e8,0x1003f47f0,0x1003f47f8,0x1003f4820,
      0x1003f969c,0x1003f96a0,0x1003f96b4,0x1003f96dc,
      0x10061cb8c,0x10061cba0,0x10061cbb4,0x10061cbf4,
      0x100493738,0x10049374c,0x10049375c,0x10049379c]
    for p in e['profiles']:
        r=json.loads(zlib.decompress(base64.b64decode(p['payload_zlib_base64'])))
        path_hygiene(json.dumps(r).encode())
        assert not r['native_messages_emitted']and not r['native_target_executed']
        assert r['protected_payload104_before']==r['protected_payload104_final']
        writes=r['protected_output_writes'];later=p['label']in expected_cases[1:3]
        assert r['inline128_before']=='a5'*128
        if later:
            assert len(writes)==128
            assert all(w['pc']=='0x1002212a0'and w['width_B']==1 for w in writes)
            assert [int(w['address'],16)for w in writes]==list(range(0x700020c3,0x70002043,-1))
            result=integer(r['montgomery_calls'][-1]['returned']['output']).to_bytes(128,'big')
            assert bytes(int(w['value'],16)for w in reversed(writes))==result==bytes.fromhex(r['inline128_final'])
            third=r['montgomery_calls'][63:];assert len(third)==31
            representative=integer(third[10]['entry']['right']).to_bytes(128,'big')
            assert representative[:9]==bytes.fromhex('006664706300000001')
            N=integer(third[0]['entry']['modulus']);assert int.from_bytes(result,'big')==pow(int.from_bytes(representative,'big'),65537,N)
            extra=r['input_ool_byte_reads'][-16:]
            assert [(q['offset_B'],int(q['pc'],16),q['width_B'])for q in extra]==[(o,pc,1)for o,pc in zip(extra_offsets,extra_pcs)]
            der=bytes.fromhex(r['initial_ool756_hex']);items=list(tlvs(der))
            assert (4,589,609)in items and der[589:609].hex()=='0000000200000004294e5e300000000483705b57'
            assert any(t==6 and der[a:z].hex()=='2a864886f76364070102'for t,a,z in items)
            assert all(q['bytes_hex']==der[q['offset_B']:q['offset_B']+1].hex()for q in extra)
            extension_reads+=len(extra)
        else:
            assert not writes and r['inline128_final']==r['inline128_before']
        if p['label']=='reference_Mach_boundary':
            event=r['events'][-1]
            assert event['name']=='libSystem/_vm_deallocate'and event['site']=='0x10049e114'and 'result'not in event
            assert [int(a,16)for a in event['args'][:3]]==[0x6600,0xa5a5a5a5a5a5a5a5,0]
            assert int(event['args'][1],16)==struct.unpack_from('<Q',bytes.fromhex(r['protected_payload104_final']),72)[0]
            assert r['task_self_reads']==[{'pc':'0x10049e0f8','address':'0x6000000800','width_B':4,'bytes_hex':'00660000'}]
            assert not r['reply_completed']
        if p['label']=='first_certificate_NULL':
            assert r['reply_completed']and r['reply_size_B']==36 and r['application_status_u32']==0xffff5bd4
            assert not r['certificate_owners_final']and not r['montgomery_calls']
            last=r['events'][-1];assert last['site']=='0x10000468c'and last['name']=='libSystem/_mig_deallocate'
            assert int(last['args'][1],16)==756
        total+=len(writes)
    assert total==256 and extension_reads==32
    return {'inline_store_result_joins':total,'additional_extension_reads':extension_reads,'fdpc_prefix_cases':2}


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest()=='89e69070a0c96d42000ce2accae357d5b9bc6bddd9a94a8ed2ae4d5f5d1a5b6b'
    previous,current=json.loads(raw),json.loads(read(BASE/MANIFEST))
    old={r['path']:r for r in previous['files']};new={r['path']:r for r in current['files']}
    assert len(old)==len(previous['files'])==8171 and len(new)==len(current['files'])==8178
    assert not old.keys()-new.keys()and new.keys()-old.keys()==ADDED
    assert {p for p in old if old[p]!=new[p]}==CHANGED
    assert current['inputs_preserved']==previous['inputs_preserved']
    for r in current['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==new[p]['sha256']and size(BASE/p)==new[p]['size_bytes']
    report=read(BASE/'fpsd1200_certificate_report.md')
    assert all(f'| FV{i} |'in report for i in range(1,9))and all(f'**QG{i}**'in report for i in range(1,8))
    e=json.loads(read(ROOT/'fpsd1200_certificate_checks.json'))
    assert e['verified_counts']==COUNTS and sha(ROOT/'recover_fpsd1200_certificate.py')==e['generator_sha256']
    for n,h in e['dependencies'].items():assert sha(ROOT/n)==h
    assert e['new_IDA_access']and not any(e[k]for k in ['new_IDB_mutations','new_native_execution','full_goal_complete'])
    receipt=json.loads(read(ROOT/'fpsd1200_certificate_audit.json'))
    assert receipt['fresh_replay_completed']and receipt['process_exit_code']==0 and not receipt['native_target_executed']
    assert receipt['auditor_sha256']==sha(ROOT/'audit_fpsd1200_certificate.py')
    assert receipt['checks_sha256']==sha(ROOT/'fpsd1200_certificate_checks.json')
    assert receipt['IDA_SDK_readback_sha256']==sha(ROOT/'fpsd1200_certificate_ida_readback.json')
    assert receipt['daemon_sha256']==e['daemon_sha256']and receipt['dependencies']==e['dependencies']
    for n,h in receipt['public_DER_inputs'].items():assert sha(ROOT/n)==h
    finite=receipt['result'];assert {k:v for k,v in finite.items()if k!='exponent_group_summaries'}==FINITE
    groups=finite['exponent_group_summaries'];assert len(groups)==8
    assert [(g['case'],g['key'],g['calls'])for g in groups]==[(case,key,calls)for case,keys in
      [('reference_atomic_guard',[('Root',32),('AAA',31)]),('reference_task_data_guard',[('Root',32),('AAA',31),('CoreFP_leaf',31)]),
       ('reference_Mach_boundary',[('Root',32),('AAA',31),('CoreFP_leaf',31)])]for key,calls in keys]
    assert all(g['exponent']==65537 and g['complete_exponent_order_checked']for g in groups)
    att=json.loads(read(ROOT/'fpsd1200_certificate_ida_readback.json'))
    assert not att['IDB_mutated']and att['spans']==[{'start':s['start'],'size_B':int(s['end'],16)-int(s['start'],16),'sha256':s['sha256']}for s in e['spans']]
    assert att['SDK_context']['compile_only']['exit_code']==0
    joins=data_joins(e)
    assert current['validation']['fpsd1200_certificate_increment_checks']==COUNTS
    assert current['validation']['fpsd1200_certificate_static_scope']==e['scope']
    assert current['validation']['reports']==previous['validation']['reports']+1==412
    assert current['validation']['unavailable_external_primary_references']==previous['validation']['unavailable_external_primary_references']
    assert current['goal_status']=='active'and len(OWNED)==16
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene((BASE/p).read_bytes())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    print(json.dumps({'unchanged_manifest_entries':len(old)-len(CHANGED),'owned_physical_files':len(OWNED),
      'original_inputs_preserved':3,'pinned_fresh_audit':{k:v for k,v in finite.items()if k!='exponent_group_summaries'},
      'publication_does_not_replay_instructions':True,**joins,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
