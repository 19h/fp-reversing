#!/usr/bin/env python3
"""Independent fresh A64 replay, live-epoch digest and route-convergence audit.
O(profiles + visits + effects + previous oracle stores + solver resources)
time; O(profiles + largest decoded case + source decoder cache) space.
All target/API/PAC operations are private models; no native target executes.
"""
import json,hashlib,base64,zlib
from collections import Counter
import z3
from daemon_receive_tools import ROOT,IMAGE,SOURCE
from capture_daemon_record720 import sha
from capture_daemon_record720_fingerprint import capture
from prove_daemon_record720_fingerprint import obligations
from probe_daemon_record720_fingerprint import cases
from probe_daemon_record720_handoff import produced
from replay_daemon_record720_release import replay
from recover_daemon_descriptor_producers import verify_used_fixups
from rpc502_certificate_oracles import tlv_at,digest_oracles

WRITERS={0x1000c69b8,0x1000c69e8,0x1000c6a00,0x1000c6a04}
def unpack(row):
    b=zlib.decompress(base64.b64decode(row['payload_zlib_base64']))
    if 'payload_sha256'in row:assert hashlib.sha256(b).hexdigest()==row['payload_sha256']
    return json.loads(b)

def event_value(e):return int.from_bytes(bytes.fromhex(e.get('bytes_hex',e.get('after_hex'))),'little')

def audit(c,t):
    out=Counter();F=int(c['SP'],16);P=int(c['allocation_owner_address'],16);U=int(c['logical_U64'],16);D=int(c['logical_D32'],16);raw=bytes.fromhex(c['extension']['payload_hex']);assert len(raw)==D
    steps=[p for p,b in t['steps']];es=t['events'];snaps={}
    for s in t['ABI_snapshots']:snaps.setdefault(s['pc'],s)
    def one(pc,kind):
        ee=[e for e in es if e['pc']==hex(pc)and e['kind']==kind];assert len(ee)==1,(hex(pc),len(ee));return ee[0]
    def val(pc,kind):return event_value(one(pc,kind))
    reads=[e for e in es if e['kind']=='read'and U<=int(e['address'],16)<U+D]
    assert reads and all(bytes.fromhex(e['bytes_hex'])==raw[int(e['address'],16)-U:int(e['address'],16)-U+e['size_bytes']]for e in reads)
    assert not any(e['kind']=='write'and int(e['address'],16)<U+D and U<int(e['address'],16)+e['size_bytes']for e in es)
    out['borrowed_input_spans_checked']+=1;out['borrowed_input_reads_checked']+=len(reads)
    root=tlv_at(raw,0,D);is_root=root is not None and root['tag']==0x30
    assert (0x10040f7a4 in steps)==is_root
    h=None
    if is_root:
        a=snaps['0x100478ef4'];assert a['known_GPRs']['x8']=='0x10040f7a4';C=int(a['known_GPRs']['x0'],16);I=int(a['known_GPRs']['x1'],16)
        adjustment=0xf0 if c['extension']['variant']=='prior_runtime_variant'else 0
        assert C==F-0x330-adjustment and I==C+0x1f8
        attach=one(0x1004ab0dc,'write');assert int(attach['address'],16)==C+0x60;Q=event_value(attach);assert Q==C-0x6f0 and val(0x10040f8e8,'read')==Q
        assert val(0x10040f8e0,'read')==(root['total']^0x8b3dc651);copy=one(0x10040f8ec,'write');assert int(copy['address'],16)==Q and event_value(copy)==(root['total']^0x8b3dc651)
        out['callback_context_and_total_links_checked']+=1
        init=snaps['0x10040f9e4'];R=int(init['known_GPRs']['x0'],16);key=((R^0xf9d49974)*0xda51a827)&0xffffffff
        assert R&7==0 and val(0x10040f944,'write')==(key^0xb308)and val(0x10040f940,'write')==(key^0x7efd0a1c)and val(0x10040f94c,'write')==R-0x64
        edge=next(e for e in t['edges']if e['pc']=='0x10040f9e4');assert edge['target']=='0x10045c4f0'and edge['slot']=='0x1010a0170'and edge['modifier']=='0xa88b'
        out['initializer_records_and_source_calls_checked']+=1
        # Read actual source-store epochs before the initializer returns.
        stop=steps.index(0x10040f9e8);mem={}
        before_return=set(steps[:stop])
        for e in es:
            if int(e['pc'],16)in before_return and e['kind']=='write':
                for j,b in enumerate(bytes.fromhex(e['after_hex'])):mem[int(e['address'],16)+j]=b
            if e['pc']=='0x10040f9f4':break
        ctx=R-0x64
        def read32(a):return int.from_bytes(bytes(mem[a+j]for j in range(4)),'little')
        assert read32(ctx+92)==20 and read32(ctx+96)==2
        # These context stores are captured again below by exact writer epochs;
        # later callback cleanup never supplies a digest oracle.
        assert steps.count(0x10040f7a4)==1 and steps.count(0x100478ef8)>=1
        begin=steps.index(0x10040f7a4);end=steps.index(0x100478ef8);assert begin<end
        live_writes=[e for e in es if e['kind']=='write'and int(e['pc'],16)in WRITERS]
        assert len(live_writes)==20 and all(e['size_bytes']==1 for e in live_writes)
        sink=Q+0x5ec;assert {int(e['address'],16)for e in live_writes}==set(range(sink,sink+20))
        actual=bytes(next(bytes.fromhex(e['after_hex'])[0]for e in live_writes if int(e['address'],16)==sink+j)for j in range(20))
        digest=hashlib.sha1(raw[:root['total']]).digest();encoded=bytes(b^0x98 for b in digest);assert actual==encoded
        # Source order is retained even when PCs repeat. Every digest writer is
        # inside the first callback interval and precedes its normal return.
        callback_steps=set(steps[begin:end]);assert WRITERS<=callback_steps and all(begin<=j<end for j,pc in enumerate(steps)if pc in WRITERS)
        assert int(snaps['0x100478ef8']['known_GPRs']['x0'],16)==0
        out['live_root_digest_oracles_checked']+=1;out['digest_source_byte_stores_checked']+=20;out['normal_zero_callback_returns_checked']+=1
        h={'payload_label':c['extension']['payload_label'],'variant':c['extension']['variant'],'source_span':{'address':hex(U),'length_bytes':root['total'],'declared_bytes':D},'user_record':hex(C),'work_record':hex(Q),'digest_sink':hex(sink),'digest_context':hex(ctx),'SHA1_hex':digest.hex(),'encoded_hex':actual.hex(),'first_writer_step':min(steps.index(p)for p in WRITERS),'callback_return_step':end}
    else:
        assert not any(int(e['pc'],16)in WRITERS for e in es);out['non_root_controls_checked']+=1
    initwrites=[e for e in es if e['kind']=='write'and P<=int(e['address'],16)<P+720]
    assert len(initwrites)==75 and all(0x100b0b6fc<=int(e['pc'],16)<0x100b0b880 for e in initwrites)
    out['owner_initialization_only_write_paths_checked']+=1
    frees=[a for a in t['API_models']if a['binding']['symbol']=='_free']
    assert all(a['binding']['symbol']in['_malloc','_free']for a in t['API_models'])
    if frees:
        assert len(frees)==1 and frees[0]['pc']=='0x1001c6100'and frees[0]['arguments1']==[hex(P)]
        assert t['boundary']['pc']=='0x100b90ef4'and int(t['boundary']['detail']['address'],16)==F+0x24f8 and not any(t['allocation_defined_mask720'])
        out['normal_owner_release_paths_checked']+=1
    else:
        assert c['extension']['payload_label'].startswith('certificate_')and t['boundary']['pc']=='0x10041f770'and t['boundary']['detail']['address']=='0x1010c5320'
        assert sum(t['allocation_defined_mask720'])==161;out['version_state_frontiers_preserved']+=1
    return out,h

def prefix_key(c,cfg):
    h=c['extension']['payload_hex'];F=int(c['SP'],16);P=c['allocation_owner_address'];U=c['logical_U64'];runtime=c['runtime_variant'];by={g['address']:g['bytes_hex']for g in c['known_byte_groups']}
    return F,P,U,h,runtime,by['0x1010b6570'],cfg['physical_pattern']

def main():
    c=json.loads((ROOT/'daemon_record720_fingerprint_source.json').read_text());assert c==capture()
    for name in c['dependencies']:
        assert sha(ROOT/name)==c['dependencies'][name]
    p=json.loads((ROOT/'daemon_record720_fingerprint_profiles.json').read_text());assert p['source_sha256']==sha(SOURCE)
    for n,h in p['dependencies'].items():assert sha(ROOT/n)==h
    proofs=json.loads((ROOT/'daemon_record720_fingerprint_proofs.json').read_text());qs,counts=obligations(c);assert counts==proofs['source_lift_counts'];out=Counter();total=Counter();summaries=[];old={};pool={};fix=set()
    for row in json.loads((ROOT/'daemon_record720_release_profiles.json').read_text())['cases']:
        if row['context']['extension']['payload_hex']is not None:old[prefix_key(row['context'],row['configuration'])]=row
    for (name,expr),r in zip(qs,proofs['proofs'],strict=True):
        assert r['name']==name
        for key,query in [('original_file',expr),('file',z3.simplify(expr))]:
            path=ROOT/r[key];assert sha(path)==r['original_sha256'if key=='original_file'else'sha256'];v=z3.parse_smt2_file(str(path));s=z3.Solver();s.set(timeout=30000);s.add(*v);assert s.check()==z3.unsat
            t=z3.Solver();t.set(timeout=30000);t.add(z3.Xor(z3.And(*v),query));assert t.check()==z3.unsat;out['SMT_files_checked']+=1
        out['source_proofs_rebuilt']+=1
    expected_smt={r[k]for r in proofs['proofs']for k in ['file','original_file']};assert {q.name for q in ROOT.glob('daemon_fingerprint720_*.smt2')}==expected_smt
    for row,(ctx,cfg)in zip(p['cases'],cases(),strict=True):
        assert row['context']==ctx and row['configuration']==cfg;t=unpack(row)
        checks=replay(ctx,cfg,t);total.update(checks);a,h=audit(ctx,t);out.update(a)
        if h:summaries.append(h)
        out['source_visits_checked']+=len(t['steps'])
        for address,r in t['source_pool'].items():
            assert IMAGE.read(int(address,16),4).hex()==r['bytes_hex'];assert address not in pool or pool[address]==r;pool[address]=r
        fix.update(int(a,16)for a in t['used_fixups'])
        k=prefix_key(ctx,cfg)
        if k in old:
            prior=unpack(old[k]);assert t['steps'][:len(prior['steps'])]==prior['steps']and t['events'][:len(prior['events'])]==prior['events'];out['retained_release_prefixes_matched']+=1
        # Construct the original header components again; this is a component
        # handover, not an invented continuous native input producer.
        producer=produced(int(ctx['SP'],16),int(ctx['logical_U64'],16),int(ctx['logical_D32'],16));assert hashlib.sha256(json.dumps(producer,sort_keys=True,separators=(',',':')).encode()).hexdigest()==ctx['input_producer_sha256'];out['input_component_hashes_checked']+=1
        if out['input_component_hashes_checked']%8==0:print(json.dumps({'fresh_cases':out['input_component_hashes_checked'],'A64_instructions':total['A64_instructions_checked']}),flush=True)
    # Refresh the pre-existing independent digest oracle on retained whole-worker
    # evidence. This identifies convergence without asserting caller continuity.
    previous=json.loads((ROOT/'rpc502_certificate_profiles.json').read_text());old_hashes=[]
    for row in previous['cases']:
        t=unpack(row);oracles=digest_oracles(t,bytes.fromhex(row['case']['file_hex']))
        for r in oracles:
            if r.get('output_size',0):assert r['hits'];out['retained_worker_digest_oracles_refreshed']+=1
            if r['schema_entry']=='0x10040f7a4'and r.get('output_size',0):old_hashes.append(r)
    for h in summaries:
        if h['payload_label'].startswith('certificate_'):
            matches=[q for q in old_hashes if q['standard_digest_hex']==h['SHA1_hex']and q['length_bytes']==h['source_span']['length_bytes']];assert matches;out['same_input_worker_root_digests_matched']+=1
    fixups=verify_used_fixups(fix);out.update(distinct_original_opcodes_checked=len(pool),original_fixups_checked=len(fix),IDB_ranges=len(c['live_IDB_matches']),IDB_bytes=sum(r['size_bytes']for r in c['live_IDB_matches']),exhaustive_byte_banks=len(c['exhaustive_banks']),source_lift_visits=sum(counts.values()))
    result={'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['daemon_record720_fingerprint_source.json','daemon_record720_fingerprint_profiles.json','daemon_record720_fingerprint_proofs.json','replay_daemon_record720_release.py','rpc502_certificate_oracles.py','rpc502_certificate_profiles.json']},'verified_counts':dict(out),'independent_A64_totals':dict(total),'source_fixups':fixups,'root_digest_cases':summaries,'all_checks_pass':True,'native_target_executed':False,'idb_mutated':False,'new_port_emission_established':False,'full_goal_complete':False}
    (ROOT/'daemon_record720_fingerprint_checks.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'verified_counts':dict(out),'A64':dict(total)}),flush=True)

if __name__=='__main__':main()
