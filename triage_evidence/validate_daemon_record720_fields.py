#!/usr/bin/env python3
"""Rebuild field contracts and independently replay every MAX-CPU case.
O(profiles+visits+effects+solver resources) time; O(profiles+largest case+
decoder cache) space. No native target, synchronization or IPC executes.
"""
import json,hashlib
from collections import Counter
import z3
import unicorn as uc
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,IMAGE,SOURCE
from capture_daemon_record720 import sha
from capture_daemon_record720_fields import capture
from prove_daemon_record720_fields import obligations
from probe_daemon_record720_fields import cases
from replay_daemon_record720_fields import replay
from validate_daemon_record720_fingerprint import unpack,event_value
from rpc502_certificate_oracles import tlv_at
from recover_daemon_descriptor_producers import verify_used_fixups

WRITERS={'root':{0x1000c69b8,0x1000c69e8,0x1000c6a00,0x1000c6a04},'key':{0x100265474,0x1002654a8,0x1002654c0,0x1002654c8},'TBS':{0x1002c38d0,0x1002c3904,0x1002c391c,0x1002c3924}}
def children(raw,node):
    pos=node['content'];end=pos+node['length'];out=[]
    while pos<end:
        t=tlv_at(raw,pos,end-pos);assert t is not None;out.append(t);pos+=t['total']
    assert pos==end;return out

def atomic_microchecks():
    rows=[]
    for address in [0x6900000000,0x6900001010]:
      for old in [0,0x5d96,0xa94ef,0xffffffff,0x80005d96,0x5d960000]:
        u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);u.mem_map(0x200000,4096);u.mem_write(0x200000,IMAGE.read(0x100503d18,4));u.mem_map(address&~4095,4096);u.mem_write(address,old.to_bytes(4,'little'))
        for reg,value in [(ar.UC_ARM64_REG_X21,address),(ar.UC_ARM64_REG_W11,0x5d96),(ar.UC_ARM64_REG_W12,0xa94ef),(ar.UC_ARM64_REG_NZCV,0xa0000000)]:u.reg_write(reg,value)
        u.emu_start(0x200000,0x200004,count=1);actual=int.from_bytes(bytes(u.mem_read(address,4)),'little');expected=0xa94ef if old==0x5d96 else old
        assert actual==expected and u.reg_read(ar.UC_ARM64_REG_W11)==old and u.reg_read(ar.UC_ARM64_REG_W12)==0xa94ef and u.reg_read(ar.UC_ARM64_REG_NZCV)==0xa0000000
        rows.append({'address':hex(address),'old_word':hex(old),'new_word':hex(actual),'comparison_return':hex(old),'NZCV_preserved':True})
    return rows

def audit(c,t):
    out=Counter();raw=bytes.fromhex(c['extension']['payload_hex']);U=int(c['logical_U64'],16);P=int(c['allocation_owner_address'],16);F=int(c['SP'],16);events=t['events'];snaps={}
    for s in t['ABI_snapshots']:snaps.setdefault(s['pc'],s)
    C=int(snaps['0x100478ef4']['known_GPRs']['x0'],16);Q=C-0x6f0
    def one(pc,kind):
        rows=[e for e in events if e['pc']==hex(pc)and e['kind']==kind];assert len(rows)==1,(hex(pc),len(rows));return rows[0]
    def value(pc,kind):return event_value(one(pc,kind))
    root=tlv_at(raw,0,len(raw));T=children(raw,root)[0];fields=children(raw,T);assert len(fields)==7;version=children(raw,fields[0])[0];serial,algorithm,issuer,validity,subject,spki=fields[1:];OID=children(raw,algorithm)[0]
    assert raw[version['content']:version['content']+version['length']]==b'\x02'
    for pc,offset,n,expected in [(0x10044f7a8,0,4,T['total']^0x8b3dc651),(0x10044f7b0,8,8,U+T['start']),(0x100161c0c,0x10,4,0x428bf566),(0x1004150f4,0x18,4,OID['length']^0x8b3dc651),(0x1004150fc,0x20,8,U+OID['content']),(0x100413258,0x28,4,issuer['length']^0x8b3dc651),(0x100413260,0x30,8,U+issuer['content']),(0x10000cd3c,0x38,4,subject['length']^0x8b3dc651),(0x10000cd44,0x40,8,U+subject['content'])]:
        e=one(pc,'write');assert int(e['address'],16)==C+offset and e['size_bytes']==n and event_value(e)==expected;out['callback_user_fields_checked']+=1
    serial_bytes=raw[serial['content']:serial['content']+serial['length']];assert len(serial_bytes)==1
    assert value(0x1000abd64,'write')==(len(serial_bytes)^0x8b3dc651)and int(one(0x1000abd64,'write')['address'],16)==Q+0x18
    stores=[e for e in events if e['pc']=='0x1000af114'];assert len(stores)==1 and int(stores[0]['address'],16)==Q+4 and bytes.fromhex(stores[0]['after_hex'])==bytes(b^0x98 for b in serial_bytes);out['serial_field_pairs_checked']+=1
    # Each hash is compared at its original serializer-store epoch. No later
    # frame snapshot substitutes for source output.
    pubbits=children(raw,spki)[1];assert pubbits['tag']==3 and raw[pubbits['content']]==0
    spans={'root':raw[:root['total']],'TBS':raw[T['start']:T['start']+T['total']],'key':raw[pubbits['content']+1:pubbits['content']+pubbits['length']]};digests={}
    for role,pcs in WRITERS.items():
        es=[e for e in events if e['kind']=='write'and int(e['pc'],16)in pcs];assert len(es)==20 and all(e['size_bytes']==1 for e in es);addresses=sorted(int(e['address'],16)for e in es);assert addresses==list(range(addresses[0],addresses[0]+20));actual=bytes(next(bytes.fromhex(e['after_hex'])[0]for e in es if int(e['address'],16)==a)for a in addresses);digest=hashlib.sha1(spans[role]).digest();assert actual==bytes(b^0x98 for b in digest);out['independent_digest_outputs_checked']+=1;out['digest_source_byte_stores_checked']+=20;digests[role]={'sink':hex(addresses[0]),'length_bytes':len(spans[role]),'SHA1_hex':digest.hex(),'encoded_hex':actual.hex()}
    assert int(digests['root']['sink'],16)==Q+0x5ec and int(digests['TBS']['sink'],16)==Q+0x598 and int(digests['key']['sink'],16)==Q+0x468
    mem={}
    for e in events:
        if e['kind']=='write':
            for j,b in enumerate(bytes.fromhex(e['after_hex'])):mem[int(e['address'],16)+j]=b
    reads=[e for e in events if e['kind']=='read'and U<=int(e['address'],16)<U+len(raw)];assert reads and all(bytes.fromhex(e['bytes_hex'])==raw[int(e['address'],16)-U:int(e['address'],16)-U+e['size_bytes']]for e in reads)
    out['borrowed_input_reads_checked']+=len(reads)
    assert not any(e['kind']=='write'and U<=int(e['address'],16)<U+len(raw)for e in events)
    own=[e for e in events if e['kind']=='write'and P<=int(e['address'],16)<P+720];assert len(own)==75 and all(0x100b0b6fc<=int(e['pc'],16)<0x100b0b880 for e in own);out['owner_initializer_only_paths_checked']+=1
    named=c['extension']['payload_label']=='certificate_named';ready=c['extension']['readiness_byte'];b=t['boundary'];names={}
    if named:
        for role,offset in [('issuer',0x1c),('subject',0xe8)]:
            D=Q+offset;count=int.from_bytes(bytes(mem[D+j]for j in range(4)),'little');text=bytes(mem[D+4+j]for j in range(count+1));assert count==11 and text==b'/CN=Fixture\0';names[role]={'record':hex(D),'raw_count':count,'text_hex':text.hex()};out['name_workspace_records_checked']+=1
        ae=[e for e in events if e['pc']=='0x100503d18'];assert len(ae)==2 and ae[0]['kind']=='read'and ae[0]['bytes_hex']=='965d0000'and ae[1]['kind']=='write'and ae[1]['after_hex']=='ef940a00'and all(int(e['address'],16)==0x1010b5de0 and e['size_bytes']==4 for e in ae);out['source_CASAL_acquisitions_checked']+=1
        s=snaps['0x100503d1c'];assert int(s['known_GPRs']['x11'],16)==0x5d96 and int(s['known_GPRs']['x12'],16)==0xa94ef
        if ready is None:assert b['pc']=='0x10048d694'and b['detail']['address']=='0x1010c5798';out['unavailable_readiness_frontiers_preserved']+=1
        elif ready==0:
            e=one(0x100634280,'write');assert int(e['address'],16)==0x1010b5de0 and e['after_hex']=='965d0000';assert b['pc']=='0x100b90ef4'and not any(t['allocation_defined_mask720']);assert len(t['API_models'])==2 and t['API_models'][-1]['arguments1']==[hex(P)];out['readiness_zero_restore_and_release_checked']+=1
        else:assert ready==1 and b['pc']=='0x100633f04'and int(b['detail']['address'],16)==int(b['SP'],16)+0x2e8;out['readiness_one_frame_frontier_preserved']+=1
    else:
        assert b['pc']=='0x100610bd0'and int(b['detail']['address'],16)==Q+0x20 and b['detail']['size_bytes']==1
        assert Q+0x20 not in mem and not any(int(g['address'],16)<=Q+0x20<int(g['address'],16)+len(g['bytes_hex'])//2 for g in c['known_byte_groups']);out['undefined_empty_name_frontiers_preserved']+=1
    return out,{'case_index':c['case_index'],'user_record':hex(C),'workspace':hex(Q),'names':names,'digests':digests,'boundary':b['pc']}

def main():
    src=json.loads((ROOT/'daemon_record720_fields_source.json').read_text());assert src==capture();p=json.loads((ROOT/'daemon_record720_fields_profiles.json').read_text());proofs=json.loads((ROOT/'daemon_record720_fields_proofs.json').read_text());counts=Counter();totals=Counter();summaries=[];pool={};fix=set()
    for obj,script in [(src,'capture_daemon_record720_fields.py'),(p,'probe_daemon_record720_fields.py'),(proofs,'prove_daemon_record720_fields.py')]:
        assert obj['generator_sha256']==sha(ROOT/script)
        for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h
    qs,lifts=obligations(src);assert lifts==proofs['source_lift_counts']
    for (name,expr),r in zip(qs,proofs['proofs'],strict=True):
        assert name==r['name']
        for key,query in [('original_file',expr),('file',z3.simplify(expr))]:
            path=ROOT/r[key];assert sha(path)==r['original_sha256'if key=='original_file'else'sha256'];v=z3.parse_smt2_file(str(path));s=z3.Solver();s.set(timeout=30000);s.add(*v);assert s.check()==z3.unsat;s=z3.Solver();s.set(timeout=30000);s.add(z3.Xor(z3.And(*v),query));assert s.check()==z3.unsat;counts['SMT_files_checked']+=1
        counts['source_proofs_rebuilt']+=1
    smt={r[k]for r in proofs['proofs']for k in ['file','original_file']};assert smt=={q.name for q in ROOT.glob('daemon_fields720_*.smt2')}
    parent=json.loads((ROOT/'daemon_record720_fingerprint_profiles.json').read_text());parents={r['case_index']:r for r in parent['cases']}
    for row,(c,cfg)in zip(p['cases'],cases(),strict=True):
        assert c==row['context']and cfg==row['configuration'];t=unpack(row);totals.update(replay(c,cfg,t));a,s=audit(c,t);counts.update(a);summaries.append(s)
        before=unpack(parents[c['extension']['parent_case_index']]);assert t['steps'][:len(before['steps'])]==before['steps']and t['events'][:len(before['events'])]==before['events'];counts['frozen_default_CPU_prefixes_matched']+=1
        for pc,r in t['source_pool'].items():assert IMAGE.read(int(pc,16),4).hex()==r['bytes_hex'];assert pc not in pool or pool[pc]==r;pool[pc]=r
        fix.update(int(a,16)for a in t['used_fixups']);counts['source_visits_checked']+=len(t['steps']);print(json.dumps({'fresh_cases':totals['fresh_cases_checked'],'A64_instructions':totals['A64_instructions_checked']}),flush=True)
    atomics=atomic_microchecks();counts.update(isolated_CASAL_cases_checked=len(atomics),source_lift_visits=sum(lifts.values()),original_fixups_checked=len(fix),distinct_original_opcodes_checked=len(pool),IDB_ranges=len(src['live_IDB_matches']),IDB_bytes=sum(r['size_bytes']for r in src['live_IDB_matches']))
    out={'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['daemon_record720_fields_source.json','daemon_record720_fields_proofs.json','daemon_record720_fields_profiles.json','replay_daemon_record720_fields.py','probe_daemon_record720_fields.py']},'verified_counts':dict(counts),'independent_A64_totals':dict(totals),'source_fixups':verify_used_fixups(fix),'isolated_CASAL_cases':atomics,'case_summaries':summaries,'all_checks_pass':True,'native_target_executed':False,'idb_mutated':False,'new_port_emission_established':False,'full_goal_complete':False};(ROOT/'daemon_record720_fields_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':dict(counts),'A64':dict(totals)}),flush=True)

if __name__=='__main__':main()
