#!/usr/bin/env python3
"""Rebuild source contracts, input components and independently replay every
release/reader case. O(profiles+visits+effects+solver resources) time;
O(profiles+largest mapped case+decoder cache) space. No native target execution.
"""
import json,hashlib
from collections import Counter
import z3
from daemon_receive_tools import ROOT,TABLE,IMAGE
from capture_daemon_record720 import sha
from capture_daemon_record720_release import capture
from capture_daemon_record720_handoff import source_inputs
from prove_daemon_record720_release import obligations
from probe_daemon_record720_release import cases
from replay_daemon_descriptor_producers import unpack
from replay_daemon_record720_release import replay,instruction
from daemon_digest_output_access import register_access,key
from recover_daemon_descriptor_producers import verify_used_fixups

def audit(c,t):
    F=int(c['SP'],16);P=int(c['allocation_owner_address'],16);U=int(c['logical_U64'],16);D=int(c['logical_D32'],16);events=t['events'];apis=t['API_models'];out=Counter();snap={s['pc']:s for s in t['ABI_snapshots']};free=[m for m in apis if m['binding']['symbol']=='_free'];h=c['extension']['payload_hex']
    def event(pc,kind):
        r=[e for e in events if e['pc']==hex(pc)and e['kind']==kind];assert len(r)==1,(hex(pc),len(r));return r[0]
    def value(e):return int.from_bytes(bytes.fromhex(e.get('after_hex',e.get('bytes_hex'))),'little')
    if '0x1003e54a4'in snap:
        s=snap['0x1003e54a4'];SP=int(s['SP'],16);FP=int(s['known_GPRs']['x29'],16);A=FP-0xa8;K=(((A&0xffffffff)^0xe732d262)*0xba209ef7)&0xffffffff
        assert int(s['known_GPRs']['x26'],16)==0x1fc1 and int(s['known_GPRs']['x21'],16)==D^0x8b3dc651
        for pc,off,n,expected in [(0x1003e5558,0,4,(0x80d1-K)&0xffffffff),(0x1003e5578,8,8,U),(0x1003e5580,0x18,8,SP+0x324),(0x1003e5570,0x20,8,SP+0x278),(0x1003e5594,0x28,4,(D+0x67ac8198-K)&0xffffffff),(0x1003e5560,0x30,8,SP+0x21c),(0x1003e5568,0x38,8,SP+0x1a4)]:
            e=event(pc,'write');assert int(e['address'],16)==A+off and e['size_bytes']==n and value(e)==expected;out['reader_record_fields_checked']+=1
        guard=event(0x10044ddcc,'read');I=(value(guard)+0xaf506591)&0xffffffff;assert I==0 and D!=0
        edge=next(e for e in t['edges']if e['pc']=='0x10044dea8');assert edge['slot']==hex(TABLE+0x80e4*8);out['reader_count_guards_checked']+=1
    if free:
        assert len(free)==1 and free[0]['pc']=='0x1001c6100'and free[0]['arguments1']==[hex(P)];assert hex(P)not in t['allocated_owners']and not any(t['allocation_defined_mask720'])
        rd=[e for e in events if e['kind']=='read'and P<=int(e['address'],16)<P+720];assert len(rd)==1 and rd[0]['pc']=='0x100260f18'and int(rd[0]['address'],16)==P+0x2c0 and rd[0]['size_bytes']==8 and value(rd[0])==0
        sw=[e for e in events if e['kind']=='write'and P<=int(e['address'],16)<P+720];assert len(sw)==75
        dec=event(0x100435d00,'read');R=int(snap['0x100435cd8']['known_GPRs']['x19'],16);K=(((R&0xffffffff)^0xb5da7ac1)*0x5de29be3)&0xffffffff;assert int(dec['address'],16)==R+16 and(value(dec)+K)&0xffffffff==0xbbb3;assert value(event(0x100435d08,'read'))==P
        result=event(0x100270ac4,'write');assert int(result['address'],16)==R and value(result)==0x364c5349
        assert t['boundary']['pc']=='0x100b90ef4'and int(t['boundary']['detail']['address'],16)==F+0x24f8
        tainted={'x'+str(j)for j in range(18)}|{'nzcv'};after=False
        for pc,raw in t['steps']:
            if pc==0x1001c6100:after=True;continue
            if not after:continue
            i=instruction(pc);rr,ww=register_access(i);assert not any(key(i.reg_name(r))in tainted for r in rr),(hex(pc),'volatile after free')
            tainted.difference_update(key(i.reg_name(r))for r in ww)
        out['source_free_requests_checked']+=1;out['retired_owner_masks_checked']+=1;out['void_call_liveness_paths_checked']+=1
    elif h is None:
        assert U!=0 and D!=0 and t['boundary']['pc']=='0x100315ae8'and int(t['boundary']['detail']['address'],16)==U;assert t['boundary']['detail']['size_bytes']==1;out['unowned_input_frontiers_preserved']+=1
    else:
        assert h in ['3000','3003020101','3000020101']and t['boundary']['pc']=='0x10040f7e0';s=snap['0x100478ef4'];T=int(s['known_GPRs']['x1'],16);assert int(s['known_GPRs']['x8'],16)==0x10040f7a4
        edge=next(e for e in t['edges']if e['pc']=='0x100478ef4');assert edge['kind']=='blraaz'and edge['slot']=='0x1010389a8'and edge['modifier']=='0x0'
        data={}
        for e in events:
            if e['kind']=='write':
                for j,b in enumerate(bytes.fromhex(e['after_hex'])):
                    a=int(e['address'],16)+j
                    if T<=a<T+32:data[a]=b
        for off,n,expected in [(0,4,0x21e8ae12),(4,4,(3 if h=='3003020101'else 0)^0x8b3dc651),(8,8,U+2),(16,4,(5 if h=='3003020101'else 2)^0x8b3dc651),(24,8,U)]:
            assert int.from_bytes(bytes(data[T+off+j]for j in range(n)),'little')==expected;out['callback_record_fields_checked']+=1
        assert len(data)==28 and all(T+j not in data for j in range(20,24));out['zero_modifier_callbacks_checked']+=1
    if not free:assert sum(t['allocation_defined_mask720'])==161 and not any(e['kind']=='read'and P<=int(e['address'],16)<P+720 for e in events)
    if h is not None:
        b=bytes.fromhex(h);reads=[e for e in events if e['kind']=='read'and U<=int(e['address'],16)<U+len(b)];assert reads and all(bytes.fromhex(e['bytes_hex'])==b[int(e['address'],16)-U:int(e['address'],16)-U+e['size_bytes']]for e in reads)
        assert not any(e['kind']=='write'and U<=int(e['address'],16)<U+len(b)for e in events);out['borrowed_input_spans_checked']+=1;out['borrowed_byte_reads_checked']+=len(reads)
    return out

def main():
    src=json.loads((ROOT/'daemon_record720_release_source.json').read_text());assert src==capture();p=json.loads((ROOT/'daemon_record720_release_proofs.json').read_text());qs,counts=obligations(src);assert counts==p['source_lift_counts']and len(qs)==len(p['proofs'])==22
    for(name,f),r in zip(qs,p['proofs']):
        assert name==r['name'];s=z3.Solver();s.set(timeout=30000);s.add(f);assert str(s.check())=='unsat'
        for fk,hk in [('file','sha256'),('original_file','original_sha256')]:
            path=ROOT/r[fk];assert sha(path)==r[hk];s=z3.Solver();s.set(timeout=30000);s.from_file(str(path));assert str(s.check())=='unsat'
    prof=json.loads((ROOT/'daemon_record720_release_profiles.json').read_text());assert prof['generator_sha256']==sha(ROOT/'probe_daemon_record720_release.py')
    for n,h in prof['dependencies'].items():assert sha(ROOT/n)==h
    expected=list(cases());assert len(expected)==len(prof['cases'])==768;totals=Counter();semantic=Counter();fix=set();pool={};front=Counter();input_keys=set()
    for j,(r,(c,cfg))in enumerate(zip(prof['cases'],expected)):
        assert r['context']==c and r['configuration']==cfg;t=unpack(r);assert len(t['steps'])==r['source_visits'];semantic.update(audit(c,t));totals.update(replay(c,cfg,t));fix.update(int(a,16)for a in t['used_fixups']);pool.update({a:v['bytes_hex']for a,v in t['source_pool'].items()});front[t['boundary']['pc']]+=1
        keyin=(int(c['SP'],16),int(c['logical_U64'],16),int(c['logical_D32'],16))
        if keyin not in input_keys:
            F,U,D=keyin;header=(U^0x9898989898989898).to_bytes(8,'big')+(D^0x98989898).to_bytes(4,'big');out=source_inputs(F,header);assert hashlib.sha256(json.dumps(out,sort_keys=True,separators=(',',':')).encode()).hexdigest()==c['input_producer_sha256'];input_keys.add(keyin);semantic['fresh_input_producers_checked']+=1;semantic['input_fragment_source_visits_checked']+=out['source_visits']
        if(j+1)%64==0:print(json.dumps({'independent_cases':j+1,'A64_instructions':totals['A64_instructions_checked']}),flush=True)
    assert front=={'0x100b90ef4':384,'0x100315ae8':192,'0x10040f7e0':192};original=verify_used_fixups(fix)
    for a,b in pool.items():assert IMAGE.read(int(a,16),4).hex()==b
    verified={'source_proofs_rebuilt':len(qs),'SMT_files_checked':len(qs)*2,'source_lift_visits':sum(counts.values()),'main_source_visits':sum(r['source_visits']for r in prof['cases']),'distinct_original_opcodes_checked':len(pool),'original_fixups_checked':len(original['records']),'IDB_ranges':len(src['live_IDB_matches']),'IDB_bytes':sum(r['size_bytes']for r in src['live_IDB_matches']),'IDB_normalized_pointer_fields':sum(len(r['normalized_fields'])for r in src['live_IDB_matches']),'exhaustive_byte_banks':len(src['exhaustive_banks']),**dict(semantic)}
    result={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['daemon_record720_release_source.json','daemon_record720_release_profiles.json','daemon_record720_release_proofs.json','daemon_record720_release_replay.py','replay_daemon_record720_release.py','capture_daemon_record720_release.py','prove_daemon_record720_release.py','probe_daemon_record720_release.py']},'verified_counts':verified,'independent_A64_totals':dict(totals),'frontier_counts':dict(front),'original_fixups':original,'source_pool':pool,'native_target_executed':False,'idb_mutated':False,'registry_publication_established':False,'new_port_emission_established':False,'full_goal_complete':False,'all_checks_pass':True};(ROOT/'daemon_record720_release_checks.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'verified_counts':verified,'independent_A64_totals':dict(totals),'frontiers':dict(front)}),flush=True)
if __name__=='__main__':main()
