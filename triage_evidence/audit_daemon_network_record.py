#!/usr/bin/env python3
"""Independent record/source replay, initializer lifetime and cut-state audit.

O(receipts+visits*(register state+byte effects)+source+queries) time/space;
30 s/query. Native APIs/IPC, allocation/free and hardware PAC do not run.
"""
import json,subprocess
from pathlib import Path
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_daemon_network_identity import Lift as ParentLift
from audit_daemon_pidpath_consumer import bytes_at
from audit_daemon_return_bank_origins import UpstreamReplay
import recover_daemon_network_record as R

class Lift(ParentLift):
    def __init__(self,c):
        super().__init__(c)
        if c['entry_PC']=='0x1005a8cd4':
            p=json.loads(read(ROOT/'daemon_network_identity_checks.json'))
            matches=[r['trace'] for r in p['retained_cases'] if r['trace']['boundary']['registers31']==c['entry_registers31']
                     and r['trace']['boundary']['SP']==c['caller_SP'] and r['trace']['boundary_NZCV']==c['entry_NZCV']]
            assert len(matches)==1
            reads=[r for r in matches[0]['source_reads'] if int(r['address'],16) in FIXUPS
                   and FIXUPS[int(r['address'],16)]['kind'].startswith('auth-')]
            r=reads[-1];slot=int(r['address'],16);target=int.from_bytes(bytes.fromhex(r['bytes_hex']),'little')
            assert slot==R.TABLE+8*0x58d7 and FIXUPS[slot]['target']==target==0x100473d54
            self.last_authenticated_load=(slot,target);self.counts['authenticated_entry_origins_checked']+=1

    def integer(self,x):
        value=super().integer(x)
        if self.pc in [0x10084ac6c,0x1008b3140]:
            index,off=(0x4ca,0x2a60) if self.pc==0x10084ac6c else (0x100b,0x4bb0)
            slot=R.TABLE+8*index;target=FIXUPS[slot]['target']
            if value==target:
                s=int(self.c['caller_SP'],16);saved=z3.Concat(*[self.bytes[s+off+j] for j in range(7,-1,-1)])
                assert self.projected(saved)==target;self.last_authenticated_load=(slot,target)
                self.counts['saved_continuation_origins_checked']+=1
        return value

    def one(self,i):
        if i.mnemonic=='paciza':return
        return super().one(i)

class Initializer(UpstreamReplay):
    def code(self,u,a,n,d):
        if self.seq==len(self.steps):
            s=int(self.p['frame_base'],16)
            for off,(value,pc) in (R.ROOTS|R.FOLLOW_ROOTS).items():
                assert int.from_bytes(u.mem_read(s+off,8),'little')==value
                self.counts['new_live_root_cells_checked']+=1
        return super().code(u,a,n,d)

def fixture_bytes(row,kind):
    return {int(f['address'],16)+j:b for f in row['initial_'+kind+'_fixtures'] for j,b in enumerate(bytes.fromhex(f['bytes_hex']))}

def state_bytes(row):
    out=fixture_bytes(row,'private')|fixture_bytes(row,'image')
    for w in row['source_writes']:out.update({int(w['address'],16)+j:b for j,b in enumerate(bytes.fromhex(w['after_hex']))})
    return out

def join(before,after,effects=(),same_registers=True):
    if same_registers:
        assert before['boundary']['registers31']==after['entry_registers31'] and before['boundary_NZCV']==after['entry_NZCV']
    assert before['boundary']['SP']==after['caller_SP']
    expected=state_bytes(before)
    for f in effects:expected.update({int(f['address'],16)+j:b for j,b in enumerate(bytes.fromhex(f['bytes_hex']))})
    assert expected==fixture_bytes(after,'private')|fixture_bytes(after,'image')

def interfaces(e):
    parent=json.loads(read(ROOT/'daemon_network_identity_checks.json'));parents={c['parent_case_index']:c for c in parent['retained_cases']}
    starts={};counts=Counter()
    for c in e['conditional_cases']:
        before=parents[c['parent_case_index']]['trace']
        s=int(before['caller_SP'],16)
        saved=[w for w in before['source_writes'] if w['address']==hex(s+0x4bb0)]
        assert len(saved)==1 and saved[0]['pc']=='0x100505a70' and saved[0]['after_hex']==(0x100671718).to_bytes(8,'little').hex()
        for row,effect in zip(c['intervals'],c['root_premises']):
            assert before['boundary']['pc']==row['entry_PC'] and before['boundary']['kind']=='before_unknown_private_read'
            d=before['boundary']['detail'];assert d['address']==effect['address'] and d['snapshot']['known_mask_hex']==effect['before_known_mask_hex']=='00'*8
            join(before,row,[effect]);before=row;counts['additional_root_joins']+=1
        calls=[call for row in c['intervals'] for call in row['source_calls']]
        saved=[w for row in c['intervals'] for w in row['source_writes'] if w['address']==hex(s+0x2a60)]
        assert len(saved)==1 and saved[0]['pc']=='0x1004dbe04' and saved[0]['after_hex']==(0x100752244).to_bytes(8,'little').hex()
        assert [(call['pc'],call['target']) for call in calls]==[(hex(R.CALL),hex(R.ENTRY)),(hex(R.NETWORK_CALL),hex(R.Parent.ENTRY))]
        s=int(c['intervals'][0]['caller_SP'],16);assert calls[0]['arguments8'][0]==hex(s+0x10cb8)
        assert calls[1]['arguments8'][0]==hex(s-0x6e) and calls[1]['SP']==hex(s-0x70)
        starts[c['parent_case_index']]=before
    return starts,counts

def consumers(e,starts,counts):
    outputs=[]
    for c in e['cold_cases']:
        row=c['trace'];before=starts[c['parent_case_index']]
        join(before,row,[{'address':hex(R.Parent.CACHE),'bytes_hex':'00'}])
        s=int(before['boundary']['SP'],16)+0x70;b=row['boundary']
        assert b['pc']=='0x1000040d8' and b['detail']['symbol']=='IOKit/_IOMainPort'
        assert b['SP']==hex(s-0xb0) and b['registers31'][:2]==['0x0',hex(s-0xb0)]
        counts['cold_main_port_joins']+=1
    for c in e['warm_cases']:
        row=c['trace'];before=starts[c['parent_case_index']];data=bytes.fromhex(c['configuration']['MAC6_hex']);flag=c['configuration']['network_flag8']
        additions=[{'address':hex(R.Parent.CACHE),'bytes_hex':(bytes([flag])+data).hex()},
                   {'address':hex(R.RECORD-4),'bytes_hex':(b'\xa5'*4+b'\xee'*10+b'\x5a'*4).hex()}]
        join(before,row,additions);assert row['entry_PC']==hex(R.Parent.ENTRY) and row['boundary']['pc']==hex(R.AFTER_CALL)
        current=state_bytes(row);assert bytes(current[R.RECORD+j] for j in range(10))==bytes.fromhex(c['record10_hex'])==b'\x06\0\0\0'+data
        assert bytes(current[R.RECORD-4+j] for j in range(4))==b'\xa5'*4 and bytes(current[R.RECORD+10+j] for j in range(4))==b'\x5a'*4
        s=int(row['boundary']['SP'],16);assert bytes(current[s+0x10cb8+j] for j in range(8))==R.RECORD.to_bytes(8,'little')
        path=s+0xc070+c['configuration']['cursor64']+32
        assert not any(int(x['address'],16)<path+1024 and path<int(x['address'],16)+x['size_bytes']
                       for r in [row,*c['continuation']['intervals']] for x in r['source_reads'])
        assert len(row['source_calls'])==1 and row['source_calls'][0]['pc']=='0x1002680d4'
        assert row['source_calls'][0]['target']=='0x10046f89c' and row['source_calls'][0]['arguments8'][:3]==[hex(s-0x6e),hex(R.RECORD+4),'0x6']
        before=row;follow=c['continuation'];join(before,follow['intervals'][0]);before=follow['intervals'][0]
        for j,(after,effect) in enumerate(zip(follow['intervals'][1:],follow['root_premises'])):
            assert before['boundary']['detail']['snapshot']['known_mask_hex']==effect['before_known_mask_hex']=='00'*8
            additions=[effect]+(follow['additional_image_premises'] if j==1 else [])
            assert before['boundary']['detail']['address']==effect['address'];join(before,after,additions);before=after;counts['additional_root_joins']+=1
        assert follow['additional_image_premises']==[{'address':'0x1010b66a8','bytes_hex':'00'*8,'provenance':'separate_acquisition_controller_image_premise'}]
        counts['additional_controller_image_joins']+=1
        b=before['boundary'];assert b['pc']==hex(R.ONCE) and b['detail']['symbol']=='libSystem/_pthread_once'
        assert b['registers31'][:2]==['0x1010b8cd0','0x10040ebd4'] and b['registers31'][19]=='0x0' and b['registers31'][26]=='0x593d'
        preserved=[w for after in follow['intervals'] for w in after['source_writes'] if w['pc']=='0x1004f7464']
        assert len(preserved)==1 and preserved[0]['address']==hex(s+0x998) and preserved[0]['after_hex']==R.RECORD.to_bytes(8,'little').hex()
        counts['warm_record_joins']+=1;outputs.append({'MAC6_hex':data.hex(),'flag8':flag,'record_pointer64':hex(R.RECORD),'pending_once':hex(R.ONCE)})
    for c in e['zero_cases']:
        before=starts[c['parent_case_index']];row=c['trace'];event=c['return_premise']
        join(before,row,same_registers=False)
        assert row['entry_registers31']==event['return_registers31'] and row['entry_NZCV']==event['return_NZCV']
        assert row['entry_registers31'][18:30]==before['boundary']['registers31'][18:30]
        assert row['entry_registers31'][0]=='0x0' and row['entry_registers31'][30]==hex(R.AFTER_NETWORK)
        assert event['separate_internal_component_return_premise'] and not event['component_output_effects_modeled'] and not event['native_API_executed']
        assert row['entry_PC']==hex(R.AFTER_NETWORK) and row['boundary']['pc']==hex(R.AFTER_CALL)
        assert len(row['source_writes'])==1 and row['source_writes'][0]['pc']=='0x10020eb48' and row['source_writes'][0]['after_hex']=='00'*8
        suffix=c['suffix'];join(row,suffix);assert suffix['boundary']['pc']=='0x100671718' and not suffix['source_calls']
        assert len(suffix['source_writes'])==1 and suffix['source_writes'][0]['pc']=='0x10084ac60'
        cfg=row['configuration'];assert int.from_bytes(bytes.fromhex(suffix['source_writes'][0]['after_hex']),'little')==cfg['cursor64']+0x420
        counts['zero_return_and_restoration_joins']+=1
    return {'warm_outputs':outputs,'verified_counts':dict(counts)}

def sdk_checks():
    code='''#include <pthread.h>
_Static_assert(sizeof(void*)==8 && sizeof(int)==4,"widths");
_Static_assert(sizeof(pthread_once_t)==16,"current_once_control_size");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_once),int(*)(pthread_once_t*,void(*)(void))),"once_prototype");
int network_record_once_probe(pthread_once_t *control,void (*callback)(void)) {return pthread_once(control,callback);}
'''
    cmd=['xcrun','clang','-target','arm64e-apple-macos14','-std=c11','-S','-O1','-x','c','-','-o','-']
    p=subprocess.run(cmd,input=code,text=True,capture_output=True,timeout=30);assert p.returncode==0 and not p.stderr,p.stderr
    assert '_pthread_once' in p.stdout
    sdk=Path(subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip())
    return {'command':cmd,'source':code,'assembly':p.stdout,'exit_code':0,
            'headers':[{'SDK_relative_header':n,'sha256':sha(sdk/n)} for n in ['usr/include/pthread.h','usr/include/pthread/pthread.h','usr/include/sys/_pthread/_pthread_types.h']],
            'scope':'Compile-only current arm64e ABI comparison; historical once implementation/control extent and native pairing unknown.',
            'native_API_executed':False,'emitted_object':False}

def build():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e['generator_sha256']==sha(R.__file__)
    assert e['dependencies']=={n:sha(ROOT/n) for n in R.DEPS}
    counts=Counter();lifts=[]
    for j,row in enumerate(R.intervals(e)):
        result=Lift(row).run();result['interval_index']=j;lifts.append(result);counts.update(result['verified_counts'])
    init=json.loads(read(ROOT/'daemon_return_bank_origins_checks.json'));runs=[];totals=Counter()
    for j,c in enumerate(init['upstream_cases']):
        for pattern in [0,3]:
            result=Initializer(c,pattern).run();result['profile_index']=j;runs.append(result);totals.update(result['verified_counts'])
    assert e['root_writer_evidence']==R.root_evidence() and e['source_regions']==R.source() and e['bank_rules']==R.banks()
    starts,joins=interfaces(e);consumer=consumers(e,starts,joins)
    assert len(R.obligations())==len(e['source_proofs'])==8
    for q in e['source_proofs']:
        s=z3.Solver();s.set(timeout=30000);s.from_string(q['query']);assert s.check()==z3.unsat and q['premises_nonvacuous']
    return {'scope':__doc__,'generator_sha256':sha(R.__file__),'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
            'source_sha256':sha(SOURCE),'dependencies':e['dependencies'],'verified_counts':e['verified_counts'],
            'independent_lifts':lifts,'independent_totals':dict(counts),'initializer_lifts':runs,'initializer_totals':dict(totals),
            'consumer_interfaces':consumer,'source_queries_unsat':8,'SDK_checks':sdk_checks(),
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'native_epoch_join_established':False,
            'full_goal_complete':False,'all_checks_pass':True}

if __name__=='__main__':
    e=build();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps({'new':e['independent_totals'],'initializer':e['initializer_totals']}),flush=True)
