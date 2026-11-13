#!/usr/bin/env python3
"""Independent source replay, cached-path/record/seed joins and failure reseal.

O(receipts+visits*(register state+byte effects)+query DAG) time/space;
solver work separate, 30 s/query. Native APIs/IPC/PAC remain unexecuted.
"""
import json,subprocess
from pathlib import Path
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,TABLE
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_daemon_context_unseal import Lift as ParentLift
from audit_daemon_environment_outputs import Lift as BaseLift,DEC
from audit_daemon_network_record import Lift as RecordLift,fixture_bytes,state_bytes,join
from audit_daemon_return_bank_origins import UpstreamReplay
from recover_daemon_return_bank_origins import Algebra
from lskd_values_symbolic import mem,cell
from validate_daemon_context_seal import encode
import recover_daemon_context_state_publish as R

class Lift(ParentLift):
    def __init__(self,c):
        super().__init__(c);self.retained_X5_origin=None;self.retained_memory_origins={};self.loaded_X5_origin=None

    def store(self,a,n,value,pc):
        at=self.projected(a)
        for k in list(self.retained_memory_origins):
            if at<k+8 and k<at+n:del self.retained_memory_origins[k]
        i=next(DEC.disasm(IMAGE.read(pc,4),pc))
        if n==8 and self.retained_X5_origin and i.mnemonic=='str' and i.reg_name(i.operands[0].reg)=='x5':
            assert self.projected(value)==self.retained_X5_origin[1]
            self.retained_memory_origins[at]=self.retained_X5_origin;self.counts['retained_X5_pointer_stores_checked']+=1
        return super().store(a,n,value,pc)

    def load(self,a,n):
        value=super().load(a,n)
        if self.pc==0x1005da0a0:
            assert n==8;at=self.projected(a);origin=self.retained_memory_origins.get(at)
            assert origin and self.projected(value)==origin[1]
            self.loaded_X5_origin=origin;self.counts['retained_X5_pointer_reloads_checked']+=1
        return value

    def one(self,i):
        if any(i.reg_name(r) in ['x5','w5'] for r in i.regs_access()[1]):self.retained_X5_origin=None
        out=super().one(i)
        if i.address==0x10051c01c:
            assert i.mnemonic=='ldr' and i.reg_name(i.operands[0].reg)=='x5'
            assert self.last_authenticated_load==(0x10103d758,0x1005d21d4)
            self.retained_X5_origin=self.last_authenticated_load
        if i.address==0x1005da0a0:
            assert i.mnemonic=='ldr' and i.reg_name(i.operands[0].reg)=='x5'
            self.retained_X5_origin=self.loaded_X5_origin
        return out

    def integer(self,x):
        if self.pc==0x1006eab3c:
            value=BaseLift.integer(self,x)
            if value==0x1005d21d4:
                assert self.retained_X5_origin==(0x10103d758,value)
                self.last_authenticated_load=self.retained_X5_origin;self.counts['retained_X5_origins_checked']+=1
            return value
        if self.pc in [0x10084ac6c,0x1008b3140,0x100831198,0x10079af60]:
            # These returns can occur after the adapter restores SP. The
            # interval-entry SP can still be inside its 112-byte frame.
            value=BaseLift.integer(self,x)
            index,off={0x10084ac6c:(0x4ca,0x2a60),0x1008b3140:(0x100b,0x4bb0),
                       0x100831198:(0x86a,0x9110),0x10079af60:(0x5e,0x4ec8)}[self.pc]
            slot=TABLE+8*index;target=FIXUPS[slot]['target']
            if value==target:
                s=BaseLift.integer(self,self.read('sp'))
                saved=z3.Concat(*[self.bytes[s+off+j] for j in range(7,-1,-1)])
                assert self.projected(saved)==target;self.last_authenticated_load=(slot,target)
                if self.pc==0x10079af60:self.saved_continuation_fixup=(slot,target)
                self.counts['dynamic_SP_saved_continuation_origins_checked']+=1
            return value
        return super().integer(x)

class Initializer(UpstreamReplay):
    def code(self,u,a,n,d):
        if self.seq==len(self.steps):
            s=int(self.p['frame_base'],16)
            for off,(value,pc) in R.ROOTS.items():
                assert int.from_bytes(u.mem_read(s+off,8),'little')==value
                self.counts['new_live_root_cells_checked']+=1
        return super().code(u,a,n,d)

def return_join(before,event,after,effects=()):
    assert event['call_site']==before['boundary']['pc'] and event['symbol']==before['boundary']['detail']['symbol']
    assert after['entry_PC']==event['continuation_PC']==hex(int(event['call_site'],16)+4)
    assert after['entry_registers31']==event['return_registers31'] and after['entry_NZCV']==event['return_NZCV']
    assert after['entry_Q_registers32']==event['return_Q_registers32']
    assert after['entry_registers31'][18:30]==before['boundary']['registers31'][18:30]
    assert int(after['entry_registers31'][30],16)==int(event['call_site'],16)+4
    for j in range(8,16):assert int(after['entry_Q_registers32'][j],16)&((1<<64)-1)==int(before['boundary']['Q_registers32'][j],16)&((1<<64)-1)
    assert event['ABI_return_and_output_premise'] and not event['native_API_executed']
    join(before,after,effects,same_registers=False)

def interfaces(e):
    p=json.loads(read(ROOT/'daemon_context_lock_use_checks.json'));counts=Counter();D=R.Parent.Parent.D
    for c in e['cases']:
        before=p['allocation_cases'][c['parent_allocation_case_index']]['intervals'][-1];initial=state_bytes(before)
        s=int(before['caller_SP'],16);rows=c['intervals'];result=int(c['second_pointer_return64'],16);retired=False
        for row,t in zip(rows,c['transitions']):
            ev=t['import_return']
            if ev:return_join(before,ev,row,t['effects']);counts['import_return_joins']+=1
            else:
                join(before,row,t['effects']);assert before['boundary']['Q_registers32']==row['entry_Q_registers32']
                assert before['boundary']['pc']==row['entry_PC'];d=before['boundary']['detail']
                assert before['boundary']['kind']=='before_unknown_private_read' and d['snapshot']['known_mask_hex']=='00'*8
                assert t['effects'][0]['address']==d['address'];counts['additional_root_joins']+=1
            owners=before['foreign_owners'].copy()
            if ev and ev.get('allocated_owner_premise'):owners.append({'address':hex(result),'size_bytes':21})
            if ev and ev.get('retired_owner_premise'):
                assert ev['retired_owner_premise']=={'address':hex(R.Parent.ALLOC),'size_bytes':21}
                owners.remove({'address':hex(R.Parent.ALLOC),'size_bytes':21});retired=True;counts['declared_owner_retirements']+=1
            assert owners==row['foreign_owners']
            if retired:
                for x in row['source_reads']+row['source_writes']:
                    a=int(x['address'],16);assert not(a<R.Parent.ALLOC+21 and R.Parent.ALLOC<a+x['size_bytes'])
            before=row
        assert rows[0]['source_writes'][0]['pc']==hex(R.ENTRY) and rows[0]['source_writes'][0]['address']==hex(D+0x10)
        assert int.from_bytes(bytes.fromhex(rows[0]['source_writes'][0]['after_hex']),'little')==result
        counts['full_pointer_publications']+=1
        final=state_bytes(rows[-1]);assert bytes(final[D+j] for j in range(552)).hex()==c['final_context_hex']
        if not result:
            raw=bytes(initial[D+j] for j in range(552));assert raw[0x10:0x18]==bytes(8)
            assert bytes.fromhex(c['final_context_hex'])==encode(raw,0x78396e8d)
            assert int(c['final_reference64'],16)==R.Parent.Parent.reference_encode(D,0xc41c69cd)
            pub=[w for r in rows for w in r['source_writes'] if w['address']==hex(R.Parent.Parent.CELL)]
            assert len(pub)==1 and pub[0]['pc']=='0x1009a2014'
            seal=rows[5];writes=[w for w in seal['source_writes'] if D<=int(w['address'],16)<D+552]
            assert sum(w['size_bytes'] for w in writes)==2184
            assert all(w['source_visit_index']<pub[0]['source_visit_index'] for w in writes)
            imports=[r['boundary']['detail']['symbol'] for r in rows[:-1]]
            assert imports==['libSystem/_free','libSystem/_pthread_once','libSystem/_pthread_rwlock_unlock',
                'libSystem/_pthread_once','libSystem/_pthread_rwlock_wrlock','libSystem/_pthread_once','libSystem/_pthread_rwlock_unlock']
            assert rows[2]['boundary']['registers31'][0]=='0x6600001000' and rows[4]['boundary']['registers31'][0]=='0x1010b7478'
            assert rows[6]['boundary']['registers31'][0]=='0x1010b7478'
            assert rows[-1]['boundary']['pc']==hex(R.STOP) and rows[-1]['boundary']['detail']['snapshot']['known_mask_hex']=='00'*8
            counts.update(failure_reseal_context_checks=1,encoded_reference_publications=1,reseal_context_write_bytes=2184)
        else:
            assert not retired and c['final_reference64']==hex(D)
            assert bytes(final[R.B+j] for j in range(21))==R.Parent.PATH==bytes.fromhex(c['decoded_path_hex'])
            assert int.from_bytes(bytes(final[D+0x10+j] for j in range(8)),'little')==R.B
            assert bytes(final[D+0x1c+j] for j in range(4))==b'\6\0\0\0'
            mac=bytes.fromhex(c['MAC6_premise_hex']) if c['MAC6_premise_hex'] else bytes(6)
            assert bytes(final[D+0x20+j] for j in range(6))==mac
            copies=[w for r in rows for w in r['source_writes'] if w['pc']=='0x10059ccd8']
            reads=[x for r in rows for x in r['source_reads'] if x['pc']=='0x10059ccd4']
            assert [x['address'] for x in reads]==[hex(R.RECORD+4+j) for j in range(5,-1,-1)]
            assert [x['address'] for x in copies]==[hex(D+0x20+j) for j in range(5,-1,-1)]
            assert [w['after_hex'] for w in copies]==[x['bytes_hex'] for x in reads]
            pathwrites=[w for r in rows for w in r['source_writes'] if R.B<=int(w['address'],16)<R.B+21]
            assert len(pathwrites)==22 and all(w['size_bytes']==1 for w in pathwrites)
            assert [w['pc'] for w in pathwrites]==['0x1004d4cac']*20+['0x1005c3d98','0x100597960']
            assert [int(w['address'],16)-R.B for w in pathwrites]==list(range(21))+[20]
            assert not any(R.B<=int(x['address'],16)<R.B+21 for r in rows for x in r['source_reads'])
            assert rows[-1]['boundary']['pc']==hex(R.ARC)
            context=[w for r in rows for w in r['source_writes'] if D<=int(w['address'],16)<D+552]
            assert len(context)==23 and sum(w['size_bytes'] for w in context)==126
            defaults={0x1d8:(4,0),0x158:(8,0xe3b88695c0d52dbc),0x168:(4,0x0912f04b),
                      0x190:(8,0xfffffffffffffffb),0x198:(8,0xe3b88695c0d52dbc),0x1d0:(8,0xfffffffffffffffb),0x1a8:(4,0x0912f04b)}
            for off in list(range(0x170,0x190,8))+list(range(0x1b0,0x1d0,8)):defaults[off]=(8,0)
            for off,(n,value) in defaults.items():assert int.from_bytes(bytes(final[D+off+j] for j in range(n)),'little')==value
            counts.update(successful_path_decodes=1,decoded_path_write_events=22,decoded_path_bytes=21,context_network_count_copies=1,context_network_data_bytes=6,raw_context_write_bytes=126,descriptor_default_fields_checked=len(defaults))
    for c in e['entropy_cases']:
        before=e['cases'][c['parent_case_index']]['intervals'][-1];row=c['intervals'][0];return_join(before,c['import_return'],row)
        seed=int(c['random_return32'],16);ws=[w for w in row['source_writes'] if 0x1010c784c<=int(w['address'],16)<0x1010c784c+2496]
        assert len(ws)==624 and [w['address'] for w in ws]==[hex(0x1010c784c+4*j) for j in range(624)]
        assert all(w['size_bytes']==4 for w in ws) and ws[0]['pc']=='0x100a8c0c4' and all(w['pc']=='0x100ab75a8' for w in ws[1:])
        values=[int.from_bytes(bytes.fromhex(w['after_hex']),'little') for w in ws];assert values[0]==seed
        for j in range(1,624):assert values[j]==((values[j-1]^(values[j-1]>>30))*1812433253+j)&0xffffffff
        other=[w for w in row['source_writes'] if w not in ws];assert len(other)==1 and other[0]['pc']=='0x100b4daec' and other[0]['after_hex']=='70020000'
        b=row['boundary'];assert b['pc']==hex(R.CLOCK) and int(b['registers31'][0],16)==int(b['SP'],16)+0x230 and b['registers31'][1]=='0x0'
        counts.update(random_return_joins=1,generator_state_words_checked=624,generator_state_bytes_checked=2496,pending_clock_boundaries=1)
    return {'verified_counts':dict(counts),'scope':'Local source composition under separate import, metadata, owner and root premises; native reachability, exclusion and transport remain unknown.'}

def obligations():
    qs=[]
    def prove(name,bad):
        q=z3.Solver();q.set(timeout=30000);assert q.check()==z3.sat;q.add(bad);assert q.check()==z3.unsat,name
        qs.append({'label':name,'query':q.to_smt2(),'premises_nonvacuous':True,'result':'unsat'})
    ptr=z3.BitVec('csp_pointer64',64);v=Algebra();v.seed('x0',ptr);v.seed('x22',0x6500115b20);v.run_block(R.ENTRY,R.ENTRY+12)
    prove('all_u64_second_pointer_published_before_NULL_selection',z3.Or(cell(v,0x6500115b30,8)!=ptr,v.read('w8')!=z3.If(ptr==0,z3.BitVecVal(1,32),z3.BitVecVal(0,32))))
    byte=z3.BitVec('csp_encoded8',8);v=Algebra();v.seed('x20',R.Parent.ALLOC);v.seed('x0',R.B);v.seed('x10',0);mem(v,R.Parent.ALLOC,1,byte)
    v.run_block(0x1004d4ca0,0x1004d4cb0);prove('all_byte_original_path_decode_is_XOR_98',cell(v,R.B,1)!=(byte^0x98))
    v=Algebra();v.seed('x4',6);v.seed('x20',R.RECORD+4);v.seed('x27',0x6500115b40);mem(v,R.RECORD+9,1,byte)
    v.run_block(0x10059ccd0,0x10059ccdc);prove('original_reverse_copy_preserves_arbitrary_network_byte',cell(v,0x6500115b45,1)!=byte)
    count=z3.BitVec('csp_count32',32);v=Algebra();v.seed('sp',0x6800060000);v.seed('x22',0x6500115b20)
    mem(v,0x6800060998,8,R.RECORD);mem(v,R.RECORD,4,count);v.run_block(0x100597974,0x100597980)
    prove('all_u32_network_record_count_published_without_conversion',cell(v,0x6500115b3c,4)!=count)
    previous,index=z3.BitVecs('csp_previous32 csp_index32',32);v=Algebra();v.seed('w0',previous);v.seed('w8',index);v.seed('w12',1812433253)
    v.run_block(0x100ab7598,0x100ab75a4);prove('all_u32_original_generator_seed_recurrence',v.read('w0')!=((previous^z3.LShR(previous,30))*1812433253+index))
    upper=z3.BitVec('csp_unspecified_upper32',32);v=Algebra();v.seed('x0',z3.Concat(upper,previous));v.seed('x20',0x1010c784c)
    v.run_block(0x100a8c0c4,0x100a8c0c8);prove('random_seed_store_ignores_unspecified_upper32',cell(v,0x1010c784c,4)!=previous)
    return qs

def sdk_checks():
    code='''#include <stdlib.h>
#include <stdint.h>
#include <sys/time.h>
#include <stddef.h>
_Static_assert(sizeof(void*)==8,"pointer64");
_Static_assert(sizeof(struct timeval)==16,"timeval16");
_Static_assert(_Alignof(struct timeval)==8,"timeval_align8");
_Static_assert(offsetof(struct timeval,tv_sec)==0,"seconds_offset0");
_Static_assert(offsetof(struct timeval,tv_usec)==8,"microseconds_offset8");
_Static_assert(sizeof(((struct timeval*)0)->tv_sec)==8,"seconds64");
_Static_assert(sizeof(((struct timeval*)0)->tv_usec)==4,"microseconds32");
_Static_assert(__builtin_types_compatible_p(__typeof__(&arc4random),uint32_t(*)(void)),"random_prototype");
_Static_assert(__builtin_types_compatible_p(__typeof__(&gettimeofday),int(*)(struct timeval*,void*)),"clock_prototype");
uint32_t seed_probe(void){return arc4random();}
int clock_probe(struct timeval *out){return gettimeofday(out,0);}
'''
    cmd=['xcrun','clang','-target','arm64e-apple-macos14','-std=c11','-S','-O1','-x','c','-','-o','-']
    p=subprocess.run(cmd,input=code,text=True,capture_output=True,timeout=30);assert p.returncode==0 and not p.stderr,p.stderr
    assert '_arc4random' in p.stdout and '_gettimeofday' in p.stdout
    sdk=Path(subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip())
    return {'command':cmd,'source':code,'assembly':p.stdout,'exit_code':0,
            'headers':[{'SDK_relative_header':n,'sha256':sha(sdk/n)} for n in ['usr/include/stdlib.h','usr/include/sys/time.h','usr/include/sys/_types/_timeval.h']],
            'scope':'Compile-only current arm64e ABI comparison; historical SDK/runtime identity and native clock output remain unknown.',
            'native_API_executed':False,'emitted_object':False}

def build():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e['generator_sha256']==sha(R.__file__) and e['dependencies']=={n:sha(ROOT/n) for n in R.DEPS}
    counts=Counter();lifts=[]
    for j,row in enumerate(R.intervals(e)):
        r=Lift(row).run();r['interval_index']=j;lifts.append(r);counts.update(r['verified_counts'])
        print(json.dumps({'interval':j,'source_visits':counts['source_visits']}),flush=True)
    runs=[];totals=Counter()
    for j,c in enumerate(json.loads(read(ROOT/'daemon_return_bank_origins_checks.json'))['upstream_cases']):
        r=Initializer(c,3).run();r['profile_index']=j;runs.append(r);totals.update(r['verified_counts'])
    qs=obligations()
    return {'scope':__doc__,'generator_sha256':sha(R.__file__),'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
            'source_sha256':sha(SOURCE),'dependencies':e['dependencies'],'verified_counts':e['verified_counts'],
            'independent_lifts':lifts,'independent_totals':dict(counts),'interfaces':interfaces(e),'source_proofs':qs,'source_queries_unsat':len(qs),
            'initializer_lifts':runs,'initializer_totals':dict(totals),'SDK_checks':sdk_checks(),'all_checks_pass':True,
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'native_epoch_join_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps({'replay':e['independent_totals'],'interfaces':e['interfaces']}),flush=True)
