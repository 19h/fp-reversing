#!/usr/bin/env python3
"""Independent source replay and process-path scratch/result interface audit.

O(receipts+visits*(register state+byte effects)+queries) time/space;
30 s/query. No native API/IPC, allocation/free, hardware PAC or IDB mutation.
"""
import json,subprocess
from pathlib import Path
from collections import Counter
import z3
from daemon_receive_tools import ROOT,IMAGE,TABLE,qword
from verify_daemon_reader_record_payloads_publication import read,sha
import audit_daemon_audit_scratch as Parent
import recover_daemon_pidpath_consumer as R

class Lift(Parent.Lift):
    def integer(self,x):
        value=super().integer(x)
        if self.pc in [0x100831198,0x10079af60]:
            slot,off=(TABLE+8*0x86a,0x9110) if self.pc==0x100831198 else (TABLE+8*0x5e,0x4ec8)
            if value==qword(slot):
                s=int(self.c['caller_SP'],16)
                saved=z3.Concat(*[self.bytes[s+off+j] for j in range(7,-1,-1)])
                assert self.projected(saved)==value
                if self.pc==0x100831198:self.last_authenticated_load=(slot,value)
                else:self.saved_continuation_fixup=(slot,value)
        return value

    def one(self,i):
        if i.mnemonic=='ldrsw':
            self.pc=i.address;self.write(i.reg_name(i.operands[0].reg),z3.SignExt(32,self.load(self.address(i,i.operands[1]),4)));return
        return super().one(i)

def bytes_at(row):
    out={}
    for f in row['initial_private_fixtures']:
        out.update({int(f['address'],16)+j:b for j,b in enumerate(bytes.fromhex(f['bytes_hex']))})
    for w in row['source_writes']:
        at=int(w['address'],16)
        if R.Base.P<=at<at+w['size_bytes']<=R.Base.P+R.Base.SIZE:
            out.update({at+j:b for j,b in enumerate(bytes.fromhex(w['after_hex']))})
    return out

def basis_interface(b):
    prefix,fill=b['prefix'],b['fill'];s=int(fill['caller_SP'],16);r=int(b['scratch_base64'],16);event=b['BSM_return_premise']
    assert prefix['boundary']['pc']==hex(R.Parent.BSM) and fill['entry_PC']==hex(R.AFTER_BSM)
    assert event['return_registers31']==fill['entry_registers31'] and event['return_NZCV']==fill['entry_NZCV']
    assert event['return_registers31'][18:30]==prefix['boundary']['registers31'][18:30]
    assert event['void_return_premise'] and 'return32' not in event and not event['native_API_executed']
    assert event['output']=={'address':hex(s+0x571c),'bytes_hex':'00000000'}
    zeroes=[w for w in fill['source_writes'] if w['pc']=='0x100761650']
    assert len(zeroes)==1024
    assert [int(w['address'],16) for w in zeroes]==list(range(r+32,r+1056))
    assert all(w['size_bytes']==1 and w['after_hex']=='00' for w in zeroes)
    extra=[w for w in fill['source_writes'] if w not in zeroes]
    assert len(extra)==2 and [(w['pc'],w['address']) for w in extra]==[('0x100665684',hex(s+0x9110)),('0x1008310ec',hex(s+0x9b8))]
    assert int.from_bytes(bytes.fromhex(extra[0]['after_hex']),'little')==0x10069381c
    assert int.from_bytes(bytes.fromhex(extra[1]['after_hex']),'little')==8
    for access in fill['source_reads']+fill['source_writes']:
        a=int(access['address'],16);assert not(a<s+0x5720 and s+0x571c<a+access['size_bytes'])
    assert not fill['source_calls']
    assert fill['boundary']['pc']==hex(R.PHASE) and fill['boundary']['detail']['snapshot']['known_mask_hex']=='00'*8
    current=bytes_at(fill);original=bytes_at(prefix)
    assert bytes(current[r+j] for j in range(32))==bytes(original[r+j] for j in range(32))
    return {'zero_bytes':1024,'first_zero':hex(r+32),'last_zero':hex(r+1055),'PID_accesses_during_fill':0,
            'copied_token32_preserved':True,'saved_PID_continuation':'0x10069381c','saved_pointer_cell_reused_as_u64':8,
            'undefined_phase_bytes_preserved':8,'native_API_executed':False}

def PID_interface(c,b):
    row=c['trace'];s=int(row['caller_SP'],16);before=b['fill'];r=int(b['scratch_base64'],16);pid=c['configuration']['PID32']
    assert row['entry_registers31']==before['boundary']['registers31'] and row['entry_NZCV']==before['boundary_NZCV']
    expected=bytes_at(before);actual={}
    for f in row['initial_private_fixtures']:actual.update({int(f['address'],16)+j:b for j,b in enumerate(bytes.fromhex(f['bytes_hex']))})
    for off,n,value in [(0x9d0,8,0x6cf4),(0x870,8,0x100e99700),(0x868,8,0x100f4e190),(0x571c,4,pid)]:
        expected.update({s+off+j:b for j,b in enumerate(value.to_bytes(n,'little'))})
    assert actual==expected
    assert row['boundary']['pc']==hex(R.PATH) and row['boundary']['detail']['symbol']=='libSystem/_proc_pidpath'
    assert row['boundary']['registers31'][:3]==[hex(pid),hex(r+32),'0x400'] and row['boundary']['detail']['modifier']=='0x4469'
    load=[r for r in row['source_reads'] if r['pc']==hex(R.PID)];assert len(load)==1 and load[0]['address']==hex(s+0x571c) and load[0]['size_bytes']==4
    assert not row['source_calls']
    return {'PID32':hex(pid),'PID_source':hex(s+0x571c),'call_site':hex(R.PATH),'buffer':hex(r+32),'capacity_bytes':1024,
            'phase_and_bank_roots_are_separate_premises':True,'native_API_executed':False}

def result_interface(c,parent):
    row=c['trace'];event=c['return_premise'];s=int(row['caller_SP'],16);ret=c['configuration']['path_result32']
    assert row['entry_registers31']==event['return_registers31'] and row['entry_NZCV']==event['return_NZCV']
    assert row['entry_registers31'][18:30]==parent['trace']['boundary']['registers31'][18:30]
    assert event['return32']==hex(ret) and event['unspecified_upper_X0_fixture'] and not event['output_memory_effects_modeled']
    expected=bytes_at(parent['trace']);actual={}
    for f in row['initial_private_fixtures']:actual.update({int(f['address'],16)+j:b for j,b in enumerate(bytes.fromhex(f['bytes_hex']))})
    assert actual==expected
    calls=row['source_calls'];assert len(calls)==1 and calls[0]['pc']=='0x1006939a0' and calls[0]['target']==hex(R.COMPARE)
    assert calls[0]['arguments8'][0]==hex(s+0x10cb8)
    result=[w for w in row['source_writes'] if w['pc']=='0x100412eb4'];assert len(result)==1
    index=int.from_bytes(bytes.fromhex(result[0]['after_hex']),'little');signed=ret-(1<<32) if ret>>31 else ret
    assert index==(0x16ff if signed<1 else 0x16fc)
    if signed<1:
        assert row['boundary']['pc']==hex(R.ERROR) and row['boundary']['registers31'][28]=='0x74c29dee'
        assert c['scratch_cursor64']==hex(c['configuration']['cursor64'])
    else:
        assert row['boundary']['pc']==hex(R.POSITIVE)
        assert c['scratch_cursor64']==hex(c['configuration']['cursor64']+0x420)
    return {'return32':hex(ret),'signed_return':signed,'comparison_record':hex(s+0x10cb8),'result_index':hex(index),
            'cursor_restored':signed<1,'boundary':row['boundary']['pc'],'native_API_executed':False}

def sdk_checks():
    code='''#include <libproc.h>
#include <stdint.h>
#include <sys/types.h>
_Static_assert(sizeof(void*)==8,"pointer64");
_Static_assert(sizeof(pid_t)==4 && ((pid_t)-1)<0,"signed_PID32");
_Static_assert(sizeof(int)==4,"return32");
_Static_assert(__builtin_types_compatible_p(__typeof__(&proc_pidpath),int(*)(int,void*,uint32_t)),"process_path_prototype");
int pidpath_consumer_probe(pid_t pid,void *buffer) {return proc_pidpath(pid,buffer,1024);}
'''
    cmd=['xcrun','clang','-target','arm64e-apple-macos14','-std=c11','-S','-O1','-x','c','-','-o','-']
    p=subprocess.run(cmd,input=code,text=True,capture_output=True,timeout=30);assert p.returncode==0 and not p.stderr,p.stderr
    assert '_proc_pidpath' in p.stdout and 'mov\tw2, #1024' in p.stdout
    sdk=Path(subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip())
    return {'command':cmd,'source':code,'assembly':p.stdout,'exit_code':0,
            'headers':[{'SDK_relative_header':n,'sha256':sha(sdk/n)} for n in ['usr/include/libproc.h','usr/include/sys/proc_info.h']],
            'scope':'Compile-only current Darwin arm64e ABI comparison; historical SDK and runtime implementation identity unknown.',
            'native_API_executed':False,'emitted_object':False}

def build():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e['generator_sha256']==sha(R.__file__)
    assert e['dependencies']=={n:sha(ROOT/n) for n in R.DEPS}
    lifts=[];totals=Counter()
    for j,row in enumerate(R.intervals(e)):
        result=Lift(row).run();result.update(interval_index=j,kind='original');lifts.append(result);totals.update(result['verified_counts'])
    alternate=[]
    for j,b in enumerate(e['basis_cases']):
        for pid in [0x12345678,0xffffffff]:
            row=b['fill'];s=int(row['caller_SP'],16)
            variant={**row,'initial_private_fixtures':row['initial_private_fixtures']+
                     [{'address':hex(s+0x571c),'bytes_hex':pid.to_bytes(4,'little').hex(),'provenance':'alternate_declared_BSM_output'}]}
            result=Lift(variant).run();result.update(basis_index=j,alternate_PID32=hex(pid),kind='alternate_PID_fill')
            lifts.append(result);totals.update(result['verified_counts'])
            alternate.append({'basis_index':j,'PID32':hex(pid),'identical_source_frames_effects_and_boundary':True})
    fresh=R.obligations();assert [q['label'] for q in fresh]==[q['label'] for q in e['source_proofs']]
    for q in e['source_proofs']:
        s=z3.Solver();s.set(timeout=30000);s.from_string(q['query']);assert s.check()==z3.unsat
    return {'scope':__doc__,'generator_sha256':sha(R.__file__),'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
            'source_sha256':sha(R.SOURCE),'dependencies':e['dependencies'],'independent_lifts':lifts,'independent_totals':dict(totals),
            'basis_interfaces':[basis_interface(b) for b in e['basis_cases']],
            'PID_interfaces':[PID_interface(c,e['basis_cases'][c['basis_index']]) for c in e['PID_cases']],
            'result_interfaces':[result_interface(c,e['PID_cases'][c['PID_case_index']]) for c in e['result_cases']],
            'alternate_PID_controls':alternate,'verified_counts':e['verified_counts'],'source_queries_unsat':len(fresh),'SDK_checks':sdk_checks(),
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'full_goal_complete':False,'all_checks_pass':True}

if __name__=='__main__':
    e=build();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['independent_totals']),flush=True)
