#!/usr/bin/env python3
"""Independent scalar lift and network helper interface/SDK audit.

O(receipts+visits*(register state+byte effects)+source+queries) time/space;
30 s/query. Imports remain declared ABI premises, never native execution.
"""
import json,subprocess,struct
from pathlib import Path
from collections import Counter
import z3
from daemon_receive_tools import ROOT,IMAGE,FIXUPS,SOURCE
from verify_daemon_reader_record_payloads_publication import read,sha
import audit_daemon_pidpath_consumer as Parent
from audit_daemon_environment_outputs import DEC
import recover_daemon_network_identity as R

class Lift(Parent.Lift):
    def run(self):
        c=self.c;pc=int(c['entry_PC'],16);by_read={};by_write={}
        for row in c['source_reads']:by_read.setdefault(row['source_visit_index'],[]).append(row)
        for row in c['source_writes']:by_write.setdefault(row['source_visit_index'],[]).append(row)
        assert len(c['source_visits'])==len(c['source_frames'])
        for ix,(visit,frame) in enumerate(zip(c['source_visits'],c['source_frames'])):
            assert visit['pc']==frame['pc']==hex(pc);self.pc=pc;self.frame(frame);self.events=[]
            raw=IMAGE.read(pc,4);assert visit['bytes_hex']==raw.hex();i=next(DEC.disasm(raw,pc));m=i.mnemonic;next_pc=pc+4
            if m in ['pacibsp','paciasp','autibsp','autiasp']:pass
            elif m in ['braa','blraa','ret','retab']:
                target=self.integer(self.read('x30' if m in ['ret','retab'] else i.reg_name(i.operands[0].reg)))
                edge={'pc':hex(pc),'target':hex(target),'kind':m,'modifier':None}
                if m in ['braa','blraa']:
                    origin=self.last_authenticated_load;assert origin and origin[1]==target
                    word=int.from_bytes(IMAGE.read(origin[0],8),'little');assert word>>63 and not((word>>48)&7)
                    modifier=self.integer(self.read(i.reg_name(i.operands[1].reg)));assert modifier==(word>>32)&65535
                    edge['modifier']=hex(modifier);self.counts['original_authenticated_edges_checked']+=1
                self.edges.append(edge)
                if m=='blraa':self.write('x30',z3.BitVecVal(pc+4,64))
                next_pc=target
            elif m=='b':next_pc=i.operands[0].imm
            elif m.startswith('b.'):
                if self.projected(self.condition(m[2:])):next_pc=i.operands[0].imm
            elif m in ['cbz','cbnz']:
                val=self.integer(self.read(i.reg_name(i.operands[0].reg)))
                if (val==0)==(m=='cbz'):next_pc=i.operands[1].imm
            elif m in ['tbz','tbnz']:
                val=self.integer(self.read(i.reg_name(i.operands[0].reg)));bit=i.operands[1].imm
                if bool(val&(1<<bit))==(m=='tbnz'):next_pc=i.operands[2].imm
            else:self.one(i)
            for kind,expected in [('read',by_read.get(ix,[])),('write',by_write.get(ix,[]))]:
                actual=[e for e in self.events if e['kind']==kind];assert len(actual)==len(expected),(hex(pc),kind)
                for a,e in zip(actual,expected):
                    assert a['address']==e['address'] and a['size_bytes']==e['size_bytes']
                    assert a['bytes_hex']==e['bytes_hex' if kind=='read' else 'after_hex'],(hex(pc),a,e)
                    if 'known_mask_hex' in e:assert a['known_mask_hex']==e['known_mask_hex']
                    self.counts[kind+'_bytes_checked']+=a['size_bytes']
            self.counts['source_visits']+=1;pc=next_pc
        assert c['boundary']['pc']==hex(pc);self.pc=pc;self.frame({**c['boundary'],'NZCV':c['boundary_NZCV']})
        assert self.edges==[{k:e[k] for k in ['pc','target','kind','modifier']} for e in c['logical_edges']]
        assert not self.symbols
        return {'boundary':hex(pc),'verified_counts':dict(self.counts),'all_checks_pass':True,'native_target_executed':False}

def interfaces(e):
    p=json.loads(read(ROOT/(R.Parent.P+'_checks.json')));retained=[]
    for c in e['retained_cases']:
        before=p['result_cases'][c['parent_case_index']]['trace'];after=c['trace']
        assert after['entry_registers31']==before['boundary']['registers31'] and after['entry_NZCV']==before['boundary_NZCV']
        assert after['caller_SP']==before['boundary']['SP'] and Parent.bytes_at(before)=={
            int(f['address'],16)+j:b for f in after['initial_private_fixtures'] for j,b in enumerate(bytes.fromhex(f['bytes_hex']))}
        assert after['boundary']['pc']=='0x1005a8cd4' and after['boundary']['detail']['snapshot']['known_mask_hex']=='00'*8
        retained.append({'parent_case_index':c['parent_case_index'],'undefined_root_preserved':True})
    warm=cold=0
    for c in e['cache_cases']:
        row=c['trace'];cfg=row['configuration'];flag=cfg['flag8'];target=int(c['output64'],16)
        assert row['entry_PC']==hex(R.ENTRY) and int(row['entry_registers31'][0],16)==target
        if flag&1:
            warm+=1;assert row['boundary']['pc']==hex(R.RETURN) and int(row['boundary']['registers31'][0],16)==flag
            copies=[w for w in row['source_writes'] if w['pc'] in ['0x10000423c','0x100004240']]
            assert len(copies)==(2 if target else 0)
            if target:assert [(w['address'],w['size_bytes'],w['after_hex']) for w in copies]==[(hex(target+4),2,'98ba'),(hex(target),4,'10325476')]
        else:
            cold+=1;assert row['boundary']['pc']=='0x1000040d8'
            assert row['boundary']['detail']['symbol']=='IOKit/_IOMainPort'
            assert row['boundary']['registers31'][:2]==['0x0',hex(int(row['caller_SP'],16)-64)]
        assert not row['source_calls']
    results={}
    for c in e['inner_cases']:
        rows=c['intervals'];events=c['API_return_premises'];assert len(rows)==len(events)+1
        for before,event,after in zip(rows,events,rows[1:]):
            assert event['call_site']==before['boundary']['pc'] and event['symbol']==before['boundary']['detail']['symbol']
            assert not event['native_API_executed'] and event['ABI_return_and_output_premise']
            assert after['entry_PC']==hex(int(event['call_site'],16)+4) and after['entry_registers31']==event['return_registers31']
            assert after['entry_NZCV']==event['return_NZCV'] and after['caller_SP']==before['boundary']['SP']
            assert after['entry_registers31'][18:30]==before['boundary']['registers31'][18:30]
            assert int(after['entry_registers31'][30],16)==int(event['call_site'],16)+4
            expected=Parent.bytes_at(before)
            if 'output' in event:
                f=event['output'];expected.update({int(f['address'],16)+j:b for j,b in enumerate(bytes.fromhex(f['bytes_hex']))})
            actual={int(f['address'],16)+j:b for f in after['initial_private_fixtures'] for j,b in enumerate(bytes.fromhex(f['bytes_hex']))}
            assert actual==expected and after['initial_image_fixtures']==before['initial_image_fixtures']
        results[c['name']]={'result32':c['result32'],'output6_hex':c['output6_hex'],'imports':len(events)}
    expected={'empty':(5,'eeeeeeeeeeee'),'builtin_false_exhausted':(5,'eeeeeeeeeeee'),
              'parent_failure':(9,'eeeeeeeeeeee'),'missing_MAC':(0,'eeeeeeeeeeee')}
    for name,r in results.items():assert (r['result32'],r['output6_hex'])==expected.get(name,(0,'0123456789ab'))
    return {'retained_joins':retained,'warm_entries':warm,'cold_pending_IOMainPort_entries':cold,'inner_controls':results}

def source_audit(e):
    s=e['source'];assert s==R.source();checked=[]
    for row in s['stubs']:
        a=int(row['entry'],16);w=struct.unpack('<4I',IMAGE.read(a,16))
        assert w[0]&0x9f00001f==0x90000011
        imm=((w[0]>>5)&0x7ffff)<<2|((w[0]>>29)&3);imm-=1<<21 if imm>>20 else 0
        page=(a&~4095)+(imm<<12)
        assert w[1]&0xffc003ff==0x91000231 and w[2:]==(0xf9400230,0xd71f0a11)
        slot=page+((w[1]>>10)&4095);assert slot==int(row['slot'],16)
        word=int.from_bytes(IMAGE.read(slot,8),'little')
        assert word>>62==3 and (word>>32)&65535==0 and (word>>48)&7==1
        checked.append({'stub':hex(a),'slot':hex(slot),'address_diversity':1,'key':'IA','diversity':0})
    calls=s['calls'];assert len(calls)==33 and Counter(x['symbol'] for x in calls)['internal_MAC_iterator_helper']==3
    for row in calls:
        pc=int(row['pc'],16);word=int.from_bytes(IMAGE.read(pc,4),'little');assert word>>26==0x25
        disp=word&0x3ffffff;disp-=1<<26 if disp>>25 else 0
        assert pc+4*disp==int(row['target'],16)
    assert s['direct_branch_census']['matches']==[{'pc':hex(pc),'target':hex(R.INNER),'kind':'bl','word':hex(int.from_bytes(IMAGE.read(pc,4),'little'))} for pc in [0x100004120,0x1000041cc,0x1000041f4]]
    assert len(s['fixup_references'])==1 and s['fixup_references'][0]['slot']=='0x1010a1718'
    for object_address,string_address,length in [(0x1010b19d8,0x101033c8d,12),(0x1010b19f8,0x101033ca2,9)]:
        assert FIXUPS[object_address+16]['target']==string_address and int.from_bytes(IMAGE.read(object_address+24,8),'little')==length
    return {'original_stubs_checked':checked,'direct_calls_checked':33,'original_fixups_checked':len(s['original_fixups']['records']),
            'constant_CFStrings_checked':2,'complete_text_words_scanned':s['direct_branch_census']['text_size_bytes']//4}

def sdk_checks():
    code='''#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>
_Static_assert(sizeof(void*)==8,"pointer64");
_Static_assert(sizeof(mach_port_t)==4 && sizeof(io_object_t)==4 && sizeof(io_iterator_t)==4 && sizeof(io_registry_entry_t)==4,"names32");
_Static_assert(sizeof(kern_return_t)==4 && sizeof(CFIndex)==8 && sizeof(CFRange)==16,"ABI_widths");
_Static_assert(__builtin_types_compatible_p(__typeof__(&IOMainPort),kern_return_t(*)(mach_port_t,mach_port_t*)),"main_port");
_Static_assert(__builtin_types_compatible_p(__typeof__(&IORegistryEntryGetParentEntry),kern_return_t(*)(io_registry_entry_t,const char*,io_registry_entry_t*)),"parent_entry");
void network_identity_probe(CFDataRef data,UInt8 *out) {CFDataGetBytes(data,CFRangeMake(0,6),out);}
'''
    cmd=['xcrun','clang','-target','arm64e-apple-macos14','-std=c11','-S','-O1','-x','c','-','-o','-']
    p=subprocess.run(cmd,input=code,text=True,capture_output=True,timeout=30);assert p.returncode==0 and not p.stderr,p.stderr
    assert '_CFDataGetBytes' in p.stdout and 'mov\tw2, #6' in p.stdout
    sdk=Path(subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip())
    headers=[]
    for name in ['IOKit/IOKitLib.h','IOKit/IOTypes.h','CoreFoundation/CFData.h','CoreFoundation/CFBase.h']:
        framework,leaf=name.split('/');relative=f'System/Library/Frameworks/{framework}.framework/Headers/{leaf}'
        headers.append({'SDK_relative_header':relative,'sha256':sha(sdk/relative)})
    lib=(sdk/headers[0]['SDK_relative_header']).read_text();excerpts=[]
    for name in ['IOMainPort','IOObjectRelease','IOIteratorNext','IOServiceGetMatchingServices',
                 'IORegistryEntryCreateCFProperty','IORegistryEntryGetParentEntry','IOBSDNameMatching']:
        start=lib.index('\n'+name+'(');doc=lib.rfind('/*!',0,start);end=lib.index(';',start)+1
        excerpts.append({'symbol':name,'SDK_relative_header':headers[0]['SDK_relative_header'],
                         'first_line':lib.count('\n',0,doc)+1,'text':lib[doc:end]})
    return {'command':cmd,'source':code,'assembly':p.stdout,'exit_code':0,'headers':headers,'primary_header_excerpts':excerpts,
            'scope':'Compile-only current Darwin arm64e ABI comparison; historical runtime identity unknown.',
            'native_API_executed':False,'emitted_object':False}

def build():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e['generator_sha256']==sha(R.__file__)
    assert e['dependencies']=={n:sha(ROOT/n) for n in R.DEPS}
    lifts=[];counts=Counter()
    for j,row in enumerate(R.intervals(e)):
        result=Lift(row).run();result['interval_index']=j;lifts.append(result);counts.update(result['verified_counts'])
    assert len(R.obligations())==len(e['source_proofs'])==3
    for q in e['source_proofs']:
        solver=z3.Solver();solver.set(timeout=30000);solver.from_string(q['query']);assert solver.check()==z3.unsat
    return {'scope':__doc__,'generator_sha256':sha(R.__file__),'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
            'source_sha256':sha(SOURCE),'dependencies':e['dependencies'],'independent_lifts':lifts,'independent_totals':dict(counts),
            'interfaces':interfaces(e),'source_audit':source_audit(e),'SDK_checks':sdk_checks(),'source_queries_unsat':3,
            'verified_counts':e['verified_counts'],'native_API_executed':False,'native_daemon_kext_pairing_established':False,
            'full_goal_complete':False,'all_checks_pass':True}

if __name__=='__main__':
    e=build();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['independent_totals']),flush=True)
