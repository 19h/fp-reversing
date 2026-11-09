#!/usr/bin/env python3
"""Original receipt call graph, private CMS ABI and reference lifetime checks.

Reads original bytes/metadata/cache only; no native CMS, file or IPC execution.
Extraction O(B+I+F); local CFG reachability O(V+E); retained space O(B+I+F+V+E).
SMT cost is separate.
"""
import json
from pathlib import Path
import re
import struct
import subprocess
from arcade_service_reader import Service,ROOT,THIN_SHA,CS,sha
from arcade_objc_metadata import recover as objc_metadata
from bootpolicy_cache_reader import Cache,Dylib


def stub(s,a):
    ins=list(CS.disasm(s.read(a,24),a));selector=None;sel_slot=None
    if ins[0].op_str.startswith('x1,'):
        assert [i.mnemonic for i in ins[:2]]==['adrp','ldr']
        page=int(ins[0].op_str.split('#')[1],0);off=int(ins[1].op_str.split('#')[1].split(']')[0],0)
        sel_slot=page+off;selector=s.cstring(s.qword(sel_slot));ins=ins[2:]
    assert [i.mnemonic for i in ins[:4]]==['adrp','add','ldr','braa']
    slot=int(ins[0].op_str.split('#')[1],0)+int(ins[1].op_str.split('#')[1],0)
    return {'address':hex(a),'bytes':s.read(a,24 if selector else 16).hex(),'selector':selector,
        'selector_slot':None if sel_slot is None else hex(sel_slot),'binding':s.decoded_fixups[slot]}


def cfg(r):
    ins=r['instructions'];nodes={int(i['ea'],16):i for i in ins};edges={}
    for a,i in nodes.items():
        m=i['mnemonic'];op=i['operands'];n=a+4;out=[]
        if m in ('ret','retab','retaa'):pass
        elif m=='b':out=[int(op[1:],0)]
        elif m.startswith('b.') or m in ('cbz','cbnz','tbz','tbnz'):out=[n,int(op.split('#')[-1],0)]
        elif m in ('br','braa','braaz'):raise ValueError('unresolved local CFG edge')
        else:out=[n]
        edges[a]=[x for x in out if x in nodes]
    return nodes,edges


def reachable(edges,start,removed=None):
    seen=set();todo=[start]
    while todo:
        a=todo.pop()
        if a==removed or a in seen:continue
        seen.add(a);todo.extend(edges[a])
    return seen


def main():
    s=Service();meta=objc_metadata(s);methods=[r for r in meta['methods'] if r['class']=='FP_ISPurchaseReceipt']
    allranges={int(r['start'],16):r for r in s.ranges()};ranges=[];calls=[];stubs={}
    stub_sections=[r for r in s.sections if r['section'] in ('__stubs','__auth_stubs','__objc_stubs')]
    for m in methods:
        a=int(m['implementation'],16);r=dict(allranges[a]);r['method']=m['selector'];r['kind']=m['kind'];ranges.append(r)
        for i in r['instructions']:
            if i['mnemonic'] not in ('bl','b') or not i['operands'].startswith('#'):continue
            target=int(i['operands'][1:],0)
            if a<=target<int(r['end'],16):continue
            edge={'method':m['selector'],'callsite':i['ea'],'instruction':i['mnemonic'],'target':hex(target)}
            if any(sec['address']<=target<sec['address']+sec['size'] for sec in stub_sections):
                if target not in stubs:stubs[target]=stub(s,target)
                edge.update({'kind':'original_stub','symbol':stubs[target]['binding']['target'],'selector':stubs[target]['selector']})
            else:edge['kind']='direct_original_internal'
            calls.append(edge)
    cache=Cache();security=Dylib(cache,'/System/Library/Frameworks/Security.framework/Versions/A/Security')
    names=['_SecCmsDecoderCreate','_SecCmsDecoderUpdate','_SecCmsDecoderFinish','_SecCmsDecoderDestroy']
    cache_functions=[]
    for name in names:
        a=security.exports[name]['address'];r=security.function(a);r['export']=name;cache_functions.append(r)
    free_stub=0x18806c3d0;slot=0x1e2104c30;pointer=cache.pointer(slot);target=int(pointer['target'],16)
    malloc=Dylib(cache,'/usr/lib/system/libsystem_malloc.dylib');assert malloc.exports['_free']['address']==target
    finish=next(r for r in cache_functions if r['export']=='_SecCmsDecoderFinish');nodes,edges=cfg(finish)
    returns={a for a,i in nodes.items() if i['mnemonic'] in ('ret','retab','retaa')};entry=int(finish['start'],16);free_call=0x184fc3ad4
    assert nodes[free_call]['mnemonic']=='bl' and nodes[free_call]['operands']==hex(free_stub).replace('0x','#0x')
    assert nodes[free_call-4]['operands']=='x0, x19'
    normal=reachable(edges,entry);without=reachable(edges,entry,free_call)
    assert returns<=normal and not(returns&without)
    create=next(r for r in cache_functions if r['export']=='_SecCmsDecoderCreate');cn,ce=cfg(create)
    out_store=0x184fbebd8;fail_entry=0x184fbebf0
    assert cn[out_store]['mnemonic']=='str' and cn[out_store]['operands']=='x24, [x19]'
    assert not(out_store in reachable(ce,fail_entry))
    explicit_out_stores=[a for a,i in cn.items() if i['mnemonic'].startswith(('str','stp')) and '[x19' in i['operands']]
    assert explicit_out_stores==[out_store]
    decode=next(r for r in ranges if r['method']=='_decodeReceiptData:toDecodedMessage:')
    prefix=[i for i in decode['instructions'] if int(i['ea'],16)<0x1000018ac]
    assert not any(i['mnemonic'].startswith(('str','stp')) and re.search(r'\[sp, #(?:0x)?8\]',i['operands']) for i in prefix)
    query='''(set-logic QF_BV)
(declare-fun result () (_ BitVec 32))
(define-fun z_after_cmp1 () Bool (= result #x00000001))
(define-fun z_after_ccmp4 () Bool (ite (not z_after_cmp1) (= result #x00000004) true))
(define-fun value () (_ BitVec 64) (ite z_after_ccmp4 #x0000000000000000 #x000000000000ffff))
(assert (not (= (= value #x0000000000000000) (or (= result #x00000001) (= result #x00000004)))))
(check-sat)
'''
    p=ROOT/'arcade_receipt_trust_result.smt2';p.write_text(query);run=subprocess.run(['z3',str(p)],capture_output=True,text=True,check=True)
    assert run.stdout.strip()=='unsat' and not run.stderr
    proof={'path':p.name,'sha256':sha(p.read_bytes()),'result':'unsat','scope':'Local CMP/CCMP/CSEL trust-result predicate only; no native trust evaluation.'}
    sdk=Path('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk')
    cfile=ROOT/'arcade_receipt_layouts.c';cmd=['/usr/bin/clang','-target','arm64e-apple-macos','-isysroot',str(sdk),'-fsyntax-only','-Wall','-Wextra','-Werror',str(cfile)]
    run=subprocess.run(cmd,capture_output=True,text=True);assert run.returncode==0,(run.stdout,run.stderr)
    ro=0x1000681d8;size=struct.unpack('<I',s.read(ro+8,4))[0];assert size==80
    oid_object=0x100065a60;oid_ptr=s.qword(oid_object+16);oid_size=s.qword(oid_object+24);oid_text=s.read(oid_ptr,oid_size).decode()
    assert oid_text=='1.2.840.113635.100.6.2.1'
    out={'scope':__doc__,'service_sha256':THIN_SHA,'receipt_class':{'name':'FP_ISPurchaseReceipt','class_address':'0x100068aa8','class_ro':hex(ro),
        'class_ro_original_bytes':s.read(ro,72).hex(),'instance_size_bytes':size},
        'ranges':ranges,'calls':calls,'stubs':list(stubs.values()),'cache_uuid':cache.uuid,'security_uuid':security.uuid,
        'reference_security_functions':cache_functions,
        'free_binding':{'stub':hex(free_stub),'bytes':cache.read(free_stub,16).hex(),'pointer':pointer,'target':hex(target),
            'library':malloc.path,'uuid':malloc.uuid,'exact_export':'_free','original_nlist':malloc.symbols_at(target)},
        'finish_free_dominance':{'entry':finish['start'],'free_call':hex(free_call),'returns':[hex(a) for a in sorted(returns)],
            'reachable_returns_without_free':[],'instruction_nodes':len(nodes),'edges':sum(map(len,edges.values())),
            'scope':'Local normal-return CFG, external calls assumed to return normally; X19 is the saved input context.'},
        'create_output':{'saved_output_register':'X19 <- X7','only_explicit_output_store':hex(out_store),'failure_entry':hex(fail_entry),
            'failure_can_reach_output_store':False,'caller_slot_initialized_before_create':False,
            'scope':'Original caller prefix and reference callee local data flow; no native failure event.'},
        'trust_result_proof':proof,'sdk_compile':{'command':cmd,'source_sha256':sha(cfile.read_bytes()),'exit_code':0},
        'required_oid_literal':{'object':hex(oid_object),'original_object_bytes':s.read(oid_object,32).hex(),
            'string_fixup':s.decoded_fixups[oid_object+16],'string_address':hex(oid_ptr),'length_bytes':oid_size,'text':oid_text},
        'sdk_trust_header':{'path':str(sdk/'System/Library/Frameworks/Security.framework/Headers/SecTrust.h'),
            'sha256':sha((sdk/'System/Library/Frameworks/Security.framework/Headers/SecTrust.h').read_bytes())},
        'cache_files_used':[cache.files[p] for p in sorted(cache.used)],'runtime_cache_pairing':'unknown',
        'native_receipt_operations_executed':False,'full_goal_complete':False,'generator_sha256':sha(Path(__file__).read_bytes())}
    (ROOT/'arcade_receipt_contracts.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'receipt_methods':len(ranges),'direct_call_edges':len(calls),'resolved_stubs':len(stubs),'reference_cms_functions':4,
        'finish_free_dominates_normal_returns':True,'trust_result_proofs_unsat':1,'sdk_compile_exit':0}))


if __name__=='__main__':main()
