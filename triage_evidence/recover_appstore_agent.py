#!/usr/bin/env python3
"""Original appstoreagent ObjC receiver mappings and selected call graph.

No target runtime, listener, framework, connection or notification runs.
O(B+F+M+I) extraction with original bytes/fixups/method metadata/instructions.
"""
import bisect
import json
from pathlib import Path
import struct
import subprocess
from appstore_agent_reader import Agent,ROOT,THIN_SHA,CS,sha
from arcade_service_reader import code_signature
from recover_arcade_receipt import cfg,reachable


def methods(s,a,owner,kind):
    if not a:return []
    flags,count=struct.unpack('<2I',s.read(a,8));small=bool(flags&0x80000000);direct=bool(flags&0x40000000)
    stride=flags&0xfffc;assert stride==(12 if small else 24) and count<=2048,(hex(a),hex(flags),count)
    out=[]
    for j in range(count):
        p=a+8+j*stride;raw=s.read(p,stride)
        if small:
            n,t,i=struct.unpack('<3i',raw);ns=p+n;np=ns if direct else s.qword(ns);tp=p+4+t;imp=p+8+i
        else:np,tp,imp=[s.qword(p+k*8) for k in range(3)];ns=p
        out.append({'class':owner,'kind':kind,'entry':hex(p),'entry_bytes':raw.hex(),'list':hex(a),'flags':hex(flags),
            'selector':s.cstring(np),'selector_address':hex(np),'type_encoding':s.cstring(tp),'type_address':hex(tp),
            'implementation':hex(imp),'compiler_entry':imp in s.starts,'selector_reference':hex(ns),'selector_fixup':s.decoded_fixups.get(ns)})
    return out


def stub(s,a):
    raw=s.read(a,24);ins=list(CS.disasm(raw,a));sel=None;ss=None
    if ins[0].op_str.startswith('x1,') and ins[0].mnemonic=='adrp' and ins[1].mnemonic=='ldr':
        ss=int(ins[0].op_str.split('#')[1],0)+int(ins[1].op_str.split('#')[1].split(']')[0],0)
        sel=s.cstring(s.qword(ss));ins=ins[2:]
    if [i.mnemonic for i in ins[:4]]!=['adrp','add','ldr','braa']:
        return {'address':hex(a),'bytes':raw.hex(),'kind':'unresolved_original_stub'}
    slot=int(ins[0].op_str.split('#')[1],0)+int(ins[1].op_str.split('#')[1],0)
    return {'address':hex(a),'bytes':s.read(a,24 if sel else 16).hex(),'kind':'original_bound_stub','selector':sel,
        'selector_slot':None if ss is None else hex(ss),'binding':s.decoded_fixups[slot]}


def main():
    s=Agent();classes=s.class_inventory();allmethods=[]
    for c in classes:
        allmethods+=methods(s,int(c['instance_method_list'],16),c['name'],'instance')
        allmethods+=methods(s,int(c['class_method_list'],16),c['name'],'class')
    (ROOT/'appstore_agent_objc_metadata.json').write_text(json.dumps({'source_sha256':THIN_SHA,'classes':classes,'methods':allmethods,
        'runtime_objc_registration_executed':False},indent=2)+'\n')
    selected_classes={'XPCServiceBroker','XPCServiceClient','XPCServiceEntitlements','XPCServiceCatalog',
        'RepairService','FairPlayRepair','ArcadeRepair','RepairApplicationTask',
        '_TtC13appstoreagent26CodeSignatureVersionRepair'}
    selected=[m for m in allmethods if m['class'] in selected_classes or m['selector'] in ('listener:shouldAcceptNewConnection:','getRepairServiceWithReplyHandler:')]
    helpers={0x1000b2bfc:'client constructor, connection and catalog arguments',
        0x1000b2ee4:'client internal policy predicate',0x1000b3088:'service vending and entitlement gate',
        0x100125414:'peer audit-token entitlement context constructor',0x100125684:'capability or alternate boolean entitlement predicate',
        0x100163f34:'catalog repair policy pair atomic copy getter',0x100163f84:'catalog repair policy pair atomic copy setter',
        0x1000d5fec:'pair copy retains two object references',0x1001632a8:'pair assignment consumes two object references',
        0x10012367c:'startup catalog configuration including repair capability and factory',
        0x100124afc:'repair service factory block invoke',0x1000f12e0:'repair service singleton getter',
        0x1000f1338:'repair service singleton once block',0x1000f14a8:'queued repair request block',
        0x1000f158c:'repair task completion forwarding block',0x1000d3458:'repair task options and log-key constructor',
        0x10010108c:'broker queued client block',0x100101098:'broker invalidation block',
        0x10012880c:'Arcade repair status from options helper',
        0x10004c20c:'application Arcade classification with internal-policy alternate',
        0x100034fe8:'FairPlay repair supplied status or fresh status helper',
        0x100035ecc:'platform2 path-to-protected-FairPlay status adapter'}
    existing={int(m['implementation'],16) for m in selected}
    for a,label in helpers.items():
        if a not in existing:selected.append({'class':'original helper','kind':'private C ABI or block',
            'selector':label,'implementation':hex(a),'type_encoding':'unknown; registers recovered from original callers'})
    text=next(sec for sec in s.sections if sec['section']=='__text');ranges=[];edges=[];stubs={}
    stub_secs=[sec for sec in s.sections if sec['section'] in ('__stubs','__auth_stubs','__objc_stubs')]
    for m in selected:
        a=int(m['implementation'],16);ix=bisect.bisect_right(s.starts,a)-1;ca=s.starts[ix];z=s.starts[ix+1] if ix+1<len(s.starts) else text['address']+text['size']
        raw=s.read(a,z-a);ins=list(CS.disasm(raw,a));assert len(ins)*4==len(raw)
        r={'class':m['class'],'kind':m['kind'],'method':m['selector'],'type_encoding':m['type_encoding'],'start':hex(a),'end':hex(z),
            'compiler_start':hex(ca),'complete_compiler_range':a==ca,'bytes':raw.hex(),'sha256':sha(raw),
            'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ins]};ranges.append(r)
        for i in ins:
            if i.mnemonic not in ('b','bl') or not i.op_str.startswith('#'):continue
            target=int(i.op_str[1:],0)
            if a<=target<z:continue
            e={'class':m['class'],'method':m['selector'],'callsite':hex(i.address),'target':hex(target),'instruction':i.mnemonic}
            if any(sec['address']<=target<sec['address']+sec['size'] for sec in stub_secs):
                if target not in stubs:stubs[target]=stub(s,target)
                ss=stubs[target];e.update({'kind':ss['kind'],'selector':ss.get('selector'),'symbol':ss.get('binding',{}).get('target')})
            else:e['kind']='direct_original_internal'
            edges.append(e)
    constants=[]
    for a,kind in [(0x100590b78,'peer capability entitlement'),(0x10059aa78,'repair capability token'),
        (0x100597738,'service unavailable error description'),(0x100597758,'not entitled error description')]:
        p=s.qword(a+16);n=s.qword(a+24);raw=s.read(p,n)
        constants.append({'role':kind,'cfstring':hex(a),'string_address':hex(p),'length_bytes':n,'text':raw.decode(),
            'cfstring_bytes':s.read(a,32).hex(),'string_bytes':raw.hex(),'string_pointer_fixup':s.decoded_fixups[a+16]})
    bindings=[s.decoded_fixups[a] for a in [0x1005a89e8,0x1005a8c70,0x1005a8c30,0x1005a8fb0,0x100570df0,0x10058ca18,
        0x1005a87b8,0x1005a8820]]
    proofs=[]
    queries={
      'appstore_agent_gate_short_circuit.smt2':'''(set-logic QF_BV)
(declare-fun member () (_ BitVec 32))
(declare-fun alternateKey () (_ BitVec 64))
(define-fun csinc () (_ BitVec 32) (ite (distinct alternateKey #x0000000000000000) member #x00000001))
(define-fun taken () Bool (= ((_ extract 0 0) csinc) #b1))
(assert (distinct taken (or (= alternateKey #x0000000000000000) (= ((_ extract 0 0) member) #b1))))
(check-sat)
''',
      'appstore_agent_arcade_status.smt2':'''(set-logic QF_BV)
(declare-fun status () (_ BitVec 32))
(define-fun delta () (_ BitVec 32) (bvadd status #x0000a65b))
(define-fun first () Bool (or (and (bvule delta #x00000003) (distinct delta #x00000001)) (= status #xffff5b82) (= status #xffff5b80)))
(define-fun final () Bool (or (and (bvule delta #x00000003) (distinct delta #x00000001)) (= status #xffff5b80) (= status #xffff5b82)))
(define-fun expected () Bool (or (= status #xffff59a5) (= status #xffff59a7) (= status #xffff59a8) (= status #xffff5b82) (= status #xffff5b80)))
(assert (or (distinct first expected) (distinct final expected)))
(check-sat)
'''}
    for name,query in queries.items():
        p=ROOT/name;p.write_text(query);run=subprocess.run(['z3',str(p)],capture_output=True,text=True,check=True)
        assert run.stdout.strip()=='unsat' and not run.stderr
        proofs.append({'path':name,'sha256':sha(p.read_bytes()),'result':'unsat','scope':'Local original arithmetic/branch predicate only; API inputs remain conditional.'})
    vending=next(x for x in ranges if x['start']=='0x1000b3088');nodes,graph=cfg(vending)
    assert 0x1000b3124 in reachable(graph,0x1000b3088)
    assert 0x1000b3124 not in reachable(graph,0x1000b3088,0x1000b3110)
    assert nodes[0x1000b3114]['mnemonic']=='tbz' and nodes[0x1000b3114]['operands']=='w0, #0, #0x1000b31f8'
    dominance={'entry':'0x1000b3088','removed_gate_call':'0x1000b3110','factory_invoke':'0x1000b3124',
        'factory_unreachable_without_gate_call':True,'gate_low_bit_required':True,'scope':'Local intraprocedural normal control flow, excluding PAC faults and exceptions.'}
    daemon=Path('/Users/___/Downloads/zut/fairplayd.arm64e');ds=code_signature(daemon.read_bytes())
    db=next(x for x in ds['blobs'] if x.get('xml_entitlements'))
    out={'scope':__doc__,'source_sha256':THIN_SHA,'uuid':s.meta['uuid'],'classes_total':len(classes),'methods_total':len(allmethods),
        'selected_classes':sorted(selected_classes),'selected_ranges':ranges,'call_edges':edges,'stubs':list(stubs.values()),
        'constants':constants,'interface_fixups':bindings,
        'proofs':proofs,'vending_gate_cfg':dominance,
        'arcade_status_policy':{'status_helper':'0x10012880c','getter_selector':'fairplayStatus',
            'accepted_common_status_signed32':[-0xa65b,-0xa659,-0xa658,-0xa47e,-0xa480],
            'daemon_repair_status_signed32':-42352,'daemon_status_in_common_set':False,
            'no_active_account_and_arcade_classification_short_circuit':True,'full_repair_semantics_established':False},
        'repair_policy':{'entitlement':'com.apple.private.appstored','required_array_token':'Repair','alternate_boolean_key':None,
            'catalog_pair_offset_bytes':432,'catalog_factory_offset_bytes':136,'client_entitlement_context_offset_bytes':40,
            'context_capability_array_offset_bytes':8,'context_sec_task_offset_bytes':16,'context_pid_offset_bytes':24,
            'policy_set_call':'0x100124044','factory_set_call':'0x100124058','factory_block':'0x10058ca08','factory_invoke':'0x100124afc',
            'gate_call':'0x1000b3110','constructor_block_call':'0x1000b3124','success_reply_call':'0x1000b3144',
            'unavailable_error_code_u32':512,'not_entitled_error_code_u32':505,
            'daemon_thin_sha256':sha(daemon.read_bytes()),'daemon_xml_entitlement_blob_sha256':db['sha256'],
            'daemon_xml_entitlement':db['xml_entitlements'].get('com.apple.private.appstored'),
            'signature_authenticated':False,'effective_peer_entitlement':'unknown'},
        'native_listener_executed':False,'native_repair_executed':False,'full_goal_complete':False,
        'generator_sha256':sha(Path(__file__).read_bytes())}
    (ROOT/'appstore_agent_contracts.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'classes':len(classes),'methods':len(allmethods),'selected_method_ranges':len(ranges),'call_edges':len(edges),'stubs':len(stubs)}))
    for m in selected:print(json.dumps({k:m[k] for k in ('class','kind','selector','implementation','type_encoding')}))


if __name__=='__main__':main()
