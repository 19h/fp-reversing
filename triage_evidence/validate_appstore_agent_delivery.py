#!/usr/bin/env python3
"""Original receiver metadata/CFG/SMT and finite private-case verification.

No target runtime/framework/entitlement/account/IPC call runs. Time linear in
retained bytes, metadata, instructions and links, plus two SMT invocations.
"""
import hashlib
import json
from pathlib import Path
import plistlib
import struct
import subprocess
import sys
from appstore_agent_reader import Agent,ROOT,SOURCE,SHA,THIN_SHA,PLIST,CS,sha
from arcade_service_reader import code_signature
from recover_arcade_receipt import cfg,reachable


def read(name):return json.loads((ROOT/name).read_text())


def main():
    subprocess.run([sys.executable,str(ROOT/'recover_appstore_agent.py')],check=True,stdout=subprocess.DEVNULL)
    s=Agent();r=read('appstore_agent_contracts.json');inv=read('appstore_agent_inventory.json');meta=read('appstore_agent_objc_metadata.json');p=read('appstore_agent_profiles.json');checks=[]
    def check(ok,label):
        assert ok,label
        checks.append(label)
    check(sha(SOURCE.read_bytes())==SHA==inv['source_sha256'],'original universal identity')
    check(sha(s.data)==THIN_SHA==r['source_sha256']==meta['source_sha256']==p['source_sha256'],'selected original thin identity')
    check(s.meta['uuid']==inv['uuid']==r['uuid']=='f79c256d-2b9d-36a6-bfba-d2a880093cc6','selected UUID')
    check(sha(PLIST.read_bytes())==inv['launch_agent_sha256']=='614637685e78f2b3403776607c1f1e3f75816c486c46edf12cb21c4ad47d7512','original launch-agent identity')
    check(plistlib.loads(PLIST.read_bytes())==inv['launch_agent'],'original plist exact decode')
    check(len(s.starts)==10899 and len(s.decoded_fixups)==41985 and len(meta['classes'])==529 and len(meta['methods'])==2264,'function/fixup/class/method counts')
    check(s.decoded_fixups=={int(x['address'],16):x for x in inv['fixups']},'all original format12 fixup words and chain membership')
    for m in meta['methods']:
        a=int(m['entry'],16);raw=bytes.fromhex(m['entry_bytes']);flags=m['flags'];small=bool(int(flags,16)&0x80000000)
        check(s.read(a,len(raw))==raw and s.cstring(int(m['selector_address'],16))==m['selector'] and s.cstring(int(m['type_address'],16))==m['type_encoding'],f'original method metadata {m["class"]}:{m["selector"]}')
        if small:
            n,t,i=struct.unpack('<3i',raw);target=a+8+i
        else:target=s.qword(a+16)
        check(target==int(m['implementation'],16),f'original method implementation {m["entry"]}')
    check(len(r['selected_ranges'])==103 and len(r['call_edges'])==1600 and len(r['stubs'])==169,'selected graph counts')
    nodes={}
    for row in r['selected_ranges']:
        a=int(row['start'],16);raw=bytes.fromhex(row['bytes']);ix=s.starts.index(a)
        check(row['complete_compiler_range'] and int(row['end'],16)==s.starts[ix+1] and s.read(a,len(raw))==raw and sha(raw)==row['sha256'],f'complete original range {row["start"]}')
        decoded=[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(raw,a)]
        check(decoded==row['instructions'] and len(decoded)*4==len(raw),f'original instruction decode {row["start"]}')
        nodes.update({i['ea']:i for i in decoded})
    for edge in r['call_edges']:
        i=nodes[edge['callsite']]
        check(i['mnemonic']==edge['instruction'] and int(i['operands'][1:],0)==int(edge['target'],16),f'original branch target {edge["callsite"]}')
    for st in r['stubs']:
        check(s.read(int(st['address'],16),len(bytes.fromhex(st['bytes']))).hex()==st['bytes'],f'original stub bytes {st["address"]}')
        if st['kind']=='original_bound_stub':
            check(s.decoded_fixups[int(st['binding']['address'],16)]==st['binding'],f'original stub import chain {st["address"]}')
            if st['selector'] is not None:check(s.cstring(s.qword(int(st['selector_slot'],16)))==st['selector'],f'original stub selector {st["address"]}')
    for fix in r['interface_fixups']:check(s.decoded_fixups[int(fix['address'],16)]==fix,f'interface original fixup {fix["address"]}')
    for c in r['constants']:
        a=int(c['cfstring'],16);ptr=int(c['string_address'],16);n=c['length_bytes']
        check(s.read(a,32).hex()==c['cfstring_bytes'] and s.qword(a+16)==ptr and s.qword(a+24)==n and s.read(ptr,n).decode()==c['text'],f'original constant {c["role"]}')
    check({c['role']:c['text'] for c in r['constants']}=={'peer capability entitlement':'com.apple.private.appstored','repair capability token':'Repair','service unavailable error description':'Service is not available.','not entitled error description':'Not entitled for this service.'},'exact policy and failure literals')
    classes={x['name']:x['class'] for x in meta['classes']}
    check(s.qword(0x1005a89e8)==int(classes['XPCServiceClient'],16) and s.qword(0x1005a87b8)==int(classes['ArcadeRepair'],16) and s.qword(0x1005a8820)==int(classes['FairPlayRepair'],16),'original client and repair class references')
    check(classes['XPCServiceCatalog']=='0x1005e3620' and classes['RepairService']=='0x1005e0f38','catalog and factory class addresses')
    check(s.qword(0x100570df0)==0x10059aa78 and s.qword(0x10058ca18)==0x100124afc,'original Repair token and global factory pointers')
    policy=r['repair_policy'];ds=code_signature(Path('/Users/___/Downloads/zut/fairplayd.arm64e').read_bytes());db=next(x for x in ds['blobs'] if x.get('xml_entitlements'))
    check(db['sha256']==policy['daemon_xml_entitlement_blob_sha256'] and db['xml_entitlements']['com.apple.private.appstored']==policy['daemon_xml_entitlement']==['Repair'],'original daemon declared XML capability')
    for proof in r['proofs']:
        path=ROOT/proof['path'];run=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True)
        check(sha(path.read_bytes())==proof['sha256'] and run.stdout.strip()=='unsat' and not run.stderr,f'full-width SMT {path.name}')
    row=next(x for x in r['selected_ranges'] if x['start']=='0x1000b3088');nn,graph=cfg(row)
    check(0x1000b3124 in reachable(graph,0x1000b3088) and 0x1000b3124 not in reachable(graph,0x1000b3088,0x1000b3110),'factory invocation locally dominated by capability call')
    check(nn[0x1000b3114]['mnemonic']=='tbz' and nn[0x1000b3114]['operands']=='w0, #0, #0x1000b31f8','factory guarded by gate low bit')
    launch=inv['launch_agent'];check(len(launch['MachServices'])==14 and all(v is True for v in launch['MachServices'].values()) and launch['MachServices']['com.apple.appstoreagent.xpc'],'fourteen declared true MachServices including broker')
    check(launch['LimitLoadToSessionType']==['Aqua'] and 'com.apple.appstored.ASDRepairBundleID' in launch['LaunchEvents']['com.apple.distnoted.matching'] and 'com.apple.fairplayd.resync-fpkeybag' in launch['LaunchEvents']['com.apple.notifyd.matching'],'session and repair/keybag launch events')
    check(p['generator_sha256']==sha((ROOT/'probe_appstore_agent.py').read_bytes()) and p['source_contracts_sha256']==sha((ROOT/'appstore_agent_contracts.json').read_bytes()),'finite private generator and original contracts pinned')
    check(len(p['profiles'])==25 and not p['native_target_executed'] and not p['hardware_PAC_checked'],'25 private cases, no native target/PAC validation')
    for row in p['profiles']:
        name=row['fixture']['label'];check(row['matches_expected'] and row['result_u32']==row['expected_u32'] and row['stop_reason']=='returned_to_private_fixture' and row['steps']<=3000,f'completed finite case {name}')
        h=hashlib.sha256()
        for pc in row['visited_original_instructions']:
            pc=int(pc,16);h.update(struct.pack('<Q',pc));h.update(s.read(pc,4))
        check(h.hexdigest()==row['original_instruction_bytes_sha256'],f'visited original-byte readback {name}')
    cases={x['fixture']['label']:x for x in p['profiles']}
    for name in ('repair_token_present','repair_token_missing','token_short_circuits_alternate_query'):
        check(not any(e['symbol']=='Security/_SecTaskCopyValueForEntitlement' for e in cases[name]['API_records']),f'no alternate query on short circuit {name}')
    check(cases['arcade_active_status_ffff5a90']['result_u32']==0 and cases['arcade_no_active_account_daemon_repair_status']['result_u32']==1,'same daemon status with distinct modeled account paths')
    counts={'classes':529,'methods':2264,'format12_fixups':41985,'selected_original_ranges':103,'direct_call_edges':1600,
        'original_stubs':169,'declared_mach_services':14,'full_width_smt_unsat':2,'vending_gate_cfg_checks':1,
        'private_gate_cases':12,'private_arcade_cases':13,'private_cases':25,'assertions':len(checks)}
    (ROOT/'appstore_agent_profile_checks.json').write_text(json.dumps({'scope':__doc__,'verified_counts':counts,'checks':checks,
        'native_target_executed':False,'full_goal_complete':False},indent=2)+'\n')
    quality={'scope':'Original appstoreagent receiver/capability/queued-repair selection increment only.','verified_counts':counts,
        'QG1':{'status':'pass','evidence':'Descriptive technical analysis.'},
        'QG2':{'status':'pass','evidence':'AS1-AS6 with dependencies, probes and verification boundaries.'},
        'QG3':{'status':'pass_for_increment','evidence':'Receiver and capability/selection increment covered; full objective active.'},
        'QG4':{'status':'pass','evidence':'Original byte extents, u32/signed32/u64 fields, local CFG/SMT and probe budgets.'},
        'QG5':{'status':'pass_for_stated_claims','evidence':'Listener admission, capability, declared XML, effective identity, scheduling and repair completion separated.'},
        'QG6':{'status':'pass','evidence':'Original source/chain/metadata/selector/plist readbacks, two SMT queries and 25 finite cases.'},
        'QG7':{'status':'pass','evidence':'Impact-labeled native transport, notification, feedback and lifetime continuation.'},
        'native_target_executed':False,'full_goal_complete':False}
    (ROOT/'appstore_agent_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n')
    subprocess.run([sys.executable,str(ROOT/'validate_rpc502_sidecar_delivery.py')],check=True)
    print(json.dumps(counts))


if __name__=='__main__':main()
