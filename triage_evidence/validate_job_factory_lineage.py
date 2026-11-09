#!/usr/bin/env python3
"""Verify static job/table/property bindings and evidence integrity.

Original-byte recapture, independent disassembly and compiled SDK constants.
No recovered target code, port operations or process creation executes.
"""
import copy,json,subprocess
from recover_job_factory_lineage import ROOT,P,FLAGS,SDK,sha,h,CS,build

PATTERNS='''
plist_import|stp|x20, xzr, [sp, #0x88]
plist_import|add|x4, sp, #0x48
plist_import|mov|x1, x19
plist_import|mov|x2, x21
job_import|mov|x26, x4
job_import|str|x26, [sp, #0x30]
job_import|ldr|x4, [sp, #0x30]
job_import|mov|x6, x26
job_import|mov|x2, x26
job_create|mov|x28, x4
job_create|stp|x28, x8, [sp, #0x40]
job_create|str|x28, [sp, #0x40]
job_create|ldp|x4, x24, [sp, #0x40]
job_create|mov|x19, x6
job_create|mov|x7, x19
property_context|mov|x19, x0
property_context|mov|x22, x2
property_context|mov|w0, #0x18
property_context|stp|x19, x22, [x0]
property_context|str|x21, [x0, #0x10]
base_init|mov|x21, x4
base_init|add|x19, x22, #0x218
base_init|ldp|q0, q1, [x21]
base_init|stp|q0, q1, [x19]
base_init|ldp|q0, q1, [x21, #0x20]
base_init|stp|q0, q1, [x19, #0x20]
base_init|ldr|x9, [x21, #0x40]
base_init|str|x9, [x22, #0x258]
job_install|str|x21, [x19, #0xf8]
job_install|ldr|x8, [x19, #0x250]
job_install|ldr|x1, [x19, #0x258]
job_install|blraaz|x8
property_schema|mov|x3, x1
property_schema|mov|x8, x0
property_schema|ldp|x19, x22, [x2]
property_schema|mov|x1, x19
property_schema|mov|x2, x8
property_schema|mov|x4, x22
schema_dispatch|mov|x24, x3
schema_dispatch|mov|x21, x2
schema_dispatch|mov|x20, x1
schema_dispatch|add|x0, x22, #0x68
schema_dispatch|ldr|x0, [x0, #8]
schema_dispatch|ldr|x9, [x8, #0x10]!
schema_dispatch|mov|x1, x20
schema_dispatch|mov|x2, x24
schema_dispatch|mov|x3, x23
schema_dispatch|blraa|x9, x8
schema_register|str|x21, [x19]
MachServices_outer|mov|x0, x2
MachServices_outer|stp|x1, x3, [sp, #0x20]
MachServices_iterator|ldp|x8, x3, [x0, #0x20]
MachServices_iterator|mov|x0, x8
MachServices_iterator|mov|w0, #1
MachServices_entry|ldr|x8, [x19, #0x230]
MachServices_entry|ldr|x5, [x19, #0x258]
MachServices_entry|mov|x0, x19
MachServices_entry|mov|x1, x21
MachServices_entry|mov|x2, x22
MachServices_entry|mov|x3, #0
MachServices_entry|mov|x4, x20
MachServices_entry|blraaz|x8
callback3|mov|x19, x5
callback3|mov|x20, x0
callback3|mov|x3, x16
callback3|mov|x5, x0
endpoint_constructor|str|x24, [x0, #0x60]
endpoint_constructor|stp|x23, x22, [x0, #0x90]
producer0|ldr|x20, [x28, #0xc8]!
producer0|add|x1, x20, #0x1a8
producer0|str|x21, [x20, #0x100]
producer0|str|x20, [x21, #0xc8]
producer0|stp|x16, x20, [x0, #0x90]
explicit_instance_request|add|x1, x24, #0x1a8
explicit_instance_request|mov|w3, #0
callback0|str|w21, [x19, #0x178]
callback0|str|w21, [x19, #0x17c]
callback0|str|wzr, [x19, #0x124]
callback2|mov|w8, #0x203
callback2|ldr|x8, [x20, #0xa0]
callback2|ldr|x8, [x20, #0xa8]
callback2|mov|w0, #0x10
callback4|mov|x0, x2
callback5|mov|x20, x0
callback5|mov|x7, x20
callback5|mov|x0, x20
callback5|ldr|w0, [x0, #0xe0]
callback5|ldr|x8, [x20, #0xc0]!
socket_constructor|mov|x23, x0
socket_constructor|str|x23, [x0, #0x38]
callback6|ldp|x9, x10, [x8, #0x10]!
callback6|str|x9, [x10]
callback7|ldr|x21, [x20, #0xc0]
callback7|ldr|x23, [x21, #0x38]
callback7|ldrh|w8, [x23, #0x12c]
callback7|add|w8, w8, #1
callback7|strh|w8, [x23, #0x12c]
callback7|orr|w8, w8, #8
'''

def verify(s):
 assert s['source_sha256']=='1ba04f6d568343f1be0467e5ef0a4700c4b204b49182eb38f0de636efb176168'
 assert all(s[k]is False for k in FLAGS);rows=[]
 def need(v,role,mn,op):
  found=[q for q in v['roles'][role]['instructions']if q['mnemonic']==mn and q['operands']==op]
  assert found,(v['label'],role,mn,op)
  rows.extend({'variant':v['label'],'role':role,**q}for q in found)
 for v in s['variants']:
  rr=v['roles'];assert len(rr)==32 and v['fixup_reference']['fixups_compared']==2447 and v['fixup_reference']['all_matches']
  for line in PATTERNS.strip().splitlines():role,mn,op=line.split('|');need(v,role,mn,op)
  for role,dest in [('plist_import','job_import'),('job_import','job_create'),('job_import','job_install'),
                    ('job_create','base_init'),('job_create','property_context'),('MachServices_iterator','MachServices_entry'),
                    ('callback3','endpoint_constructor'),('explicit_instance_request','producer0'),('callback5','socket_constructor')]:
   need(v,role,'bl','#'+rr[dest]['start'])
  for role,name,tail in [('MachServices_outer','_xpc_dictionary_apply','bl'),('job_create','_xpc_dictionary_apply_f','bl'),
      ('schema_register','_os_map_str_insert','b'),('callback6','_objc_release','b')]:
   assert v['stubs'][name]['binding']['symbol']==name;need(v,role,tail,'#'+v['stubs'][name]['address'])
  assert [p['symbol']for p in v['schema_type_bindings']]==['__xpc_type_bool','__xpc_type_int64','__xpc_type_string','__xpc_type_array','__xpc_type_dictionary']
  block=v['MachServices_block'];assert block['address']=='0x100081b10'and len(bytes.fromhex(block['bytes']))==32
  pp=block['pointers'];assert pp[0]['symbol']=='__NSConcreteGlobalBlock'and pp[1]['target']==rr['MachServices_outer']['start']and pp[1]['authenticated']and all(p['chain_membership_verified']for p in pp)
  assert len(v['producers'])==7 and len(v['wrapper_literal_references'])==8 and sum(len(q['tables'])for q in v['producers'])==8
  for p in v['producers']:
   assert p['start']==rr[p['role']]['start']
   for table in p['tables']:
    assert len(table['entries'])==8
    for k,e in enumerate(table['entries']):
     assert e['index']==k and e['target']==v['callback_targets'][k]==rr['callback'+str(k)]['start']
     assert e['job_offset_bytes']==0x218+8*k and e['stack_offset_bytes']==table['stack_base_bytes']+8*k
     for ins in e['address_instructions']+[e['sign'],e['store']]:assert ins in rr[p['role']]['instructions']
     assert e['sign']['mnemonic']=='paciza'and e['sign']['operands']=='x16'
    assert table['cookie_stack_offset_bytes']==table['stack_base_bytes']+64
  for r in rr.values():
   raw=bytes.fromhex(r['bytes']);assert h(raw)==r['sha256']and len(raw)==int(r['end'],16)-int(r['start'],16)==4*len(r['instructions'])
   for j,i in enumerate(r['instructions']):
    pc=int(r['start'],16)+4*j;b=raw[4*j:4*j+4];assert i['ea']==hex(pc)and i['bytes']==b.hex()and i['LLVM']['bytes']==b.hex()
    cc=list(CS.disasm(b,pc))
    if cc:assert(i['mnemonic'],i['operands'])==(cc[0].mnemonic,cc[0].op_str)
    else:assert i['decoder']=='LLVM'and(i['mnemonic'],i['operands'])==(i['LLVM']['mnemonic'],i['LLVM']['operands'])
 cv={'label':'cache','roles':s['cache_functions']};cf=cv['roles'];assert len(cf)==6 and s['cache_uuid']=='2bd06591-e751-3e84-963f-b08dab6af23a'
 for role,mn,op in[
  ('apply_f','stp','x0, x2, [sp]'),('apply_f','str','x1, [sp, #0x10]'),
  ('function_adapter','ldp','x22, x21, [x1, #8]'),('function_adapter','ldr','x1, [x20, #0x10]'),
  ('function_adapter','mov','x2, x21'),('function_adapter','blraaz','x22'),
  ('apply_block','stp','x19, x20, [sp, #0x18]'),('block_adapter','ldr','x21, [x1, #8]'),
  ('block_adapter','mov','x1, x0'),('block_adapter','ldr','x2, [x20, #0x10]'),
  ('block_adapter','ldr','x9, [x8, #0x10]!'),('block_adapter','mov','x0, x21'),('block_adapter','blraa','x9, x8'),
  ('walker','ldr','x0, [x24, x25, lsl #3]'),('walker','ldr','x27, [x0]'),
  ('walker','mov','x1, x20'),('walker','blraaz','x21')]:need(cv,role,mn,op)
 for a,b in[('apply_f','walker'),('apply_block','walker'),('function_adapter','key_accessor'),('block_adapter','key_accessor')]:need(cv,a,'bl','#'+cf[b]['start'])
 for role,export in[('apply_f','_xpc_dictionary_apply_f'),('apply_block','_xpc_dictionary_apply')]:assert hex(s['cache_exports'][export]['address'])==cf[role]['start']
 for r in cf.values():
  raw=bytes.fromhex(r['bytes']);assert h(raw)==r['sha256']and len(raw)==int(r['end'],16)-int(r['start'],16)==4*len(r['instructions'])
  for j,i in enumerate(r['instructions']):
   pc=int(r['start'],16)+4*j;cc=list(CS.disasm(raw[4*j:4*j+4],pc));assert len(cc)==1 and(i['ea'],i['mnemonic'],i['operands'])==(hex(pc),cc[0].mnemonic,cc[0].op_str)
 job=s['job_declaration'];assert job['sha256']=='ca21543400f3ead9e96d2434f968184b6acd2e1e3de57322ca3da663831eae3c'
 assert job['frozen_comparison_match']and not job['live_job_state_refreshed'];p=job['plist']
 assert p['Label']=='com.apple.fairplayd'and p['UserName']==p['GroupName']=='_fpsd'
 assert p['MachServices']=={'com.apple.unfreed':{'HostSpecialPort':17},'com.apple.arcade.fpsd':{'HostSpecialPort':31},'com.apple.fairplayd':True,'com.apple.fpsd':True,'com.apple.fpsd.sim':True,'com.apple.fairplayd.xpc':True}
 assert p['KeepAlive']=={'Crashed':True}and p['EnablePressuredExit']is False and p['EnableTransactions']is False
 assert p['EnvironmentVariables']=={'DYLD_PAGEIN_LINKING':'0'}and 'MultipleInstances'not in p and '_Conclave'not in p and 'DaemonNotifications'not in p
 assert s['verified_source_counts']['callback_slots_checked']==128
 return rows

def sdk_checks():
 code='''#include <stdint.h>
#include <mach/mach.h>
#include <sys/errno.h>
#define A(x) static_assert((x), #x)
A(sizeof(void*)==8); A(sizeof(uint64_t)==8); A(sizeof(uint32_t)==4);
A(sizeof(uint16_t)==2); A(sizeof(mach_port_name_t)==4);
A(EBUSY==16); A(EINVAL==22); A(EALREADY==37);
'''
 cmd=['/usr/bin/clang','-arch','arm64','-isysroot',str(SDK),'-std=c++17','-fsyntax-only','-x','c++','-']
 r=subprocess.run(cmd,input=code,capture_output=True,text=True);assert r.returncode==0 and not r.stderr,r.stderr
 return{'command':cmd,'code':code,'code_sha256':h(code.encode()),'assertions':8,'exit_code':r.returncode,
         'stderr':r.stderr,'compiler_path':'/usr/bin/clang','compiler_sha256':sha('/usr/bin/clang')}

def alterations(s):
 controls=[]
 changes=[('callback_slot',lambda q:q['variants'][0]['producers'][0]['tables'][0]['entries'][3].update(target=q['variants'][0]['callback_targets'][4])),
 ('cookie_offset',lambda q:q['variants'][0]['producers'][0]['tables'][0].update(cookie_stack_offset_bytes=0)),
 ('block_target',lambda q:q['variants'][0]['MachServices_block']['pointers'][1].update(target=q['variants'][0]['roles']['callback0']['start'])),
 ('declaration_slot',lambda q:q['job_declaration']['plist']['MachServices']['com.apple.unfreed'].update(HostSpecialPort=34)),
 ('x1_instruction',lambda q:q['variants'][1]['roles']['job_create']['instructions'][10].update(operands='x0, x0')),
 ('property_binding',lambda q:q['variants'][0]['schema_type_bindings'][-1].update(symbol='__xpc_type_array'))]
 for name,mutate in changes:
  q=copy.deepcopy(s);mutate(q)
  try:verify(q)
  except AssertionError:controls.append({'alteration':name,'rejected':True})
  else:raise AssertionError('Accepted altered evidence: '+name)
 return controls

def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert s==build();rows=verify(s);sdk=sdk_checks();negative=alterations(s)
 counts={**s['verified_source_counts'],'instruction_assertions':len(rows),'SDK_assertions':8,'SDK_compilations':1,'rejected_evidence_alterations':len(negative)}
 c={'generator_sha256':sha(__file__),'dependencies':{'recover_'+P+'.py':sha(ROOT/('recover_'+P+'.py'))},
    'source_recapture_match':True,'instruction_assertions':rows,'SDK_checks':sdk,'alterations':negative,
    'verified_counts':counts,'all_checks_pass':True,'static_scope':'Both original slices, bounded table/literal/direct-branch locators, ordinary plist and instance paths, typed property-to-MachServices callback, callback roles and socket activation owner. Native job identity, admission, scheduling and IPC unknown.',
    **{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
