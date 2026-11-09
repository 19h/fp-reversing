#!/usr/bin/env python3
"""Validate dual-slice interface anchors, frozen metadata and actual SDK ABI.
O(B+F+I) recapture plus O(I) checks; no target execution or metadata refresh.
"""
import copy,json,struct,subprocess
from recover_launchd_variant_binding import ROOT,P,FLAGS,SDK,CS,sha,h,build
EXPECTED={
 'arm64e':{'uuid':'f5ce73f2-36d5-3916-8ab0-ee0d6c8a1d71','subtype':0x80000002,'sha256':'c8593a95e0937884b71e014c38b27f84db2c292f6a5e904a452d69a9a365bdb6','roles':{'fixed22':0x10002d3a8,'cleanup':0x10002fd84,'publisher':0x10003012c,'fixed16':0x100035930,'parser':0x10005c840,'constructor':0x100047064,'task_field':0x1000479cc,'owner_query':0x100003708,'send_name':0x100046c28,'send_object':0x10005cb6c,'exception':0x100043fd0},'setter':0x10005e260,'sites':[0x10002d498,0x10002fec8,0x10003055c,0x100035a04],'counts':[1194,0]},
 'arm64e.x1':{'uuid':'62af2b7d-327e-334a-a1d7-83777efc3c12','subtype':0x8000000c,'sha256':'c7ca2883eefa4264d7f42fa8a8e2585a5406494dab564af39558e4cb5be2fc64','roles':{'fixed22':0x10002ca6c,'cleanup':0x10002f3b8,'publisher':0x10002f730,'fixed16':0x100034ef8,'parser':0x10005b810,'constructor':0x100046328,'task_field':0x100046c54,'owner_query':0x1000036d8,'send_name':0x100045ef8,'send_object':0x10005bb3c,'exception':0x10004336c},'setter':0x10005d224,'sites':[0x10002cb5c,0x10002f4f0,0x10002fb60,0x100034fcc],'counts':[1176,27]}}
def verify(s):
 assert s['source_sha256']=='1ba04f6d568343f1be0467e5ef0a4700c4b204b49182eb38f0de636efb176168'and s['source_size_bytes']==1319360 and s['runtime_selected_slice']=='unknown';assert len(s['variants'])==2
 checks=[]
 for v in s['variants']:
  e=EXPECTED[v['label']];roles=v['roles'];assert v['uuid']==e['uuid']and int(v['slice']['subtype'],16)==e['subtype']and v['slice']['sha256']==e['sha256'];assert set(roles)==set(e['roles'])and all(int(roles[k]['start'],16)==a for k,a in e['roles'].items())
  assert v['fixups_count']==2447 and v['fixup_reference']['fixups_compared']==2447 and v['fixup_reference']['all_matches'];assert len(v['setter_branch_candidates'])==4 and sorted(int(q['site'],16)for q in v['setter_branch_candidates'])==e['sites'];assert int(v['stubs']['_host_set_special_port']['address'],16)==e['setter'];assert v['host_property_literal']['text']=='HostSpecialPort'
  assert [sum(len(r['instructions'])for r in roles.values()),sum(len(r['extended'])for r in roles.values())]==e['counts']
  for name,r in roles.items():
   raw=bytes.fromhex(r['bytes']);assert h(raw)==r['sha256']and int(r['end'],16)-int(r['start'],16)==len(raw)==4*len(r['instructions'])
   for j,i in enumerate(r['instructions']):
    b=raw[4*j:4*j+4];assert int(i['ea'],16)==int(r['start'],16)+4*j and i['bytes']==i['LLVM']['bytes']==b.hex();cc=list(CS.disasm(b,int(i['ea'],16)))
    if cc:assert i['decoder']=='Capstone'and(i['mnemonic'],i['operands'])==(cc[0].mnemonic,cc[0].op_str)
    else:assert i['decoder']=='LLVM'and(i['mnemonic'],i['operands'])==(i['LLVM']['mnemonic'],i['LLVM']['operands'])and i['mnemonic']in['pacibsppc','autibsppc','retabsppc','addpt']
   assert r['extended']==[i for i in r['instructions']if i['decoder']=='LLVM']
  def one(role,mn,op=None):
   found=[i for i in roles[role]['instructions']if i['mnemonic']==mn and(op is None or i['operands']==op)];assert len(found)==1,(v['label'],role,mn,op,found);i=found[0];checks.append({'variant':v['label'],'role':role,'site':i['ea'],'mnemonic':mn,'operands':i['operands']});return i
  def after(role,i,delta,mn,op=None):
   found=next(q for q in roles[role]['instructions']if int(q['ea'],16)==int(i['ea'],16)+delta);assert found['mnemonic']==mn and(op is None or found['operands']==op);checks.append({'variant':v['label'],'role':role,'site':found['ea'],'mnemonic':mn,'operands':found['operands']});return found
  def target(i):return int(i['operands'].split('#')[-1],0)
  # Integer property and mixed-signedness task property branches.
  a=one('parser','str','w21, [x20, #0x54]');after('parser',a,-16,'cmp','x0, #8');after('parser',a,-12,'b.lt');after('parser',a,-8,'cmp','x21, #0x24');after('parser',a,-4,'b.hi')
  a=one('task_field','cmp','w1, #6');b=after('task_field',a,4,'b.hi');c=one('task_field','cmp','w1, #0xb');assert target(b)==int(c['ea'],16);after('task_field',c,4,'b.gt');after('task_field',c,8,'str','w1, [x0, #0x50]')
  one('parser','bl','#'+roles['task_field']['start']);one('constructor','stp','x19, x20, [sp, #0x30]');one('constructor','bl','#'+v['stubs']['_xpc_dictionary_apply']['address'])
  # Shared selector2/3 table destination; owner predicate instructions retained.
  jt=v['owner_query_jump_table'];words=struct.unpack('<10i',bytes.fromhex(jt['bytes']));assert jt['targets']==[hex(int(jt['relative_base'],16)+w)for w in words]and jt['targets'][2]==jt['targets'][3]
  one('owner_query','ubfx','w22, w8, #6, #1');one('owner_query','and','w0, w22, #1')
  one('publisher','str','w8, [x19, #0x50]');a=one('publisher','mov','w8, #0x18');after('publisher',a,4,'str','w8, [x19, #0x54]')
  # Last ordinary setter path, its actual argument carriers, and cache/error convergence.
  setter=one('publisher','bl','#'+hex(e['setter']));after('publisher',setter,-4,'mov','x1, x21');after('publisher',setter,-8,'mov','x0, x20');after('publisher',setter,-12,'mov','x2, x0');after('publisher',setter,-16,'bl','#'+roles['send_name']['start']);after('publisher',setter,-20,'mov','w1, #1')
  branch=after('publisher',setter,4,'cbnz');cache=after('publisher',setter,8,'str','x19, [x23, x21, lsl #3]');after('publisher',setter,12,'mov','w0, #0');error=next(i for i in roles['publisher']['instructions']if int(i['ea'],16)==target(branch));assert(error['mnemonic'],error['operands'])==('sxtw','x0, w0');after('publisher',error,4,'bl','#'+v['stubs']['__os_assumes_log']['address']);end=after('publisher',error,8,'b');assert target(end)==int(cache['ea'],16)
  one('publisher','ldrsw','x21, [x19, #0x54]');a=one('publisher','cmp','w21, #0x18');after('publisher',a,4,'b.ne');one('publisher','bl','#'+roles['exception']['start'])
  # Cleanup condition and both fixed-index calls; no runtime ownership conclusion.
  a=one('cleanup','and','w8, w20, #0xfffffffb');after('cleanup',a,4,'cmp','w8, #0x19');skip=after('cleanup',a,8,'b.ne');after('cleanup',a,12,'bl','#'+v['stubs']['_mach_host_self']['address']);after('cleanup',a,16,'mov','x1, x20');after('cleanup',a,20,'mov','w2, #0');after('cleanup',a,24,'bl','#'+hex(e['setter']));after('cleanup',a,28,'cbnz');assert target(skip)==int(a['ea'],16)+32;one('cleanup','str','xzr, [x8, x20, lsl #3]')
  for role,op in[('fixed22','w1, #0x16'),('fixed16','w1, #0x10')]:a=one(role,'bl','#'+hex(e['setter']));after(role,a,-4,'mov',op)
  one('send_name','bl','#'+roles['send_object']['start']);one('send_name','b','#'+v['stubs']['_xpc_mach_send_get_right']['address']);a=one('send_object','bl','#'+v['stubs']['_xpc_mach_send_create_with_disposition']['address']);after('send_object',a,-4,'mov','w1, #0x11');one('exception','b','#'+v['stubs']['_host_set_exception_ports']['address'])
 # Only the earlier normal-slice body bytes are asserted equal to previous capture.
 old=json.loads((ROOT/'host_special_registration_source.json').read_text())['launchd']['ranges'];oldmap={r['start']:r['bytes']for r in old};assert all(oldmap[b['start']]==b['bytes']for b in s['variants'][0]['roles'].values())
 sections=[{r['name']:r for r in v['file_backed_sections']}for v in s['variants']];assert sections[0]['__text']['size_bytes']==377680 and sections[1]['__text']['size_bytes']==373524
 for name in['__cstring','__auth_got','__got']:assert sections[0][name]['sha256']==sections[1][name]['sha256']and sections[0][name]['size_bytes']==sections[1][name]['size_bytes']
 assert sections[0]['__cstring']['size_bytes']==94135
 obs=json.loads((ROOT/(P+'_observations.json')).read_text());assert s['native_observation_sha256']==sha(ROOT/(P+'_observations.json'))and obs['runtime_selected_slice']=='unknown'and obs['generator_sha256']==s['generator_sha256'];a,b,c=obs['queries'];assert a['pid']==1 and a['flavor']==19 and a['return_value']==0 and a['errno']==1 and not a['architecture_valid']and a['cpu_type']is None and a['cpu_subtype']is None;assert b['pid']!=1 and b['return_value']==8 and b['architecture_valid']and b['cpu_type']==0x100000c;assert c['pid']==1 and c['path']=='/sbin/launchd'and c['return_value']==13 and c['errno']==0
 assert all(s[k]is False and obs[k]is False for k in FLAGS)
 return checks
def sdk_checks():
 code='''#include <stddef.h>
#include <mach/machine.h>
#include <sys/proc_info.h>
#include <libproc.h>
#define A(x) _Static_assert((x), #x)
A(CPU_TYPE_ARM64==0x0100000c); A(CPU_SUBTYPE_ARM64E==2); A(CPU_SUBTYPE_ARM64E_X1==12);
A(CPU_SUBTYPE_ARM64_ALL==0); A((unsigned)CPU_SUBTYPE_MASK==0xff000000u);
A(CPU_SUBTYPE_HAS_ARM64E(0x80000002u)); A(CPU_SUBTYPE_HAS_ARM64E(0x8000000cu));
A(!CPU_SUBTYPE_HAS_ARM64X1(0x80000002u)); A(CPU_SUBTYPE_HAS_ARM64X1(0x8000000cu));
A(sizeof(cpu_type_t)==4); A(sizeof(cpu_subtype_t)==4); A(sizeof(struct proc_archinfo)==8);
A(offsetof(struct proc_archinfo,p_cputype)==0); A(offsetof(struct proc_archinfo,p_cpusubtype)==4);
A(PROC_PIDARCHINFO==19); A(PROC_PIDARCHINFO_SIZE==8);
'''
 cmd=['/usr/bin/clang','-arch','arm64','-isysroot',str(SDK),'-std=c11','-fsyntax-only','-x','c','-'];r=subprocess.run(cmd,input=code,capture_output=True,text=True);assert r.returncode==0 and not r.stderr
 return {'command':cmd,'code':code,'code_sha256':h(code.encode()),'assertions':16,'exit_code':r.returncode,'stderr':r.stderr,'compiler_path':'/usr/bin/clang','compiler_sha256':sha('/usr/bin/clang')}
def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert s==build();checks=verify(s);negative=[]
 for name,alter in[
  ('wrong_slice_subtype',lambda q:q['variants'][1]['slice'].__setitem__('subtype','0x80000002')),
  ('wrong_alternate_role',lambda q:q['variants'][1]['roles']['publisher'].__setitem__('start','0x10003012c')),
  ('missing_setter_candidate',lambda q:q['variants'][1]['setter_branch_candidates'].pop()),
  ('changed_property_literal',lambda q:q['variants'][1]['host_property_literal'].__setitem__('text','TaskSpecialPort')),
  ('changed_jump_destination',lambda q:q['variants'][1]['owner_query_jump_table']['targets'].__setitem__(2,'0x0')),
  ('changed_instruction_record',lambda q:q['variants'][1]['roles']['task_field']['instructions'][4].__setitem__('operands','w1, #7')),
  ('missing_extended_word',lambda q:q['variants'][1]['roles']['publisher']['extended'].pop()),
  ('claimed_runtime_slice',lambda q:q.__setitem__('runtime_selected_slice','arm64e.x1'))]:
  q=copy.deepcopy(s);alter(q)
  try:verify(q)
  except(AssertionError,KeyError,ValueError,StopIteration):negative.append(name)
  else:raise AssertionError('Accepted alteration: '+name)
 sdk=sdk_checks();counts={**s['verified_source_counts'],'interface_instruction_assertions':len(checks),'SDK_assertions':16,'SDK_compilations':1,'rejected_evidence_alterations':len(negative),'frozen_metadata_queries':3}
 obj={'generator_sha256':sha(__file__),'dependencies':{'recover_'+P+'.py':sha(ROOT/('recover_'+P+'.py'))},'source_recapture_match':True,'instruction_assertions':checks,'SDK_checks':sdk,'rejected_alterations':negative,'verified_counts':counts,'static_scope':'22 complete compiler-bounded bodies in two launchd slices; selected interface contracts and selected LLVM byte agreement. No whole-function equivalence, full-image decode, native launchd slice identity, registration, protected exchange or hardware authentication proof.','all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(obj,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
