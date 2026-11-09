#!/usr/bin/env python3
"""Fresh static recapture plus independent frozen-endpoint parsing.
No launchctl re-query, native target call, registration change or target fixture.
"""
import ast,copy,json,re,struct,subprocess,uuid
from datetime import datetime
from recover_rpc700_endpoint_inventory import ROOT,P,FLAGS,SDK,CS,APIS,sha,h,build

COUNTS={'cache_images':4113,'declared_GOT_words':1815207,'slide_maps':14,'slide_chain_entries':30802349,'API_chain_matches':5,'host_getter_chain_matches':1,'host_setter_chain_matches':0,'raw_flag8_executable_maps':36,'stub_candidate_start_sites':2477972,'getter_stubs':1,'branch_words_scanned':65480381,'branch_matches':3,'complete_functions':7,'instructions':513,'function_bytes':2052}

def verify_observation(o):
 assert o['native_inspection_executed']and o['native_launchd_interrogation_executed']and o['uid']==501
 assert all(o[k]is False for k in['FairPlay_requests_sent','registration_modified','kernel_port_objects_observed','receiver_identified','full_goal_complete'])
 assert [r['domain']for r in o['domain_observations']]==['system','gui/501']
 labels=[r['domain']+'/'+n for r in o['domain_observations']for n in r['selected_apple_job_labels']]
 assert len(labels)==len(set(labels))==880 and all('/com.apple.'in n for n in labels)
 assert [len(r['selected_apple_job_labels'])for r in o['domain_observations']]==[428,452]
 assert [r['services_rows_total']for r in o['domain_observations']]==[443,481]
 assert [r['argv'][2]for r in o['queries']]==labels
 def timestamps(r):
  a=datetime.fromisoformat(r['started_UTC']);b=datetime.fromisoformat(r['ended_UTC']);assert a.tzinfo and b.tzinfo and b>=a
  assert r['exit_code']==0 and not r['stderr']and re.fullmatch('[0-9a-f]{64}',r['stdout_sha256'])
 for r in o['domain_observations']:timestamps(r)
 assocs=[];endpoints=0
 for row in o['queries']:
  timestamps(row);assert row['argv'][:2]==['/bin/launchctl','print']and len(row['argv'])==3
  text=row['selected_text'];assert h(text.encode())==row['selected_text_sha256']
  # Independent block parser, separate from the capture's state machine.
  parsed=[]
  for m in re.finditer(r'^\t\t"([^"\n]+)" = \{\n(.*?)^\t\t\}$',text,re.M|re.S):
   r={'service':m[1]}
   for line in m[2].splitlines():
    f=re.fullmatch(r'\t\t\t([^=]+) = (.+)',line);assert f,line
    key=f[1].strip();assert key not in r;r[key]=f[2]
   parsed.append(r)
  assert parsed==row['endpoints'];endpoints+=len(parsed)
  for e in parsed:
   if 'host-special port'in e:assocs.append({'job':row['argv'][2],**e})
 assert endpoints==2038 and assocs==o['host_associations']and len(assocs)==18
 slots=[int(re.fullmatch(r'(\d+) \(.+\)',r['host-special port'])[1])for r in assocs]
 assert sorted(slots)==[10,11,12,13,14,15,17,18,19,23,24,27,29,30,31,33,35,36]and 34 not in slots
 fp=[r for r in assocs if r['job']=='system/com.apple.fairplayd'];assert[(r['service'],r['host-special port'],r['active'])for r in fp]==[('com.apple.unfreed','17 (fairplay)','1'),('com.apple.arcade.fpsd','31 (fairplayd)','1')]
 managed=[e for row in o['queries']if 'managedappdistribution'in row['argv'][2]for e in row['endpoints']]
 assert len(managed)==4 and all(e['active']=='0'and e['watching']=='1'and'host-special port'not in e for e in managed)
 for probe in o['capture_probes']:assert h(probe['code'].encode())==probe['sha256'];ast.parse(probe['code'])
 return{'domain_queries':2,'selected_Apple_job_queries':880,'successful_job_queries':880,'endpoints':endpoints,'host_associations':18,'host_indices':sorted(slots),'active_associations':sum(r['active']=='1'for r in assocs),'inactive_associations':sum(r['active']=='0'for r in assocs),'managed_app_endpoints':4,'slot34_printed':False}

def verify(s):
 assert s['cache_uuid']=='2bd06591-e751-3e84-963f-b08dab6af23a'and s['verified_source_counts']==COUNTS
 rows=[];fs=s['API_functions'];assert set(fs)==set(APIS)
 addresses={'_host_get_special_port':'0x180548a54','_host_set_special_port':'0x18056895c','_mach_ports_lookup':'0x180553a14','_mach_ports_register':'0x18054f880'}
 for n,f in fs.items():assert f['start']==addresses[n]and any(q['name']==n for q in f['original_nlist'])
 old=json.loads((ROOT/'host_special_registration_source.json').read_text())['cache_functions']
 for name,ea in[('_host_get_special_port','0x180548acc'),('_host_set_special_port','0x1805689e4')]:
  f=fs[name];assert next(q for q in old if q['start']==f['start'])['bytes']==f['bytes']
  i=next(q for q in f['instructions']if q['ea']==ea);assert(i['mnemonic'],i['operands'])==('bl','#0x18055a894');rows.append({'function':f['start'],**i})
 t=s['image_table'];rh=bytes.fromhex(t['root_header_bytes']);offset,count=struct.unpack_from('<II',rh,0x1c0);raw=bytes.fromhex(t['bytes'])
 assert(offset,count)==(t['file_offset'],t['count'])and len(raw)==32*count and h(raw)==t['sha256']and count==len(s['image_headers'])==4113
 assert str(uuid.UUID(bytes=rh[88:104]))==s['cache_uuid']
 for j,row in enumerate(s['image_headers']):
  assert struct.unpack_from('<Q',raw,32*j)[0]==int(row['address'],16)
  bb=bytes.fromhex(row['header_bytes']);assert h(bb)==row['header_sha256'];n,z=struct.unpack_from('<II',bb,16);assert len(bb)==32+z
  at=32;sec=[];uid=None
  for _ in range(n):
   cmd,size=struct.unpack_from('<II',bb,at)
   if cmd==0x1b:uid=bb[at+8:at+24].hex()
   if cmd==0x19:
    ns=struct.unpack_from('<I',bb,at+64)[0]
    for k in range(ns):
     q=bb[at+72+80*k:at+152+80*k];a,sz=struct.unpack_from('<QQ',q,32);sec.append({'name':q[:16].split(b'\0')[0].decode(),'segment':q[16:32].split(b'\0')[0].decode(),'address':a,'size':sz})
   at+=size
  assert at==len(bb)and uid==row['UUID_bytes']and sec==row['sections']
  assert[{k:q[k]for k in['name','segment','address','size']}for q in row['declared_GOT_sections']]==[q for q in sec if q['name']in['__got','__auth_got']]
 assert sum(q['words']for r in s['image_headers']for q in r['declared_GOT_sections'])==1815207
 assert sum(q['chain_entries_visited']for q in s['chain_maps'])==30802349 and len(s['chain_maps'])==14
 assert [q['mapping']for q in s['chain_maps']]==[q for q in s['cache_mappings']if q['slide_off']]
 expected=[('_host_get_special_port','0x1e2103890'),('_mach_ports_lookup','0x1e2103b60'),('_mach_ports_register','0x1e2103b68'),('_mach_ports_lookup','0x2696d45a8'),('_mach_ports_register','0x2daa3cd40')]
 assert[(r['API'],r['pointer']['address'])for r in s['chain_matches']]==expected
 for r in s['chain_matches']:
  p=r['pointer'];assert p['chain_membership_verified']and p['authenticated']and p['target']==addresses[r['API']]and not r['within_declared_GOT']and not r['declared_section_owners']
 assert[(r['address'],r['target'])for r in s['known_pointer_controls']]==[('0x1e2103b60',addresses['_mach_ports_lookup']),('0x1e2103b68',addresses['_mach_ports_register'])]
 assert len(s['getter_stubs'])==1;st=s['getter_stubs'][0];assert st['address']=='0x188079af0'and st['pointer']['address']=='0x1e2103890'and st['pointer']['target']==addresses['_host_get_special_port']
 zz=list(CS.disasm(bytes.fromhex(st['bytes']),int(st['address'],16)));assert [i.mnemonic for i in zz]==['adrp','add','ldr','braa']and st['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in zz]
 assert [q['mapping']for q in s['stub_maps']]==[q for q in s['cache_mappings']if q['initprot']&4 and q['flags']&8]
 assert sum(q['candidate_start_sites']for q in s['stub_maps'])==2477972
 targets={int(k,16):v for k,v in s['branch_targets'].items()};assert targets=={0x180548a54:'getter_direct',0x18056895c:'setter_direct',0x188079af0:'getter_stub'}
 lo=min(targets)-(1<<27);hi=max(targets)+(1<<27)+4;expectedmaps=[]
 for m in s['cache_mappings']:
  if not m['initprot']&4:continue
  a=(max(lo,m['va'])+3)&~3;z=min(hi,m['va']+m['size'])&~3
  if a<z:expectedmaps.append((m,hex(a),hex(z),(z-a)//4))
 assert[(q['mapping'],q['start'],q['end'],q['aligned_words_scanned'])for q in s['branch_maps']]==expectedmaps
 assert sum(q[3]for q in expectedmaps)==65480381
 assert[(q['address'],q['target'])for q in s['branch_matches']]==[('0x181ed46b8','0x188079af0'),('0x181ed4778','0x188079af0'),('0x185537ca0','0x188079af0')]
 callers=s['caller_functions'];assert set(callers)=={'0x181ed4660','0x181ed4728','0x185537c74'}
 for f in list(fs.values())+list(callers.values()):
  bb=bytes.fromhex(f['bytes']);cc=list(CS.disasm(bb,int(f['start'],16)));assert h(bb)==f['sha256']and len(bb)==int(f['end'],16)-int(f['start'],16)==4*len(cc)==4*len(f['instructions'])
  assert[(i['ea'],i['mnemonic'],i['operands'])for i in f['instructions']]==[(hex(i.address),i.mnemonic,i.op_str)for i in cc]
 for q in s['branch_matches']:
  pc=int(q['address'],16);w=struct.unpack('<I',bytes.fromhex(q['bytes']))[0];im=w&0x3ffffff;im=im-(1<<26)if im&(1<<25)else im
  assert w&0xfc000000==0x94000000 and pc+4*im==int(q['target'],16)
  f=callers[q['function']];ii=f['instructions'];ix=next(j for j,i in enumerate(ii)if i['ea']==q['address']);assert(ii[ix]['mnemonic'],ii[ix]['operands'])==('bl','#0x188079af0')
  selector=1 if q['address']=='0x185537ca0'else 2
  assert[(i['mnemonic'],i['operands'])for i in ii[ix-3:ix]]==[('add','x3, sp, #0xc'if selector==1 or q['address']=='0x181ed46b8'else'x3, sp, #8'),('mov','w1, #-1'),('mov',f'w2, #{selector}')]
  rows.extend({'function':f['start'],**i}for i in ii[ix-3:ix+1])
 assert sha(ROOT/(P+'_observations.json'))==s['observation_sha256'];assert all(s[k]is False for k in FLAGS);return rows

def sdk_checks():
 code='''#include <mach/mach.h>
#include <mach/host_priv.h>
#include <mach/host_special_ports.h>
#define A(x) static_assert((x), #x)
A(HOST_PORT==1);A(HOST_PRIV_PORT==2);A(HOST_UNFREED_PORT==17);A(HOST_FAIRPLAYD_PORT==31);
A(HOST_MANAGEDAPPDISTD_PORT==34);A(HOST_MAX_SPECIAL_PORT==36);A(HOST_LOCAL_NODE==-1);
A(sizeof(mach_port_t)==4);A(sizeof(void*)==8);
A(__is_same(decltype(&host_get_special_port),kern_return_t(*)(host_priv_t,int,int,mach_port_t*)));
A(__is_same(decltype(&host_set_special_port),kern_return_t(*)(host_priv_t,int,mach_port_t)));
'''
 cmd=['/usr/bin/clang','-arch','arm64','-isysroot',str(SDK),'-std=c++17','-fsyntax-only','-x','c++','-'];r=subprocess.run(cmd,input=code,capture_output=True,text=True);assert r.returncode==0 and not r.stderr,r.stderr
 return{'command':cmd,'code':code,'code_sha256':h(code.encode()),'assertions':code.count('A(')-1,'exit_code':r.returncode,'stderr':r.stderr,'compiler_path':'/usr/bin/clang','compiler_sha256':sha('/usr/bin/clang'),'scope':'Current installed SDK indices, name/pointer widths and public function types; no target-kernel semantic-name or native owner pairing.'}

def proofs():
 q='''(set-option :timeout 10000)
(set-logic QF_BV)
(declare-fun delta () (_ BitVec 64))
(assert (bvsge delta #xfffffffff8000000))
(assert (bvsle delta #x0000000007fffffc))
(assert (= (bvand delta (_ bv3 64)) (_ bv0 64)))
(define-fun encoded () (_ BitVec 26) ((_ extract 25 0) (bvlshr delta (_ bv2 64))))
(define-fun decoded () (_ BitVec 64) (bvshl ((_ sign_extend 38) encoded) (_ bv2 64)))
(assert (distinct delta decoded))
(check-sat)
'''
 r=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=q,capture_output=True,text=True);assert r.returncode==0 and r.stdout.strip()=='unsat'and not r.stderr,(r.stdout,r.stderr)
 return[{'name':'signed_imm26_roundtrip_including_negative_endpoint','query':q,'result':'unsat','scope':'Auxiliary B/BL immediate arithmetic only, for all aligned deltas in [-2^27,2^27-4] B. No code reachability, arbitrary indirect calls or native execution proof.'}]

def alterations(s,o):
 def target(q):q['chain_matches'][0]['pointer']['target']='0x18056895c'
 def branch(q):q['branch_matches'][0]['bytes']='1f2003d5'
 def selector(q):next(i for i in q['caller_functions']['0x181ed4660']['instructions']if i['ea']=='0x181ed46b4').update(operands='w2, #0x22')
 def bound(q):q['branch_maps'][-1]['end']=hex(int(q['branch_maps'][-1]['end'],16)-4)
 def index(q):q['host_associations'][0]['host-special port']='34 (managedappdistd)'
 def missing(q):q['queries'].pop()
 def active(q):next(r for r in q['queries']if r['argv'][2]=='system/com.apple.managedappdistributiond')['endpoints'][0]['active']='1'
 def scope(q):q['receiver_identified']=True
 out=[]
 for name,source,change,check in [('chain_target',s,target,verify),('branch_word',s,branch,verify),('caller_selector',s,selector,verify),('branch_range_end',s,bound,verify),('printed_host_index',o,index,verify_observation),('missing_job_query',o,missing,verify_observation),('managed_endpoint_state',o,active,verify_observation),('native_owner_claim',o,scope,verify_observation)]:
  q=copy.deepcopy(source);change(q)
  try:check(q)
  except AssertionError:out.append({'alteration':name,'rejected':True})
  else:raise AssertionError('Accepted altered evidence '+name)
 return out

def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert s==build();o=json.loads((ROOT/(P+'_observations.json')).read_text());rows=verify(s);obs=verify_observation(o);sdk=sdk_checks();pr=proofs();neg=alterations(s,o)
 old=json.loads((ROOT/'rpc700_publication_observations.json').read_text());oldmanaged=[e for r in old['commands']if 'managedappdistribution'in r['argv'][2]for e in r['endpoints']];assert len(oldmanaged)==4 and all(e['active']=='1'for e in oldmanaged)
 c={'generator_sha256':sha(__file__),'dependencies':{'recover_'+P+'.py':sha(ROOT/('recover_'+P+'.py'))},'source_recapture_match':True,'instruction_assertions':rows,'observation_checks':obs,'SDK_checks':sdk,'proofs':pr,'alterations':neg,'solver':{'path':'/opt/homebrew/bin/z3','sha256':sha('/opt/homebrew/bin/z3')},
  'snapshot_comparison':{'prior_started_UTC':old['started_UTC'],'prior_ended_UTC':old['ended_UTC'],'new_domain_started_UTC':o['domain_observations'][0]['started_UTC'],'new_job_query_started_UTC':o['started_UTC'],'new_job_query_ended_UTC':o['ended_UTC'],'prior_managed_endpoints_active':4,'new_managed_endpoints_inactive':4,'same_kernel_objects_proved':False},
  'verified_counts':{**s['verified_source_counts'],**s['observation_counts'],'instruction_assertions':len(rows),'SDK_assertions':sdk['assertions'],'SDK_compilations':1,'scalar_queries_unsat':len(pr),'rejected_evidence_alterations':len(neg)},'all_checks_pass':True,
  'static_scope':'Whole selected cache image/GOT metadata and v5 slide-chain inventory; selected shared-stub shape/raw flag8 executable mappings; all representable direct B/BL source ranges to three fixed targets and complete matched callers. Indirect/dynamic/other-image references and hardware PAC remain outside this scope.',
  'native_observation_scope':'Frozen 2 domain listings and 880 listed com.apple. job queries in system and gui/501, at recorded times; 2038 endpoint records and 18 printed host associations. Non-atomic, time-bound metadata; no kernel-slot occupancy, receiver identity or FairPlay request proof.',
  'native_inspection_executed':True,'native_launchd_interrogation_executed':True,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(c['verified_counts']),flush=True)
if __name__=='__main__':main()
