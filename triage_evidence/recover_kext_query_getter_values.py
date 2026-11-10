#!/usr/bin/env python3
"""Pin provider metadata getters,their internal records and daemon consumption."""
import hashlib,json,struct
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,POOL,TABLE,selected,qword
from kernel_native_reader import Kernel
from recover_kext_aes_handoff import function
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha
from recover_daemon_xpc_core_bridge import FLAGS,IMAGE as DAEMON,SOURCE as DAEMON_SOURCE
P='kext_query_getter_values'
SCOPE='Source-established version4c0b0000 and capability1f8 for the pinned base-provider getter routes,with exact internal bank/pointer/record/return contracts and conditional daemon cache specialization. Ordinary returns,stable original tables,guard/PAC and live connection/provider/build pairing remain premises;no native transaction or hardware capability semantics are asserted.'
OBSERVATION={'database': '71c5aa51f433', 'observed_UTC': '2026-11-10', 'input_sha256': '2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c', 'read_only': True, 'IDB_mutation_requested': False, 'recall_matches': 0, 'functions': [{'start': '0xfffffe000a5a299c', 'end': '0xfffffe000a5a2bac', 'size_bytes': 528, 'sha256': '29dba6231cafb21f4275b2a3e195b278d162ff523fb4f5e2621a86fbc5dea2ef'}, {'start': '0xfffffe000a5a49d8', 'end': '0xfffffe000a5a4bc0', 'size_bytes': 488, 'sha256': 'd89e99f2785788031ef111a5fe5617302c87e43f55bc8f38736fc15c9c3e56ee'}, {'start': '0xfffffe000a66a5a8', 'end': '0xfffffe000a66a7e0', 'size_bytes': 568, 'sha256': '9266041c1c8c48ef1bfc76bf361f7974d4724170f2bbf42cdb9992cb16e143b5'}, {'start': '0xfffffe000a5c22a8', 'end': '0xfffffe000a5c22b8', 'size_bytes': 16, 'sha256': 'b416e2a6d2004dda88794649bf0f3b50ab2948e9b0fa80253b4d115b1805b8ea'}, {'start': '0xfffffe000a5aec10', 'end': '0xfffffe000a5aec24', 'size_bytes': 20, 'sha256': 'c80fa9a1948582be84d8fe18cd64197a4c04ef0eef0a331d59fc3446b06d90a5'}]}
ENTRIES={'version_getter':0xfffffe000a5a299c,'capability_getter':0xfffffe000a5a49d8,'version_adapter':0xfffffe000a66a5a8,'capability_leaf':0xfffffe000a5c22a8,'status_leaf':0xfffffe000a5aec10,'version_UserClient':0xfffffe000a5050c8,'capability_UserClient':0xfffffe000a505120,'version_provider_stub':0xfffffe000a504ed4,'capability_provider_stub':0xfffffe000a504edc}
SPECS=[('version_A','A',0x16,0x88,'pool',-4),('version_B','D',0x87,-0xc3,'pool',-4),('version_TABLE','D',0x87,-0xac,'pool',-12),('version_call','E',0x98,0xee6,'table',0),('capability_A','D',0x47,0xa2,'pool',0),('capability_B','A',0x5c,-0xb6,'pool',-4),('capability_TABLE','B',0x37,-7,'pool',-12),('capability_call','A',0xd8,0xf45,'table',0),('adapter_A','A',0x3e,0xa7,'pool',0),('adapter_B','B',0x37,-0x1e,'pool',-4),('adapter_TABLE','A',0xd8,0x13,'pool',-12),('adapter_call','A',0xd8,0xf1f,'table',0)]
OLD=[('daemon_iokit_census','query22_status_and_size'),('daemon_iokit_census','query23_status_and_size'),('daemon_iokit_census','kext_version_publication'),('daemon_iokit_census','kext_capability_publication'),('daemon_query_state','helper_cache_fields'),('daemon_query_state','helper_zero_capability_dispatch'),('daemon_query_state','caller_normal_return_marker'),('daemon_query_fallback','composed_version_marker'),('daemon_query_fallback','composed_capability_fallback')]
DEPS=['kext_port_tools.py','kernel_native_reader.py','recover_kext_aes_handoff.py','recover_kext_cold_init.py','daemon_word_round_tools.py','validate_daemon_mode_one_word_schedule.py','validate_daemon_existing_scalar_reader.py','validate_daemon_constructor_inputs.py','validate_daemon_list_output.py','validate_daemon_reader_container_origins.py','daemon_iokit_census_contracts.json','daemon_iokit_census_proofs.json','daemon_query_state_contracts.json','daemon_query_state_proofs.json','daemon_query_fallback_contracts.json','daemon_query_fallback_proofs.json']
for parent,name in OLD:
 row=next(p for p in json.loads(read(ROOT/(parent+'_proofs.json')))['proofs']if p['name']==name);DEPS.append(row['original_file'])
def build():
 assert sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c' and sha(DAEMON_SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e';k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');fs={}
 for name,a in ENTRIES.items():
  f=function(k,e,a);raw=bytes.fromhex(f.pop('bytes_hex'));assert IMAGE.read(a,len(raw))==raw;f['bytes']=raw.hex();fs[name]=f
 for r in OBSERVATION['functions']:
  f=next(f for f in fs.values()if f['start']==r['start']);assert f['end']==r['end']and len(bytes.fromhex(f['bytes']))==r['size_bytes']and f['sha256']==r['sha256']
 families={'A':(0xfffffe0007949dd0,0xfffffe000792fbc0),'B':(0xfffffe0007949fd0,0xfffffe000792ffc0),'D':(0xfffffe000792fcc0,0xfffffe00079391f0),'E':(0xfffffe0007941f60,0xfffffe000794a0d0)};banks={};rules=[]
 for name,(l,r)in families.items():
  for side,a in[('L',l),('R',r)]:banks[name+side]={'address':hex(a),'bytes':IMAGE.read(a,256).hex()};assert k.read(a,256)==IMAGE.read(a,256)
 for name,fam,key,add,base,bias in SPECS:
  row=selected(*families[fam],key,add,POOL if base=='pool'else TABLE,bias);row.update(name=name,family=fam,original_pointer=pointer(k,int(row['slot'],16)));rules.append(row)
 look={r['name']:r for r in rules}
 for name,target,div in[('version_call',ENTRIES['version_adapter'],0x5c97),('capability_call',ENTRIES['capability_leaf'],0x7787),('adapter_call',ENTRIES['status_leaf'],0x3936)]:assert int(look[name]['target'],16)==target and int(look[name]['original_pointer']['diversity'],16)==div
 for name in['version_TABLE','capability_TABLE','adapter_TABLE']:assert int(look[name]['target'],16)==TABLE
 pool=[{'offset':hex(off),'slot':hex(POOL+off),'value':hex(qword(POOL+off)),'original_pointer':pointer(k,POOL+off)}for off in[0xc08,0x158,0x458,0x638,0x840,0xbb8,0x4f0,0x578]]
 old=json.loads(read(ROOT/'daemon_iokit_census_contracts.json'));queries=[]
 for row in old['kext_query_contracts']:
  # Recapture the complete typed dispatch record and provider vtable pointer.
  descriptor=pointer(k,0xfffffe000846b770+(row['selector']-1)*8);assert descriptor==row['descriptor_pointer'];record=int(descriptor['target'],16);assert k.read(record,48).hex()==row['descriptor_original48_hex'];assert list(struct.unpack('<6Q',IMAGE.read(record,48)))==[int(v,16)for v in row['descriptor_normalized_fields6']]
  for key in['method_pointer','provider_slot']:assert pointer(k,int(row[key]['slot'],16))==row[key]
  queries.append(row)
 daemon=[]
 for name in['daemon_iokit_census_contracts.json','daemon_query_state_contracts.json','daemon_query_fallback_contracts.json']:
  for f in json.loads(read(ROOT/name))['spans']:
   raw=bytes.fromhex(f['bytes_hex']);assert DAEMON.read(int(f['start'],16),len(raw))==raw;daemon.append({'source':name,'label':f.get('label'),'start':f['start'],'bytes_checked':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
 cp=SOURCE.parent/(SOURCE.name+'.c');lines=cp.read_text().splitlines();excerpts=[]
 for a,z in[(130194,130230),(130928,130960),(223044,223081),(151378,151385),(138758,138765)]:excerpts.append({'input_name':cp.name,'input_sha256':sha(cp),'first_line':a,'last_line':z,'text':'\n'.join(lines[a-1:z])})
 return {'generator_sha256':sha(__file__),'static_scope':SCOPE,'image_name':SOURCE.name,'image_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'daemon_image_sha256':sha(DAEMON_SOURCE),'dependencies':{n:sha(ROOT/n)for n in DEPS},'fragments':fs,'banks':banks,'bank_rules':rules,'literal_pool_records':pool,'retained_query_routes':queries,'daemon_recaptures':daemon,'associated_C':excerpts,'IDA_observation':OBSERVATION,'IDA_observation_repeated_on_validation':False,'new_IDA_access':True,'verified_source_counts':{'kext_source_ranges':len(fs),'kext_source_instructions':sum(len(f['instructions'])for f in fs.values()),'kext_source_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'exhaustive_bank_rules':len(rules),'exhaustive_bank_inputs':len(rules)*256,'literal_bank_bytes':2048,'literal_pool_records':len(pool),'saved_IDA_functions_matched':5,'saved_IDA_bytes_matched':1620,'daemon_ranges_recaptured':len(daemon),'daemon_bytes_recaptured':sum(r['bytes_checked']for r in daemon)},**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
