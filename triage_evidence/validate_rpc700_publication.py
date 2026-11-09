#!/usr/bin/env python3
"""Validate frozen read-only observations and recapture static census; no launchctl.
O(plist bytes + snapshot bytes) time; O(census + largest plist) space.
"""
import copy,json,re
from pathlib import Path
from recover_rpc700_publication import P,ROOT,FLAGS,build,sha,digest
def check(s,o):
 assert len(s['plists'])==931 and len({r['path']for r in s['plists']})==931
 assert all(s['directory_exists'].values())
 fallback=[r for r in s['plists']if r['parser']!='plistlib'];assert len(fallback)==1
 f=fallback[0];assert f['path']=='/System/Library/LaunchAgents/com.apple.familycircled.plist'and f['fallback_exit']==0 and f['label']=='com.apple.familycircled'
 assert bytes.fromhex(f['original_prefix_hex']).startswith(b'<?xml version=1.0 encoding=UTF-8?>')
 declarations=[(r['label'],e['key_path'],e['value'])for r in s['plists']for e in r['host_special_ports']];assert len(declarations)==19 and len({v for _,_,v in declarations})==18 and all(v!=34 for _,_,v in declarations)
 assert ('com.apple.fairplayd','/MachServices/com.apple.unfreed/HostSpecialPort',17)in declarations
 assert ('com.apple.fairplayd','/MachServices/com.apple.arcade.fpsd/HostSpecialPort',31)in declarations
 assert len(o['commands'])==3 and o['started_UTC']<=o['ended_UTC'] and o['native_launchd_interrogation_executed']is True
 assert o['kernel_uuid']['stdout'].lower()=='9b65bd6e-027b-34d1-a22b-ac03dccffc84'and o['kernel_uuid']['exit_code']==0
 total=0
 for cmd in o['commands']:
  assert cmd['exit_code']==0 and not cmd['stderr'] and cmd['argv'][:2]==['/bin/launchctl','print']
  assert cmd['started_UTC']<=cmd['ended_UTC'] and digest(cmd['selected_text'].encode())==cmd['selected_text_sha256']
  text=cmd['selected_text'];assert '\tstate = running\n'in text
  blocks=re.findall(r'\t\t"([^"]+)" = \{\n(.*?)\t\t\}',text,re.S);parsed=[]
  for name,b in blocks:
   row={'service':name}
   for k,v in re.findall(r'^\t\t\t([^=\n]+) = ([^\n]+)$',b,re.M):row[k.strip()]=v
   parsed.append(row)
  assert parsed==cmd['endpoints']and all(e['active']=='1'and e['managed']=='1'and re.fullmatch('0x[0-9a-f]+',e['port'])for e in parsed);total+=len(parsed)
 assert total==10
 fp=o['commands'][0];eps={e['service']:e for e in fp['endpoints']};assert len(eps)==6 and eps['com.apple.unfreed']['host-special port']=='17 (fairplay)'and eps['com.apple.arcade.fpsd']['host-special port']=='31 (fairplayd)'
 assert len(o['commands'][1]['endpoints'])==len(o['commands'][2]['endpoints'])==2
 assert all('host-special port'not in e for c in o['commands'][1:]for e in c['endpoints'])
 for obj in [s,o]:assert obj['generator_sha256']==sha(ROOT/('recover_'+P+'.py'))and all(obj[k]is False for k in FLAGS)
 return {'plists':931,'native_parser_fallbacks':1,'host_special_declarations':19,'distinct_declared_slots':18,'slot34_declarations_in_scope':0,'observed_jobs':3,'observed_endpoints':10,'observed_host_special_endpoints':2}
def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());o=json.loads((ROOT/(P+'_observations.json')).read_text());assert s==build();counts=check(s,o);bad=[]
 for name in ['slot34','missing_plist','fallback','active','host17','endpoint','uuid','target_effect']:
  a,b=copy.deepcopy(s),copy.deepcopy(o)
  if name=='slot34':next(r for r in a['plists']if r['host_special_ports'])['host_special_ports'][0]['value']=34
  elif name=='missing_plist':a['plists'].pop()
  elif name=='fallback':next(r for r in a['plists']if r['parser']!='plistlib')['fallback_exit']=1
  elif name=='active':b['commands'][0]['endpoints'][0]['active']='0'
  elif name=='host17':next(e for e in b['commands'][0]['endpoints']if 'host-special port'in e)['host-special port']='34 (unknown)'
  elif name=='endpoint':b['commands'][1]['endpoints'].pop()
  elif name=='uuid':b['kernel_uuid']['stdout']='unknown'
  else:b['FairPlay_requests_sent']=True
  try:check(a,b)
  except AssertionError:bad.append(name)
  else:raise AssertionError('Alteration accepted: '+name)
 counts['rejected_alterations']=len(bad)
 scope={'plist_roots':4,'nonrecursive':True,'live_snapshots_refreshed_in_validator':False,'kernel_slot_occupancy_unknown':True,'RPC700_receiver_unknown':True,'native_target_protocol_success_unknown':True}
 result={'generator_sha256':sha(__file__),'dependencies':{'recover_'+P+'.py':sha(ROOT/('recover_'+P+'.py'))},'source_recapture_match':True,'observation_parsing_match':True,'verified_counts':counts,'static_scope':scope,'rejected_controls':bad,'all_checks_pass':True,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(counts))
if __name__=='__main__':main()
