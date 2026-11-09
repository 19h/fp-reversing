#!/usr/bin/env python3
"""Bounded plist census and read-only launchd observation. No target requests.
Time O(plist bytes + captured text); space O(census + largest plist/text).
Original files are never rewritten; native inspection uses launchctl/plutil/sysctl.
"""
import hashlib,json,os,plistlib,re,subprocess
from datetime import datetime,timezone
from pathlib import Path
P='rpc700_publication';ROOT=Path(__file__).resolve().parent
DIRS=['/System/Library/LaunchDaemons','/System/Library/LaunchAgents','/Library/LaunchDaemons','/Library/LaunchAgents']
FLAGS=['FairPlay_requests_sent','target_instructions_executed','target_instructions_emulated','registration_modified','receiver_identified','kernel_port_object_identity_proved','full_goal_complete']
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def digest(b):return hashlib.sha256(b).hexdigest()
def clock():return datetime.now(timezone.utc).isoformat()
def special(obj,path=''):
 out=[]
 if isinstance(obj,dict):
  for k,v in obj.items():
   q=path+'/'+k
   if k=='HostSpecialPort':out.append({'key_path':q,'value':v})
   out.extend(special(v,q))
 elif isinstance(obj,list):
  for i,v in enumerate(obj):out.extend(special(v,path+'/'+str(i)))
 return out
def build():
 rows=[]
 for directory in DIRS:
  for p in sorted(Path(directory).glob('*.plist')):
   b=p.read_bytes();r={'path':str(p),'size_bytes':len(b),'sha256':digest(b),'parser':'plistlib'}
   try:o=plistlib.loads(b)
   except Exception as e:
    r.update(primary_error=type(e).__name__+': '+str(e),original_prefix_hex=b[:96].hex(),parser='plutil-json-fallback')
    a=['/usr/bin/plutil','-convert','json','-o','-',str(p)];v=subprocess.run(a,capture_output=True);assert v.returncode==0,(p,v.stderr)
    r.update(fallback_argv=a,fallback_exit=v.returncode,fallback_output_sha256=digest(v.stdout),fallback_output_size_bytes=len(v.stdout));o=json.loads(v.stdout)
   r.update(label=o.get('Label'),program=o.get('Program'),program_arguments=o.get('ProgramArguments'),MachServices=o.get('MachServices',{}),host_special_ports=special(o));rows.append(r)
 return {'scope':'Four nonrecursive *.plist roots only; static declarations, not effective kernel slot occupancy.','generator_sha256':sha(__file__),'directories':DIRS,'directory_exists':{d:Path(d).is_dir()for d in DIRS},'plists':rows,**{k:False for k in FLAGS}}
def select(text):
 lines=text.splitlines();out=[];inside=False
 for l in lines:
  if re.match(r'^\t(path|state|program|pid|domain|type) = ',l):out.append(l)
  if l=='\tendpoints = {':inside=True
  if inside:
   out.append(l)
   if l=='\t}':inside=False
 return '\n'.join(out)+'\n'
def endpoints(text):
 out=[];row=None
 for l in text.splitlines():
  m=re.fullmatch(r'\t\t"([^"]+)" = \{',l)
  if m:row={'service':m[1]};continue
  if l=='\t\t}'and row is not None:out.append(row);row=None;continue
  m=re.fullmatch(r'\t\t\t([^=]+) = (.+)',l)
  if m and row is not None:row[m[1].strip()]=m[2]
 return out
def observe():
 start=clock();rows=[]
 for label in ['system/com.apple.fairplayd','system/com.apple.managedappdistributiond',f'gui/{os.getuid()}/com.apple.managedappdistributionagent']:
  a=['/bin/launchctl','print',label];t0=clock();r=subprocess.run(a,capture_output=True);s=select(r.stdout.decode());rows.append({'argv':a,'started_UTC':t0,'ended_UTC':clock(),'exit_code':r.returncode,'stdout_size_bytes':len(r.stdout),'stdout_sha256':digest(r.stdout),'stderr':r.stderr.decode(),'selected_text':s,'selected_text_sha256':digest(s.encode()),'endpoints':endpoints(s)})
 a=['/usr/sbin/sysctl','-n','kern.uuid'];r=subprocess.run(a,capture_output=True);assert r.returncode==0
 return {'scope':'Time-bound native read-only launchd/sysctl observations; no FairPlay protocol request or registration change. Printed port handles have no established kernel-object or guest-name identity.','generator_sha256':sha(__file__),'started_UTC':start,'ended_UTC':clock(),'uid':os.getuid(),'commands':rows,'kernel_uuid':{'argv':a,'exit_code':r.returncode,'stdout':r.stdout.decode().strip(),'stdout_sha256':digest(r.stdout)},'inspection_tools':[{'path':q,'sha256':sha(q),'size_bytes':Path(q).stat().st_size}for q in ['/bin/launchctl','/usr/bin/plutil','/usr/sbin/sysctl']],'native_inspection_executed':True,'native_launchd_interrogation_executed':True,**{k:False for k in FLAGS}}
def main():
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');p=ROOT/(P+'_observations.json');assert not p.exists(),'Observation is immutable: do not silently refresh a published snapshot';o=observe();p.write_text(json.dumps(o,indent=2)+'\n');print(json.dumps({'plists':len(s['plists']),'special_declarations':sum(len(r['host_special_ports'])for r in s['plists']),'fallbacks':sum(r['parser']!='plistlib'for r in s['plists']),'observed_jobs':len(o['commands'])}))
if __name__=='__main__':main()
