#!/usr/bin/env python3
"""Prepare sanitized publication, rebuild logical inventory and compress JSON.

Historical proof results remain historical; inventory hashes identify current
redacted bytes. Only the current research source certificates are replayed.
"""
import argparse,hashlib,json,os,subprocess
from pathlib import Path
from compression import zstd
from scrub_username_paths import Scrubber
P='daemon_mode_one_scatter'
EXTRA=['.gitignore']+['triage_evidence/'+n for n in['scrub_username_paths.py','verify_username_paths_history.py','publish_username_path_scrub.py',P+'_pre_redaction_audit.json']]
PRIVACY=['username_path_scrub_report.md']+EXTRA+['triage_evidence/'+n for n in['username_path_scrub_history_before.json','username_path_scrub_history_rewrite.json','username_path_scrub_current_files.json','username_path_scrub_history_audit.json']]
def sha(b):return hashlib.sha256(b).hexdigest()
def storage(root,name):
 p=root/name
 if p.is_file():return p,False
 p=root/(name+'.zst')
 if name.endswith('.json')and p.is_file():return p,True
 raise FileNotFoundError(name)
def read(root,name):
 p,c=storage(root,name);b=p.read_bytes();return zstd.decompress(b)if c else b
def write(root,name,raw):
 p=root/name;p.parent.mkdir(parents=True,exist_ok=True)
 if name.endswith('.json')and len(raw)>=65536:
  # The temporary input already contains sanitized bytes.
  p.write_bytes(raw);subprocess.run(['zstd','--ultra','-22','-q','-T1','-f','--',str(p)],check=True);q=Path(str(p)+'.zst');assert zstd.decompress(q.read_bytes())==raw;p.unlink();return q
 archive=Path(str(p)+'.zst')
 if name.endswith('.json')and archive.exists():archive.unlink()
 p.write_bytes(raw);return p
def prepare(source,destination,username):
 scrub=Scrubber(username);m=json.loads(read(source,'triage_evidence/interface_manifest.json'));names={r['path']for r in m['files']}|{r['path']for r in m['inputs_preserved']}|set(EXTRA);changes=[];observed=[];written=[]
 history=json.loads(read(destination,'triage_evidence/username_path_scrub_history_rewrite.json'));known={r['original_logical_sha256']:r for r in history['changed_records']if 'original_logical_sha256'in r}
 names.add('triage_evidence/interface_manifest.json')
 for name in sorted(names):
  raw=read(source,name);original_sha=sha(raw);observed.append({'path':name,'source_logical_sha256':original_sha})
  try:existing=read(destination,name)
  except FileNotFoundError:existing=None
  if existing is not None:
   existing_sha=sha(existing)
   if existing_sha==original_sha:continue
   if original_sha in known and known[original_sha]['sanitized_logical_sha256']==existing_sha:
    changes.append({'path':name,'original_logical_sha256':original_sha,'sanitized_logical_sha256':existing_sha,'replacements':known[original_sha]['replacements']});continue
  clean,n=scrub.text(raw);assert not scrub.text(clean)[1]
  if existing!=clean:written.append(str(write(destination,name,clean).relative_to(destination)))
  if n:changes.append({'path':name,'original_logical_sha256':sha(raw),'sanitized_logical_sha256':sha(clean),'replacements':n})
 # Runtime reference locators avoid storing a username while selecting the
 # same original binaries under the current user's home directory.
 for name,key,relative in [('triage_evidence/daemon_receive_tools.py','SOURCE','Downloads/zut/fairplayd.arm64e'),('triage_evidence/resolve_kernel_collection_interfaces.py','CACHE','Downloads/fpx/img4_dump/kernelcache.macho')]:
  p=destination/name;text=p.read_text();lines=text.splitlines();found=[j for j,line in enumerate(lines)if line.startswith(key+'=')or line.startswith(key+' =')];assert len(found)==1;lines[found[0]]=key+" = Path.home() / "+repr(relative);p.write_text('\n'.join(lines)+'\n');written.append(name)
 result={'scope':'Current published logical artifacts plus missing local evidence and original references;username path components are redacted. Two runtime source locators use Path.home().','source_observations':observed,'changed_logical_files':changes,'changed_logical_file_count':len(changes),'replacements':sum(r['replacements']for r in changes),'prepared_storage_paths':written,'portable_reference_locators':['triage_evidence/daemon_receive_tools.py','triage_evidence/resolve_kernel_collection_interfaces.py'],'username_recorded':False,'all_prepared_content_scanned':True}
 write(destination,'triage_evidence/username_path_scrub_current_files.json',(json.dumps(result,indent=2)+'\n').encode());print(json.dumps({'prepared_logical_artifacts':len(names),'redacted_files':len(changes),'storage_paths_written':len(written)}),flush=True)
def manifest(root):
 m=json.loads(read(root,'triage_evidence/interface_manifest.json'));names={r['path']for r in m['files']}|set(PRIVACY);rows=[];reports=[];links=0;jsons=0;unavailable=[]
 for name in sorted(names):
  raw=read(root,name);rows.append({'path':name,'size_bytes':len(raw),'sha256':sha(raw)})
  if name.startswith('triage_evidence/')and name.endswith('.json'):json.loads(raw);jsons+=1
  if '/'not in name and name.endswith('.md'):reports.append(name)
 import re
 for name in reports:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',read(root,name).decode()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   target=raw.split('#',1)[0];p=Path(target)if target.startswith('/')else root/target
   if not p.exists()and not(target.endswith('.json')and Path(str(p)+'.zst').exists()):
    alias=re.sub(r'^/(?:Users|home)/_+(?=/|$)',lambda _:str(Path.home()),str(p))
    if alias==str(p)or not Path(alias).exists():
     sdk=json.loads(read(root,'triage_evidence/kernel_root_port_construct_source.json'))['SDK_context'];assert name=='kernel_root_port_construct_report.md'and target==sdk['path'],(name,target);unavailable=m['validation']['unavailable_external_primary_references']
   links+=1
 old_inputs=m['inputs_preserved'];new_inputs=[]
 for row in old_inputs:
  raw=read(root,row['path']);r={**row,'sha256':sha(raw),'size_bytes':len(raw)}
  if r['sha256']!=row['sha256']:r['pre_redaction_sha256']=row['sha256'];r['username_path_redaction_applied']=True
  new_inputs.append(r)
 quality=json.loads(read(root,'triage_evidence/'+P+'_quality_gates.json'));m.update(files=rows,inputs_preserved=new_inputs,goal_status='active')
 m['privacy_migration']={'status':'username_paths_redacted','historical_artifact_hashes':'Earlier nested manifests/dependency digests and scientific validation results refer to pre-redaction content;they are retained as provenance and are not all replayed. This root inventory hashes current decoded logical content.','current_source_certificates':'Replayed after redaction for '+P,'history_audit':'triage_evidence/username_path_scrub_history_audit.json','full_goal_complete':False}
 m['validation'].update(reports=len(reports),direct_json_files=jsons,local_markdown_links=links,unavailable_external_primary_references=unavailable,**{P+'_increment_checks':quality['verified_counts'],P+'_static_scope':quality['static_scope']})
 raw=(json.dumps(m,indent=2)+'\n').encode();write(root,'triage_evidence/interface_manifest.json',raw);print(json.dumps({'manifest_sha256':sha(raw),'logical_artifacts':len(rows),'reports':len(reports),'direct_JSON':jsons,'local_links':links}),flush=True)
def main():
 p=argparse.ArgumentParser();p.add_argument('mode',choices=['prepare','manifest']);p.add_argument('--source');p.add_argument('--destination',required=True);p.add_argument('--username');a=p.parse_args();root=Path(a.destination)
 if a.mode=='prepare':assert a.username and a.source;prepare(Path(a.source),root,a.username)
 else:manifest(root)
if __name__=='__main__':main()
