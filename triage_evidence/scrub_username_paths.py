#!/usr/bin/env python3
"""Scrub a supplied username path component, including decoded Zstandard blobs.

The username is supplied at runtime and never written to the audit. Replacement
components have equal encoded length. Ordinary non-path identifiers are retained.
History rewriting uses an isolated, newly initialized repository, never an input
repository's object database. Changed archives use zstd --ultra -22 -q -T1.
"""
import argparse,base64,concurrent.futures,hashlib,json,os,re,subprocess,tempfile
from pathlib import Path
from compression import zstd
MAGIC=b'\x28\xb5\x2f\xfd'
def digest(b):return hashlib.sha256(b).hexdigest()
class Scrubber:
 def __init__(self,username):
  assert username and all(c.isalnum()or c in'._-'for c in username)
  self.username=username;self.replacement='_'*len(username);u=re.escape(username.encode());r=self.replacement.encode()
  sep=rb'(?:/|\\+|%2[fF]|%5[cC]|\\u002[fF]|\\u005[cC])'
  end=rb'(?=(?:/|\\|%2[fF]|%5[cC]|[\x00\s\x22\x27<>`]|$))'
  self.rules=[(re.compile(b'('+sep+b')'+u+end,re.I),lambda m:m[1]+r)]
  # JSON unicode escape representations of the username.
  escaped=''.join('\\u%04x'%ord(c)for c in username).encode()
  replacement=''.join('\\u%04x'%ord('_')for c in username).encode()
  self.rules.append((re.compile(b'('+sep+b')'+re.escape(escaped)+end,re.I),lambda m:m[1]+replacement))
  for enc in('utf-16-le','utf-16-be'):
   for separator in('/','\\','%2F','%5C'):
    a=(separator+username).encode(enc);b=(separator+self.replacement).encode(enc)
    suffix=b'|'.join(re.escape(c.encode(enc))for c in('/','\\','%2F','%5C','\x00','"',"'",' '))
    self.rules.append((re.compile(re.escape(a)+b'(?=(?:'+suffix+b'|$))'),lambda m,b=b:b))
  # Hexadecimal byte strings are common in the evidence set.
  for separator in('/','\\'):
   a=(separator+username).encode().hex().encode();b=(separator+self.replacement).encode().hex().encode()
   suffix=b'|'.join(c.encode().hex().encode()for c in('/','\\','%2F','%5C','\x00','"',"'",' '))
   self.rules.append((re.compile(re.escape(a)+b'(?=(?:'+suffix+b'|$))',re.I),lambda m,b=b:b))
  # Base64 anchors cover all three alignment phases of a home-directory root.
  self.base64_anchors=[]
  for root in('/Users/','/home/','C:\\Users\\'):
   for phase in range(3):
    raw=b'X'*phase+(root+username).encode();encoded=base64.b64encode(raw)
    anchor=encoded[(4 if phase else 0):-4]
    if len(anchor)>=8:self.base64_anchors.append(anchor)
 def text(self,data):
  out=data;n=0
  for pattern,replacement in self.rules:
   out,k=pattern.subn(replacement,out);n+=k
  # Decode only candidate base64 tokens containing a derived anchor; long
  # unrelated hex dumps are left alone. A re-encoded token is checked again.
  if any(a in out for a in self.base64_anchors):
   def transform(m):
    nonlocal n
    token=m[0]
    if not any(a in token for a in self.base64_anchors):return token
    try:raw=base64.b64decode(token,validate=True)
    except ValueError:return token
    changed=raw;count=0
    for pattern,replacement in self.rules:changed,k=pattern.subn(replacement,changed);count+=k
    if count:n+=count;return base64.b64encode(changed)
    return token
   out=re.sub(rb'[A-Za-z0-9+/]{16,}={0,2}',transform,out)
  return out,n
 def logical(self,data):
  compressed=data.startswith(MAGIC);raw=zstd.decompress(data)if compressed else data;out,n=self.text(raw)
  return out,n,compressed
 def blob(self,data):
  out,n,compressed=self.logical(data)
  if not n:return data,{'changed':False,'compressed':compressed,'replacements':0}
  if compressed:
   with tempfile.TemporaryDirectory(prefix='fp-path-redaction-')as td:
    p=Path(td)/'sanitized-input';p.write_bytes(out)
    r=subprocess.run(['zstd','--ultra','-22','-q','-T1','-c',str(p)],capture_output=True);assert r.returncode==0,r.stderr.decode()
    encoded=r.stdout;assert zstd.decompress(encoded)==out
  else:encoded=out
  assert self.logical(encoded)[1]==0
  return encoded,{'changed':True,'compressed':compressed,'replacements':n,'original_logical_sha256':digest(zstd.decompress(data)if compressed else data),'sanitized_logical_sha256':digest(out),'original_stored_sha256':digest(data),'sanitized_stored_sha256':digest(encoded)}
 def selftest(self):
  u=self.username;r=self.replacement;tests=[]
  for raw,expected in[(f'/Users/{u}/evidence',f'/Users/{r}/evidence'),(f'/home/{u}',f'/home/{r}'),(f'C:\\Users\\{u}\\evidence',f'C:\\Users\\{r}\\evidence'),(f'file:///Users/{u}/evidence',f'file:///Users/{r}/evidence'),(f'%2FUsers%2F{u}%2Fevidence',f'%2FUsers%2F{r}%2Fevidence')]:
   for enc in('utf-8','utf-16-le','utf-16-be'):
    a,n=self.text(raw.encode(enc));assert a==expected.encode(enc)and n;tests.append('positive-'+enc)
  raw=f'/Users/{u}/evidence'.encode();a,n=self.text(raw.hex().encode());assert a==f'/Users/{r}/evidence'.encode().hex().encode()and n;tests.append('hex')
  a,n=self.text(base64.b64encode(raw));assert base64.b64decode(a)==f'/Users/{r}/evidence'.encode()and n;tests.append('base64')
  raw=('prefix '+u+' declaration /usr/include/stdint.h').encode();assert self.text(raw)==(raw,0);tests.append('nonpath-negative')
  return len(tests)

def object_stream(repo):
 names=subprocess.check_output(['git','-C',str(repo),'rev-list','--objects','--all']).splitlines();objects=[]
 for line in names:
  oid,_,name=line.partition(b' ');objects.append((oid.decode(),name.decode(errors='replace')))
 process=subprocess.Popen(['git','-C',str(repo),'cat-file','--batch'],stdin=subprocess.PIPE,stdout=subprocess.PIPE)
 try:
  for oid,name in objects:
   process.stdin.write((oid+'\n').encode());process.stdin.flush();header=process.stdout.readline().split();assert header[0].decode()==oid
   kind=header[1].decode();n=int(header[2]);data=process.stdout.read(n);assert len(data)==n and process.stdout.read(1)==b'\n'
   yield oid,name,kind,data
  process.stdin.close();assert process.wait()==0
 finally:
  if process.poll()is None:process.terminate();process.wait()

def audit(repo,scrubber,output):
 rows=[];counts={};total=0
 for oid,name,kind,data in object_stream(repo):
  counts[kind]=counts.get(kind,0)+1
  if kind not in('blob','commit','tag'):continue
  raw,n,compressed=scrubber.logical(data);total+=len(raw)
  if n:rows.append({'object_id':oid,'path':scrubber.text(name.encode())[0].decode(),'type':kind,'compressed':compressed,'replacements_required':n,'stored_sha256':digest(data),'logical_sha256':digest(raw)})
 result={'mode':'reachable_history_username_path_scan','objects':counts,'logical_bytes_scanned':total,'affected_objects':rows,'affected_object_count':len(rows),'replacements_required':sum(r['replacements_required']for r in rows),'username_recorded':False,'selftests_passed':scrubber.selftest()}
 Path(output).write_text(json.dumps(result,indent=2)+'\n');return result

def rewrite(source,destination,scrubber,output,workers):
 destination=Path(destination);assert not destination.exists();subprocess.run(['git','init','--bare','-q',str(destination)],check=True)
 export=subprocess.Popen(['git','-C',str(source),'fast-export','--all','--show-original-ids','--signed-tags=strip'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 log=tempfile.TemporaryFile();imp=subprocess.Popen(['git','--git-dir',str(destination),'fast-import','--quiet'],stdin=subprocess.PIPE,stdout=log,stderr=log)
 pending=[];rows=[];objects=0;kind=None;oid=None
 def flush():
  nonlocal objects
  item=pending.pop(0)
  if isinstance(item,bytes):imp.stdin.write(item);return
  future,original,category=item;data,meta=future.result();imp.stdin.write(f'data {len(data)}\n'.encode());imp.stdin.write(data);objects+=1
  if meta['changed']:rows.append({'original_object_id':original,'type':category,**meta})
  if objects%250==0:print(json.dumps({'objects_transformed':objects,'objects_changed':len(rows)}),flush=True)
 with concurrent.futures.ThreadPoolExecutor(max_workers=workers)as pool:
  while line:=export.stdout.readline():
   if line==b'blob\n':kind='blob';oid=None
   elif line.startswith(b'commit '):kind='commit';oid=None
   elif line.startswith(b'tag '):kind='tag';oid=None
   if line.startswith(b'original-oid '):oid=line.split()[1].decode();continue
   if line.startswith(b'data '):
    n=int(line.split()[1]);raw=export.stdout.read(n);assert len(raw)==n
    pending.append((pool.submit(scrubber.blob,raw),oid,kind))
   else:
    cleaned,_=scrubber.text(line);pending.append(cleaned)
   while sum(not isinstance(q,bytes)for q in pending)>=workers:flush()
  while pending:flush()
 imp.stdin.close();export_error=export.stderr.read();assert export.wait()==0,export_error.decode();assert imp.wait()==0
 result={'mode':'isolated_fast_export_import','source_commit_count':int(subprocess.check_output(['git','-C',str(source),'rev-list','--all','--count'])),'destination_commit_count':int(subprocess.check_output(['git','--git-dir',str(destination),'rev-list','--all','--count'])),'data_records_processed':objects,'changed_records':rows,'changed_record_count':len(rows),'username_recorded':False,'selftests_passed':scrubber.selftest(),'archive_command':['zstd','--ultra','-22','-q','-T1'],'historical_validation':'Recorded scientific validations predate path-only rewriting;new blob identities and manifests require a separate post-redaction audit.'}
 assert result['source_commit_count']==result['destination_commit_count'];Path(output).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items()if k!='changed_records'}),flush=True)

def main():
 p=argparse.ArgumentParser();p.add_argument('mode',choices=['audit','rewrite','selftest']);p.add_argument('--username',required=True);p.add_argument('--source',default='.');p.add_argument('--destination');p.add_argument('--output');p.add_argument('--workers',type=int,default=8);a=p.parse_args();s=Scrubber(a.username)
 if a.mode=='selftest':print(json.dumps({'selftests_passed':s.selftest()}))
 elif a.mode=='audit':r=audit(a.source,s,a.output);print(json.dumps({k:v for k,v in r.items()if k!='affected_objects'}),flush=True)
 else:assert a.destination;rewrite(a.source,a.destination,s,a.output,a.workers)
if __name__=='__main__':main()
