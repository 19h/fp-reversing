#!/usr/bin/env python3
"""Independent username-path detector for all stored Git objects and Zstd data.

This does not call the redaction implementation. Usernames are runtime inputs;
only object identifiers, counts and repository-relative names enter the audit.
"""
import argparse,base64,concurrent.futures,hashlib,json,re,subprocess
from compression import zstd
MAGIC=b'\x28\xb5\x2f\xfd'
def offending(data,username):
 u=username.encode();roots=[b'/Users/'+u,b'/home/'+u,b'\\Users\\'+u,b'/'+u+b'/',b'\\'+u+b'\\']
 needles=[]
 for root in roots:
  needles.extend([root.lower(),root.hex().encode().lower()])
  for enc in('utf-16-le','utf-16-be'):needles.append(root.decode().encode(enc).lower())
  needles.append(b''.join(b'%%%02x'%c for c in root))
 lower=data.lower().replace(b'\\/',b'/')
 if any(n in lower for n in needles):return True
 # Independently normalize percent and JSON unicode escapes.
 if b'%'in lower:lower=re.sub(rb'%([0-9a-f]{2})',lambda m:bytes([int(m[1],16)]),lower)
 if b'\\u00'in lower:lower=re.sub(rb'\\u00([0-9a-f]{2})',lambda m:bytes([int(m[1],16)]),lower)
 if any(n in lower for n in needles):return True
 anchors=[base64.b64encode(root)[:8]for root in roots[:3]]
 if any(a in data for a in anchors):
  for token in re.findall(rb'[A-Za-z0-9+/]{16,}={0,2}',data):
   if not any(a in token for a in anchors):continue
   try:decoded=base64.b64decode(token,validate=True).lower()
   except ValueError:continue
   if any(n in decoded for n in needles):return True
 return False
def inspect(raw,username):
 compressed=raw.startswith(MAGIC)
 if compressed:raw=zstd.decompress(raw)
 return compressed,len(raw),offending(raw,username)
def main():
 p=argparse.ArgumentParser();p.add_argument('--repo',default='.');p.add_argument('--username',required=True);p.add_argument('--output',required=True);p.add_argument('--workers',type=int,default=8);a=p.parse_args()
 # Independent positive/negative controls are constructed only in memory.
 for enc in('utf-8','utf-16-le','utf-16-be'):assert offending(('/Users/'+a.username+'/evidence').encode(enc),a.username)
 assert not offending(b'plain declaration /usr/include/stdint.h',a.username)
 objects=subprocess.check_output(['git','-C',a.repo,'cat-file','--batch-all-objects','--batch-check=%(objectname)']).splitlines()
 process=subprocess.Popen(['git','-C',a.repo,'cat-file','--batch'],stdin=subprocess.PIPE,stdout=subprocess.PIPE);bad=[];counts={};archives=logical_bytes=0
 pending=[];finished=0
 def finish():
  nonlocal archives,logical_bytes,finished
  oid,kind,future=pending.pop(0);compressed,n,found=future.result();archives+=compressed;logical_bytes+=n;finished+=1
  if found:bad.append({'object_id':oid.decode(),'type':kind})
  if finished%1000==0:print(json.dumps({'stored_objects_scanned':finished,'offending_objects':len(bad)}),flush=True)
 with concurrent.futures.ProcessPoolExecutor(max_workers=a.workers)as pool:
  for oid in objects:
   process.stdin.write(oid+b'\n');process.stdin.flush();header=process.stdout.readline().split();assert header[0]==oid;kind=header[1].decode();n=int(header[2]);raw=process.stdout.read(n);assert len(raw)==n and process.stdout.read(1)==b'\n';counts[kind]=counts.get(kind,0)+1
   pending.append((oid,kind,pool.submit(inspect,raw,a.username)))
   if len(pending)>=2*a.workers:finish()
  while pending:finish()
 process.stdin.close();assert process.wait()==0
 result={'scope':'All physically stored Git objects,including unreachable objects;raw,decoded Zstandard,UTF16,escaped,percent,hex and anchored Base64 path representations. Author names/emails and non-path identifiers are outside the requested path scrub.','objects':counts,'stored_objects_scanned':len(objects),'compressed_objects_decoded':archives,'logical_bytes_scanned':logical_bytes,'offending_objects':bad,'all_checks_pass':not bad,'username_recorded':False,'positive_controls':3,'negative_controls':1}
 from pathlib import Path
 Path(a.output).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result),flush=True);assert not bad
if __name__=='__main__':main()
