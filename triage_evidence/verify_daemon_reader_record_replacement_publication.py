#!/usr/bin/env python3
"""Independent read-only hash/JSON/link/ownership audit; no target effects.
O(total bytes+links) time, O(manifest+largest JSON) memory.
"""
import hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent;P='daemon_reader_record_replacement'

# Read-only logical-artifact access during the external JSON-to-Zstandard migration.
import compression.zstd
_INFO={}
def canonical(p):
 p=Path(p)
 return Path(str(p)[:-4])if p.name.endswith('.json.zst')else p
def storage(p):
 p=Path(p)
 if Path.is_file(p):return p,False
 archive=Path(str(p)+'.zst')
 if p.suffix=='.json'and Path.is_file(archive):return archive,True
 raise FileNotFoundError(p)
def exists(p):
 p=Path(p)
 return Path.exists(p)or(p.suffix=='.json'and Path.is_file(Path(str(p)+'.zst')))
def binary(p):
 q,compressed=storage(p)
 try:return (compression.zstd.ZstdFile(q,'rb')if compressed else q.open('rb')),q,compressed
 except FileNotFoundError:
  q,compressed=storage(p)
  return (compression.zstd.ZstdFile(q,'rb')if compressed else q.open('rb')),q,compressed
def info(p):
 q,compressed=storage(p);st=q.stat();key=(str(q),st.st_size,st.st_mtime_ns)
 if key not in _INFO:
  stream,q,compressed=binary(p);h=hashlib.sha256();n=0
  with stream:
   while chunk:=stream.read(1<<20):h.update(chunk);n+=len(chunk)
  _INFO[key]=(n,h.hexdigest())
 return _INFO[key]
def sha(p):return info(p)[1]
def size(p):return info(p)[0]
def read(p):
 stream,q,compressed=binary(p)
 with stream:return stream.read().decode('utf-8')

def main():
 path=ROOT/'interface_manifest.json';m=json.loads(read(path));assert m['goal_status']=='active'
 seen=set();reports=[];jsons=links=0;unavailable=[]
 for row in m['inputs_preserved']:
  q=BASE/row['path'];assert size(q)==row['size_bytes']and sha(q)==row['sha256']
 for row in m['files']:
  assert row['path']not in seen;seen.add(row['path']);q=BASE/row['path']
  assert exists(q)and size(q)==row['size_bytes']and sha(q)==row['sha256'],row['path']
  if q.parent==ROOT and q.suffix=='.json':json.loads(read(q));jsons+=1
  if q.parent==BASE and q.suffix=='.md':reports.append(q)
 for report in reports:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',read(report)):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   name=raw.split('#',1)[0];target=Path(name)if name.startswith('/')else report.parent/name
   if not exists(target):
    sdk=json.loads(read(ROOT/'kernel_root_port_construct_source.json'))['SDK_context']
    assert report.name=='kernel_root_port_construct_report.md'and name==sdk['path'],(report.name,raw)
    assert sdk['sha256']=='959cc098bb307ccc44a2193a9ff7b8ec8bbcedc335933512cdbe13d3c9088185'
    installed=Path('/Library/Developer/CommandLineTools/SDKs/MacOSX27.2.sdk/usr/include/mach/port.h');current_sha=sha(installed)
    assert current_sha!=sdk['sha256']
    unavailable.append({'report':report.name,'path':name,'historical_sha256':sdk['sha256'],
     'status':'historical_external_reference_unavailable','installed_comparison_path':str(installed),
     'installed_comparison_sha256':current_sha,'equivalence_established':False})
   links+=1
 assert unavailable==m['validation']['unavailable_external_primary_references']and len(unavailable)==1
 assert len(m['files'])==7308 and len(reports)==307 and jsons==2195
 assert m['validation']['reports']==len(reports)and m['validation']['direct_json_files']==jsons and m['validation']['local_markdown_links']==links
 scripts=['recover_'+P+'.py','validate_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
 owned={str(canonical(q).relative_to(BASE))for q in ROOT.glob(P+'_*')if exists(q)}|{'triage_evidence/'+n for n in scripts}|{P+'_report.md'}
 assert len(owned)==10 and owned<=seen
 prior=json.loads(read(ROOT/(P+'_prior_manifest.json')));assert seen-{r['path']for r in prior['files']}==owned
 c=json.loads(read(ROOT/(P+'_checks.json')));d=json.loads(read(ROOT/(P+'_delivery.json')));g=json.loads(read(ROOT/(P+'_quality_gates.json')))
 assert c['all_checks_pass']and d['all_checks_pass']and all(g['QG'+str(j)]['status']=='pass_for_increment'for j in range(1,8))
 assert d['prior_artifacts_checked']==7298 and d['prior_artifacts_unchanged']==7291 and len(d['allowed_changes'])==7
 changed={r['path']for r in d['allowed_changes']}
 for row in prior['files']:
  if row['path']not in changed:assert sha(BASE/row['path'])==row['sha256']
 assert m['validation'][P+'_increment_checks']==g['verified_counts']and m['validation'][P+'_static_scope']==c['static_scope']
 for n,digest in g['report_sha256'].items():assert sha(BASE/n)==digest
 for n,digest in g['evidence_sha256'].items():assert sha(ROOT/n)==digest
 print(json.dumps({'manifest_sha256':sha(path),'artifacts_rehashed':len(seen),'reports_checked':len(reports),
    'compressed_logical_artifacts':sum(storage(BASE/r['path'])[1]for r in m['files']),'direct_JSON_parsed':jsons,'local_links_checked':links,'unavailable_external_primary_references':len(unavailable),'prior_artifacts_preserved':7298,'prior_artifacts_unchanged':7291,
    'allowed_existing_changes':7,'all_checks_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
