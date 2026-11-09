#!/usr/bin/env python3
"""Exhaustive file-offset scan under an explicit XOR/DER/RSA/ASCII classifier.

For each offset the XOR key is determined by decoded tag30. Only82-form root
lengths512..8192 bytes,SEQUENCE TBS,parseable RSA keys and ASCII Name values
are classified. Other encodings/algorithms/representations are not excluded.
O(B+C*P+R*pow) time,O(B+C*P+R) space;public certificate bytes only.
No native target/API or IDB operations.
"""
import hashlib,json
from pathlib import Path
from daemon_receive_tools import SOURCE,IMAGE,ROOT
from rpc502_startup_tools import certificate_view
from rpc502_auth_models import name_text

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def scan():
 b=SOURCE.read_bytes();maps=[bytes(x^k for x in range(256))for k in range(256)];rows=[];candidates=0
 for i in range(len(b)-12):
  k=b[i]^0x30
  if b[i+1]^k!=0x82 or b[i+4]^k!=0x30 or b[i+5]^k not in[0x81,0x82]:continue
  n=4+((b[i+2]^k)<<8)+(b[i+3]^k)
  if not 512<=n<=8192 or i+n>len(b):continue
  candidates+=1;raw=b[i:i+n].translate(maps[k])
  try:v=certificate_view(raw)
  except(AssertionError,ValueError,KeyError,UnicodeDecodeError,IndexError):continue
  va=next((va+i-fo for va,fo,size in IMAGE.segments if fo<=i and i+n<=fo+size),None);rows.append({'file_offset':hex(i),'XOR_byte':hex(k),'size_bytes':n,'source_VA':hex(va)if va is not None else None,'original_encoded_sha256':hashlib.sha256(b[i:i+n]).hexdigest(),'DER_sha256':hashlib.sha256(raw).hexdigest(),'certificate':v})
 return candidates,rows

def relation(child,parent):
 algs={'300d06092a864886f70d0101050500':('sha1','3021300906052b0e03021a05000414'),'300d06092a864886f70d01010b0500':('sha256','3031300d060960864801650304020105000420')};alg,prefix=algs[child['algorithm_der_hex']];n=int(parent['modulus_hex'],16);s=int(child['signature_hex'],16);assert 0<=s<n;width=(n.bit_length()+7)//8;em=pow(s,parent['exponent'],n).to_bytes(width,'big');digest=hashlib.new(alg,bytes.fromhex(child['tbs_hex'])).digest();tail=bytes.fromhex(prefix)+digest;pad=width-len(tail)-3;expected=b'\0\1'+b'\xff'*pad+b'\0'+tail;return {'hash':alg,'exact_encoded_message_equality':em==expected,'padding_ff_bytes':pad,'TBS_digest_hex':digest.hex(),'native_trust_acceptance':False}

def build():
 candidates,rows=scan();edges=[];groups={}
 for a,c in enumerate(rows):
  v=c['certificate'];key=(v['modulus_hex'],v['exponent']);groups.setdefault(key,[]).append(a)
  for b,p in enumerate(rows):
   if name_text(v,'issuer')==name_text(p['certificate'],'subject'):edges.append({'child_index':a,'issuer_index':b,**relation(v,p['certificate'])})
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['rpc502_startup_tools.py','rpc502_auth_models.py','rpc502_certificate_oracles.py','daemon_receive_tools.py']},'source_size_bytes':SOURCE.stat().st_size,'classified_candidates':candidates,'records':rows,'unique_DER_count':len({r['DER_sha256']for r in rows}),'unique_RSA_key_count':len(groups),'shared_RSA_key_groups':[indices for indices in groups.values()if len(indices)>1],'same_Name_signature_relations':edges,'matching_relations':sum(e['exact_encoded_message_equality']for e in edges),'native_target_executed':False,'full_goal_complete':False};return out

def main():
 out=build();(ROOT/'rpc502_auth_certificate_inventory.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'certificates':len(out['records']),'classifier_candidates':out['classified_candidates'],'unique_DER':out['unique_DER_count'],'unique_RSA_keys':out['unique_RSA_key_count'],'relations':len(out['same_Name_signature_relations']),'matching_relations':out['matching_relations']}),flush=True)
if __name__=='__main__':main()
