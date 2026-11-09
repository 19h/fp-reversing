#!/usr/bin/env python3
"""Whole-worker TLV/certificate/digest and CPU-capability finite fixtures.

No target PC/frame/register overrides. APIs remain inherited declarations;
A72 versus MAX selects a private CPU before image mapping. O(C*(B+V+E+S))
bounded time/space;no native target/API/IDB operations or authentication claim.
"""
import base64,hashlib,json,zlib
from pathlib import Path
from probe_rpc502_body import BodyProbe,file_for_body,ROOT,SOURCE
from rpc502_body_fixtures import tlv,certificate

def cases():
 out=[]
 def add(label,body,fixture=None,v=2,A=0,C=128):out.append({'label':label,'body_hex':body.hex(),'file_hex':file_for_body(body,v=v,A=A,C=C,n=4096).hex(),'fixture':fixture or {}})
 for tag in [0,1,2,3,4,5,6,0x13,0x17,0x18,0x1f,0x30,0x31,0x80,0xa0,0xff]:add('tag_'+hex(tag),bytes([tag,0]))
 for h in ['', '30','300100','300200','30800000','308100','30810100','30820000','3082000100','3084ffffffff','30850000000001']:
  add('length_'+(h or'empty'),bytes.fromhex(h))
 for n in [63,64,65,127,128,129]:add('definite_'+str(n),tlv(0x30,bytes(n)))
 for label,kw in [('empty_names',{'name':None}),('named',{}),('v1',{'version':False}),('key64',{'modulus_bytes':64}),('key256',{'modulus_bytes':256}),('md5_oid',{'oid_last':4}),('sha256_oid',{'oid_last':11}),('serial_zero',{'serial':b'\0'})]:add('certificate_'+label,certificate(**kw),{'body_cpu_model':'MAX'})
 add('certificate_A72',certificate(name=None),{'body_cpu_model':'A72'})
 add('certificate_trailing',certificate(name=None)+bytes.fromhex('aabbccdd'),{'body_cpu_model':'MAX'})
 add('certificate_inner_oid_mismatch',certificate(name=None).replace(bytes.fromhex('2a864886f70d010105'),bytes.fromhex('2a864886f70d010104'),1),{'body_cpu_model':'MAX'})
 return out

def run_case(case):
 q=BodyProbe(bytes.fromhex(case['file_hex']),case['fixture']);r=q.run();return r,q.instruction_bank

def main():
 pool={};rows=[];sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
 for case in cases():
  r,bank=run_case(case)
  for a,item in bank.items():assert a not in pool or pool[a]==item;pool[a]=item
  payload=json.dumps(r,separators=(',',':')).encode();rows.append({'case':case,'payload_zlib_base64':base64.b64encode(zlib.compress(payload)).decode()});print(case['label'],r['steps'],r['stop_reason'],r['records'][-1],len(r['schema_callbacks']),flush=True)
 deps=['probe_rpc502_body.py','rpc502_body_fixtures.py','probe_rpc502_supp.py','probe_rpc502_supp_cases.py','probe_rpc502_parser.py','probe_rpc502_sidecar_contents.py','probe_rpc502_sidecar_copy.py','probe_rpc502_sidecar_mapping.py','probe_rpc502_sidecar_data.py','probe_rpc502_sidecar_metadata.py','probe_rpc502_sidecar_io.py','daemon_rpc502_context_probe.py','daemon_rpc502_probe.py','daemon_receive_tools.py','daemon_receive_fixups.txt'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'original_instruction_pool':list(pool.values()),'cases':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'rpc502_certificate_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print('COUNTS',len(rows),len(pool),flush=True)

if __name__=='__main__':main()
