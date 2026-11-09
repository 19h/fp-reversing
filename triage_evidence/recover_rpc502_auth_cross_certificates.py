#!/usr/bin/env python3
"""Public signature relationships joining preserved AMS/CoreFP DER to daemon CA.

Original daemon file bytes are re-decoded. Earlier cache/CoreFP DER extracts
remain source-pinned snapshots;this does not refresh installed images or
establish endpoint use,native identity selection or authentication.
O(B+P+integer pow) bounded work/space;no native target/API/IDB operation.
"""
import hashlib,json
from pathlib import Path
from daemon_receive_tools import SOURCE,ROOT
from rpc502_startup_tools import certificate_view
from rpc502_auth_models import name_text
from scan_rpc502_auth_certificates import relation

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def build():
 inv=json.loads((ROOT/'rpc502_auth_certificate_inventory.json').read_text());parents=[e for e in inv['records']if any(a['value']=='Apple FairPlay AAA Certification Authority'for a in e['certificate']['subject'])];assert len(parents)==1;p=parents[0];off=int(p['file_offset'],16);k=int(p['XOR_byte'],16);raw=bytes(x^k for x in SOURCE.read_bytes()[off:off+p['size_bytes']]);parent=certificate_view(raw);assert parent==p['certificate'];rows=[]
 for der,meta in [('ams_core_certificate.der','ams_core_certificate.json'),('corefp_fppineboard_certificate.der','corefp_fppineboard_certificate.json')]:
  b=(ROOT/der).read_bytes();v=certificate_view(b);m=json.loads((ROOT/meta).read_text());expected=m.get('sha256',m.get('DER_sha256'));assert hashlib.sha256(b).hexdigest()==expected;assert name_text(v,'issuer')==name_text(parent,'subject');r=relation(v,parent);assert r['exact_encoded_message_equality'];rows.append({'preserved_DER_path':der,'metadata_path':meta,'DER_sha256':sha(ROOT/der),'metadata_sha256':sha(ROOT/meta),'subject_ASCII':name_text(v,'subject').decode(),'issuer_ASCII':name_text(v,'issuer').decode(),'signature_relation_to_original_daemon_CA':r,'parent_source_file_offset':p['file_offset'],'parent_DER_sha256':p['DER_sha256'],'native_pairing_or_acceptance':False})
 return {'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['rpc502_auth_certificate_inventory.json','rpc502_auth_models.py','rpc502_startup_tools.py','scan_rpc502_auth_certificates.py','ams_core_certificate.der','ams_core_certificate.json','corefp_fppineboard_certificate.der','corefp_fppineboard_certificate.json']},'daemon_parent_certificate':p,'cross_component_relations':rows,'all_mathematical_relations_match':True,'native_target_executed':False,'full_goal_complete':False}

def main():
 out=build();(ROOT/'rpc502_auth_cross_component_certificates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cross_component_public_signature_relations':len(out['cross_component_relations']),'all_match':True}),flush=True)
if __name__=='__main__':main()
