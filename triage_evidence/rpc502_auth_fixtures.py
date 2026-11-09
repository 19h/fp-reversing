"""Declared DER mutations for issuer-policy exploration;no valid signature claim.

Rebuild lengths after changing only the issuer Name of the frozen synthetic
certificate. Reuse exact subject Name bytes from the source Key-Services DER
for one case. Definite-length traversal and construction are O(B).
"""
from pathlib import Path
from rpc502_body_fixtures import certificate,tlv
from rpc502_startup_tools import tlv_at,children
ROOT=Path(__file__).resolve().parent

def span(raw,n):return raw[n['start']:n['start']+n['total']]
def name(attrs):
 return tlv(0x30,b''.join(tlv(0x31,tlv(0x30,tlv(6,bytes.fromhex(oid))+tlv(0x13,value)))for oid,value in attrs))
def replace_issuer(raw,issuer):
 root=tlv_at(raw,0,len(raw));top=children(raw,root);tbs=children(raw,top[0]);idx=3 if tbs[0]['tag']==0xa0 else 2
 body=b''.join(issuer if j==idx else span(raw,n)for j,n in enumerate(tbs));return tlv(0x30,tlv(0x30,body)+b''.join(span(raw,n)for n in top[1:]))
def samples():
 raw=certificate(name=None);key=(ROOT/'rpc502_startup_key_services.der').read_bytes();top=children(key,tlv_at(key,0,len(key)));tbs=children(key,top[0]);subject=span(key,tbs[5]);return {'empty':raw,'prefix_C_US':replace_issuer(raw,name([('550406',b'US')])),'exact_key_services_DN':replace_issuer(raw,subject),'mismatch_C_GB':replace_issuer(raw,name([('550406',b'GB')])),'root':(ROOT/'rpc502_startup_root.der').read_bytes(),'key_services':key}
