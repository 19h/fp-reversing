"""Explicit unsigned certificate-signature variants;no acceptance claim.

Only the signature BIT STRING is replaced in the frozen empty-Name fixture;
DER lengths are rebuilt. Public Key-Services bytes supply deterministic
within-range/range-boundary representatives. O(B) work and space.
"""
from pathlib import Path
from rpc502_body_fixtures import certificate,tlv
from rpc502_startup_tools import tlv_at,children,certificate_view
ROOT=Path(__file__).resolve().parent

def replace_signature(raw,signature):
 top=children(raw,tlv_at(raw,0,len(raw)));parts=[raw[n['start']:n['start']+n['total']]for n in top[:2]];return tlv(0x30,b''.join(parts)+tlv(3,b'\0'+signature))

def cases():
 original=certificate(name=None);ca=certificate_view((ROOT/'rpc502_startup_key_services.der').read_bytes());N=int(ca['modulus_hex'],16);S=int(ca['signature_hex'],16)%N;assert 0<S<N
 return [('short128',original),('zero256',replace_signature(original,bytes(256))),('nonzero256',replace_signature(original,S.to_bytes(256,'big'))),('equal_modulus256',replace_signature(original,N.to_bytes(256,'big')))]
