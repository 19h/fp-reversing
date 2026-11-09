"""Independent byte-layout/hash/public-output oracles;no target execution.

O(block bytes) data work;integer pow cost depends on fixed public-key widths.
Local mismatch masks are byte-valued;not a complete native verifier model.
"""
import hashlib
from pathlib import Path
from rpc502_startup_tools import certificate_view
ROOT=Path(__file__).resolve().parent
PREFIX={20:bytes.fromhex('3021300906052b0e03021a05000414'),32:bytes.fromhex('3031300d060960864801650304020105000420')}
H0=0xd036cea0;H1=0x62b16bcc;H2=0x40df01a2

def regions(width,h):
 p=PREFIX[h];n=width-h-len(p)-3;assert n>=8;return {'width':width,'digest_extent':h,'pad_count':n,'separator':2+n,'prefix_start':3+n,'prefix_extent':len(p),'digest_start':width-h}

def expected_block(width,digest):
 v=regions(width,len(digest));return b'\0\1'+b'\xff'*v['pad_count']+b'\0'+PREFIX[len(digest)]+digest

def stage_oracles(case,source):
 raw=source.read_bytes();aaa=certificate_view(bytes(x^0x98 for x in raw[0xff63a4:0xff63a4+889]));leaf=certificate_view(bytes.fromhex(case['body_hex']));root=certificate_view((ROOT/'rpc502_startup_root.der').read_bytes());wire=bytes.fromhex(case['second_hex']);off=12+len(bytes.fromhex(case['body_hex']))+4;out=[]
 for child,parent,width in[(aaa,root,256),(leaf,aaa,128)]:
  N=int(parent['modulus_hex'],16);S=int(child['signature_hex'],16);d=hashlib.sha1(bytes.fromhex(child['tbs_hex'])).digest();em=pow(S,parent['exponent'],N).to_bytes(width,'big');out.append({'public_output':em,'digest':d,'expected':expected_block(width,d)})
 S=int.from_bytes(wire[off:off+128],'big');N=int(leaf['modulus_hex'],16);d=hashlib.sha256(wire[:8]).digest();em=pow(S,leaf['exponent'],N).to_bytes(128,'big');out.append({'public_output':em,'digest':d,'expected':expected_block(128,d)});return out

def header_error(a,b):return(a^0x98)|(b^0x99)
def pad_error(error,b):return error|(b^0x67)
def separator_error(error,b):return error|(b^0x98)
def prefix_error(error,a,b):return error|(a^b)
def first_difference(a,b):
 assert len(a)==len(b)
 for j,(x,y)in enumerate(zip(a,b)):
  if x!=y:return j+1,x-y
 return len(a),0
