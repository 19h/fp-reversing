"""Independent journal/DER/RSA byte helpers; no target execution or acceptance claim.

Definite-length TLV traversal O(B), RSA oracle uses Python integer pow; its
cost depends on key/exponent widths. Malformed extents fail closed.
"""
import base64,hashlib,json,struct,zlib
from rpc502_certificate_oracles import tlv_at

def unpack(w):return json.loads(zlib.decompress(base64.b64decode(w['payload_zlib_base64'])))
def journals(r):
 for w in r['startup_chunks']:yield unpack(w)
 yield {'phase':'worker'if r['startup_events']and r['startup_events'][-1]['kind']=='worker_ABI_fixture_entry'else'unfinished_startup','source_visit_count':r['original_visit_count'],'ordered_source_bytes_sha256':r['original_ordered_bytes_sha256'],'source_visits_zlib_base64':r['original_visits_zlib_base64'],'records':r['records'],'image_writes':r.get('image_writes',[]),'stack_stores':[],'owner_stores':r['owner_stores'],'original_fixup_reads':r['original_fixup_reads']}
def visits(j):
 b=zlib.decompress(base64.b64decode(j['source_visits_zlib_base64']));assert len(b)%8==0;return struct.unpack('<'+'Q'*(len(b)//8),b)
def children(raw,node):
 cursor=node['content'];end=cursor+node['length'];out=[]
 while cursor<end:
  n=tlv_at(raw,cursor,end-cursor);assert n is not None;out.append(n);cursor+=n['total']
 assert cursor==end;return out

def certificate_view(raw):
 root=tlv_at(raw,0,len(raw));assert root and root['total']==len(raw)and root['tag']==0x30
 top=children(raw,root);assert len(top)==3;tbs,alg,sig=top;cs=children(raw,tbs);version=cs.pop(0)if cs[0]['tag']==0xa0 else None;serial,inneralg,issuer,validity,subject,spki=cs[:6]
 def span(n):return raw[n['start']:n['start']+n['total']]
 def value(n):return raw[n['content']:n['content']+n['length']]
 def names(n):
  result=[]
  for group in children(raw,n):
   for attr in children(raw,group):
    oid,val=children(raw,attr);result.append({'OID_bytes_hex':value(oid).hex(),'value_tag':hex(val['tag']),'value':value(val).decode('ascii')})
  return result
 sp=children(raw,spki);bits=sp[1];assert bits['tag']==3 and value(bits)[0]==0;key=value(bits)[1:];keynode=tlv_at(key,0,len(key));assert keynode and keynode['total']==len(key);ints=children(key,keynode);assert len(ints)==2 and all(n['tag']==2 for n in ints);n,e=[int.from_bytes(key[v['content']:v['content']+v['length']],'big')for v in ints];assert sig['tag']==3 and value(sig)[0]==0
 return {'serial_hex':value(serial).hex(),'subject':names(subject),'issuer':names(issuer),'validity':[value(t).decode('ascii')for t in children(raw,validity)],'algorithm_der_hex':span(alg).hex(),'inner_algorithm_der_hex':span(inneralg).hex(),'tbs_offset_bytes':tbs['start'],'tbs_size_bytes':tbs['total'],'tbs_hex':span(tbs).hex(),'modulus_hex':hex(n),'exponent':e,'modulus_bits':n.bit_length(),'signature_hex':value(sig)[1:].hex(),'DER_sha256':hashlib.sha256(raw).hexdigest()}

def rsa_sha1_relation(child,issuer):
 n=int(issuer['modulus_hex'],16);e=issuer['exponent'];width=(n.bit_length()+7)//8;s=int(child['signature_hex'],16);assert 0<=s<n
 em=pow(s,e,n).to_bytes(width,'big');digest=hashlib.sha1(bytes.fromhex(child['tbs_hex'])).digest();tail=bytes.fromhex('3021300906052b0e03021a05000414')+digest;pad=width-len(tail)-3;expected=b'\x00\x01'+b'\xff'*pad+b'\x00'+tail
 return {'issuer_modulus_bits':n.bit_length(),'exponent':e,'encoded_message_hex':em.hex(),'TBS_SHA1_hex':digest.hex(),'expected_encoded_message_hex':expected.hex(),'padding_ff_bytes':pad,'exact_equality':em==expected,'native_or_target_authentication':False}
