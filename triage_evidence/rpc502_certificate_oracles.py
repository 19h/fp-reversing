"""Independent finite TLV and standard-digest byte oracles;no target code."""
import hashlib,struct
MASK=0xffffffff;K=0x8b3dc651;BASE=0x5300000000

def tlv_at(raw,offset,extent):
 if extent<2 or offset<0 or offset+extent>len(raw):return None
 tag=raw[offset];b=raw[offset+1]
 if tag&31==31:return None
 h=2
 if b<128:n=b
 else:
  count=b&127
  if count==0 or count>4 or 2+count>extent:return None
  n=int.from_bytes(raw[offset+2:offset+2+count],'big');h+=count
 if h+n>extent:return None
 return {'tag':tag,'start':offset,'content':offset+h,'length':n,'total':h+n,'header':h}

def item_argument(call):
 p=int(call['argument_pointer'],16);b=bytes.fromhex(call['entry_view']['prefix64_hex']);key=((p^0xe732d262)*0xba209ef7)&MASK;points={e['slot_offset']:bytes.fromhex(e['bytes_hex'])for e in call['entry_view']['pointed_views']};cursor=(int.from_bytes(points[56][:4],'little')-0x50af9a6f)&MASK;return {'key':key,'mode':(struct.unpack_from('<I',b,0)[0]+key)&MASK,'input':struct.unpack_from('<Q',b,8)[0],'available':(struct.unpack_from('<I',b,40)[0]+key-0x67ac8198)&MASK,'cursor':cursor}

def callback_item(call):
 b=bytes.fromhex(call['x1_view']['prefix64_hex']);return {'tag':struct.unpack_from('<I',b,0)[0]^0x21e8ae22,'length':struct.unpack_from('<I',b,4)[0]^K,'content':struct.unpack_from('<Q',b,8)[0]-BASE,'total':struct.unpack_from('<I',b,16)[0]^K,'start':struct.unpack_from('<Q',b,24)[0]-BASE}

def digest_oracles(r,file_raw):
 out=[]
 for ptr,life in r['digest_context_lifetimes'].items():
  if life['schema_call']is None:continue
  schema=r['schema_callbacks'][life['schema_call']];call=r['body_helper_calls'][life['introduced_at_call']];p=int(call['argument_pointer'],16);key=((p^0xf9d49974)*0xda51a827)&MASK;b=bytes.fromhex(call['entry_view']['prefix64_hex']);algorithm=(((struct.unpack_from('<I',b,8)[0]^key)&511)^30);ctx=bytes.fromhex(next(e['bytes_hex']for e in call['returned_view']['pointed_views']if e['slot_offset']==16));size=struct.unpack_from('<I',ctx,92)[0]
  if size==0:out.append({'schema_entry':schema['entry'],'algorithm':algorithm,'output_size':0,'context_pointer':hex(int(ptr))});continue
  item=callback_item(schema)
  if schema['entry']=='0x10040f7a4':start=item['start'];n=item['total'];role='certificate'
  elif schema['entry']=='0x10000aecc':
   a=tlv_at(file_raw,item['content'],item['length']);bits=tlv_at(file_raw,a['start']+a['total'],item['length']-a['total']);assert bits['tag']==3 and file_raw[bits['content']]==0;start=bits['content']+1;n=bits['length']-1;role='RSAPublicKey'
  elif schema['entry']=='0x10043e878':
   root=next(c for c in r['schema_callbacks']if c['entry']=='0x10040f7a4');root=callback_item(root);tbs=tlv_at(file_raw,root['content'],root['length']);start=tbs['start'];n=tbs['total'];role='TBSCertificate'
  else:raise AssertionError(schema['entry'])
  assert (algorithm,size)in[(1,16),(2,20)];h=(hashlib.md5 if algorithm==1 else hashlib.sha1)(file_raw[start:start+n]).digest();pattern=bytes(x^0x98 for x in h);mem={};stores={}
  for e in r['core_stack_stores']:
   if e['step_index']>=schema['return_step']:break
   a=int(e['address'],16)
   for j,v in enumerate(bytes.fromhex(e['actual_after_hex'])):mem[a+j]=v;stores[a+j]=e
  hits=[]
  for a in mem:
   if bytes(mem.get(a+j,-1)for j in range(size)if a+j in mem)==pattern and all(a+j in mem for j in range(size)):
    hits.append({'address':hex(a),'bytes_hex':pattern.hex(),'writer_pcs':sorted({stores[a+j]['pc']for j in range(size)}),'last_store_steps':[stores[a+j]['step_index']for j in range(size)]})
  out.append({'schema_entry':schema['entry'],'algorithm':algorithm,'output_size':size,'context_pointer':hex(int(ptr)),'role':role,'file_offset_bytes':start,'length_bytes':n,'standard_digest_hex':h.hex(),'encoded_digest_hex':pattern.hex(),'hits':hits})
 return out
