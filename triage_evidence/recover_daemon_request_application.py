#!/usr/bin/env python3
"""Pin original callback/application source plus installed-cache libbsm body.
O(source+cache-hash bytes+instructions), O(image+instructions+hash block).
The selected cache library is a composition premise, not native loader proof.
"""
import json
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS
from recover_daemon_request_consumption import FLAGS,sha
from bootpolicy_cache_reader import Cache,Dylib,CACHE
P='daemon_request_application';BSM_PATH='/usr/lib/libbsm.0.dylib';BSM_UUID='a01677ab-bd20-3c62-8b0f-c805062f95bd';BSM=0x20638d758;SLOT=0x1010a0500
def build():
 c=Cache();assert c.uuid=='2bd06591-e751-3e84-963f-b08dab6af23a';lib=Dylib(c,BSM_PATH);assert lib.uuid==BSM_UUID and lib.exports['_audit_token_to_au32']['address']==BSM
 f=lib.function(BSM);assert f['sha256']=='76ed6c9a5a2b1b51e22d1fd36ca9802e734187970d71868438eb981b52e613e5';f['exact_exports']=[n for n,v in lib.exports.items()if v['address']==BSM];f['exact_nlist']=lib.symbols_at(BSM);mp=c.mapping(BSM);f['source_file']=mp['path'];f['source_offset']=hex(mp['off']+BSM-mp['va'])
 old=json.loads((ROOT/'daemon_request_consumption_source.json').read_text());app=json.loads((ROOT/'daemon_rpc502_contracts.json').read_text());ranges=[];seen=set()
 for row in old['ranges']+app['native_ranges']:
  lo,hi=int(row['start'],16),int(row['end'],16)
  if(lo,hi)in seen:continue
  seen.add((lo,hi));raw=IMAGE.read(lo,hi-lo);ranges.append({'start':hex(lo),'end':hex(hi),'bytes_hex':raw.hex(),'instructions':[{'pc':hex(i.address),'bytes_hex':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(raw,lo)]})
 files=sorted(c.used|{str(CACHE)});return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['daemon_request_consumption_source.json','daemon_request_consumption_profiles.json','daemon_request_consumption_checks.json','daemon_rpc502_contracts.json','kernel_request_delivery_profiles.json','bootpolicy_cache_reader.py','daemon_receive_tools.py']},'ranges':ranges,'cache_uuid':c.uuid,'cache_library_path':BSM_PATH,'cache_library_uuid':lib.uuid,'cache_function':f,'cache_files':[{'path':n,'size_bytes':Path(n).stat().st_size,'sha256':sha(n)}for n in files],'logical_import_binding':{'slot':hex(SLOT),'original_word_hex':IMAGE.read(SLOT,8).hex(),'import_name':'libbsm/_audit_token_to_au32','private_target':hex(BSM),'native_runtime_pairing_established':False},**FLAGS}
if __name__=='__main__':
 out=build();(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'daemon_ranges':len(out['ranges']),'daemon_instructions':sum(len(r['instructions'])for r in out['ranges']),'cache_function_instructions':len(out['cache_function']['instructions']),'cache_files':len(out['cache_files'])}),flush=True)
