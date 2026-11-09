#!/usr/bin/env python3
"""Pin original CF source/perform bodies for produced-request daemon composition.
O(original/cache bytes+instructions+hash bytes), O(image+source+hash block).
Selected cache pairing/runtime objects remain premises; no target runs.
"""
import json
from pathlib import Path
from daemon_receive_tools import ROOT
from recover_daemon_request_consumption import FLAGS,sha
from bootpolicy_cache_reader import Cache,Dylib,CACHE
from recover_cf_receive import CF_PATH,CF_UUID,DO_SOURCE,SOURCE_CALL,PERFORM
P='cf_daemon_request'
HELPERS={0x1846db030:'CF_retain_contract',0x1846e1278:'CF_release_contract',0x1880773e0:'source_mode_runloop_lock_helper_contract',0x1880773c0:'source_mode_runloop_lock_helper_contract',0x188076ab0:'source_dispatch_observer_contract',0x184832a70:'source_post_dispatch_observer_contract',0x18806ebf0:'port_lock_helper_contract',0x18806c600:'port_unlock_helper_contract',0x1847841ec:'boost_creation_null_contract'}
GLOBALS=[(0x1ed891742,1),(0x1e01c88a8,8),(0x1e0261ea0,8),(0x1e21210e0,8)]
def build():
 old=json.loads((ROOT/'daemon_request_application_source.json').read_text());c=Cache();assert c.uuid==old['cache_uuid'];cf=Dylib(c,CF_PATH);assert cf.uuid==CF_UUID;funcs=[cf.function(a)for a in(DO_SOURCE,SOURCE_CALL,PERFORM)];helpers=[{'address':hex(a),'role':role,'original_bytes16_hex':c.read(a,16).hex()}for a,role in HELPERS.items()];pages=sorted({int(f['start'],16)&~4095 for f in funcs}|{int(f['end'],16)-1&~4095 for f in funcs}|{a&~4095 for a in HELPERS}|{a&~4095 for a,n in GLOBALS});page_data=[{'address':hex(a),'bytes_hex':c.read(a,4096).hex()}for a in pages];assert c.read(0x20638d758,140).hex()==old['cache_function']['bytes'];files=sorted(c.used|{r['path']for r in old['cache_files']}|{str(CACHE)})
 return {'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['daemon_request_application_source.json','daemon_request_application_profiles.json','daemon_request_application_checks.json','kernel_request_delivery_profiles.json','cf_receive_contracts.json','bootpolicy_cache_reader.py','recover_cf_receive.py']},'ranges':old['ranges'],'cache_function':old['cache_function'],'cache_uuid':c.uuid,'CF_path':CF_PATH,'CF_uuid':cf.uuid,'CF_functions':funcs,'CF_runtime_boundary_helpers':helpers,'CF_original_pages':page_data,'CF_runtime_global_cells':[{'address':hex(a),'size_bytes':n,'original_hex':c.read(a,n).hex(),**({'original_cache_pointer':c.pointer(a)}if n==8 else{})}for a,n in GLOBALS],'cache_files':[{'path':n,'size_bytes':Path(n).stat().st_size,'sha256':sha(n)}for n in files],**FLAGS}
if __name__=='__main__':
 out=build();(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'CF_functions':len(out['CF_functions']),'CF_instructions':sum(len(f['instructions'])for f in out['CF_functions']),'CF_pages':len(out['CF_original_pages']),'CF_helper_boundaries':len(out['CF_runtime_boundary_helpers']),'cache_files':len(out['cache_files'])}),flush=True)
