#!/usr/bin/env python3
"""Original event-publisher handler after source-created notifyd startup.

Explicit delivery of reason0/1/2/3 to the captured original global block;no
native publisher/scheduler or Mach connection. Original code runs until return
or opaque API. O(C*(B+P+V+W)) time/space,bounded four cases.
"""
import json
from pathlib import Path
from probe_notifyd_admission import Session,HEAP
from probe_notifyd_pairs import compact_row
from notifyd_ipc_reader import Notifyd,ROOT,sha


def run_event_case(f):
    q=Session(Notifyd(),{'model_port_constructor':True,'model_port_request_notification':True});startup=q.invoke('startup',q.provider.entry,[q.argc,HEAP+0x1800]);r=q.invoke('publisher_reason_'+str(f['reason_u32']),0x100006104,[0x100010a68,f['reason_u32'],f.get('subscriber_token',42),HEAP+0xc00]);return {'fixture':f,'startup':startup,'handler':r}


def main():
    rows=[];pools={'instructions':{},'functions':{},'cache_pages':{}}
    for reason in [0,1,2,3]:
        r=run_event_case({'reason_u32':reason,'subscriber_token':42,'scope':'explicit publisher reason and owned opaque event object;native scheduling not established'});print(json.dumps({'reason':reason,'stop':r['handler']['stop_reason'],'steps':r['handler']['steps'],'API_names':[e['name'] for e in r['handler']['records'] if 'name' in e]}),flush=True)
        for row in [r['startup'],r['handler']]:compact_row(row,'provider',pools)
        rows.append(r)
    out={'scope':__doc__,'generator_sha256':sha(Path(__file__).read_bytes()),'dependencies':{n:sha((ROOT/n).read_bytes()) for n in ['probe_notifyd_admission.py','probe_notifyd_pairs.py','notifyd_ipc_reader.py']},'cases':rows,'original_source_pools':{k:list(v.values()) for k,v in pools.items()},'native_target_executed':False,'full_goal_complete':False};(ROOT/'notifyd_event_profiles.json').write_text(json.dumps(out,indent=2)+'\n')

if __name__=='__main__':main()
