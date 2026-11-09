#!/usr/bin/env python3
"""Splice source-produced CoreFP version output into original private AMS caller.

Two isolated Unicorn spaces and an explicit ABI transfer, not native linking.
Only the source-produced12 output bytes/status cross the adapter. Internal
CoreFP state is retained in the child evidence and is not a native shared image.
Parent once/allocator/locks/loader bindings remain explicit private models.
"""
import json
from pathlib import Path
from probe_ams_core import Probe as AMSProbe
from probe_corefp_exports import Probe as ExportProbe
from corefp_fixups_reader import Pointers,ROOT,sha


class Bridge(AMSProbe):
    def __init__(self,f):
        super().__init__(f);self.library=Pointers();self.child_profiles=[]
    def code(self,u,pc,n,data):
        if self.library_entrypoints.get(pc)=='lxpgvVMLd0S7uRl':
            self.steps+=1;at=self.reg('x0')
            if at!=0x1ebbfd6ec:return self.stop('unexpected_version_output_cell_guard')
            child=ExportProbe(self.library,{'label':'fresh_source_CoreFP_version','mode':'version','state64':[0,0,0]});row=child.run();self.child_profiles.append(row)
            if row['stop_reason']!='returned_to_private_fixture' or row['result_u32']!=0:return self.stop('source_version_child_guard')
            out=bytes.fromhex(row['output16_bytes'])[:12];self.map_original(at);before=bytes(self.u.mem_read(at,12))
            self.u.mem_write(at,out);self.records.append({'kind':'source_CoreFP_version_ABI_transfer','target_cell':hex(at),
                'before12_bytes':before.hex(),'after12_bytes':out.hex(),'source_result_u32':row['result_u32'],'child_index':len(self.child_profiles)-1})
            return self.ret(row['result_u32'])
        return super().code(u,pc,n,data)


def main():
    rows=[];function_pool={};page_pool={};child_pool={}
    for mode in ('create_deep','import'):
        fixture={'label':mode+'_source_version_bridge','mode':mode,'continue_once':True,'allocator':'success','model_locks':True,'dlopen':'success','dlsym':'success'}
        b=Bridge(fixture);row=b.run()
        ff=row.pop('original_functions');pp=row.pop('mapped_original_pages')
        row['original_function_starts']=[x['start'] for x in ff];row['mapped_original_page_addresses']=[x['address'] for x in pp]
        for f in ff:function_pool[f['start']]=f
        for p in pp:page_pool[p['address']]=p
        row['source_version_children']=b.child_profiles
        for child in b.child_profiles:
            ff=child.pop('original_functions');child['original_function_starts']=[x['start'] for x in ff]
            for f in ff:child_pool[f['start']]=f
        rows.append(row)
    out={'scope':__doc__,'generator_sha256':sha(Path(__file__).read_bytes()),
        'AMS_parent_sha256':sha((ROOT/'probe_ams_core.py').read_bytes()),'CoreFP_child_sha256':sha((ROOT/'probe_corefp_exports.py').read_bytes()),
        'fixup_inventory_sha256':sha((ROOT/'corefp_fixups_inventory.json').read_bytes()),
        'AMS_original_functions':list(function_pool.values()),'AMS_original_pages':list(page_pool.values()),
        'CoreFP_original_functions':list(child_pool.values()),'profiles':rows,'native_target_executed':False,'hardware_PAC_checked':False,'full_goal_complete':False}
    (ROOT/'corefp_version_bridge_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
    for row in rows:print(json.dumps({'label':row['fixture']['label'],'reason':row['stop_reason'],'steps':row['steps'],'last_event':row['records'][-1]}))


if __name__=='__main__':main()
