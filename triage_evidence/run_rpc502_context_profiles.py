#!/usr/bin/env python3
"""Finite independent private fixtures, maximum three concurrent processes."""
import concurrent.futures
import json
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parent
ONCE=['--model-once']
HEAP=ONCE+['--model-heap']
LOCKS=HEAP+['--model-locks']
LOADER=LOCKS+['--sysctl-vmm','0','--model-loader']
PROFILES=[
 ('phase_pac',[]),('phase_once',ONCE),('phase_heap',HEAP),('phase_sync',LOCKS),
 ('vmm0',LOCKS+['--sysctl-vmm','0']),('vmm1',LOCKS+['--sysctl-vmm','1']),
 ('vmm_error',LOCKS+['--sysctl-vmm','0','--sysctl-status','-1']),
 ('loader_mode0',LOADER),('loader_mode1',LOADER+['--mode','1']),
 ('loader_mode2',LOADER+['--mode','2']),('loader_mode3',LOADER+['--mode','3']),
 ('loader_bp_error',LOADER+['--bootpolicy-status','5']),
 ('loader_csr1',LOADER+['--csr','1']),
 ('loader_vmm1',LOCKS+['--sysctl-vmm','1','--model-loader']),
 ('init11',LOCKS+['--lock-init-result','11']),('init12',LOCKS+['--lock-init-result','12'])]


def run(row):
    name,args=row
    p=subprocess.run([sys.executable,str(ROOT/'daemon_rpc502_context_probe.py'),*args,
        '--output',f'rpc502_context_{name}.json'],check=True,capture_output=True,text=True)
    return {'profile':name,**json.loads(p.stdout)}


if __name__=='__main__':
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        for r in pool.map(run,PROFILES):print(json.dumps(r),flush=True)
