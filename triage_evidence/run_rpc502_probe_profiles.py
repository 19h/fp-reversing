#!/usr/bin/env python3
"""Run ten bounded private fixtures; no native target/system/IPC APIs."""
import concurrent.futures
import json
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parent
PROFILES=[('pid123',['--pid','123']),('pid0',[]),('csr0',['--csr-config','0']),
 ('qosfail',['--qos-query','5','--csr-config','0']),
 ('qossetfail',['--qos-set','5','--csr-config','0']),
 ('csr10',['--csr-config','0x10']),('csr4',['--csr-config','4']),
 ('csr1',['--csr-config','1']),('csrerr',['--csr-config','0','--csr-result','5']),
 ('cpuabcd',['--cpu','0xabcd'])]


def run(row):
    name,args=row
    p=subprocess.run([sys.executable,str(ROOT/'daemon_rpc502_probe.py'),*args,
                      '--output',f'rpc502_probe_{name}.json'],capture_output=True,text=True,check=True)
    return {'profile':name,**json.loads(p.stdout)}


if __name__=='__main__':
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        for result in pool.map(run,PROFILES):print(json.dumps(result),flush=True)
