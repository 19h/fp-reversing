#!/usr/bin/env python3
"""Read-only current reference config bytes/metadata,not daemon runtime state."""
import json,os,stat,hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parent

def main():
    path=Path('/etc/notify.conf');before=path.stat();raw=path.read_bytes();after=path.stat();assert (before.st_ino,before.st_mtime_ns,before.st_size)==(after.st_ino,after.st_mtime_ns,after.st_size)
    (ROOT/'notifyd_policy_reference.conf').write_bytes(raw);out={'scope':__doc__,'source_path':str(path),'size_bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'uid':after.st_uid,'gid':after.st_gid,'mode_permissions_octal':oct(stat.S_IMODE(after.st_mode)),'mode_complete_u16':after.st_mode&65535,'inode':after.st_ino,'mtime_ns':after.st_mtime_ns,'stable_read':True,'daemon_loaded_these_bytes_established':False,'native_target_API_executed':False,'generator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()};(ROOT/'notifyd_policy_reference.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out))
if __name__=='__main__':main()
