"""LAB ONLY: read a bounded sample of an existing synthetic file.
No writes; no raw block access. Not proof of device identity or media health.
"""
import hashlib, time
from pathlib import Path

def sample_read(lab_root, name, sample_mib=32):
    root=Path(lab_root).absolute()
    if not (root/'LAB_ONLY.marker').is_file(): raise PermissionError('Lab marker required')
    if Path(name).name!=name or name in {'.','..'} or not 1<=sample_mib<=64: raise ValueError('Invalid lab sample')
    p=root/name
    if p.is_symlink() or not p.is_file(): raise ValueError('Not a regular lab file')
    digest=hashlib.sha256(); size=0; start=time.monotonic()
    with p.open('rb') as f:
        remaining=sample_mib*1024*1024
        while remaining:
            block=f.read(min(1024*1024,remaining))
            if not block: break
            digest.update(block); size+=len(block); remaining-=len(block)
    if not size: raise IOError('Empty sample')
    return {'bytes':size,'sha256':digest.hexdigest(),'MiBps':size/1048576/max(time.monotonic()-start,1e-6),'status':'READ_SAMPLE_ONLY'}
