"""LAB-ONLY sampled write/read probe in a newly created demo directory.
Never accepts a device path from the operator. No actual USB detection.
Production requires native device/volume handles and authorized identity checks.
"""
import os, hashlib, time, uuid
from pathlib import Path

def sample_probe(lab_root, size_mib=32):
    if not 1 <= size_mib <= 64: raise ValueError('1–64 MiB only')
    root = Path(lab_root).absolute()
    if not (root / 'LAB_ONLY.marker').is_file():
        raise PermissionError('Dedicated lab marker required; no live media')
    p = root / ('probe-' + uuid.uuid4().hex + '.bin')
    expected = hashlib.sha256(); start = time.monotonic()
    with p.open('xb') as f:
        for _ in range(size_mib):
            b = os.urandom(1024*1024); expected.update(b); f.write(b)
        f.flush(); os.fsync(f.fileno())
    write_s = time.monotonic()-start; start = time.monotonic(); actual = hashlib.sha256()
    with p.open('rb') as f:
        while b := f.read(1024*1024): actual.update(b)
    read_s = time.monotonic()-start
    if actual.digest() != expected.digest(): raise IOError('Sample hash mismatch')
    return {'status':'SAMPLE_PASSED','sampleMiB':size_mib,'writeMiBps':size_mib/max(write_s,1e-6),'readMiBps':size_mib/max(read_s,1e-6),'artifact':p.name,'limitations':'May be cached; not physical block verification; retained.'}

if __name__ == '__main__':
    import argparse, json
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('new_lab_parent')
    root=Path(parser.parse_args().new_lab_parent)/('probe-lab-'+uuid.uuid4().hex)
    root.mkdir(parents=True,exist_ok=False)
    with (root/'LAB_ONLY.marker').open('xb') as f: f.write(b'Dedicated synthetic test only')
    print(json.dumps(sample_probe(root),indent=2))
