"""Read-only SMB connection checks and create-only copy primitive.
LAB EXAMPLE: no production device authorization or native handle confinement.
Not a standalone transfer application. Never run against live OT storage.
"""
import hashlib, os, time, subprocess, json
from pathlib import Path

def check_plain(path):
    p = Path(path).absolute()
    for part in (p, *p.parents):
        if part.is_symlink() or (part.exists() and getattr(part.lstat(), "st_file_attributes", 0) & 0x400):
            raise ValueError("Symlink or reparse point prohibited in lab example")
    return p

BUFFER = 4 * 1024 * 1024

def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        while block := f.read(BUFFER):
            h.update(block)
    return h.hexdigest()

def copy_verified(source, destination, expected_hash):
    """Caller must authorize both paths. Existing bytes are never modified."""
    source, destination = check_plain(source), check_plain(destination)
    if digest(source) != expected_hash:
        raise ValueError('Source hash mismatch')
    if destination.exists():
        if digest(destination) != expected_hash:
            raise FileExistsError('Conflict preserved; allocate a new attempt')
        return 'ALREADY_VERIFIED'
    with source.open('rb') as src, destination.open('xb') as dst:
        while block := src.read(BUFFER):
            dst.write(block)
        dst.flush(); os.fsync(dst.fileno())
    if digest(destination) != expected_hash:
        raise IOError('Destination mismatch; preserve failed attempt')
    return 'VERIFIED'

def windows_smb_observations():
    """Read-only observations; actual authorization is server enforced."""
    if os.name != 'nt':
        raise NotImplementedError('Use Linux mount/session diagnostics')
    cmd = ['powershell.exe','-NoProfile','-NonInteractive','-Command',
           'Get-SmbConnection | Select-Object ServerName,ShareName,Dialect,Signed,Encrypted | ConvertTo-Json -Compress']
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=True)
    return json.loads(result.stdout or '[]')

# Windows: Path(r'\\ingestion01.facility.local\IndustrialIncoming')
# Linux: Path('/mnt/industrial-incoming') (admin-provisioned SMB mount)
# Do not accept arbitrary paths from operator input. Verify mount identity.
