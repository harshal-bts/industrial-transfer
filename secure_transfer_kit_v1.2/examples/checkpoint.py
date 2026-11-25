"""Illustrative append-only event journal for dedicated lab directories.
No database compaction, deletion or replacement. Single writer only. Production
requires authenticated journal, locking, durable directory metadata and reconciliation.
"""
import json, uuid, os, datetime
from pathlib import Path

def record(lab_root, transfer_id, event, verified_bytes):
    root=Path(lab_root)
    if not (root/'LAB_ONLY.marker').is_file(): raise PermissionError('lab marker required')
    if verified_bytes<0: raise ValueError('invalid bytes')
    doc={'eventId':uuid.uuid4().hex,'transferId':str(uuid.UUID(transfer_id)),
         'event':event,'verifiedBytes':verified_bytes,'utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
    name=root/(doc['eventId']+'.event.json')
    with name.open('xb') as f:
        f.write(json.dumps(doc,sort_keys=True).encode()); f.flush(); os.fsync(f.fileno())
    return name

def read_events(lab_root, transfer_id):
    root=Path(lab_root); tid=str(uuid.UUID(transfer_id)); events=[]
    for p in root.glob('*.event.json'):
        try: doc=json.loads(p.read_bytes())
        except (ValueError,OSError): continue  # production reports corruption explicitly
        if doc.get('transferId')==tid: events.append(doc)
    return sorted(events,key=lambda x:(x['utc'],x['eventId']))
