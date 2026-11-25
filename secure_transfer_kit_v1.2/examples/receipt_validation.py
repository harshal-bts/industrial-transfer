"""LAB ONLY: verify signed receipt binding. Not a commit service or deletion gate.
The trusted public key must be independently provisioned. A signed assertion
alone cannot prove durable storage. No USB or deletion functions are provided.
"""
import re, uuid
from transfer_demo import verify

def validate_commit_receipt(blob, trusted_server_key, *, transfer_id, sender_id, manifest_hash, server_id):
    tid=str(uuid.UUID(transfer_id))
    if not re.fullmatch(r'[0-9a-f]{64}',manifest_hash): raise ValueError('Invalid expected manifest hash')
    expected={'transferId':tid,'senderId':sender_id,'manifestHash':manifest_hash,'serverId':server_id,'status':'COMMITTED'}
    result=verify(blob,trusted_server_key)
    if not isinstance(result,dict) or any(result.get(k)!=v for k,v in expected.items()):
        raise ValueError('Receipt is not a matching commit acknowledgment')
    return result
