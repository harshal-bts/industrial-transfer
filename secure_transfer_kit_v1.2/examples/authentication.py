"""Illustrative password verifier, not production account management.
PBKDF2-HMAC-SHA256 example using Python stdlib; production prefer Argon2id
or approved Windows identity. No embedded credentials, no file writes.
"""
import hashlib,hmac,secrets
ITERATIONS=600_000

def hash_password(password):
    salt=secrets.token_bytes(16)
    return {'salt':salt.hex(),'iterations':ITERATIONS,'digest':hashlib.pbkdf2_hmac('sha256',password.encode(),salt,ITERATIONS).hex()}

def verify_password(password, record):
    if record['iterations']!=ITERATIONS: raise ValueError('unexpected KDF parameters')
    calculated=hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(record['salt']),ITERATIONS)
    return hmac.compare_digest(calculated,bytes.fromhex(record['digest']))
