"""
provision_smb_poc.py
One-command provisioning helper for a 2-Laptop SMB 3.1.1 Proof-of-Concept (POC).
Generates:
  - Ed25519 Provisioning, Sender, and Server signing keypairs
  - RSA-3072 OAEP Server decryption keypair
  - Salted Argon2id `accounts.json`
  - Signed `machine_config.signed.json` for Laptop 1 (Part A Exporter) and Laptop 2 (Part C Server)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_REPO_ROOT = str(Path(__file__).resolve().parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import industrial_secure_transfer  # noqa: E402,F401
from industrial_secure_transfer.core.auth import hash_password_argon2id
from industrial_secure_transfer.core.config import create_signed_config_dict
from industrial_secure_transfer.core.crypto import (
    generate_ed25519_keypair,
    generate_rsa_keypair,
    serialize_private_key_pem,
    serialize_public_key_pem,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Provision signed configs & keys for a 2-Laptop SMB 3.1.1 POC"
    )
    parser.add_argument("--server-host", required=True, help="Laptop 2 hostname or IP address (e.g. 192.168.1.50 or SERVER-LAPTOP)")
    parser.add_argument("--source-dir", default=r"C:\IST_POC\SourceDataset", help="Source dataset directory on Laptop 1")
    parser.add_argument("--server-base-dir", default=r"C:\IST_POC_Server", help="Base directory on Laptop 2 for shares, quarantine & repo")
    parser.add_argument("--operator-user", default="operator.name", help="Operator username for Part A login")
    parser.add_argument("--operator-pass", default="DemoTransfer2026!", help="Operator password for Part A login")
    parser.add_argument("--out-dir", default=r".\poc_bundle", help="Output directory for laptop1_part_a and laptop2_part_c bundles")
    args = parser.parse_args()

    out_root = Path(args.out_dir).resolve()
    part_a_dir = out_root / "laptop1_part_a_config"
    part_c_dir = out_root / "laptop2_part_c_config"
    part_a_dir.mkdir(parents=True, exist_ok=True)
    part_c_dir.mkdir(parents=True, exist_ok=True)

    # 1. Generate keypairs
    prov_priv, prov_pub = generate_ed25519_keypair()
    sender_priv, sender_pub = generate_ed25519_keypair()
    server_sign_priv, server_sign_pub = generate_ed25519_keypair()
    server_rsa_priv, server_rsa_pub = generate_rsa_keypair(key_size=3072)

    prov_pub_pem = serialize_public_key_pem(prov_pub)
    sender_priv_pem = serialize_private_key_pem(sender_priv)
    sender_pub_pem = serialize_public_key_pem(sender_pub)
    server_sign_priv_pem = serialize_private_key_pem(server_sign_priv)
    server_sign_pub_pem = serialize_public_key_pem(server_sign_pub)
    server_rsa_priv_pem = serialize_private_key_pem(server_rsa_priv)
    server_rsa_pub_pem = serialize_public_key_pem(server_rsa_pub)

    srv_base = Path(args.server_base_dir)
    incoming_unc = f"\\\\{args.server_host}\\IndustrialIncoming"
    receipts_unc = f"\\\\{args.server_host}\\IndustrialReceipts"

    common_keys = {
        "provisioning_key_id": "PROV-POC-01",
        "sender_signing_key_id": "SENDER-POC-01",
        "recipient_encryption_key_id": "SERVER-RSA-01",
        "recipient_rsa_public_key_pem": server_rsa_pub_pem,
        "trusted_sender_public_keys_pem": {"SENDER-POC-01": sender_pub_pem},
        "trusted_server_signing_keys_pem": {"SRV-SIGN-01": server_sign_pub_pem},
        "min_free_space_bytes": 100 * 1024 * 1024,
        "authorized_usb_devices": [],
    }

    # 2. Part A Config (Laptop 1) — NEVER contains server private keys
    part_a_cfg = create_signed_config_dict(
        {
            **common_keys,
            "version": 1,
            "machine_id": "IND-PC-001",
            "role": "PART_A_EXPORTER",
            "state_journal_dir": r"C:\IST_POC\Journal_PartA",
            "smb_endpoint": {
                "server_name": args.server_host,
                "incoming_share_path": incoming_unc,
                "receipt_share_path": receipts_unc,
                "require_smb311": True,
                "require_encryption": True,
            },
            "jobs": [
                {
                    "job_id": "JOB-WIFI-SMB-01",
                    "name": f"Direct SMB 3.1.1 Transfer to {args.server_host}",
                    "source_root": args.source_dir,
                    "transfer_method": "SMB",
                    "discovery_mode": "INCREMENTAL",
                    "stability_window_seconds": 5.0,
                    "chunk_size_bytes": 4 * 1024 * 1024,
                }
            ],
        },
        prov_priv,
    )

    # 3. Part C Config (Laptop 2)
    part_c_cfg = create_signed_config_dict(
        {
            **common_keys,
            "version": 1,
            "machine_id": "ING-SRV-001",
            "role": "PART_C_SERVER",
            "state_journal_dir": str(srv_base / "Journal_PartC"),
            "quarantine_dir": str(srv_base / "Quarantine"),
            "committed_repository_dir": str(srv_base / "CommittedRepository"),
            "smb_endpoint": {
                "server_name": args.server_host,
                "incoming_share_path": str(srv_base / "Incoming"),
                "receipt_share_path": str(srv_base / "Receipts"),
                "require_smb311": True,
                "require_encryption": True,
            },
            "jobs": [],
        },
        prov_priv,
    )

    # 4. Write Laptop 1 (Part A) bundle
    (part_a_dir / "provisioning_pub.pem").write_text(prov_pub_pem, encoding="utf-8")
    (part_a_dir / "sender_signing_priv.pem").write_text(sender_priv_pem, encoding="utf-8")
    (part_a_dir / "machine_config.signed.json").write_text(json.dumps(part_a_cfg, indent=2), encoding="utf-8")
    pw_hash = hash_password_argon2id(args.operator_pass, time_cost=2, memory_cost_kib=16384)
    accounts_doc = {
        "accounts": {
            args.operator_user: {
                "password_hash": pw_hash,
                "role": "OPERATOR",
            }
        }
    }
    (part_a_dir / "accounts.json").write_text(json.dumps(accounts_doc, indent=2), encoding="utf-8")

    # 5. Write Laptop 2 (Part C) bundle
    (part_c_dir / "provisioning_pub.pem").write_text(prov_pub_pem, encoding="utf-8")
    (part_c_dir / "server_rsa_priv.pem").write_text(server_rsa_priv_pem, encoding="utf-8")
    (part_c_dir / "server_signing_priv.pem").write_text(server_sign_priv_pem, encoding="utf-8")
    (part_c_dir / "machine_config.signed.json").write_text(json.dumps(part_c_cfg, indent=2), encoding="utf-8")

    print("=" * 72)
    print("2-LAPTOP SMB 3.1.1 POC BUNDLE GENERATED SUCCESSFULLY")
    print("=" * 72)
    print(f"Laptop 1 (Part A) Config Dir : {part_a_dir}")
    print(f"Laptop 2 (Part C) Config Dir : {part_c_dir}")
    print(f"Target SMB Server Host       : {args.server_host}")
    print(f"Incoming UNC Share           : {incoming_unc}")
    print(f"Receipts UNC Share           : {receipts_unc}")
    print(f"Operator Login               : {args.operator_user} / {args.operator_pass}")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
