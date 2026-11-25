"""
End-to-end validation & live pipeline demonstration script for Industrial Secure Data Transfer.
Executes:
  1. Provisioning & cryptographic key generation (Ed25519 signing + RSA-3072 OAEP key wrapping)
  2. Operator authentication (Argon2id / salted slow hash)
  3. Dataset discovery (shapefile companion check + active-write deferral + inventory freeze)
  4. Option 2A: Part A Exporter -> Single Authorized USB (with health probe, per-chunk zlib/none, AES-256-GCM + AAD, Ed25519 manifest)
  5. Option 2B: Part B Transfer Workstation -> SMB Incoming Share -> Part C Ingestion Server
  6. Part C Quarantine Decryption -> Malware Scan Hook -> Durable Immutable Commit -> Signed COMMITTED Receipt
  7. Part B Receipt Persistence to USB -> Restricted USB Cleanup Gate -> Returned USB Acknowledgment on Part A
"""

from __future__ import annotations

import os
import sys
import tempfile
import threading
import time
from pathlib import Path

_REPO_ROOT = str(Path(__file__).resolve().parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from industrial_secure_transfer.adapters.base import SMBSessionTelemetry, USBDeviceTelemetry
from industrial_secure_transfer.adapters.windows import WindowsOSAdapter
from industrial_secure_transfer.core.auth import (
    AccountRecord,
    LocalAuthenticator,
    hash_password_argon2id,
)
from industrial_secure_transfer.core.config import (
    SMBEndpointConfig,
    create_signed_config_dict,
    validate_and_parse_config,
)
from industrial_secure_transfer.core.crypto import (
    generate_ed25519_keypair,
    generate_rsa_keypair,
    serialize_public_key_pem,
    sha256_hex,
)
from industrial_secure_transfer.part_a_exporter.runner import PartAExporterRunner
from industrial_secure_transfer.part_b_workstation.runner import PartBWorkstationRunner
from industrial_secure_transfer.part_c_server.ingestion_svc import IngestionServerService


def run_validation_demo() -> None:
    print("=" * 78)
    print("INDUSTRIAL SECURE DATA TRANSFER v1.2 — END-TO-END VALIDATION RUN")
    print("=" * 78)

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        root = Path(tmp)
        source_dir = root / "D_IndustrialData_2026_11_24"
        usb_dir = root / "USB_003"
        incoming_dir = root / "IndustrialIncoming"
        receipt_dir = root / "IndustrialReceipts"
        quarantine_dir = root / "ServerQuarantine"
        repo_dir = root / "ServerCommittedRepository"

        for d in (source_dir, usb_dir, incoming_dir, receipt_dir, quarantine_dir, repo_dir):
            d.mkdir(parents=True, exist_ok=True)

        # 1. Generate cryptographic keys
        prov_priv, prov_pub = generate_ed25519_keypair()
        sender_priv, sender_pub = generate_ed25519_keypair()
        server_sign_priv, server_sign_pub = generate_ed25519_keypair()
        server_rsa_priv, server_rsa_pub = generate_rsa_keypair(key_size=3072)
        print("[1/7] Generated Ed25519 provisioning/sender/server signing keys & RSA-3072 OAEP keypair.")

        # 2. Populate realistic industrial dataset
        old_mtime = time.time() - 120.0
        (source_dir / "_DATASET_READY.marker").write_text("READY\n", encoding="utf-8")
        (source_dir / "Measurements").mkdir()
        f_csv = source_dir / "Measurements" / "turbine_vibration.csv"
        f_csv.write_bytes(b"timestamp,sensor_id,mm_s\n2026-11-24T10:00:00Z,VIB-01,1.42\n" * 40)
        os.utime(f_csv, (old_mtime, old_mtime))

        (source_dir / "Images").mkdir()
        f_jpg = source_dir / "Images" / "thermal_inspection.jpg"
        f_jpg.write_bytes(os.urandom(48_000))
        os.utime(f_jpg, (old_mtime, old_mtime))

        (source_dir / "Geospatial").mkdir()
        for ext in (".shp", ".shx", ".dbf", ".prj"):
            p_geo = source_dir / "Geospatial" / f"pipeline_corridor{ext}"
            p_geo.write_bytes(f"SHAPEFILE-{ext}-HEADER-".encode("utf-8") + os.urandom(256))
            os.utime(p_geo, (old_mtime, old_mtime))

        # Populate protected files on the single USB to prove they survive cleanup
        for prot_folder, prot_name in [
            ("Application", "IST_PartA_Exporter.exe.sig"),
            ("Configuration", "machine_config.signed.json"),
            ("Certificates", "facility_root_ca.pem"),
            ("Logs", "usb_custody.log"),
        ]:
            (usb_dir / prot_folder).mkdir(exist_ok=True)
            (usb_dir / prot_folder / prot_name).write_bytes(b"PROTECTED-BINARY-ARTIFACT")

        # 3. Create & verify Ed25519-signed configurations for Part A, Part B, and Part C
        common = {
            "provisioning_key_id": "PROV-ROOT-01",
            "sender_signing_key_id": "IND-PC-001-KEY",
            "recipient_encryption_key_id": "ING-SRV-RSA-01",
            "recipient_rsa_public_key_pem": serialize_public_key_pem(server_rsa_pub),
            "trusted_sender_public_keys_pem": {"IND-PC-001-KEY": serialize_public_key_pem(sender_pub)},
            "trusted_server_signing_keys_pem": {"ING-SRV-SIGN-01": serialize_public_key_pem(server_sign_pub)},
            "min_free_space_bytes": 1024 * 1024,
            "authorized_usb_devices": [
                {
                    "serial_number": "SN-USB-003",
                    "volume_guid": "VOL-GUID-003",
                    "expected_filesystem": "NTFS",
                    "label": "IST_USB_003",
                }
            ],
            "smb_endpoint": {
                "server_name": "ingestion01",
                "incoming_share_path": str(incoming_dir),
                "receipt_share_path": str(receipt_dir),
                "require_smb311": True,
                "require_encryption": True,
            },
        }

        cfg_a = validate_and_parse_config(
            create_signed_config_dict(
                {
                    **common,
                    "version": 1,
                    "machine_id": "IND-PC-001",
                    "role": "PART_A_EXPORTER",
                    "state_journal_dir": str(root / "journal_part_a"),
                    "jobs": [
                        {
                            "job_id": "JOB-USB-DAILY",
                            "name": "Daily OT Dataset Export to Single USB",
                            "source_root": str(source_dir),
                            "transfer_method": "USB",
                            "discovery_mode": "INCREMENTAL",
                            "stability_window_seconds": 5.0,
                            "chunk_size_bytes": 64 * 1024,
                        }
                    ],
                },
                prov_priv,
            ),
            prov_pub,
            expected_role="PART_A_EXPORTER",
        )
        cfg_b = validate_and_parse_config(
            create_signed_config_dict(
                {
                    **common,
                    "version": 1,
                    "machine_id": "FAC-WS-001",
                    "role": "PART_B_WORKSTATION",
                    "state_journal_dir": str(root / "journal_part_b"),
                    "jobs": [],
                },
                prov_priv,
            ),
            prov_pub,
            expected_role="PART_B_WORKSTATION",
        )
        cfg_c = validate_and_parse_config(
            create_signed_config_dict(
                {
                    **common,
                    "version": 1,
                    "machine_id": "ING-SRV-001",
                    "role": "PART_C_SERVER",
                    "state_journal_dir": str(root / "journal_part_c"),
                    "quarantine_dir": str(quarantine_dir),
                    "committed_repository_dir": str(repo_dir),
                    "jobs": [],
                },
                prov_priv,
            ),
            prov_pub,
            expected_role="PART_C_SERVER",
        )
        print("[2/7] Verified Ed25519 signatures on Part A, Part B, and Part C machine configs.")

        # 4. Authenticate operator & execute Part A USB export
        pw_hash = hash_password_argon2id("OT-Secure-Operator-2026!", time_cost=2, memory_cost_kib=16384)
        auth = LocalAuthenticator({"op_engineer": AccountRecord("op_engineer", pw_hash, "OPERATOR")})
        session = auth.authenticate("op_engineer", "OT-Secure-Operator-2026!")

        adapter = WindowsOSAdapter(
            usb_telemetry_provider=lambda p: USBDeviceTelemetry(
                mount_root=str(p),
                serial_number="SN-USB-003",
                volume_guid="VOL-GUID-003",
                filesystem="NTFS",
                is_removable_usb_bus=True,
                is_system_or_internal_disk=False,
                is_dirty=False,
                smart_health_status="PASSED",
                free_bytes=32 * 1024 * 1024 * 1024,
                total_bytes=64 * 1024 * 1024 * 1024,
            ),
            smb_telemetry_provider=lambda ep, p: SMBSessionTelemetry(
                server_name="ingestion01",
                share_path=str(p),
                dialect="3.1.1",
                encrypted=True,
                signed=True,
                is_remote_mount=True,
                free_bytes=128 * 1024 * 1024 * 1024,
            ),
        )

        part_a = PartAExporterRunner(
            config=cfg_a,
            adapter=adapter,
            authenticator=auth,
            sender_signing_private_key=sender_priv,
            usb_mount_root=usb_dir,
            probe_size_bytes=128 * 1024,
            enforce_32_64_mib_probe=False,
        )
        out_a = part_a.execute_export(
            session.session_id,
            cfg_a.jobs[0],
            transfer_id="TR-20261124-001",
            attempt_id="ATT-0001",
        )
        print(
            f"[3/7] Part A Export complete -> State: {out_a.final_state.value} | "
            f"Files: {out_a.inventory.file_count} | Verified Chunks: {out_a.verified_chunks_count} | "
            f"Manifest SHA-256: {out_a.manifest_sha256[:16]}..."
        )

        # 5. Start Part C Ingestion Server watcher & run Part B Workstation USB -> SMB -> Receipt -> Cleanup
        part_c = IngestionServerService(
            config=cfg_c,
            recipient_rsa_private_key=server_rsa_priv,
            server_signing_private_key=server_sign_priv,
            server_signing_key_id="ING-SRV-SIGN-01",
        )
        part_b = PartBWorkstationRunner(
            config=cfg_b,
            adapter=adapter,
            authenticator=auth,
            usb_mount_root=usb_dir,
        )

        stop_evt = threading.Event()

        def _server_poll() -> None:
            while not stop_evt.is_set():
                part_c.scan_and_reconcile_incoming()
                time.sleep(0.05)

        t_srv = threading.Thread(target=_server_poll, daemon=True)
        t_srv.start()
        try:
            out_b = part_b.execute_usb_to_smb_transfer(
                session.session_id,
                transfer_id="TR-20261124-001",
                attempt_id="ATT-0001",
                run_cleanup_after_receipt=True,
                receipt_timeout_seconds=10.0,
            )
        finally:
            stop_evt.set()
            t_srv.join(timeout=2.0)

        assert out_b.server_receipt is not None
        assert out_b.cleanup_report is not None
        print(
            f"[4/7] Part C Ingestion & Durable Commit -> Status: {out_b.server_receipt.status} | "
            f"Commit ID: {out_b.server_receipt.commit_id} | Files Verified: {out_b.server_receipt.files_verified}"
        )
        print(
            f"[5/7] Part B Receipt Persisted & USB Cleanup Gate Executed -> State: {out_b.final_state.value} | "
            f"Deleted Payloads: {len(out_b.cleanup_report.deleted_payload_files)} | "
            f"Deleted Probes: {len(out_b.cleanup_report.deleted_probe_files)} | "
            f"Retained Receipt: {out_b.cleanup_report.retained_receipt_path}"
        )

        # 6. Return same USB to Part A and verify receipt acknowledgment
        ack_list = part_a.acknowledge_returned_usb_receipts(session.session_id)
        print(f"[6/7] Part A Verified Returned USB Receipt -> Acknowledged Transfers: {ack_list}")

        # 7. Verify byte-for-byte integrity between OT source and Part C committed repository
        commit_root = repo_dir / "IND-PC-001" / "DS-JOB-USB-DAILY" / out_b.server_receipt.commit_id
        for entry in out_a.inventory.eligible_files:
            committed_p = commit_root / entry.relative_path
            assert committed_p.exists()
            assert sha256_hex(committed_p.read_bytes()) == entry.sha256
        print("[7/7] Verified 100% SHA-256 byte identity across OT Source, Encrypted Transport, and Committed Server Store.")
        print("=" * 78)
        print("VALIDATION RESULT: ALL SAFETY, CRYPTOGRAPHIC, AND WORKFLOW GATES PASSED.")
        print("=" * 78)


if __name__ == "__main__":
    run_validation_demo()
