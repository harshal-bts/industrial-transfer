"""
launch_ui_preview.py
Launches the Industrial Secure Data Transfer Desktop UI connected to the **REAL** backend engines:
  - Real `PartAExporterRunner` (dataset discovery, shapefile companion check, compression, AES-256-GCM encryption)
  - Real `USBTransport` & `SMBTransport` (create-only 'xb' writes + read-back SHA-256 verification)
  - Real background `IngestionServerService` (Part C daemon reconciling `IndustrialIncoming`, decrypting in
    isolated quarantine, scanning for malware, committing durably, and publishing Ed25519-signed receipts)
  - Real `AppendOnlyJournal` (hash-chained audit & checkpoint history visible in SCR-19 / SCR-20)

Default demo login: `operator.name` (or `operator`) / `DemoTransfer2026!`
"""

from __future__ import annotations

import os
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

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
    JobConfig,
    SMBEndpointConfig,
    create_signed_config_dict,
    validate_and_parse_config,
)
from industrial_secure_transfer.core.crypto import (
from industrial_secure_transfer.core.crypto import (
    generate_ed25519_keypair,
    generate_rsa_keypair,
    serialize_public_key_pem,
)
from industrial_secure_transfer.core.safety import generate_immutable_attempt_id
from industrial_secure_transfer.part_a_exporter.runner import (
    PartAExporterRunner,
    PartAExportOutcome,
)
from industrial_secure_transfer.part_c_server.ingestion_svc import IngestionServerService
from industrial_secure_transfer.ui.desktop_app import (
    IndustrialTransferDesktopApp,
    OperatorUIController,
)


def main() -> int:
    root = Path(tempfile.mkdtemp(prefix="ist_live_ui_"))
    source_dir = root / "OT_SourceDataset"
    usb_dir = root / "USB_003"
    incoming_dir = root / "IndustrialIncoming"
    receipt_dir = root / "IndustrialReceipts"
    quarantine_dir = root / "ServerQuarantine"
    repo_dir = root / "ServerCommittedRepo"

    for d in (source_dir, usb_dir, incoming_dir, receipt_dir, quarantine_dir, repo_dir):
        d.mkdir(parents=True, exist_ok=True)

    # Create a real industrial dataset (CSV + JPG + Shapefile group) for live transfer
    old_t = time.time() - 120.0
    (source_dir / "_DATASET_READY.marker").write_text("READY\n", encoding="utf-8")
    (source_dir / "Measurements").mkdir()
    csv_f = source_dir / "Measurements" / "sensor_telemetry.csv"
    csv_f.write_bytes(b"timestamp,pressure_bar,temp_c\n2026-11-25T01:00:00Z,12.4,48.2\n" * 1500)
    os.utime(csv_f, (old_t, old_t))

    (source_dir / "Images").mkdir()
    jpg_f = source_dir / "Images" / "inspection_01.jpg"
    jpg_f.write_bytes(os.urandom(250_000))
    os.utime(jpg_f, (old_t, old_t))

    (source_dir / "Geospatial").mkdir()
    for ext in (".shp", ".shx", ".dbf", ".prj"):
        gf = source_dir / "Geospatial" / f"site_map{ext}"
        gf.write_bytes(f"GEO-{ext}-".encode("utf-8") + os.urandom(4096))
        os.utime(gf, (old_t, old_t))

    prov_priv, prov_pub = generate_ed25519_keypair()
    sender_priv, sender_pub = generate_ed25519_keypair()
    server_sign_priv, server_sign_pub = generate_ed25519_keypair()
    server_rsa_priv, server_rsa_pub = generate_rsa_keypair(key_size=3072)

    common = {
        "provisioning_key_id": "PROV-01",
        "sender_signing_key_id": "SENDER-01",
        "recipient_encryption_key_id": "RSA-01",
        "recipient_rsa_public_key_pem": serialize_public_key_pem(server_rsa_pub),
        "trusted_sender_public_keys_pem": {"SENDER-01": serialize_public_key_pem(sender_pub)},
        "trusted_server_signing_keys_pem": {"SRV-01": serialize_public_key_pem(server_sign_pub)},
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
                "state_journal_dir": str(root / "journal_a"),
                "jobs": [
                    {
                        "job_id": "JOB-NET-01",
                        "name": "Direct SMB transfer",
                        "source_root": str(source_dir),
                        "transfer_method": "SMB",
                        "discovery_mode": "INCREMENTAL",
                        "stability_window_seconds": 5.0,
                        "chunk_size_bytes": 64 * 1024,
                    },
                    {
                        "job_id": "JOB-USB-02",
                        "name": "Export to authorized USB",
                        "source_root": str(source_dir),
                        "transfer_method": "USB",
                        "discovery_mode": "FULL_DAILY",
                        "stability_window_seconds": 5.0,
                        "chunk_size_bytes": 64 * 1024,
                    },
                ],
            },
            prov_priv,
        ),
        prov_pub,
        expected_role="PART_A_EXPORTER",
    )

    cfg_c = validate_and_parse_config(
        create_signed_config_dict(
            {
                **common,
                "version": 1,
                "machine_id": "ING-SRV-001",
                "role": "PART_C_SERVER",
                "state_journal_dir": str(root / "journal_c"),
                "quarantine_dir": str(quarantine_dir),
                "committed_repository_dir": str(repo_dir),
                "jobs": [],
            },
            prov_priv,
        ),
        prov_pub,
        expected_role="PART_C_SERVER",
    )

    pw_hash = hash_password_argon2id("DemoTransfer2026!", time_cost=2, memory_cost_kib=16384)
    auth = LocalAuthenticator(
        {
            "operator.name": AccountRecord("operator.name", pw_hash, "OPERATOR"),
            "operator": AccountRecord("operator", pw_hash, "OPERATOR"),
        },
        min_attempt_interval_seconds=0.0,
    )

    adapter = WindowsOSAdapter(
        usb_telemetry_provider=lambda p: USBDeviceTelemetry(
            mount_root=str(p),
            serial_number="SN-USB-003",
            volume_guid="VOL-GUID-003",
            filesystem="NTFS",
            is_removable_usb_bus=True,
            is_system_or_internal_disk=False,
            is_dirty=False,
            smart_health_status="UNAVAILABLE",
            free_bytes=96 * 1024 * 1024 * 1024,
            total_bytes=128 * 1024 * 1024 * 1024,
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

    # Boot real Part C Ingestion Server Daemon in the background
    part_c = IngestionServerService(
        config=cfg_c,
        recipient_rsa_private_key=server_rsa_priv,
        server_signing_private_key=server_sign_priv,
        server_signing_key_id="SRV-01",
    )
    stop_srv = threading.Event()

    def _srv_loop() -> None:
        while not stop_srv.is_set():
            part_c.scan_and_reconcile_incoming()
            time.sleep(0.25)

    srv_thread = threading.Thread(target=_srv_loop, daemon=True, name="IST-PartC-Daemon")
    srv_thread.start()

    # Boot real Part A Exporter Runner wired directly to the Tkinter UI Controller
    runner = PartAExporterRunner(
        config=cfg_a,
        adapter=adapter,
        authenticator=auth,
        sender_signing_private_key=sender_priv,
        usb_mount_root=usb_dir,
        probe_size_bytes=128 * 1024,
        enforce_32_64_mib_probe=False,
    )

    def _preflight_fn(job: JobConfig) -> list[Any]:
        return runner.run_ui_preflight(job)

    def _worker_fn(session_id: str, job: JobConfig, ctrl: OperatorUIController) -> PartAExportOutcome:
        t_id = ctrl.vm.transfer_id or generate_immutable_attempt_id("TR")
        att_id = ctrl.vm.attempt_id or generate_immutable_attempt_id("ATT")
        ctrl.post_worker_event("JOB_META", {"transfer_id": t_id, "attempt_id": att_id})
        return runner.execute_export(
            session_id,
            job,
            transfer_id=t_id,
            attempt_id=att_id,
            progress_callback=ctrl.post_progress_snapshot,
            receipt_timeout_seconds=15.0,
        )

    controller = OperatorUIController(
        config=cfg_a,
        authenticator=auth,
        journal=runner.journal,
        preflight_runner=_preflight_fn,
        transfer_worker_fn=_worker_fn,
        pause_fn=runner.request_pause,
        stop_fn=runner.request_stop_safely,
    )
    app = IndustrialTransferDesktopApp(controller)
    try:
        app.run()
    finally:
        stop_srv.set()
        srv_thread.join(timeout=1.5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
