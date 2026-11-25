# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller `onedir` Build Specification for Part A — Exporter (Windows 10 Industrial PC)
(Section 7, DEP-01, DEP-02, SAF-03):
- Uses `onedir` packaging (`COLLECT`) to avoid PyInstaller `onefile` temp extraction/deletion behavior.
- CRITICAL (SAF-03): Explicitly excludes `industrial_secure_transfer.part_b_workstation`
  and `industrial_secure_transfer.part_b_workstation.cleanup_gate` AND `industrial_secure_transfer.part_c_server`
  so the USB cleanup code and server decryption modules are physically absent from the Part A deliverable.
- Requests no UAC privilege elevation (`uac_admin=False`).
"""

block_cipher = None

FORBIDDEN_PART_A_MODULES = [
    "industrial_secure_transfer.part_b_workstation",
    "industrial_secure_transfer.part_b_workstation.cleanup_gate",
    "industrial_secure_transfer.part_b_workstation.runner",
    "industrial_secure_transfer.part_c_server",
    "industrial_secure_transfer.part_c_server.ingestion_svc",
]

a = Analysis(
    ["../../part_a_exporter/runner.py"],
    pathex=["../../.."],
    binaries=[],
    datas=[],
    hiddenimports=[
        "industrial_secure_transfer.core.config",
        "industrial_secure_transfer.core.safety",
        "industrial_secure_transfer.core.crypto",
        "industrial_secure_transfer.core.packaging",
        "industrial_secure_transfer.core.discovery",
        "industrial_secure_transfer.core.state",
        "industrial_secure_transfer.core.eta",
        "industrial_secure_transfer.core.auth",
        "industrial_secure_transfer.adapters.base",
        "industrial_secure_transfer.adapters.windows",
        "industrial_secure_transfer.transports.smb_transport",
        "industrial_secure_transfer.transports.usb_transport",
        "industrial_secure_transfer.ui.desktop_app",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=FORBIDDEN_PART_A_MODULES,
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

# Build-time safety assertion: fail build if cleanup_gate was pulled into Analysis
for mod_entry in a.pure:
    if "cleanup_gate" in mod_entry[0]:
        raise SystemExit("SAF-03 BUILD FAILURE: cleanup_gate detected in Part A Exporter bundle!")

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,  # Mandatory for `onedir` mode
    name="IST_PartA_Exporter",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=False,  # DEP-02: Never request privilege elevation
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="IST_PartA_Exporter",
)
