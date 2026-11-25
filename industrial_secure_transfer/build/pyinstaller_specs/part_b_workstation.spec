# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller `onedir` Build Specification for Part B — Facility Transfer Workstation (Windows / Linux)
(Section 7, Section 12, DEP-01, DEP-02, SAF-03):
- Uses `onedir` packaging (`COLLECT`) to avoid PyInstaller `onefile` temp extraction/deletion behavior.
- Includes `part_b_workstation.runner` and the isolated `part_b_workstation.cleanup_gate`.
- Explicitly excludes `part_c_server` (Part B never decrypts payloads or holds server private keys).
- Requests no UAC privilege elevation (`uac_admin=False`).
"""

block_cipher = None

FORBIDDEN_PART_B_MODULES = [
    "industrial_secure_transfer.part_c_server",
    "industrial_secure_transfer.part_c_server.ingestion_svc",
]

a = Analysis(
    ["../../part_b_workstation/runner.py"],
    pathex=["../../.."],
    binaries=[],
    datas=[],
    hiddenimports=[
        "industrial_secure_transfer.core.config",
        "industrial_secure_transfer.core.safety",
        "industrial_secure_transfer.core.crypto",
        "industrial_secure_transfer.core.packaging",
        "industrial_secure_transfer.core.state",
        "industrial_secure_transfer.core.eta",
        "industrial_secure_transfer.core.auth",
        "industrial_secure_transfer.adapters.base",
        "industrial_secure_transfer.adapters.windows",
        "industrial_secure_transfer.adapters.linux",
        "industrial_secure_transfer.transports.smb_transport",
        "industrial_secure_transfer.transports.usb_transport",
        "industrial_secure_transfer.part_b_workstation.cleanup_gate",
        "industrial_secure_transfer.ui.desktop_app",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=FORBIDDEN_PART_B_MODULES,
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,  # Mandatory for `onedir` mode
    name="IST_PartB_Workstation",
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
    name="IST_PartB_Workstation",
)
