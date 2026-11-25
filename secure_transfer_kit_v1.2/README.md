# Industrial Secure Data Transfer | Engineering reference kit v1.2

**LAB ONLY — not production software.** This kit accompanies the unchanged 38-page Technical Design & Operator Guide v1.2 in `docs/`. It contains the updated interactive workflow simulator, 26 screen mockups, 14 architecture images, 2 original UI previews, real synthetic-data reference algorithms, configuration examples, and tests. No actual USB deletion, disk formatting, live network transfers, or production credentials are provided. Run only against isolated synthetic lab data, never live industrial equipment.

## Quick start (Windows or Linux development workstation)
Use a supported Python 3.10+ runtime and Tkinter. Linux may require its distribution's Python Tk package. Open a terminal in this directory. No Python installation on the industrial machine is authorized by this kit.

```text
python -m pip install -r requirements.txt
python operator_ui.py
```

Demo credentials: `operator` / `DemoTransfer2026!` (public demonstration credentials, NEVER production credentials).

- Option 1: select Direct network, review inventory, begin simulated checks, observe progress, then simulate valid receipt or rejection.
- Option 2: select Industrial PC to USB, begin checks and export, select **Simulate moving USB to Part B**, run import checks and progress, simulate valid receipt, review and simulate cleanup (no actual deletion), return the same USB, acknowledge on Part A. Standalone Option 2B is also available.
- During progress, try Pause, Stop safely, Resume / retry checks, or Simulate interruption. Mandatory failed checks block progress. Sign out after stopping, then sign in to see in-memory recovery. Closing the process discards this simulation's state; the checkpoint example is separate.
- Select **Screen design gallery (26)** for all SCR-01 through SCR-26 conceptual mockups. The interactive UI is a simpler implementation of the same flow, not a pixel-perfect rendering of all mockups. Operator history and details are read-only and in-memory.

## Real reference algorithms (synthetic data only)
```text
python transfer_demo.py ./lab-runs
python examples/usb_probe.py ./lab-runs
python examples/stream_zip.py
python -m unittest discover -s tests -v
```
GUI smoke test: `python tests/ui_smoke.py` on a desktop, or `xvfb-run -a python tests/ui_smoke.py` on Linux with Xvfb. All tests create only new dedicated synthetic artifacts and retain them; no cleanup command is supplied. `test_results.txt` records the actual tests run on Linux. `requirements.txt` lists the crypto dependency; review and pin versions in the project build pipeline.

## Package map
| File / directory | Purpose |
|---|---|
| `docs/industrial_secure_transfer_technical_design_v1.2.docx` | Source-of-truth design and illustrated operator guide |
| `docs/screen_inventory.md` | Mapping of all 26 screen IDs to files and implementation status |
| `docs/validation_report.md` | Test coverage, review findings, production gaps |
| `visuals/architecture/` | 14 architecture/workflow illustrations |
| `visuals/operator_screens/` | 26 screen PNGs matching the guide |
| `operator_ui.py`, `workflow.py` | Interactive in-memory workflow simulation, gallery and state model |
| `transfer_demo.py` | Real per-chunk compression, AES-256-GCM, RSA-OAEP, Ed25519, encrypted manifest, local-directory forwarding and quarantine reconstruction; ephemeral demo keys |
| `examples/smb_native.py` | Create-only copy and destination hash check on authorized lab paths; native SMB observations; no live session exercised |
| `examples/usb_probe.py`, `read_only_probe.py` | Synthetic sample write/read verification and read-only import probe; not physical disk checks |
| `examples/receipt_validation.py` | Real signed COMMITTED receipt binding example; no actual commit service |
| `examples/cleanup_policy.py` | Fail-closed authorization model; deletion deliberately disabled |
| `examples/stream_zip.py` | Streaming ZIP64 to encrypted memory chunks, no plaintext disk archive |
| `examples/checkpoint.py`, `eta.py`, `authentication.py` | Append-only lab events, rolling ETA and salted password hash examples |
| `config/`, `examples/windows_readonly.ps1` | Illustrative SMB/Samba/job configuration and read-only diagnostics |
| `tests/`, `test_results.txt` | Automated algorithm and workflow tests plus UI smoke test |
| `legacy/` | Previous UI versions and notes, retained for reference |
| `MANIFEST.sha256` | File hashes for archive contents (excludes itself; integrity inventory, not a digital signature) |

## Mandatory production work / exclusions
This kit is deliberately not an integrated transfer application. The UI does not invoke actual crypto, network or USB code. The real algorithm examples use synthetic directories and do not validate OS device identity, hardware health, source readiness, actual SMB session policy, malware, permissions or durable server commit. The simulated COMMITTED and cleanup screens are not receipts or authorizations. Real receipt validation must use independently trusted server keys and a durable server commit; signed quarantine verification cannot authorize cleanup. Persistent restart recovery, site authentication, role-specific deployment, source file completeness, incremental reconciliation, bounded resource and schema validation, immutable retry attempts, key management, audit, and hardware-specific tests remain required. Basic path checks are not handle-based confinement and cannot eliminate races. Strictly restrict source permissions, provision native device adapters, enforce create-only/immutable server policy and test both Windows and Linux. Windows 10 edition, OEM approval, network/VLAN, server OS and device policies remain unknown. No USB cleanup is implemented: the eventual Part B implementation must independently enforce verified device identity, exact signed inventory, trusted durable commit and safe handle-based path checks before deletion. Never delete, format, move, truncate or overwrite original local data. The app cannot guarantee behavior of the OS/runtime/administrators; enforce permissions and review runtime effects. No actual USB formatting is allowed in the application. See design and validation report for acceptance gates.
