# 2-Laptop SMB 3.1.1 Proof-of-Concept (POC) Guide

This guide walks you step-by-step through running a live **Option 1 — Direct SMB 3.1.1 Network Transfer** between two Windows laptops over your company Wi-Fi (or wired LAN):
- **Laptop 1 (OT Industrial PC):** Runs **Part A Exporter** ([`part_a_exporter/runner.py`](file:///c:/Users/LENOVO/OneDrive%20-%20BizTranSights%20Solutions,%20LLP/Industrial-Data-Transfer/industrial_secure_transfer/part_a_exporter/runner.py)) with the Tkinter Operator UI.
- **Laptop 2 (Ingestion Server):** Hosts the two SMB 3.1.1 shares (`IndustrialIncoming` and `IndustrialReceipts`) and runs **Part C Ingestion Server** ([`part_c_server/ingestion_svc.py`](file:///c:/Users/LENOVO/OneDrive%20-%20BizTranSights%20Solutions,%20LLP/Industrial-Data-Transfer/industrial_secure_transfer/part_c_server/ingestion_svc.py)).

---

## 1. Prerequisites on Both Laptops

### A. Network & Company Wi-Fi Prerequisites (Both Laptops)
1. **Same Subnet / No Wi-Fi Client Isolation:** Both laptops must be on the same Wi-Fi SSID / VLAN and able to reach each other on **TCP port 445** (SMB).
   > [!IMPORTANT]
   > Some corporate/guest Wi-Fi networks enable **AP Client Isolation** or block peer-to-peer TCP `445`. If `Test-NetConnection -Port 445` fails, connect both laptops to an internal engineering VLAN, wired switch, or a dedicated mobile/travel router for the POC.
2. **Network Profile Set to Private (or Domain):** On both laptops, ensure the Wi-Fi connection is not set to `Public` (which blocks SMB by default), or explicitly allow File and Printer Sharing on the active profile.

### B. Software Prerequisites (Both Laptops)
1. Copy the repository folder (`Industrial-Data-Transfer`) to both laptops (e.g., `C:\Industrial-Data-Transfer`).
2. **Python 3.10+** with **`cryptography`** and **`tkinter`** installed.
   - Verify on both laptops:
     ```powershell
     python -c "import tkinter, cryptography; print('OK', cryptography.__version__)"
     ```
     *(If using your Python 3.14 path on this machine: `& "C:\Users\LENOVO\AppData\Local\Programs\Python\Python314\python.exe" -c "import tkinter, industrial_secure_transfer, cryptography; print('OK', cryptography.__version__)"`)*

### C. Prerequisites on Laptop 2 (Ingestion Server)
1. **Find Laptop 2's IP Address** (run on Laptop 2):
   ```powershell
   ipconfig | Select-String "IPv4"
   ```
   *(Example: `192.168.1.50` — we will use `<LAPTOP2_IP>` below.)*
2. **Create a dedicated local Windows user for SMB share access** (or use an existing local account on Laptop 2):
   ```powershell
   # Run in Administrator PowerShell on Laptop 2
   $pw = ConvertTo-SecureString "SmbPocPass2026!" -AsPlainText -Force
   New-LocalUser -Name "ist_transfer" -Password $pw -PasswordNeverExpires
   ```
3. **Create the server directories and SMB 3.1.1 encrypted shares** (Administrator PowerShell on Laptop 2):
   ```powershell
   New-Item -ItemType Directory -Force "C:\IST_POC_Server\Incoming"
   New-Item -ItemType Directory -Force "C:\IST_POC_Server\Receipts"
   New-Item -ItemType Directory -Force "C:\IST_POC_Server\Quarantine"
   New-Item -ItemType Directory -Force "C:\IST_POC_Server\CommittedRepository"
   New-Item -ItemType Directory -Force "C:\IST_POC_Server\Journal_PartC"

   # Create IndustrialIncoming (writable for create-only chunks & manifest) with SMB encryption
   New-SmbShare -Name "IndustrialIncoming" `
       -Path "C:\IST_POC_Server\Incoming" `
       -ChangeAccess "ist_transfer" `
       -EncryptData $true

   # Create IndustrialReceipts (read-only for Part A polling) with SMB encryption
   New-SmbShare -Name "IndustrialReceipts" `
       -Path "C:\IST_POC_Server\Receipts" `
       -ReadAccess "ist_transfer" `
       -EncryptData $true

   # Allow SMB (TCP 445) in Windows Firewall on Laptop 2
   Enable-NetFirewallRule -DisplayGroup "File and Printer Sharing"
   ```
   Verify SMB 3.1.1 encryption is enabled on both shares:
   ```powershell
   Get-SmbShare -Name "IndustrialIncoming","IndustrialReceipts" | Select-Object Name,Path,EncryptData
   ```

### D. Prerequisites on Laptop 1 (OT Industrial PC / Sender)
1. **Verify TCP 445 connectivity to Laptop 2:**
   ```powershell
   Test-NetConnection -ComputerName <LAPTOP2_IP> -Port 445
   ```
   Confirm `TcpTestSucceeded : True`.
2. **Authenticate the Windows SMB session to Laptop 2:**
   ```powershell
   net use \\<LAPTOP2_IP>\IndustrialIncoming /user:<LAPTOP2_IP>\ist_transfer SmbPocPass2026!
   net use \\<LAPTOP2_IP>\IndustrialReceipts /user:<LAPTOP2_IP>\ist_transfer SmbPocPass2026!
   ```
   Verify Windows negotiated **SMB 3.1.1** with **Encrypted = True**:
   ```powershell
   dir \\<LAPTOP2_IP>\IndustrialIncoming | Out-Null
   Get-SmbConnection | Select-Object ServerName,ShareName,Dialect,Signed,Encrypted
   ```
   You should see `Dialect : 3.1.1` and `Encrypted : True`.

---

## 2. Step-by-Step POC Execution

### Step 1: Provision Cryptographic Keys & Signed Configs
On Laptop 1 (inside `C:\Industrial-Data-Transfer`), run [`provision_smb_poc.py`](file:///c:/Users/LENOVO/OneDrive%20-%20BizTranSights%20Solutions,%20LLP/Industrial-Data-Transfer/provision_smb_poc.py) replacing `<LAPTOP2_IP>` with Laptop 2's actual IP address:

```powershell
& "C:\Users\LENOVO\AppData\Local\Programs\Python\Python314\python.exe" provision_smb_poc.py `
    --server-host <LAPTOP2_IP> `
    --source-dir "C:\IST_POC\SourceDataset" `
    --server-base-dir "C:\IST_POC_Server" `
    --out-dir ".\poc_bundle"
```
This creates two separate trust-boundary folders:
- `.\poc_bundle\laptop1_part_a_config\` → Keep on **Laptop 1** (contains **no** server decryption keys).
- `.\poc_bundle\laptop2_part_c_config\` → Copy to **Laptop 2** (e.g., `C:\IST_POC_Server\config\`).

### Step 2: Prepare Sample OT Source Dataset on Laptop 1
Create a read-only style test dataset with a completion marker (`_DATASET_READY.marker`), measurement CSV, compressed image, and shapefile group:

```powershell
New-Item -ItemType Directory -Force "C:\IST_POC\SourceDataset\Measurements"
New-Item -ItemType Directory -Force "C:\IST_POC\SourceDataset\Geospatial"
Set-Content -Path "C:\IST_POC\SourceDataset\_DATASET_READY.marker" -Value "READY"
Set-Content -Path "C:\IST_POC\SourceDataset\Measurements\turbine_run.csv" -Value ("ts,rpm,temp`n2026-11-25T10:00:00Z,1800,48.5`n" * 500)
foreach ($ext in ".shp",".shx",".dbf",".prj") {
    Set-Content -Path "C:\IST_POC\SourceDataset\Geospatial\site_boundary$ext" -Value "SHAPEFILE-$ext-DATA"
}
```
> [!NOTE]
> Wait at least **5 seconds** after creating the files so the active-write stability window (`stability_window_seconds: 5.0`) considers them settled.

### Step 3: Start Part C Ingestion Server Service on Laptop 2
On **Laptop 2**, start the Ingestion Server daemon watching `C:\IST_POC_Server\Incoming`:

```powershell
python industrial_secure_transfer\part_c_server\ingestion_svc.py `
    --config-dir "C:\IST_POC_Server\config" `
    --poll-interval 2.0
```
Leave this terminal running on Laptop 2. It polls every 2 seconds for completed `manifest.signed.json` envelopes.

### Step 4: Launch Part A Exporter UI on Laptop 1 & Transfer
On **Laptop 1**, launch the Part A Exporter desktop application:

```powershell
& "C:\Users\LENOVO\AppData\Local\Programs\Python\Python314\python.exe" `
    industrial_secure_transfer\part_a_exporter\runner.py `
    --config-dir ".\poc_bundle\laptop1_part_a_config"
```

1. **Sign In (`SCR-01`):** Enter `operator.name` / `DemoTransfer2026!` and click **Sign in**.
2. **Automatic Preflight & Transfer (`SCR-03` -> `SCR-04`, `UI-03`):** Because Laptop 1's config has exactly 1 approved SMB job, valid login automatically runs:
   - Source dataset freeze & companion check (`DAT-01`),
   - Live `Get-SmbConnection` check confirming **SMB 3.1.1 + Encrypted = True** (`NET-01`),
   - Bounded-memory `zlib` + **AES-256-GCM** chunk encryption + **create-only (`xb`)** streaming to `\\<LAPTOP2_IP>\IndustrialIncoming`,
   - Destination read-back SHA-256 verification of every chunk, and
   - Publishing `manifest.signed.json` last.
3. **Server Ingestion & Signed Receipt (`SCR-05` -> `SCR-06`):**
   - Laptop 2's Part C service detects `manifest.signed.json`, verifies Laptop 1's Ed25519 signature, decrypts into `C:\IST_POC_Server\Quarantine\`, runs the malware scan hook, verifies SHA-256 hashes, commits immutably to `C:\IST_POC_Server\CommittedRepository\IND-PC-001\...`, and writes `<transferId>.receipt.json` to `C:\IST_POC_Server\Receipts\`.
   - Laptop 1 polls `\\<LAPTOP2_IP>\IndustrialReceipts`, verifies Laptop 2's Ed25519 signature, and transitions the UI to **`SCR-06` (Option 1 — transfer committed)**.

---

## 3. Optional Fault-Injection Tests During the POC
1. **Wi-Fi Drop / Pause-Resume Test (`RES-01`):**
   - Click **Pause** during a larger file transfer (or briefly toggle Wi-Fi off/on). Verify `ETA` shows `Unavailable` while paused/disconnected, no files are deleted or overwritten, and resuming skips already-verified chunks.
2. **Non-Destructive Source Verification (`SAF-01`):**
   - Confirm all files in `C:\IST_POC\SourceDataset` on Laptop 1 remain 100% untouched and byte-identical to `C:\IST_POC_Server\CommittedRepository\...` on Laptop 2.
3. **Incremental Delta Test (`DAT-01`):**
   - Re-run Part A without changing `SourceDataset`: all previously committed files are skipped as `already acknowledged`. Add one new CSV file and re-run: only the new file is encrypted and transferred.

---

## 4. Quick Troubleshooting

| Symptom | Cause | Fix |
| :--- | :--- | :--- |
| `Test-NetConnection -Port 445` fails | Company Wi-Fi AP Client Isolation or Laptop 2 firewall blocking SMB | Enable `File and Printer Sharing` firewall rule on Laptop 2, or use an internal VLAN/router without client isolation |
| `NET-01 Violation: SMB 3.1.1 is required` or `Encrypted=False` | Share created without `-EncryptData $true` or older SMB client | Run `Set-SmbShare -Name IndustrialIncoming -EncryptData $true` and `Set-SmbShare -Name IndustrialReceipts -EncryptData $true` on Laptop 2 |
| `No active Windows SMB sessions returned` | Windows hasn't opened a session yet | Run `net use \\<LAPTOP2_IP>\IndustrialIncoming /user:...` and `dir \\<LAPTOP2_IP>\IndustrialIncoming` on Laptop 1 |
| `Active write detected` / files deferred | Files created < 5 seconds ago | Wait 5 seconds after copying test files into `SourceDataset` |
