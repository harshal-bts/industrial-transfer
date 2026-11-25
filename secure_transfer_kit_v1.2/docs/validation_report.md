# Validation report | v1.2 reference kit

## Checked
- Cross-checked the 26 screen IDs from Section 22 of the Word guide against the 26 individual screen files and included the 14 architecture images and original UI screenshots. The Word document is copied unchanged from v1.2.
- Executed 25 automated unit/reference tests: cryptographic roundtrip (both direct and USB-shaped local-directory paths), corrupt ciphertext, signatures, create-only conflict, symlink rejection, quick write and read-only probes, ZIP stream, receipt binding, hash verification, checkpoint, ETA, authentication example, workflow completion, interruption, pause/resume, preflight failure, rejection and cleanup blocking.
- Ran the Tkinter GUI smoke test with a virtual Linux display: valid/invalid login, all 26 PNG images load, direct network simulation, linked USB export/import/return simulation, history/details and stop/sign-out/re-authentication recovery.
- Actual cleanup remains disabled; no formatting commands are implemented. UI calls to `delete` refer to text widgets only. Test directories contain synthetic files, not production data. Basic symlink checks strengthened in the copy and manifest code, but still subject to OS races; not a security boundary.

## Not verified / release gates
- Physical USB detection, filesystem dirty-bit support, hardware/flash health, real uncached throughput, media replacement, device-level security and USB-only deletion require Windows/Linux native implementation and physical testing.
- Live SMB encryption negotiation, actual UNC/mounted share transfers, ACL enforcement, network resilience and Windows 10 executable builds require facility infrastructure and OEM approval. No production Windows test was performed.
- Actual operator authentication, signed configuration, securely provisioned keys, source completion checks, production incremental file inventory, durable audit/restart checkpoints, malware scanning and server-side transactional commit are not integrated. The synthetic core returns QUARANTINE_VERIFIED, never a production COMMITTED receipt.
- The updated UI simulator uses fixed illustrative sizes and accelerated in-memory work units. It is not a real transfer engine or all 26 separate implemented screens. Restarting the process loses state; the append-only checkpoint example is independent. All cleanup/receipt actions in UI are simulations. The actual signed-receipt validator verifies bindings but cannot establish durability by itself.
- Production must perform independent security review, dependency pinning, OS permission/handle-based enforcement, fail-closed configuration, resource limits and real hardware acceptance tests before deployment. Neither code nor passing synthetic tests guarantees safety on an industrial computer.

See `../test_results.txt` for executable test results.
