# 🏗️ PROJECT TITAN: ARCHITECTURAL BRIEFING & ROADMAP

## 1. Executive Summary
We are evolving the existing "Titan Verifier & Spoofer" (Android Native/Kotlin) into a fully automated **Identity Orchestration Platform**.
You have access to the client-side code (the Android App/Zygisk Module). Your task is to build the **Host-Side Orchestrator** (Python) that controls this device, manages identities, and provides a modern Web Interface.

**Core Goal:** Create a robust system to manage 1000+ distinct, organic-looking O2 Germany identities on a Pixel 6, automated via ADB, without relying on UI interactions (No coordinates, no accessibility services).

---

## 2. The Tech Stack (Target Architecture)
- **Host Backend:** Python 3.12 + FastAPI (Async REST API).
- **Host Frontend:** Modern Web UI (React/Next.js or Jinja2 + TailwindCSS/HTMX) for dashboarding.
- **Database:** SQLite (`titan.db`) with atomic transaction support.
- **Device Bridge:** Direct file manipulation of `/data/adb/titan/identity` via ADB Root.
- **Data Streaming:** Binary `tar` piping for app-data backup/restore.

---

## 3. Component Specifications

### A. The Identity Engine (Generator Logic)
We must generate consistent "Hardware DNA" for a **Google Pixel 6 (oriole)** operating on **O2 Germany**.
*Constraint:* Random generation is forbidden. Use these strict rules:
1.  **Telephony:**
    -   `SIM_OPERATOR`: "26207" (MCC 262, MNC 07).
    -   `IMSI`: Must start with `26207...` (Total 15 digits).
    -   `ICCID`: Must start with `894922...` (O2 DE Prefix).
    -   `PHONE`: Format `+49176...`.
2.  **Hardware Identifiers:**
    -   `IMEI`: Must satisfy Luhn-Checksum algorithm.
    -   `TAC`: Must begin with `355543` (Pixel 6 identifier).
    -   `Widevine ID`: 32-char Hex string (Required for DRM trust).
3.  **Environment:**
    -   `LOCALE`: "de-DE".
    -   `TIMEZONE`: "Europe/Berlin".

### B. The Shifter (Storage & Backup Controller)
Responsible for swapping app states (TikTok) atomically.
*Legacy Logic Port:* We port the logic from our old "Ares" system but remove UI dependencies.
1.  **Backup:** Stream `/data/data/com.zhiliaoapp.musically` via `tar` directly to the host.
2.  **Restore:** Stream `tar` back to device.
3.  **CRITICAL FIX - Magic Permissions:**
    -   After restore, you MUST query the UID of the app (`stat -c '%u' ...`).
    -   You MUST execute `chown -R UID:UID` on the restored folder immediately.
    -   *Do not use `restorecon` unless as a desperate fallback (causes bootloops on Android 14).*

### C. The Orchestrator Flows (Automation Logic)
The backend must implement these exact state machines:

#### FLOW 1: GENESIS (Cold Start / New Account)
1.  **Sterilize:** `pm clear` TikTok **AND** `pm clear com.google.android.gms` (Google Play Services) to kill tracking tokens.
2.  **Generate:** Create new O2-compliant Identity -> Write to DB -> Write to Bridge File.
3.  **Hard Reset:** Trigger `adb reboot`. (Mandatory to reset GMS/HAL caching).
4.  **Network Init:** Wait for boot -> Airplane Mode ON (12s wait for Lease) -> Airplane Mode OFF.
5.  **Audit:** Execute Native Shell Check (verify `ro.serialno` matches DB).

#### FLOW 2: SWITCH (Warm Switch / Existing Profile)
1.  **Pre-Kill:** `am force-stop com.google.android.gms` (Prevent ID leakage).
2.  **Inject:** Update Bridge File with target identity.
3.  **Restore:** Stream `app_data.tar` + Magic Permission Fix.
4.  **Soft Reset:** `killall zygote` (Fast Framework Restart).
5.  **Validation:** Verify Native Props match.

---

## 4. The Web Command Center (UI Requirements)
We need a "Mission Control" dashboard, not a CLI tool.
1.  **Dashboard:** Live view of connected device (ADB Status), Current Identity (Serial/IP), and Audit Score (10/10).
2.  **The Vault (Account Manager):** DataGrid view of all profiles.
    -   Columns: Name, Status (Active/Banned/Warmup), Proxy-IP, Notes.
    -   Actions: Edit Credentials (Username/Pass/Email), View History.
3.  **Control Panel:** Big Buttons for [GENESIS], [SWITCH], [DEEP CLEAN].

---

## 5. Security & Robustness Protocols
1.  **Input Device spoofing:** The Python script monitors `/proc/bus/input/devices`. If empty, it flags a "Hardware Leak" error (The Native Zygisk module is responsible for fixing this, Python just audits it).
2.  **DNS Leak Protection:** IP Checks (`icanhazip.com`) must perform DNS resolution on the *Host PC*, then curl the IP directly on Android to bypass local DNS sniffing.
3.  **Atomicity:** If `adb` disconnects during a `tar` stream, the profile is marked "CORRUPTED" in the DB to prevent partial data loading.

---

## 6. Implementation Directive
**Phase 1:** Setup Python environment, FastAPI structure, and SQLite Database (migrated schema).
**Phase 2:** Implement the `TitanInjector` and `TitanShifter` classes based on the rules above.
**Phase 3:** Build the API Endpoints for the Flows.
**Phase 4:** Build the React/Web Frontend.
