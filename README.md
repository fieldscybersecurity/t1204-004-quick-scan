# CLICKFIX℠ Quick Scan Script

**Version 1.0.0**   
**Product of:** Fields Cybersecurity Services, LLC  
**Author:** Grover Fields  
**License:** MIT  

A free, read-only PowerShell script that evaluates your Windows system's defensive posture against copy-paste social engineering and clipboard hijacking attacks (MITRE ATT&CK® T1204.004).

Runs 12 non-invasive checks in under 30 seconds and reports color-coded pass/fail results. No system modifications, no data transmission, no external dependencies.

---

## System Requirements

- **OS:** Windows 10 (21H2 or later) or Windows 11
- **PowerShell:** 5.1 or later (included with Windows)
- **Privileges:** Standard user context (some checks note when admin provides additional detail)
- **Dependencies:** None — pure PowerShell, no modules to install

## Quick Start

1. Download `quickscanscript.ps1` from [clickfix.com/quick-scan](https://clickfix.com/quick-scan/)
2. Open PowerShell
3. Navigate to the download folder:
   ```powershell
   cd "$env:USERPROFILE\Downloads"
   ```
4. Run the script:
   ```powershell
   & '.\quickscanscript.ps1'
   ```
5. Review the color-coded results in your console

### Export Results as JSON

To export results for use with the CLICKFIX℠ Score & Readiness Assessment:

```powershell
& '.\quickscanscript.ps1' -ExportJSON
```

To specify an output directory:

```powershell
& '.\quickscanscript.ps1' -ExportJSON -OutputPath "C:\Reports"
```

The JSON file can be uploaded to the CLICKFIX℠ Score & Readiness Assessment for a comprehensive remediation roadmap.

### Export Results as HTML Report

To generate a branded HTML report:

```powershell
& '.\quickscanscript.ps1' -ExportHTML
```

To specify an output directory:

```powershell
& '.\quickscanscript.ps1' -ExportHTML -OutputPath "C:\Reports"
```

The HTML report includes the CLICKFIX℠ logo, an overall security grade (A–F), color-coded results for all 12 checks, and remediation guidance. The file is self-contained with no external dependencies and can be opened in any browser.

You can combine both export flags:

```powershell
& '.\quickscanscript.ps1' -ExportJSON -ExportHTML
```

## Verify File Integrity

Before running the script, verify its SHA-256 hash matches the value published here:

```
SHA-256: 2BC06D41621B4BD2C3C2F8F674C6627DCF59E5F814D80A411691F2FDBE8F456F
```

To verify in PowerShell:

```powershell
(Get-FileHash '.\quickscanscript.ps1' -Algorithm SHA256).Hash
```

If the hash does not match, do not run the file. Download a fresh copy from [clickfix.com/quick-scan](https://clickfix.com/quick-scan/).

## Execution Policy Note

If Windows blocks the script, the usual cause is the Mark of the Web on a downloaded file, not your execution policy. Clear that first:

```powershell
Unblock-File .\quickscanscript.ps1
```

Then run the script again. This marks the file as trusted locally; it does not change any policy setting.

If you still receive an error, check what your policy is set to before changing anything:

```powershell
Get-ExecutionPolicy -List
```

A policy of `Restricted` blocks all scripts, and only an administrator can change it. `RemoteSigned` and `AllSigned` are the common corporate settings.

As a last resort, you can bypass the policy for this one process only:

```powershell
powershell -ExecutionPolicy Bypass -Scope Process -File .\quickscanscript.ps1
```

`-Scope Process` applies to that one PowerShell session and ends when the window closes. It does not change your system's execution policy. Prefer `Unblock-File`: bypassing a policy is a choice you should make deliberately, not a first step.

---

## What Each Check Evaluates

| # | Check | Kill Chain Phase | What It Looks For |
|---|-------|-----------------|-------------------|
| 1 | **Run Dialog Access (Win+R)** | P3 – Paste Destination | Whether Group Policy restricts the Run dialog, a common target for pasted malicious commands. |
| 2 | **PowerShell Execution Policy** | P4 – Script Execution | Whether the effective execution policy blocks unsigned scripts (Restricted or AllSigned). |
| 3 | **PowerShell Constrained Language Mode** | P4 – Script Execution | Whether PowerShell is running in Constrained Language Mode, which limits dangerous cmdlets and .NET calls. Reported as N/A on Windows Home, which has no AppLocker or App Control policy to enforce it. |
| 4 | **Attack Surface Reduction (ASR) Rules** | P4 – Script Execution | Whether key ASR rules are enabled in block mode (Office child processes, executable content, script launches). |
| 5 | **Browser Enterprise Policies** | P1–P2 – Lure/Clipboard | Whether Chrome, Edge, or Firefox enterprise management policies are deployed. |
| 6 | **Windows Defender SmartScreen** | P4 – Script Execution | Whether SmartScreen is active to warn about unrecognized downloaded executables. |
| 7 | **Script Host Access (wscript/cscript)** | P4 – Script Execution | Whether Windows Script Host executables are blocked by ASR rules or application control. |
| 8 | **Mark of the Web (MOTW)** | P4 – Script Execution | Whether downloaded files retain their zone identifier, which triggers security prompts. |
| 9 | **VBA Macro Execution Policy** | P4 – Script Execution | Whether Office macro execution is restricted by policy (disabled or signature-only). |
| 10 | **Startup Folder Monitoring** | P5 – Persistence | Whether startup folders contain items and whether file system auditing is enabled to detect persistence. |
| 11 | **PowerShell Logging & Transcription** | P4 – Script Execution | Whether Script Block Logging, Module Logging, and Transcription are enabled for forensic visibility. |
| 12 | **Command-Line Process Auditing** | P4 – Script Execution | Whether process creation events capture the full command line (Event ID 4688). |

## Understanding the Results

- **PASS** (green): The defensive control is active and properly configured.
- **FAIL** (red): The control is missing or misconfigured. A remediation suggestion is provided.
- **MANUAL CHECK** (yellow): The control requires human review to confirm its configuration.
- **N/A** (grey): The check cannot be expressed on this edition of Windows and is excluded from the grade. On Windows Home that is currently PowerShell Constrained Language Mode only, because the edition has no AppLocker or App Control policy to enforce it.

The console summary and the HTML report both print the overall grade, and both use the same calculation.

## Kill Chain Phases

The Quick Scan Script covers phases P1 through P5 of the copy-paste attack kill chain:

- **P1** – Lure Delivery: Browser-based fake CAPTCHA or error overlays
- **P2** – Clipboard Write: JavaScript clipboard injection
- **P3** – Paste Destination: Windows Run dialog, PowerShell, cmd.exe
- **P4** – Script Execution: PowerShell, mshta, curl, bitsadmin payloads
- **P5** – Persistence: Registry run keys, scheduled tasks, startup folder drops

## JSON Export Schema

When using the `-ExportJSON` flag, the output file contains:

- **scanMetadata**: Host details, scan timestamp, script version, Windows edition
- **summary**: Total checks, pass/fail/manual counts, not-applicable count, and the number of applicable checks
- **results**: Array of all 12 check results with status, detail, kill chain phase, and remediation
- **nextStep**: Link to the CLICKFIX℠ Score & Readiness Assessment

## HTML Report

When using the `-ExportHTML` flag, the script generates a self-contained HTML file named `quick-scan-<hostname>-<timestamp>.html` that includes:

- CLICKFIX℠ logo and branding
- Overall security grade (A–F) from the failed-check count, with N/A checks excluded — A: no failures and no manual checks, B: no failures, C: 1–3 failures, D: 4–6, F: 7 or more
- System metadata (hostname, OS version, PowerShell version, scan timestamp)
- Color-coded results table with remediation guidance for each check
- Link to the CLICKFIX℠ Score & Readiness Assessment

The file has no external dependencies and can be viewed in any modern browser or attached to a report.

---

## Safety & Trust

The Quick Scan Script is **strictly read-only**:

- Makes zero registry writes
- Makes zero policy changes
- Modifies no existing files (report files are created only when you use `-ExportJSON` or `-ExportHTML`)
- Transmits zero data over the network
- Has zero external dependencies
- Requires zero installation

You can review every line of the script before running it. It is a single `.ps1` file with no obfuscation.

## Disclaimer

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL FIELDS CYBERSECURITY SERVICES, LLC, GROVER FIELDS, ITS OFFICERS, DIRECTORS, EMPLOYEES, OR AGENTS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

This script performs read-only checks and makes no modifications to your system, registry, files, or network configuration. It transmits no data over the network. Users are responsible for reviewing the script and evaluating its suitability for their environment before execution.

By downloading or executing this script, you accept the [Terms of Service](https://clickfix.com/legal/terms/) and the terms of the [MIT License](https://opensource.org/licenses/MIT) under which this software is distributed.

## Want a Comprehensive Assessment?

The Quick Scan Script provides a quick posture check. For a full assessment with a prioritized remediation roadmap, try the **CLICKFIX℠ Score & Readiness Assessment** at [clickfix.com/assessment](https://clickfix.com/assessment).

---

## Notice

CLICKFIX℠ is a service mark of Grover Fields, used under license by Fields Cybersecurity Services, LLC (ClickFix.com), and is not affiliated with the copy-paste social engineering technique (MITRE ATT&CK® T1204.004). All rights reserved. Fields Cybersecurity Services, LLC provides defensive cybersecurity consultation, education and advisory services and has no connection with any malware campaign or threat actor.

## Trademarks

The CLICKFIX℠ name and any related logos are identified in the Notice above. The MIT License that covers this software does not grant any right to use them. Modified or redistributed versions of this software must not use the CLICKFIX℠ name or branding in a way that causes confusion or suggests they are published, endorsed or sponsored by Grover Fields or Fields Cybersecurity Services, LLC.

MITRE ATT&CK® is a registered trademark of The MITRE Corporation. This project uses the ATT&CK identifier to describe the technique it assesses, and is not affiliated with, endorsed by or sponsored by MITRE.

Windows, PowerShell, Microsoft Defender, Chrome, Edge, Firefox and other third-party names are the property of their respective owners and are used only to describe what the script checks. This project is not affiliated with them.

## Contact

- **Website:** [clickfix.com](https://clickfix.com)
- **Company:** Fields Cybersecurity Services, LLC

---

Copyright © 2026 Fields Cybersecurity Services, LLC. Licensed under the MIT License.
