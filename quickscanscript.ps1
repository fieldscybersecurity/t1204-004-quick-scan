<#
.SYNOPSIS
    Quick Scan Script - Copy-Paste Attack Posture Assessment

.DESCRIPTION
    A free, read-only PowerShell script that evaluates your Windows system's
    defensive posture against copy-paste social engineering and clipboard
    hijacking attacks (MITRE ATT&CK T1204.004).

    Runs 12 non-invasive checks and reports pass/fail results. No system
    modifications, no data transmission, no external dependencies.

    Product of Fields Cybersecurity Services, LLC
    ClickFix℠ is a service mark of Grover Fields, used under license by Fields Cybersecurity Services, LLC.

.PARAMETER ExportJSON
    Export scan results as a JSON file for integration with the
    ClickFix℠ Score & Readiness Assessment.

.PARAMETER ExportHTML
    Export scan results as a branded HTML report file named after the hostname.

.PARAMETER OutputPath
    Directory for the JSON and/or HTML export files. Defaults to the current directory.

.EXAMPLE
    '.\quickscanscript.ps1'
    Runs the quick scan and displays results in the console.

.EXAMPLE
    '.\quickscanscript.ps1' -ExportHTML
    Runs the quick scan and exports a branded HTML report.

.EXAMPLE
    '.\quickscanscript.ps1' -ExportJSON -ExportHTML
    Runs the quick scan and exports both JSON and HTML reports.

.EXAMPLE
    '.\quickscanscript.ps1' -ExportHTML -OutputPath "C:\Reports"
    Runs the quick scan and exports the HTML report to a specified directory.

.NOTES
    Version:        1.0.0
    Author:         Grover Fields
    Copyright:      (c) 2026 Fields Cybersecurity Services, LLC. All rights reserved.
    License:        MIT
    Requirements:   Windows 10 21H2+ or Windows 11, PowerShell 5.1+
    Kill Chain:     P1-P5 (read-only posture checks)

.LINK
    https://clickfix.com/quick-scan/

.DISCLAIMER
    THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
    FIELDS CYBERSECURITY SERVICES, LLC, ITS OFFICERS, DIRECTORS, EMPLOYEES,
    OR AGENTS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY, WHETHER IN
    AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OUT OF, OR IN
    CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

    This script performs read-only checks and makes no modifications to your
    system, registry, files, or network configuration. It transmits no data
    over the network. Users are responsible for reviewing the script and
    evaluating its suitability for their environment before execution.

    Use of this script constitutes acceptance of the MIT License terms and
    this disclaimer. See https://clickfix.com/legal/terms/ for full terms of use.
#>

[CmdletBinding()]
param(
    [switch]$ExportJSON,
    [switch]$ExportHTML,
    [string]$OutputPath = (Get-Location).Path
)

# Sanitize -OutputPath: strip stray quotes and trailing backslashes
# (a trailing \" on the command line otherwise leaks a literal " into the path)
$OutputPath = $OutputPath.Trim().Trim('"').TrimEnd('\')
if (-not $OutputPath) { $OutputPath = (Get-Location).Path }

# ============================================================================
# CONFIGURATION
# ============================================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

# Ensure the console renders Unicode characters (e.g. ℠) correctly
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding           = [System.Text.Encoding]::UTF8

$Script:Version = "1.0.0"
$Script:ScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$Script:Hostname = $env:COMPUTERNAME
$Script:Username = $env:USERNAME
$Script:IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$Script:OSVersion = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
$Script:PSVersion = $PSVersionTable.PSVersion.ToString()

# Results collection
$Script:Results = @()
$Script:PassCount = 0
$Script:FailCount = 0
$Script:ManualCount = 0
$Script:CheckNumber = 0
$Script:TotalChecks = 12

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Write-Banner {
    $banner = @"

    ============================================================
      Quick Scan Script  v$($Script:Version)
      Copy-Paste Attack Posture Assessment
    ============================================================
      Host:       $($Script:Hostname)
      User:       $($Script:Username)
      Admin:      $($Script:IsAdmin)
      OS:         $($Script:OSVersion)
      PowerShell: $($Script:PSVersion)
      Scan Date:  $($Script:ScanDate)
    ============================================================

"@
    Write-Host $banner -ForegroundColor Cyan
}

function Add-CheckResult {
    param(
        [string]$CheckName,
        [string]$Description,
        [ValidateSet("PASS","FAIL","MANUAL CHECK")]
        [string]$Status,
        [string]$Detail,
        [string]$KillChainPhase,
        [string]$Remediation = ""
    )

    $Script:CheckNumber++

    $color = switch ($Status) {
        "PASS"          { "Green" }
        "FAIL"          { "Red" }
        "MANUAL CHECK"  { "Yellow" }
    }

    $icon = switch ($Status) {
        "PASS"          { "[PASS]" }
        "FAIL"          { "[FAIL]" }
        "MANUAL CHECK"  { "[CHECK]" }
    }

    switch ($Status) {
        "PASS"          { $Script:PassCount++ }
        "FAIL"          { $Script:FailCount++ }
        "MANUAL CHECK"  { $Script:ManualCount++ }
    }

    $checkLabel = "  [$($Script:CheckNumber)/$($Script:TotalChecks)]"
    Write-Host "$checkLabel " -NoNewline -ForegroundColor White
    Write-Host "$icon " -NoNewline -ForegroundColor $color
    Write-Host "$CheckName" -ForegroundColor $color
    Write-Host "          $Detail" -ForegroundColor Gray
    if ($Status -eq "FAIL" -and $Remediation) {
        Write-Host "          Remediation: $Remediation" -ForegroundColor DarkYellow
    }
    Write-Host ""

    $Script:Results += [PSCustomObject]@{
        CheckNumber    = $Script:CheckNumber
        CheckName      = $CheckName
        Description    = $Description
        Status         = $Status
        Detail         = $Detail
        KillChainPhase = $KillChainPhase
        Remediation    = $Remediation
        RequiresAdmin  = $false
    }
}

function Test-RegistryValue {
    param(
        [string]$Path,
        [string]$Name
    )
    try {
        $val = Get-ItemPropertyValue -Path $Path -Name $Name -ErrorAction Stop
        return $val
    } catch {
        return $null
    }
}

# ============================================================================
# SCAN CHECKS
# ============================================================================

function Test-RunDialogAccess {
    <# CHECK 1: Is the Run dialog (Win+R) restricted via Group Policy?
       Kill Chain Phase: P3 (Paste Destination) #>

    $noRun = Test-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRun"
    $noRunMachine = Test-RegistryValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRun"

    if ($noRun -eq 1 -or $noRunMachine -eq 1) {
        Add-CheckResult -CheckName "Run Dialog Access (Win+R)" `
            -Description "Checks if the Run dialog is restricted via Group Policy" `
            -Status "PASS" `
            -Detail "Run dialog is BLOCKED by Group Policy. Users cannot paste commands into Win+R." `
            -KillChainPhase "P3"
    } else {
        Add-CheckResult -CheckName "Run Dialog Access (Win+R)" `
            -Description "Checks if the Run dialog is restricted via Group Policy" `
            -Status "FAIL" `
            -Detail "Run dialog is OPEN. Attackers can instruct victims to paste malicious commands via Win+R." `
            -KillChainPhase "P3" `
            -Remediation "Set HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoRun = 1 via GPO."
    }
}

function Test-PowerShellExecutionPolicy {
    <# CHECK 2: Is the PowerShell execution policy restrictive?
       Kill Chain Phase: P4 (Script Execution) #>

    $policy = Get-ExecutionPolicy -Scope LocalMachine
    $userPolicy = Get-ExecutionPolicy -Scope CurrentUser
    $effectivePolicy = Get-ExecutionPolicy

    $restrictive = @("Restricted", "AllSigned")

    if ($effectivePolicy -in $restrictive) {
        Add-CheckResult -CheckName "PowerShell Execution Policy" `
            -Description "Checks if PowerShell execution policy blocks unsigned scripts" `
            -Status "PASS" `
            -Detail "Effective policy is '$effectivePolicy'. Unsigned scripts are blocked." `
            -KillChainPhase "P4"
    } else {
        Add-CheckResult -CheckName "PowerShell Execution Policy" `
            -Description "Checks if PowerShell execution policy blocks unsigned scripts" `
            -Status "FAIL" `
            -Detail "Effective policy is '$effectivePolicy'. Pasted PowerShell commands can execute freely." `
            -KillChainPhase "P4" `
            -Remediation "Set execution policy to 'AllSigned' or 'Restricted' via GPO: Set-ExecutionPolicy AllSigned -Scope LocalMachine"
    }
}

function Test-ConstrainedLanguageMode {
    <# CHECK 3: Is PowerShell Constrained Language Mode enforced?
       Kill Chain Phase: P4 (Script Execution) #>

    $langMode = $ExecutionContext.SessionState.LanguageMode

    if ($langMode -eq "ConstrainedLanguage") {
        Add-CheckResult -CheckName "PowerShell Constrained Language Mode" `
            -Description "Checks if PowerShell is running in Constrained Language Mode" `
            -Status "PASS" `
            -Detail "Language mode is '$langMode'. Dangerous cmdlets and .NET calls are restricted." `
            -KillChainPhase "P4"
    } elseif ($langMode -eq "FullLanguage") {
        Add-CheckResult -CheckName "PowerShell Constrained Language Mode" `
            -Description "Checks if PowerShell is running in Constrained Language Mode" `
            -Status "FAIL" `
            -Detail "Language mode is '$langMode'. All PowerShell capabilities are available to pasted commands." `
            -KillChainPhase "P4" `
            -Remediation "Deploy WDAC/AppLocker policies to enforce Constrained Language Mode."
    } else {
        Add-CheckResult -CheckName "PowerShell Constrained Language Mode" `
            -Description "Checks if PowerShell is running in Constrained Language Mode" `
            -Status "MANUAL CHECK" `
            -Detail "Language mode is '$langMode'. Review whether this mode is appropriate for your environment." `
            -KillChainPhase "P4"
    }
}

function Test-ASRRules {
    <# CHECK 4: Are relevant Attack Surface Reduction rules enabled?
       Kill Chain Phase: P4 (Script Execution) #>

    # ASR rule GUIDs relevant to copy-paste attacks
    $asrRules = @{
        "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = "Block all Office applications from creating child processes"
        "3b576869-a4ec-4529-8536-b80a7769e899" = "Block Office applications from creating executable content"
        "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = "Block executable content from email client and webmail"
        "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" = "Block Win32 API calls from Office macros"
        "56a863a9-875e-4185-98a7-b882c64b5ce5" = "Block abuse of exploited vulnerable signed drivers"
        "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = "Block Adobe Reader from creating child processes"
        "d3e037e1-3eb8-44c8-a917-57927947596d" = "Block JavaScript or VBScript from launching downloaded executable content"
        "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = "Block untrusted and unsigned processes that run from USB"
    }

    try {
        $mpPreference = Get-MpPreference -ErrorAction Stop
        $enabledIds = @($mpPreference.AttackSurfaceReductionRules_Ids)
        $enabledActions = @($mpPreference.AttackSurfaceReductionRules_Actions)
        $enabledCount = 0

        if ($enabledIds -and $enabledActions) {
            for ($i = 0; $i -lt $enabledIds.Count; $i++) {
                $ruleId = $enabledIds[$i].ToLower()
                if ($asrRules.ContainsKey($ruleId) -and $enabledActions[$i] -eq 1) {
                    $enabledCount++
                }
            }
        }

        if ($enabledCount -ge 4) {
            Add-CheckResult -CheckName "Attack Surface Reduction (ASR) Rules" `
                -Description "Checks if key ASR rules are enabled in block mode" `
                -Status "PASS" `
                -Detail "$enabledCount of $($asrRules.Count) relevant ASR rules are enabled in block mode." `
                -KillChainPhase "P4"
        } elseif ($enabledCount -gt 0) {
            Add-CheckResult -CheckName "Attack Surface Reduction (ASR) Rules" `
                -Description "Checks if key ASR rules are enabled in block mode" `
                -Status "MANUAL CHECK" `
                -Detail "Only $enabledCount of $($asrRules.Count) relevant ASR rules are enabled. Partial coverage." `
                -KillChainPhase "P4" `
                -Remediation "Enable all relevant ASR rules via Intune or GPO. Start in audit mode before blocking."
        } else {
            Add-CheckResult -CheckName "Attack Surface Reduction (ASR) Rules" `
                -Description "Checks if key ASR rules are enabled in block mode" `
                -Status "FAIL" `
                -Detail "No relevant ASR rules are enabled. Office and script-based attack vectors are unprotected." `
                -KillChainPhase "P4" `
                -Remediation "Enable ASR rules via Intune or GPO. Start in audit mode (action=2) then move to block (action=1)."
        }
    } catch {
        Add-CheckResult -CheckName "Attack Surface Reduction (ASR) Rules" `
            -Description "Checks if key ASR rules are enabled in block mode" `
            -Status "MANUAL CHECK" `
            -Detail "Unable to query ASR rules. Windows Defender may not be the active AV, or this requires admin rights." `
            -KillChainPhase "P4"
        $Script:Results[-1].RequiresAdmin = $true
    }
}

function Test-BrowserEnterprisePolicies {
    <# CHECK 5: Are browser enterprise policies configured for clipboard protection?
       Kill Chain Phase: P1-P2 (Lure Delivery / Clipboard Write) #>

    $policiesFound = @()

    # Check Chrome enterprise policies
    $chromePolPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
    if (Test-Path $chromePolPath) {
        $policiesFound += "Chrome enterprise policies detected"
    }

    # Check Edge enterprise policies
    $edgePolPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    if (Test-Path $edgePolPath) {
        $policiesFound += "Edge enterprise policies detected"

        # Check for specific clipboard/paste-related policies
        $clipboardBlocked = Test-RegistryValue -Path $edgePolPath -Name "DefaultClipboardSetting"
        if ($clipboardBlocked) {
            $policiesFound += "Edge clipboard policy configured (value: $clipboardBlocked)"
        }
    }

    # Check Firefox enterprise policies
    $firefoxPolPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"
    if (Test-Path $firefoxPolPath) {
        $policiesFound += "Firefox enterprise policies detected"
    }

    if ($policiesFound.Count -gt 0) {
        Add-CheckResult -CheckName "Browser Enterprise Policies" `
            -Description "Checks if browser enterprise policies are configured" `
            -Status "PASS" `
            -Detail "Browser policies detected: $($policiesFound -join '; ')." `
            -KillChainPhase "P1-P2"
    } else {
        Add-CheckResult -CheckName "Browser Enterprise Policies" `
            -Description "Checks if browser enterprise policies are configured" `
            -Status "FAIL" `
            -Detail "No browser enterprise policies found. Browsers are running with default (unmanaged) settings." `
            -KillChainPhase "P1-P2" `
            -Remediation "Deploy Chrome/Edge/Firefox enterprise policies via GPO or Intune to control browser behavior."
    }
}

function Test-SmartScreen {
    <# CHECK 6: Is Windows Defender SmartScreen enabled?
       Kill Chain Phase: P4 (Script Execution) #>

    $smartScreenReg = Test-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled"
    $smartScreenPolicy = Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen"

    $isEnabled = $false
    if ($smartScreenReg -and $smartScreenReg -ne "Off") {
        $isEnabled = $true
    }
    if ($smartScreenPolicy -eq 1 -or $smartScreenPolicy -eq 2) {
        $isEnabled = $true
    }
    # If neither registry value exists, SmartScreen defaults to enabled on modern Windows
    if ($null -eq $smartScreenReg -and $null -eq $smartScreenPolicy) {
        $isEnabled = $true
    }

    if ($isEnabled) {
        $detail = "SmartScreen is enabled"
        if ($smartScreenReg) { $detail += " (Explorer: $smartScreenReg)" }
        if ($smartScreenPolicy) { $detail += " (Policy: $smartScreenPolicy)" }
        Add-CheckResult -CheckName "Windows Defender SmartScreen" `
            -Description "Checks if SmartScreen is enabled to warn about unrecognized executables" `
            -Status "PASS" `
            -Detail "$detail. Downloaded executables will be screened." `
            -KillChainPhase "P4"
    } else {
        Add-CheckResult -CheckName "Windows Defender SmartScreen" `
            -Description "Checks if SmartScreen is enabled to warn about unrecognized executables" `
            -Status "FAIL" `
            -Detail "SmartScreen is DISABLED. Downloaded executables will not be checked for reputation." `
            -KillChainPhase "P4" `
            -Remediation "Enable SmartScreen via GPO: Computer Config > Admin Templates > Windows Components > Windows Defender SmartScreen."
    }
}

function Test-ScriptHostAccess {
    <# CHECK 7: Are wscript.exe and cscript.exe blocked?
       Kill Chain Phase: P4 (Script Execution) #>

    $wscriptBlocked = $false
    $cscriptBlocked = $false

    # Check Software Restriction Policies / AppLocker for script host blocks
    $srpPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers"
    $applockerPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2"

    # Check if WDAC or AppLocker policies exist
    $hasApplocker = Test-Path $applockerPath
    $hasSRP = Test-Path $srpPath

    # Also check if the executables exist and are accessible
    $wscriptExists = Test-Path "$env:SystemRoot\System32\wscript.exe"
    $cscriptExists = Test-Path "$env:SystemRoot\System32\cscript.exe"

    # Check for Defender ASR rule that blocks script hosts
    try {
        $mpPref = Get-MpPreference -ErrorAction Stop
        if ($mpPref.AttackSurfaceReductionRules_Ids) {
            # Rule for blocking JS/VBS from launching executables
            $scriptBlockRule = "d3e037e1-3eb8-44c8-a917-57927947596d"
            $idx = [Array]::IndexOf($mpPref.AttackSurfaceReductionRules_Ids.ToLower(), $scriptBlockRule)
            if ($idx -ge 0 -and $mpPref.AttackSurfaceReductionRules_Actions[$idx] -eq 1) {
                $wscriptBlocked = $true
                $cscriptBlocked = $true
            }
        }
    } catch { }

    if ($wscriptBlocked -and $cscriptBlocked) {
        Add-CheckResult -CheckName "Script Host Access (wscript/cscript)" `
            -Description "Checks if Windows Script Host executables are blocked" `
            -Status "PASS" `
            -Detail "Script host execution is blocked by ASR rules or application control policies." `
            -KillChainPhase "P4"
    } elseif ($hasApplocker -or $hasSRP) {
        Add-CheckResult -CheckName "Script Host Access (wscript/cscript)" `
            -Description "Checks if Windows Script Host executables are blocked" `
            -Status "MANUAL CHECK" `
            -Detail "Application control policies exist (AppLocker/SRP). Verify they block wscript.exe and cscript.exe." `
            -KillChainPhase "P4" `
            -Remediation "Add AppLocker or WDAC rules to block wscript.exe and cscript.exe for standard users."
    } else {
        Add-CheckResult -CheckName "Script Host Access (wscript/cscript)" `
            -Description "Checks if Windows Script Host executables are blocked" `
            -Status "FAIL" `
            -Detail "wscript.exe and cscript.exe are accessible. VBScript/JScript payloads can execute." `
            -KillChainPhase "P4" `
            -Remediation "Block wscript.exe and cscript.exe via AppLocker, WDAC, or ASR rules."
    }
}

function Test-MarkOfTheWeb {
    <# CHECK 8: Is Mark of the Web (MOTW) preserved on downloads?
       Kill Chain Phase: P4 (Script Execution) #>

    # Check if Zone.Identifier ADS is being stripped by policy
    $saveZoneInfo = Test-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation"
    $saveZoneInfoMachine = Test-RegistryValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation"

    # Value of 1 = do not preserve zone information (bad)
    # Value of 2 = preserve zone information (good / default)
    $motwDisabled = ($saveZoneInfo -eq 1) -or ($saveZoneInfoMachine -eq 1)

    if (-not $motwDisabled) {
        Add-CheckResult -CheckName "Mark of the Web (MOTW) Preservation" `
            -Description "Checks if downloaded files retain their zone identifier" `
            -Status "PASS" `
            -Detail "MOTW is preserved. Downloaded files will trigger SmartScreen and Protected View." `
            -KillChainPhase "P4"
    } else {
        Add-CheckResult -CheckName "Mark of the Web (MOTW) Preservation" `
            -Description "Checks if downloaded files retain their zone identifier" `
            -Status "FAIL" `
            -Detail "MOTW stripping is enabled by policy. Downloaded files will NOT trigger security warnings." `
            -KillChainPhase "P4" `
            -Remediation "Remove the SaveZoneInformation=1 policy or set to 2 to preserve MOTW on downloaded files."
    }
}

function Test-MacroExecutionPolicy {
    <# CHECK 9: Is VBA macro execution restricted?
       Kill Chain Phase: P4 (Script Execution) #>

    $officeVersions = @("16.0", "15.0")
    $officeApps = @("Word", "Excel", "PowerPoint")
    $macroBlocked = $false
    $macroPoliciesFound = @()

    foreach ($ver in $officeVersions) {
        foreach ($app in $officeApps) {
            $regPath = "HKCU:\Software\Policies\Microsoft\Office\$ver\$app\Security"
            $vbaWarnings = Test-RegistryValue -Path $regPath -Name "VBAWarnings"
            if ($null -ne $vbaWarnings) {
                $macroPoliciesFound += "$app $ver = $vbaWarnings"
                # 4 = disable all macros without notification
                # 3 = disable all except digitally signed
                if ($vbaWarnings -ge 3) {
                    $macroBlocked = $true
                }
            }
        }
    }

    # Also check the Trust Center settings for current user
    $blockInternetMacros = Test-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Security" -Name "BlockContentExecutionFromInternet"

    if ($blockInternetMacros -eq 1) {
        $macroBlocked = $true
        $macroPoliciesFound += "BlockContentExecutionFromInternet = 1"
    }

    if ($macroBlocked) {
        Add-CheckResult -CheckName "VBA Macro Execution Policy" `
            -Description "Checks if Office macro execution is restricted" `
            -Status "PASS" `
            -Detail "Macro restrictions detected: $($macroPoliciesFound -join '; ')." `
            -KillChainPhase "P4"
    } elseif ($macroPoliciesFound.Count -gt 0) {
        Add-CheckResult -CheckName "VBA Macro Execution Policy" `
            -Description "Checks if Office macro execution is restricted" `
            -Status "MANUAL CHECK" `
            -Detail "Macro policies found but may not fully block execution: $($macroPoliciesFound -join '; ')." `
            -KillChainPhase "P4" `
            -Remediation "Set VBAWarnings to 4 (disable all) or 3 (signed only) via GPO for all Office apps."
    } else {
        Add-CheckResult -CheckName "VBA Macro Execution Policy" `
            -Description "Checks if Office macro execution is restricted" `
            -Status "FAIL" `
            -Detail "No macro restriction policies found. Office defaults may allow macro execution." `
            -KillChainPhase "P4" `
            -Remediation "Deploy GPO to set VBAWarnings=4 for Word, Excel, PowerPoint. Enable 'Block macros from Internet'."
    }
}

function Test-StartupFolderMonitoring {
    <# CHECK 10: Are startup folder items audited?
       Kill Chain Phase: P5 (Persistence) #>

    $startupUser = [System.IO.Path]::Combine($env:APPDATA, "Microsoft\Windows\Start Menu\Programs\Startup")
    $startupAllUsers = [System.IO.Path]::Combine($env:ProgramData, "Microsoft\Windows\Start Menu\Programs\Startup")

    $userItems = @()
    $allUsersItems = @()

    if (Test-Path $startupUser) {
        $userItems = @(Get-ChildItem -Path $startupUser -File -ErrorAction SilentlyContinue)
    }
    if (Test-Path $startupAllUsers) {
        $allUsersItems = @(Get-ChildItem -Path $startupAllUsers -File -ErrorAction SilentlyContinue)
    }

    $totalItems = $userItems.Count + $allUsersItems.Count

    # Check if audit policy exists for object access (indicates monitoring)
    $auditEnabled = $false
    try {
        $auditPol = auditpol /get /subcategory:"File System" 2>$null
        if ($auditPol -match "Success|Failure|Erfolg|Succès|Éxito|Exito|成功") {
            $auditEnabled = $true
        }
    } catch { }

    if ($totalItems -eq 0 -and $auditEnabled) {
        Add-CheckResult -CheckName "Startup Folder Monitoring" `
            -Description "Checks startup folders for items and whether file system auditing is enabled" `
            -Status "PASS" `
            -Detail "No startup items found. File system auditing is enabled for detection." `
            -KillChainPhase "P5"
    } elseif ($totalItems -eq 0) {
        Add-CheckResult -CheckName "Startup Folder Monitoring" `
            -Description "Checks startup folders for items and whether file system auditing is enabled" `
            -Status "MANUAL CHECK" `
            -Detail "No startup items found, but file system auditing is not confirmed. Enable auditing for persistence detection." `
            -KillChainPhase "P5" `
            -Remediation "Enable file system object access auditing via GPO and monitor startup folder changes."
    } else {
        $itemNames = ($userItems + $allUsersItems | ForEach-Object { $_.Name }) -join ", "
        Add-CheckResult -CheckName "Startup Folder Monitoring" `
            -Description "Checks startup folders for items and whether file system auditing is enabled" `
            -Status "MANUAL CHECK" `
            -Detail "$totalItems startup item(s) found: $itemNames. Review for legitimacy." `
            -KillChainPhase "P5" `
            -Remediation "Review each startup item. Remove unauthorized entries. Enable auditing on startup folders."
    }
}

function Test-PowerShellLogging {
    <# CHECK 11: Is PowerShell script block logging and transcription enabled?
       Kill Chain Phase: P4 (Script Execution) #>

    $scriptBlockLog = Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging"
    $transcription = Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting"
    $moduleLogging = Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging"

    $enabledLogs = @()
    if ($scriptBlockLog -eq 1) { $enabledLogs += "Script Block Logging" }
    if ($transcription -eq 1) { $enabledLogs += "Transcription" }
    if ($moduleLogging -eq 1) { $enabledLogs += "Module Logging" }

    if ($enabledLogs.Count -ge 2) {
        Add-CheckResult -CheckName "PowerShell Logging & Transcription" `
            -Description "Checks if PowerShell logging captures pasted commands for forensic analysis" `
            -Status "PASS" `
            -Detail "Logging enabled: $($enabledLogs -join ', '). Pasted commands will be recorded." `
            -KillChainPhase "P4"
    } elseif ($enabledLogs.Count -eq 1) {
        Add-CheckResult -CheckName "PowerShell Logging & Transcription" `
            -Description "Checks if PowerShell logging captures pasted commands for forensic analysis" `
            -Status "MANUAL CHECK" `
            -Detail "Partial logging: $($enabledLogs -join ', '). Enable all three for full visibility." `
            -KillChainPhase "P4" `
            -Remediation "Enable Script Block Logging, Module Logging, and Transcription via GPO."
    } else {
        Add-CheckResult -CheckName "PowerShell Logging & Transcription" `
            -Description "Checks if PowerShell logging captures pasted commands for forensic analysis" `
            -Status "FAIL" `
            -Detail "No PowerShell logging is enabled. Pasted commands will leave no forensic trail." `
            -KillChainPhase "P4" `
            -Remediation "Enable all: Script Block Logging, Module Logging, and Transcription via GPO."
    }
}

function Test-CommandLineAuditing {
    <# CHECK 12: Is process creation command-line auditing enabled?
       Kill Chain Phase: P4 (Script Execution) #>

    $cmdLineAudit = Test-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled"

    # Also check the audit policy for process creation
    $processCreationAudit = $false
    try {
        $auditPol = auditpol /get /subcategory:"Process Creation" 2>$null
        if ($auditPol -match "Success|Erfolg|Succès|Éxito|Exito|成功") {
            $processCreationAudit = $true
        }
    } catch { }

    if ($cmdLineAudit -eq 1 -and $processCreationAudit) {
        Add-CheckResult -CheckName "Command-Line Process Auditing" `
            -Description "Checks if process creation events include the full command line" `
            -Status "PASS" `
            -Detail "Process creation auditing WITH command-line capture is enabled (Event ID 4688)." `
            -KillChainPhase "P4"
    } elseif ($processCreationAudit) {
        Add-CheckResult -CheckName "Command-Line Process Auditing" `
            -Description "Checks if process creation events include the full command line" `
            -Status "MANUAL CHECK" `
            -Detail "Process creation auditing is on, but command-line logging may not be enabled." `
            -KillChainPhase "P4" `
            -Remediation "Set 'Include command line in process creation events' via GPO under Admin Templates > System > Audit Process Creation."
    } else {
        Add-CheckResult -CheckName "Command-Line Process Auditing" `
            -Description "Checks if process creation events include the full command line" `
            -Status "FAIL" `
            -Detail "Process creation auditing is not enabled. Malicious commands will not appear in event logs." `
            -KillChainPhase "P4" `
            -Remediation "Enable 'Audit Process Creation' (Success) and 'Include command line in process creation events' via GPO."
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Invoke-QuickScan {
    Write-Banner

    Write-Host "  Starting Quick Scan..." -ForegroundColor White
    Write-Host "  Evaluating defensive posture against copy-paste attacks" -ForegroundColor Gray
    Write-Host "  (MITRE ATT&CK T1204.004)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor DarkGray
    Write-Host ""

    # Run all checks
    Test-RunDialogAccess             # Check 1  - P3
    Test-PowerShellExecutionPolicy   # Check 2  - P4
    Test-ConstrainedLanguageMode     # Check 3  - P4
    Test-ASRRules                    # Check 4  - P4
    Test-BrowserEnterprisePolicies   # Check 5  - P1-P2
    Test-SmartScreen                 # Check 6  - P4
    Test-ScriptHostAccess            # Check 7  - P4
    Test-MarkOfTheWeb                # Check 8  - P4
    Test-MacroExecutionPolicy        # Check 9  - P4
    Test-StartupFolderMonitoring     # Check 10 - P5
    Test-PowerShellLogging           # Check 11 - P4
    Test-CommandLineAuditing         # Check 12 - P4

    # Summary
    Write-Host "  ============================================================" -ForegroundColor DarkGray
    Write-Host ""

    $summaryColor = if ($Script:FailCount -eq 0) { "Green" }
                    elseif ($Script:FailCount -le 3) { "Yellow" }
                    else { "Red" }

    Write-Host "  SCAN COMPLETE" -ForegroundColor White
    Write-Host ""
    Write-Host "    PASS:          $($Script:PassCount) of $($Script:TotalChecks)" -ForegroundColor Green
    Write-Host "    FAIL:          $($Script:FailCount) of $($Script:TotalChecks)" -ForegroundColor Red
    Write-Host "    MANUAL CHECK:  $($Script:ManualCount) of $($Script:TotalChecks)" -ForegroundColor Yellow
    Write-Host ""

    if ($Script:FailCount -eq 0 -and $Script:ManualCount -eq 0) {
        Write-Host "  All checks passed! Your system has strong defenses" -ForegroundColor Green
        Write-Host "  against copy-paste attacks." -ForegroundColor Green
    } elseif ($Script:FailCount -eq 0) {
        Write-Host "  No failures detected. Review items marked MANUAL CHECK" -ForegroundColor Yellow
        Write-Host "  to confirm your configuration." -ForegroundColor Yellow
    } else {
        Write-Host "  $($Script:FailCount) issue(s) found. For a comprehensive assessment" -ForegroundColor $summaryColor
        Write-Host "  and remediation roadmap, try the ClickFix(SM) Score &" -ForegroundColor $summaryColor
        Write-Host "  Readiness Assessment at https://clickfix.com/assessment" -ForegroundColor $summaryColor
    }

    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor DarkGray

    # Service mark attribution
    Write-Host ""
    Write-Host "  ClickFix(SM) is a service mark of Grover Fields, used under license" -ForegroundColor DarkGray
    Write-Host "  by Fields Cybersecurity Services, LLC. All rights reserved." -ForegroundColor DarkGray
    Write-Host "  https://clickfix.com | v$($Script:Version)" -ForegroundColor DarkGray
    Write-Host ""

    # If export requested, ensure the output folder exists BEFORE exporting.
    if ($ExportHTML -or $ExportJSON) {
        if (-not (Test-Path -Path $OutputPath)) {
            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        }
    }

    # Export JSON if requested
    if ($ExportJSON) {
        Export-ScanResults
    }

    # Export HTML if requested
    if ($ExportHTML) {
        Export-HtmlReport
    }


}

function Export-ScanResults {
    $exportData = [ordered]@{
        scanMetadata = [ordered]@{
            product        = "Quick Scan Script"
            version        = $Script:Version
            scanDate       = $Script:ScanDate
            hostname       = $Script:Hostname
            username       = $Script:Username
            isAdmin        = $Script:IsAdmin
            osVersion      = $Script:OSVersion
            psVersion      = $Script:PSVersion
        }
        summary = [ordered]@{
            totalChecks    = $Script:TotalChecks
            passed         = $Script:PassCount
            failed         = $Script:FailCount
            manualCheck    = $Script:ManualCount
        }
        results = $Script:Results | ForEach-Object {
            [ordered]@{
                checkNumber    = $_.CheckNumber
                checkName      = $_.CheckName
                description    = $_.Description
                status         = $_.Status
                detail         = $_.Detail
                killChainPhase = $_.KillChainPhase
                remediation    = $_.Remediation
                requiresAdmin  = $_.RequiresAdmin
            }
        }
        upsell = [ordered]@{
            message = "For a comprehensive assessment and remediation roadmap, visit https://clickfix.com/assessment"
            product = "ClickFix℠ Score & Readiness Assessment"
            url     = "https://clickfix.com/assessment"
        }
    }

    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $fileName = "quick-scan-$($Script:Hostname.ToLower())-$timestamp.json"
    $fileName =  $fileName.ToLower()
    $filePath = Join-Path -Path $OutputPath -ChildPath $fileName

    try {
        $exportData | ConvertTo-Json -Depth 4 | Out-File -FilePath $filePath -Encoding UTF8 -ErrorAction Stop
        Write-Host ""
        Write-Host "  JSON exported: $filePath" -ForegroundColor Cyan
        Write-Host "  Upload this file to the ClickFix(SM) Score & Readiness" -ForegroundColor Gray
        Write-Host "  Assessment for a full remediation roadmap." -ForegroundColor Gray
        Write-Host ""
    } catch {
        Write-Host ""
        Write-Host "  ERROR: Failed to export JSON to $filePath" -ForegroundColor Red
        Write-Host "  $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ""
        Write-Error "Failed to export JSON to $filePath $($_.Exception.Message)"
    }
}


function Export-HtmlReport {
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $fileName = "quick-scan-$($Script:Hostname.ToLower())-$timestamp.html"
    $fileName =  $fileName.ToLower()
    $filePath = Join-Path -Path $OutputPath -ChildPath $fileName

    # Build status counts
    $passResults = $Script:Results | Where-Object { $_.Status -eq "PASS" }
    $failResults = $Script:Results | Where-Object { $_.Status -eq "FAIL" }
    $manualResults = $Script:Results | Where-Object { $_.Status -eq "MANUAL CHECK" }

    # Determine overall grade
    $grade = if ($Script:FailCount -eq 0 -and $Script:ManualCount -eq 0) { "A" }
             elseif ($Script:FailCount -eq 0) { "B" }
             elseif ($Script:FailCount -le 3) { "C" }
             elseif ($Script:FailCount -le 6) { "D" }
             else { "F" }

    $gradeColor = switch ($grade) {
        "A" { "#00875A" }
        "B" { "#36B37E" }
        "C" { "#FF8B00" }
        "D" { "#FF5630" }
        "F" { "#DE350B" }
    }

    # Build results rows
    $resultRows = ""
    foreach ($r in $Script:Results) {
        $statusClass = switch ($r.Status) {
            "PASS"          { "pass" }
            "FAIL"          { "fail" }
            "MANUAL CHECK"  { "manual" }
        }
        $statusIcon = switch ($r.Status) {
            "PASS"          { "&#10004;" }
            "FAIL"          { "&#10008;" }
            "MANUAL CHECK"  { "&#9888;" }
        }
        $encDetail = [System.Net.WebUtility]::HtmlEncode([string]$r.Detail)
        $encRemed  = [System.Net.WebUtility]::HtmlEncode([string]$r.Remediation)
        $remediationRow = ""
        if ($r.Status -eq "FAIL" -and $r.Remediation) {
            $remediationRow = "<div class=`"remediation`"><strong>Remediation:</strong> $encRemed</div>"
        }
        $resultRows += @"
        <tr class="$statusClass">
            <td class="check-num">$($r.CheckNumber)</td>
            <td class="check-name">$($r.CheckName)</td>
            <td class="check-phase">$($r.KillChainPhase)</td>
            <td class="check-status"><span class="status-badge $statusClass">$statusIcon $($r.Status)</span></td>
            <td class="check-detail">$encDetail$remediationRow</td>
        </tr>

"@
    }

    $logoBase64 = "iVBORw0KGgoAAAANSUhEUgAAArEAAAD4CAYAAAGMFY42AAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAA2ZpVFh0WE1MOmNvbS5hZG9iZS54bXAAAAAAADw/eHBhY2tldCBiZWdpbj0i77u/IiBpZD0iVzVNME1wQ2VoaUh6cmVTek5UY3prYzlkIj8+IDx4OnhtcG1ldGEgeG1sbnM6eD0iYWRvYmU6bnM6bWV0YS8iIHg6eG1wdGs9IkFkb2JlIFhNUCBDb3JlIDUuMC1jMDYxIDY0LjE0MDk0OSwgMjAxMC8xMi8wNy0xMDo1NzowMSAgICAgICAgIj4gPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4gPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIgeG1sbnM6eG1wTU09Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9tbS8iIHhtbG5zOnN0UmVmPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvc1R5cGUvUmVzb3VyY2VSZWYjIiB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iIHhtcE1NOk9yaWdpbmFsRG9jdW1lbnRJRD0ieG1wLmRpZDpGN0QzOTg5MzYyMjlGMTExOEQyQ0FDNDMzNDgxMTI4OCIgeG1wTU06RG9jdW1lbnRJRD0ieG1wLmRpZDo5RjNEQ0Q4RjlGMTExMUYxOUM2OEZBMDZGMzNFMjMxMyIgeG1wTU06SW5zdGFuY2VJRD0ieG1wLmlpZDo5RjNEQ0Q4RTlGMTExMUYxOUM2OEZBMDZGMzNFMjMxMyIgeG1wOkNyZWF0b3JUb29sPSJBZG9iZSBQaG90b3Nob3AgQ1M1LjEgV2luZG93cyI+IDx4bXBNTTpEZXJpdmVkRnJvbSBzdFJlZjppbnN0YW5jZUlEPSJ4bXAuaWlkOjJBNTc1MjYxMTE5RkYxMTE4Q0VCOEJGOEFCNkY5QjY1IiBzdFJlZjpkb2N1bWVudElEPSJ4bXAuZGlkOkY3RDM5ODkzNjIyOUYxMTE4RDJDQUM0MzM0ODExMjg4Ii8+IDwvcmRmOkRlc2NyaXB0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"

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" type="image/png" href="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAADm0lEQVR4AcRXSWgUQRR93dOzJpP0JC4oGtFEUBQUD4p4UgTFBdwTN9yNqLigxg0UoxKJXkREUQYXNCqoB1c8xYsoCmoQFyRxGaMSQ6YzmSSz9XT7q7KQSDrLZNo0/f78X9X136v6XcW0iOYrPT09W5Zlr8fj+UnQTYBGOb8RionL00wLLoAa54iiWCYIwlrqGEww4xYo6TDCHuJ663a7R5EPkdRkk3OTkDLaKaI4y44r2Q5TcHyoHVl2pgNZkiQ9ysjISBNp1gdayEtyHJjrkTAx1WIKFmRIuJXjxBAbFzFc07TdTMBMEoA1/a1wiAJzTYUsCdg4wNbCsYy9A7zmA63mk7ewDmsqA2j1RzABLe198Sv0tYCmbWjW1AW7E9LIsZTeuLymrYCQ4obnzF1kXngMV14+iej4NkeAZIVceBFWPntAsDlgdCVfgCAg/cBp2CZM4ZyRV0/RUHKW+x2ZpAtwbzkMx9S5nCv2qQyBw7T8aozHHZmkCkhZuhmuhes4T7zyK2r3r4IeauSxkUmaAMeMRUjdsI/zaP5qKAUroNXW8LgzYyjAMigLabtPwj55emfjeZ9t4lT+LB1t0BuCUPauRPy3j/d1ZQwFuHLz4ZydB/mYF675qw3zWEeNh3zkPARJgh6LovbQBqjl7w2f/7fDUEC49D70cAgQRbi3HUXq+r1gM0SbyzJkBOSiyxAcLkDXUFe0E9HXz9o80bVrKCBW9gLKrjxoAYVnSVm+FWkFpwCLxGMxcwA8xdcgypk8Dp4tRLj0Hvd7YgwFsCSxD6/h3zYf8apKFsI5cwnk414wcvnEVVgGDeXtDTfOofGOl/s9NZ0KYMnivgr4t8yDWvGBhbBPmoZ+15/BmjOGx6Ent1F/sYj7iZguBbCkWk0V/NsXIfr2OQsh2JuO1sjLUtSd2kP113l7IqZbAlhivr0KViD89AELEfv4hk65TYCq8jhR020BnIC2WaBwM2ryZ0HZsZh2SeenHB/ThemZAJZM16F+fgc9GmFRr9FzAb2mbJ+ACUj8DWqfK6FI1HX9Cxv5PfL/dFTFWrl+sRUoYQIu/KFzXG3tYE2mIKzpuFTd9P+AJv+YPtNEOl/xtTKqI7c8hLt+FS/r46bgvqJiWXkYH0Mam1wDCSgS/X5/naqqs6jF56MyHPwRwaqKsCko8EVayYkvNxAIVLASIBgMfqLvtPHUeJLwnZC0WlCutvcvmrWXuMYpivKQdfwFAAD//xUCzN8AAAAGSURBVAMA6Tez3Qu7xdsAAAAASUVORK5CYII=">
    <title>Quick Scan Report - $($Script:Hostname)</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; color: #1A1A2E; background: #F7FAFC; line-height: 1.6; }
        .header { background: linear-gradient(135deg, #2B2D42 0%, #1A1B2F 100%); color: #fff; padding: 32px 24px; }
        .header-inner { max-width: 960px; margin: 0 auto; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 16px; }
        .logo { height: 48px; }
        .header-text h1 { font-size: 1.4rem; font-weight: 700; }
        .header-text p { font-size: 0.85rem; opacity: 0.85; }
        .summary { max-width: 960px; margin: 24px auto; display: flex; gap: 16px; flex-wrap: wrap; padding: 0 24px; }
        .summary-card { flex: 1; min-width: 140px; background: #fff; border-radius: 8px; padding: 20px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .summary-card .label { font-size: 0.8rem; color: #718096; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600; }
        .summary-card .value { font-size: 2rem; font-weight: 800; margin-top: 4px; }
        .summary-card .value.pass { color: #00875A; }
        .summary-card .value.fail { color: #DE350B; }
        .summary-card .value.manual { color: #FF8B00; }
        .summary-card .value.grade { color: $gradeColor; }
        .meta { max-width: 960px; margin: 0 auto 24px; padding: 0 24px; }
        .meta-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 8px; background: #fff; border-radius: 8px; padding: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); font-size: 0.85rem; }
        .meta-item .meta-label { color: #718096; font-weight: 600; }
        .meta-item .meta-value { color: #1A1A2E; }
        .results { max-width: 960px; margin: 0 auto 24px; padding: 0 24px; }
        .results h2 { font-size: 1.2rem; margin-bottom: 12px; }
        table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        th { background: #1A1A2E; color: #fff; padding: 10px 12px; text-align: left; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.04em; }
        td { padding: 10px 12px; border-bottom: 1px solid #E2E8F0; font-size: 0.85rem; vertical-align: top; }
        tr.pass td { background: #F0FFF4; }
        tr.fail td { background: #FFF5F5; }
        tr.manual td { background: #FFFAF0; }
        .check-num { width: 40px; text-align: center; font-weight: 700; }
        .check-phase { width: 60px; text-align: center; color: #718096; font-size: 0.8rem; }
        .status-badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-weight: 600; font-size: 0.8rem; white-space: nowrap; }
        .status-badge.pass { background: #C6F6D5; color: #22543D; }
        .status-badge.fail { background: #FED7D7; color: #822727; }
        .status-badge.manual { background: #FEFCBF; color: #744210; }
        .remediation { margin-top: 6px; padding: 6px 10px; background: #FFF5F5; border-left: 3px solid #DE350B; border-radius: 0 4px 4px 0; font-size: 0.8rem; color: #822727; }
        .upsell { max-width: 960px; margin: 24px auto; padding: 0 24px; }
        .upsell-card { background: linear-gradient(135deg, #FFF7ED 0%, #FFEDD5 100%); border: 1px solid #FDBA74; border-radius: 8px; padding: 24px; text-align: center; }
        .upsell-card h3 { color: #2B2D42; margin-bottom: 8px; }
        .upsell-card p { color: #4A5568; font-size: 0.9rem; margin-bottom: 12px; }
        .upsell-card a { display: inline-block; background: #E8530E; color: #fff; padding: 8px 24px; border-radius: 6px; text-decoration: none; font-weight: 600; }
        .footer { max-width: 960px; margin: 0 auto; padding: 24px; text-align: center; font-size: 0.75rem; color: #A0AEC0; border-top: 1px solid #E2E8F0; }
        @media print { body { background: #fff; } .upsell { display: none; } .header { background: #2B2D42 !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; } }
        @media (max-width: 600px) { .header-inner { flex-direction: column; text-align: center; } .summary { flex-direction: column; } }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-inner">
            <img src="data:image/png;base64,$logoBase64" alt="ClickFix" class="logo">
            <div class="header-text">
                <h1>Quick Scan Report</h1>
                <p>Copy-Paste Attack Posture Assessment (MITRE ATT&amp;CK T1204.004)</p>
            </div>
        </div>
    </div>
    <div class="summary">
        <div class="summary-card"><div class="label">Grade</div><div class="value grade">$grade</div></div>
        <div class="summary-card"><div class="label">Passed</div><div class="value pass">$($Script:PassCount)</div></div>
        <div class="summary-card"><div class="label">Failed</div><div class="value fail">$($Script:FailCount)</div></div>
        <div class="summary-card"><div class="label">Manual Check</div><div class="value manual">$($Script:ManualCount)</div></div>
        <div class="summary-card"><div class="label">Total Checks</div><div class="value">$($Script:TotalChecks)</div></div>
    </div>
    <div class="meta">
        <div class="meta-grid">
            <div class="meta-item"><span class="meta-label">Host:</span> <span class="meta-value">$($Script:Hostname)</span></div>
            <div class="meta-item"><span class="meta-label">User:</span> <span class="meta-value">$($Script:Username)</span></div>
            <div class="meta-item"><span class="meta-label">Admin:</span> <span class="meta-value">$($Script:IsAdmin)</span></div>
            <div class="meta-item"><span class="meta-label">OS:</span> <span class="meta-value">$($Script:OSVersion)</span></div>
            <div class="meta-item"><span class="meta-label">PowerShell:</span> <span class="meta-value">$($Script:PSVersion)</span></div>
            <div class="meta-item"><span class="meta-label">Scan Date:</span> <span class="meta-value">$($Script:ScanDate)</span></div>
            <div class="meta-item"><span class="meta-label">Script Version:</span> <span class="meta-value">$($Script:Version)</span></div>
        </div>
    </div>
    <div class="results">
        <h2>Detailed Results</h2>
        <table>
            <thead><tr><th>#</th><th>Check</th><th>Phase</th><th>Status</th><th>Detail</th></tr></thead>
            <tbody>
$resultRows
            </tbody>
        </table>
    </div>
    <div class="upsell">
        <div class="upsell-card">
            <h3>Need a Full Assessment?</h3>
            <p>The ClickFix&#8480; Score &amp; Readiness Assessment provides comprehensive posture scoring, a prioritized remediation roadmap, and executive-ready reporting.</p>
            <a href="https://clickfix.com/assessment" target="_blank" rel="noopener noreferrer">Learn More</a>
        </div>
    </div>
    <div class="footer">
        ClickFix&#8480; is a service mark of Grover Fields, used under license by Fields Cybersecurity Services, LLC. All rights reserved.
        Fields Cybersecurity Services, LLC and the ClickFix&#8480; brand provide defensive cybersecurity consultation, education, and advisory services and are not affiliated with, endorsed by, or associated with the &ldquo;ClickFix&rdquo; social-engineering cyberattack technique or related malware campaigns (e.g., Lumma, Vidar, ClearFake).
        <br>https://clickfix.com | v$($Script:Version)
    </div>
</body>
</html>
"@

    try {
        $html | Out-File -FilePath $filePath -Encoding UTF8 -ErrorAction Stop
        Write-Host ""
        Write-Host "  HTML report exported: $filePath" -ForegroundColor Cyan
        Write-Host "  Open this file in any browser to view the branded report." -ForegroundColor Gray
        Write-Host ""
    } catch {
        Write-Host ""
        Write-Host "  ERROR: Failed to export HTML to $filePath" -ForegroundColor Red
        Write-Host "  $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ""
        Write-Error "Failed to export HTML to $filePath $($_.Exception.Message)"
    }
}

# Run the scan
Invoke-QuickScan