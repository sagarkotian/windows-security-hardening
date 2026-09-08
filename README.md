# Personal Windows Security TUI

[![Validate](https://github.com/sagarkotian/windows-security-hardening/actions/workflows/validate.yml/badge.svg)](https://github.com/sagarkotian/windows-security-hardening/actions/workflows/validate.yml)

`WindowsSecurityTUI.ps1` is an interactive, dependency-free PowerShell console for auditing a personal Windows 11 PC against a focused set of high-value controls. Each failed control explains:

- why the setting matters;
- the current and expected state;
- what users, applications, devices, or workflows may be affected;
- the recommended fix, its risk, restart needs, and rollback approach;
- the Microsoft source behind the recommendation.

The controls are derived from Microsoft's **Windows 11, version 25H2 security baseline**, but the profile is adapted for a personally owned workstation. It does not assume the PC is domain joined, centrally monitored, or managed through Intune.

> [!IMPORTANT]
> This is a focused personal-device hardening aid, not a complete compliance scanner or a substitute for the Microsoft Security Compliance Toolkit. Review every proposed remediation and keep recovery keys and backups available.

At startup, the tool checks for Active Directory domain membership, Microsoft Entra join, MDM enrollment, and a registered work/school account. Enterprise or domain considerations are highlighted when relevant and do not silently change the personal-device recommendations.

## Run it

Requirements:

- Windows 11;
- Windows PowerShell 5.1 or PowerShell 7;
- an elevated session for complete visibility and all remediation actions;
- WSL only when using the optional Linux-distribution audit.

A standard-user session can run the tool, but Windows restricts visibility into Defender, firewall, firmware, Security logs, and several local policies. Run as Administrator for a complete audit:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\WindowsSecurityTUI.ps1
```

Remediation actions are available only when PowerShell is running **as Administrator**. Auditing never requires accepting fixes.

For unattended, read-only output:

```powershell
.\WindowsSecurityTUI.ps1 -AuditOnly
.\WindowsSecurityTUI.ps1 -AuditOnly -ExportPath .\Reports
.\WindowsSecurityTUI.ps1 -AuditOnly -AuditWsl
.\WindowsSecurityTUI.ps1 -AuditOnly -AuditWsl -WslRunningOnly
```

The interactive menu includes **Audit WSL and installed Linux distributions**. The WSL audit inventories the WSL release, global `.wslconfig`, firewall integration, custom kernel settings, and every registered distribution. Inside each selected distribution it reports the OS and kernel, default-user privilege, UID 0 accounts, root-password state, home-directory permissions, umask, cached package updates, listening sockets, and systemd configuration.

Inspecting all distributions starts any that are stopped, which may run their configured startup services. Choose the running-only option (or use `-WslRunningOnly`) to avoid starting them. The checks do not intentionally change configuration or refresh package metadata, so pending-update counts reflect the distribution's existing package cache.

## Safety model

- Audit checks are read-only.
- Automatic fixes are opt-in and show the expected impact before changing anything.
- A group action includes only controls classified as low-risk and requires the phrase `APPLY LOW RISK`.
- High-risk changes require typing the control ID.
- Firmware, TPM, BitLocker, VBS/Memory Integrity, and other compatibility-sensitive changes are guidance-only.
- Before the first automatic fix, the tool creates a best-effort backup under `Backups\<timestamp>` containing relevant registry exports, firewall policy, audit policy, and Defender preferences where available.
- Backups and exported reports can reveal security configuration details. Store them with access controls appropriate for administrative data.
- Every attempted fix is written to `FixLog.jsonl` and the control is audited again immediately.
- If the optional context check detects Domain Group Policy, Microsoft Entra/MDM management, Defender Tamper Protection, or another management platform, local changes can be overridden. In that case, remediate in the policy owner rather than fighting policy locally.

Backups are deliberately not restored automatically. Bulk restoration can undo unrelated policy changes made after the backup. Review and restore only the relevant setting.

## Included control areas

- Secure Boot, TPM 2.0, BitLocker, VBS, and Memory Integrity
- Defender real-time scanning, cloud protection, PUA protection, and Network Protection
- Windows Firewall enforcement and logging
- SMBv1, SMB signing, guest logons, LLMNR, and NTLM hardening
- UAC, Guest account, local password policy, inactivity locking, and WDigest
- SmartScreen, AutoPlay/AutoRun, and Windows Installer elevation
- PowerShell logging, advanced audit policy, and event-log capacity
- Remote Desktop NLA and secure WinRM policy
- Optional WSL host and installed Linux distribution audit

Some controls can report **NotApplicable** (for example, RDP is disabled) or **Unknown** (for example, firmware state is unavailable or localized `auditpol` output cannot be safely interpreted). These do not lower the displayed posture score.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) before proposing changes. Report security issues according to [SECURITY.md](SECURITY.md), and never attach unsanitized audit reports or backups to an issue.

No open-source license has been selected. Until one is added, the repository contents remain under the copyright holder's default rights.

## Microsoft references

- [Windows 11 25H2 security baseline settings](https://learn.microsoft.com/en-us/intune/device-security/security-baselines/ref-windows-mdm-settings)
- [Windows security baselines](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines)
- [Microsoft Security Compliance Toolkit](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10)
- [Windows security documentation](https://learn.microsoft.com/en-us/windows/security/)
- [Compare WSL versions](https://learn.microsoft.com/en-us/windows/wsl/compare-versions)
- [Advanced WSL configuration](https://learn.microsoft.com/en-us/windows/wsl/wsl-config)

## When enterprise or domain notes apply

For a normal personal/workgroup PC, enterprise notes are informational. They become relevant if the PC is domain joined, Microsoft Entra joined, enrolled in MDM, uses organization-managed Defender settings, or depends on work resources.

On managed systems, Group Policy or Intune may overwrite local fixes. Recovery keys may need organizational escrow, domain password policy can override local policy, Credential Guard may be required in addition to Memory Integrity, and event forwarding may be centrally managed. For formal enterprise deployment or full baseline comparison, use the Security Compliance Toolkit's GPO backups and Policy Analyzer or the matching Intune baseline.
