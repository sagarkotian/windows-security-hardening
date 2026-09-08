# Contributing

Thanks for helping improve Personal Windows Security TUI.

## Before opening a change

- Keep audit checks read-only.
- Keep remediation explicit, opt-in, and reversible where practical.
- Document user impact, rollback steps, restart requirements, and authoritative sources for new controls.
- Return `Unknown` instead of guessing when a Windows API or localized command output cannot be interpreted safely.
- Never commit generated reports, backups, credentials, recovery keys, or machine-specific security data.

## Validate changes

Run the PowerShell parser before committing:

```powershell
$tokens = $null
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile(
    (Resolve-Path '.\WindowsSecurityTUI.ps1'),
    [ref]$tokens,
    [ref]$errors
) | Out-Null
$errors
```

The final command should produce no output. Test on Windows PowerShell 5.1 when changing compatibility-sensitive code. Exercise both standard-user and elevated audit paths where possible, but use a disposable Windows test environment for remediation testing.

## Pull requests

Explain the security rationale, affected Windows versions, test coverage, and any behavior that can start services or change system state. Keep unrelated changes separate.
