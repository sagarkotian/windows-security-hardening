#requires -Version 5.1

<#
.SYNOPSIS
    Interactive Windows security posture audit and guided remediation console.

.DESCRIPTION
    Audits a focused set of high-value personal Windows 11 controls derived from
    the Microsoft Windows 11, version 25H2 security baseline. Audit mode is read-only.
    Remediation is always opt-in, creates a best-effort pre-change backup, and
    rechecks the selected control after a change.

    This is not a replacement for applying and validating Microsoft's complete
    Security Compliance Toolkit baseline, Intune policy, or domain Group Policy.

.PARAMETER AuditOnly
    Run every audit, print a summary, and exit without showing the interactive UI.

.PARAMETER ExportPath
    With -AuditOnly, export JSON and HTML reports to this directory.

.PARAMETER AuditWsl
    With -AuditOnly, also inventory WSL and run read-only security checks in each
    installed Linux distribution. Starting a stopped distribution may run its
    configured startup services.

.PARAMETER WslRunningOnly
    With -AuditWsl, inspect only distributions that are already running.

.PARAMETER NoClear
    Do not clear the console when drawing TUI screens.

.EXAMPLE
    .\WindowsSecurityTUI.ps1

.EXAMPLE
    .\WindowsSecurityTUI.ps1 -AuditOnly -ExportPath .\Reports

.EXAMPLE
    .\WindowsSecurityTUI.ps1 -AuditOnly -AuditWsl -WslRunningOnly
#>

[CmdletBinding()]
param(
    [switch]$AuditOnly,
    [string]$ExportPath,
    [switch]$AuditWsl,
    [switch]$WslRunningOnly,
    [switch]$NoClear
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:ToolName = 'Personal Windows Security TUI'
$script:ToolVersion = '1.2.1'
$script:BaselineName = 'Personal Windows 11 hardening profile (Microsoft 25H2 baseline-informed)'
$script:BaselineUrl = 'https://learn.microsoft.com/en-us/intune/device-security/security-baselines/ref-windows-mdm-settings'
$script:SctUrl = 'https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10'
$script:Results = @()
$script:BackupDirectory = $null
$script:FixLog = @()
$script:RunningOnWindows = $env:OS -eq 'Windows_NT'
$script:IsAdmin = $false
$script:ComputerInfo = $null
$script:SystemContext = $null
$script:WslAudit = $null
$script:WslConfigUrl = 'https://learn.microsoft.com/en-us/windows/wsl/wsl-config'
$script:WslVersionsUrl = 'https://learn.microsoft.com/en-us/windows/wsl/compare-versions'

if ($script:RunningOnWindows) {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        $script:IsAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        $script:IsAdmin = $false
    }
}

function New-CheckResult {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Pass', 'Fail', 'NotApplicable', 'Unknown')][string]$Status,
        [Parameter(Mandatory = $true)][string]$Current,
        [Parameter(Mandatory = $true)][string]$Expected,
        [string]$Evidence = ''
    )

    [pscustomobject]@{
        Status = $Status
        Current = $Current
        Expected = $Expected
        Evidence = $Evidence
    }
}

function New-SecurityControl {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Title,
        [Parameter(Mandatory = $true)][ValidateSet('Critical', 'High', 'Medium', 'Low')][string]$Severity,
        [Parameter(Mandatory = $true)][string]$WhyItMatters,
        [Parameter(Mandatory = $true)][string]$Affected,
        [Parameter(Mandatory = $true)][string]$Recommendation,
        [Parameter(Mandatory = $true)][scriptblock]$Check,
        [scriptblock]$Fix,
        [ValidateSet('Low', 'Moderate', 'High', 'Manual')][string]$FixRisk = 'Manual',
        [string]$FixImpact = 'No automated remediation is supplied.',
        [string]$Rollback = 'Restore the previous setting from the pre-change backup or Windows settings.',
        [bool]$RestartRequired = $false,
        [string]$EnterpriseNote = '',
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$SourceUrl
    )

    [pscustomobject][ordered]@{
        Id = $Id
        Category = $Category
        Title = $Title
        Severity = $Severity
        WhyItMatters = $WhyItMatters
        Affected = $Affected
        Recommendation = $Recommendation
        Check = $Check
        Fix = $Fix
        FixRisk = $FixRisk
        FixImpact = $FixImpact
        Rollback = $Rollback
        RestartRequired = $RestartRequired
        EnterpriseNote = $EnterpriseNote
        Source = $Source
        SourceUrl = $SourceUrl
    }
}

function Get-RegistryValueState {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return [pscustomobject]@{ Exists = $false; Value = $null }
    }

    try {
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        [pscustomobject]@{ Exists = $true; Value = $item.$Name }
    }
    catch [System.Management.Automation.PSArgumentException] {
        [pscustomobject]@{ Exists = $false; Value = $null }
    }
}

function Set-RegistryDword {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][int]$Value
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        $null = New-Item -Path $Path -Force
    }
    $null = New-ItemProperty -LiteralPath $Path -Name $Name -PropertyType DWord -Value $Value -Force
}

function Test-RegistryDword {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][int]$Expected,
        [bool]$MissingIsExpected = $false,
        [string]$ExpectedText = ''
    )

    $state = Get-RegistryValueState -Path $Path -Name $Name
    if ([string]::IsNullOrWhiteSpace($ExpectedText)) {
        $ExpectedText = [string]$Expected
    }

    if (-not $state.Exists) {
        if ($MissingIsExpected) {
            return New-CheckResult -Status Pass -Current 'Not configured (secure Windows default applies)' -Expected $ExpectedText -Evidence "$Path\$Name"
        }
        return New-CheckResult -Status Fail -Current 'Not configured' -Expected $ExpectedText -Evidence "$Path\$Name"
    }

    if ([int]$state.Value -eq $Expected) {
        return New-CheckResult -Status Pass -Current ([string]$state.Value) -Expected $ExpectedText -Evidence "$Path\$Name"
    }
    New-CheckResult -Status Fail -Current ([string]$state.Value) -Expected $ExpectedText -Evidence "$Path\$Name"
}

function Get-DeviceGuardState {
    try {
        Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName 'Win32_DeviceGuard' -ErrorAction Stop
    }
    catch {
        $null
    }
}

function Get-SystemContext {
    $edition = 'Unknown edition'
    $displayVersion = 'Unknown version'
    $partOfDomain = $false
    $domainName = 'WORKGROUP'
    $azureAdJoined = $false
    $workplaceJoined = $false
    $mdmEnrolled = $false
    $currentBuild = 0

    try {
        $product = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        if ($product.ProductName) { $edition = [string]$product.ProductName }
        if ($product.DisplayVersion) { $displayVersion = [string]$product.DisplayVersion }
        if ($product.CurrentBuild) { $null = [int]::TryParse([string]$product.CurrentBuild, [ref]$currentBuild) }
        # The legacy ProductName value can still say Windows 10 on Windows 11.
        if ($currentBuild -ge 22000 -and $edition -match 'Windows 10') { $edition = $edition -replace 'Windows 10', 'Windows 11' }
    } catch {}

    try {
        $computerSystem = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $partOfDomain = [bool]$computerSystem.PartOfDomain
        if ($computerSystem.Domain) { $domainName = [string]$computerSystem.Domain }
    } catch {}

    if (Get-Command dsregcmd.exe -ErrorAction SilentlyContinue) {
        try {
            $joinState = (& dsregcmd.exe /status 2>$null) -join "`n"
            $azureAdJoined = $joinState -match '(?im)^\s*AzureAdJoined\s*:\s*YES\s*$'
            $workplaceJoined = $joinState -match '(?im)^\s*WorkplaceJoined\s*:\s*YES\s*$'
            $mdmMatch = [regex]::Match($joinState, '(?im)^\s*MdmUrl\s*:\s*(\S+)\s*$')
            $mdmEnrolled = $mdmMatch.Success -and -not [string]::IsNullOrWhiteSpace($mdmMatch.Groups[1].Value)
        } catch {}
    }

    $managedSignals = @()
    if ($partOfDomain) { $managedSignals += "Active Directory domain ($domainName)" }
    if ($azureAdJoined) { $managedSignals += 'Microsoft Entra joined' }
    if ($mdmEnrolled) { $managedSignals += 'MDM enrollment' }

    $mode = if ($managedSignals.Count -gt 0) { 'Managed/enterprise signals detected' } else { 'Personal/workgroup' }
    [pscustomobject][ordered]@{
        WindowsEdition = $edition
        DisplayVersion = $displayVersion
        Mode = $mode
        PartOfDomain = $partOfDomain
        DomainName = $domainName
        EntraJoined = $azureAdJoined
        WorkAccountRegistered = $workplaceJoined
        MdmEnrolled = $mdmEnrolled
        ManagedSignals = ($managedSignals -join '; ')
    }
}

function Invoke-WslCommand {
    param([Parameter(Mandatory = $true)][object[]]$Arguments)

    $command = Get-Command wsl.exe -ErrorAction SilentlyContinue
    if ($null -eq $command) {
        return [pscustomobject]@{ ExitCode = -1; Text = 'wsl.exe is not available.' }
    }

    $output = @()
    $exitCode = -1
    try {
        $output = @(& $command.Source @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
    }
    catch {
        $output += $_.Exception.Message
    }

    # Some Windows/PowerShell combinations surface WSL's UTF-16 output with NULs.
    $text = (($output | ForEach-Object { [string]$_ }) -join "`n") -replace "`0", ''
    [pscustomobject]@{ ExitCode = $exitCode; Text = $text.Trim() }
}

function New-WslFinding {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Pass', 'Review', 'Info', 'Unknown')][string]$Status,
        [Parameter(Mandatory = $true)][string]$Check,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Current,
        [Parameter(Mandatory = $true)][string]$Expected,
        [string]$Guidance = ''
    )

    if ([string]::IsNullOrWhiteSpace($Current)) { $Current = 'Not reported' }

    [pscustomobject][ordered]@{
        Status = $Status
        Check = $Check
        Current = $Current
        Expected = $Expected
        Guidance = $Guidance
    }
}

function Get-Wsl2Configuration {
    $path = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.wslconfig'
    $values = @{}
    if (-not (Test-Path -LiteralPath $path)) {
        return [pscustomobject]@{ Path = $path; Exists = $false; Values = $values; Error = '' }
    }

    try {
        $section = ''
        foreach ($rawLine in Get-Content -LiteralPath $path -ErrorAction Stop) {
            $line = ([string]$rawLine).Trim()
            if (-not $line -or $line.StartsWith('#') -or $line.StartsWith(';')) { continue }
            if ($line -match '^\[(.+)\]$') {
                $section = $Matches[1].Trim().ToLowerInvariant()
                continue
            }
            if ($section -eq 'wsl2' -and $line -match '^([^=]+)=(.*)$') {
                $values[$Matches[1].Trim()] = $Matches[2].Trim()
            }
        }
        [pscustomobject]@{ Path = $path; Exists = $true; Values = $values; Error = '' }
    }
    catch {
        [pscustomobject]@{ Path = $path; Exists = $true; Values = $values; Error = $_.Exception.Message }
    }
}

function ConvertFrom-WslProbe {
    param([AllowEmptyString()][string]$Text)
    $values = @{}
    foreach ($line in @($Text -split "`r?`n")) {
        if ($line -match '^([A-Z0-9_]+)=(.*)$') {
            $values[$Matches[1]] = $Matches[2].Trim()
        }
    }
    $values
}

function Get-WslDistributionInventory {
    $allResult = Invoke-WslCommand -Arguments @('--list', '--quiet')
    if ($allResult.ExitCode -ne 0) {
        return [pscustomobject]@{ Success = $false; Error = $allResult.Text; Items = @() }
    }

    [string[]]$names = @($allResult.Text -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($names.Count -eq 0) {
        return [pscustomobject]@{ Success = $true; Error = ''; Items = @() }
    }

    $verboseResult = Invoke-WslCommand -Arguments @('--list', '--verbose')
    $runningResult = Invoke-WslCommand -Arguments @('--list', '--running', '--quiet')
    [string[]]$runningNames = @()
    $runningStateKnown = $runningResult.ExitCode -eq 0
    if ($runningStateKnown) {
        $runningNames = @($runningResult.Text -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }

    $items = foreach ($name in $names) {
        $version = 'Unknown'
        $isDefault = $false
        $state = if (-not $runningStateKnown) { 'Unknown' } elseif ($runningNames -contains $name) { 'Running' } else { 'Stopped' }
        if ($verboseResult.ExitCode -eq 0) {
            $escapedName = [regex]::Escape($name)
            foreach ($line in @($verboseResult.Text -split "`r?`n")) {
                if ($line -match "^\s*(?<marker>\*)?\s*$escapedName\s+(?<state>.*?)\s+(?<version>[12])\s*$") {
                    $version = $Matches['version']
                    $isDefault = $Matches['marker'] -eq '*'
                    break
                }
            }
        }
        [pscustomobject][ordered]@{
            Name = $name
            State = $state
            WslVersion = $version
            IsDefault = $isDefault
        }
    }
    [pscustomobject]@{ Success = $true; Error = ''; RunningStateError = if ($runningStateKnown) { '' } else { $runningResult.Text }; Items = @($items) }
}

function Get-WslDistributionAudit {
    param([Parameter(Mandatory = $true)]$InventoryItem)

    $probeScript = @'
read_os_value() {
    awk -F= -v wanted="$1" '$1 == wanted { sub(/^[^=]*=/, ""); gsub(/^"|"$/, ""); print; exit }' /etc/os-release 2>/dev/null
}
one_line() { tr '\r\n' '  '; }
printf 'OS_NAME=%s\n' "$(read_os_value PRETTY_NAME | one_line)"
printf 'OS_ID=%s\n' "$(read_os_value ID | one_line)"
printf 'OS_VERSION=%s\n' "$(read_os_value VERSION_ID | one_line)"
printf 'KERNEL=%s\n' "$(uname -r 2>/dev/null | one_line)"
printf 'DEFAULT_USER=%s\n' "$(id -un 2>/dev/null | one_line)"
printf 'DEFAULT_UID=%s\n' "$(id -u 2>/dev/null | one_line)"
printf 'HOME_MODE=%s\n' "$(stat -c %a "$HOME" 2>/dev/null | one_line)"
printf 'UMASK=%s\n' "$(umask 2>/dev/null | one_line)"
printf 'UID0_ACCOUNTS=%s\n' "$(awk -F: '$3 == 0 { print $1 }' /etc/passwd 2>/dev/null | paste -sd, - | one_line)"
if command -v apt >/dev/null 2>&1; then
    printf 'PACKAGE_SOURCE=apt cached metadata\n'
    printf 'PENDING_UPDATES=%s\n' "$(apt list --upgradable 2>/dev/null | sed '1d' | wc -l | tr -d ' ')"
elif command -v apk >/dev/null 2>&1; then
    printf 'PACKAGE_SOURCE=apk cached metadata\n'
    printf 'PENDING_UPDATES=%s\n' "$(apk version -l '<' 2>/dev/null | wc -l | tr -d ' ')"
elif command -v pacman >/dev/null 2>&1; then
    printf 'PACKAGE_SOURCE=pacman cached metadata\n'
    printf 'PENDING_UPDATES=%s\n' "$(pacman -Qu 2>/dev/null | wc -l | tr -d ' ')"
else
    printf 'PACKAGE_SOURCE=unsupported package manager\n'
    printf 'PENDING_UPDATES=unknown\n'
fi
if command -v ss >/dev/null 2>&1; then
    printf 'LISTENERS=%s\n' "$(ss -H -lntu 2>/dev/null | awk '{ print $1 ":" $5 }' | sort -u | paste -sd, - | one_line)"
else
    printf 'LISTENERS=unavailable\n'
fi
if [ -r /etc/wsl.conf ]; then
    printf 'WSL_CONF=present\n'
    printf 'SYSTEMD=%s\n' "$(awk -F= 'tolower($1) ~ /^[[:space:]]*systemd[[:space:]]*$/ { gsub(/[[:space:]]/, "", $2); print tolower($2); exit }' /etc/wsl.conf)"
else
    printf 'WSL_CONF=not present\n'
    printf 'SYSTEMD=default\n'
fi
'@
    $probeResult = Invoke-WslCommand -Arguments @('--distribution', $InventoryItem.Name, '--exec', 'sh', '-c', $probeScript)
    if ($probeResult.ExitCode -ne 0) {
        return [pscustomobject][ordered]@{
            Name = $InventoryItem.Name; State = $InventoryItem.State; WslVersion = $InventoryItem.WslVersion
            IsDefault = $InventoryItem.IsDefault; OsName = 'Unknown'; OsVersion = ''; Kernel = ''
            Findings = @((New-WslFinding -Status Unknown -Check 'Distribution inspection' -Current $probeResult.Text -Expected 'Linux distribution can run read-only inspection commands' -Guidance 'Start or repair the distribution, then run the audit again.'))
        }
    }

    $values = ConvertFrom-WslProbe -Text $probeResult.Text
    $rootProbe = @'
awk -F: '$1 == "root" { if ($2 ~ /^(!|\*)/) print "locked"; else print "unlocked" }' /etc/shadow 2>/dev/null
'@
    $rootResult = Invoke-WslCommand -Arguments @('--distribution', $InventoryItem.Name, '--user', 'root', '--exec', 'sh', '-c', $rootProbe)
    $rootPassword = if ($rootResult.ExitCode -eq 0 -and $rootResult.Text) { $rootResult.Text.Trim() } else { 'unknown' }

    $findings = New-Object System.Collections.Generic.List[object]
    if ($InventoryItem.WslVersion -eq '2') {
        $findings.Add((New-WslFinding -Status Pass -Check 'WSL architecture' -Current 'WSL 2' -Expected 'WSL 2 unless a documented compatibility need requires WSL 1'))
    }
    elseif ($InventoryItem.WslVersion -eq '1') {
        $findings.Add((New-WslFinding -Status Review -Check 'WSL architecture' -Current 'WSL 1' -Expected 'WSL 2 unless a documented compatibility need requires WSL 1' -Guidance 'WSL 2 is the current default and uses a Microsoft-serviced Linux kernel in a managed VM. Back up the distribution before converting.'))
    }
    else {
        $findings.Add((New-WslFinding -Status Unknown -Check 'WSL architecture' -Current 'Could not determine WSL version' -Expected 'WSL 2 unless a documented compatibility need requires WSL 1'))
    }

    $defaultUser = if ($values.ContainsKey('DEFAULT_USER')) { $values['DEFAULT_USER'] } else { 'Unknown' }
    $defaultUid = if ($values.ContainsKey('DEFAULT_UID')) { $values['DEFAULT_UID'] } else { 'Unknown' }
    if ($defaultUid -eq '0') {
        $findings.Add((New-WslFinding -Status Review -Check 'Default Linux user' -Current "$defaultUser (UID 0)" -Expected 'An unprivileged default user' -Guidance 'Configure a normal default user and use sudo only for administrative commands.'))
    }
    elseif ($defaultUid -match '^\d+$') {
        $findings.Add((New-WslFinding -Status Pass -Check 'Default Linux user' -Current "$defaultUser (UID $defaultUid)" -Expected 'An unprivileged default user'))
    }
    else {
        $findings.Add((New-WslFinding -Status Unknown -Check 'Default Linux user' -Current $defaultUser -Expected 'An unprivileged default user'))
    }

    $uid0Accounts = if ($values.ContainsKey('UID0_ACCOUNTS')) { $values['UID0_ACCOUNTS'] } else { '' }
    if ($uid0Accounts -eq 'root') {
        $findings.Add((New-WslFinding -Status Pass -Check 'UID 0 accounts' -Current 'root only' -Expected 'Only root has UID 0'))
    }
    elseif ($uid0Accounts) {
        $findings.Add((New-WslFinding -Status Review -Check 'UID 0 accounts' -Current $uid0Accounts -Expected 'Only root has UID 0' -Guidance 'Remove UID 0 from unexpected accounts after verifying ownership and recovery access.'))
    }
    else {
        $findings.Add((New-WslFinding -Status Unknown -Check 'UID 0 accounts' -Current 'Could not read /etc/passwd' -Expected 'Only root has UID 0'))
    }

    if ($rootPassword -eq 'locked') {
        $findings.Add((New-WslFinding -Status Pass -Check 'Root password login' -Current 'Root password is locked' -Expected 'Root password locked; elevate through sudo'))
    }
    elseif ($rootPassword -eq 'unlocked') {
        $findings.Add((New-WslFinding -Status Review -Check 'Root password login' -Current 'Root has a directly usable password hash' -Expected 'Root password locked; elevate through sudo' -Guidance 'Confirm direct root login is required; otherwise lock the root password using the distribution-specific procedure.'))
    }
    else {
        $findings.Add((New-WslFinding -Status Unknown -Check 'Root password login' -Current 'Could not inspect /etc/shadow' -Expected 'Root password locked; elevate through sudo'))
    }

    $homeMode = if ($values.ContainsKey('HOME_MODE')) { $values['HOME_MODE'] } else { '' }
    try {
        $homeBits = [Convert]::ToInt32($homeMode, 8)
        if (($homeBits -band [Convert]::ToInt32('022', 8)) -eq 0) {
            $findings.Add((New-WslFinding -Status Pass -Check 'Home directory permissions' -Current $homeMode -Expected 'Not writable by group or other users'))
        }
        else {
            $findings.Add((New-WslFinding -Status Review -Check 'Home directory permissions' -Current $homeMode -Expected 'Not writable by group or other users' -Guidance 'Remove unintended group/other write permissions from the default user home directory.'))
        }
    }
    catch {
        $findings.Add((New-WslFinding -Status Unknown -Check 'Home directory permissions' -Current 'Could not determine mode' -Expected 'Not writable by group or other users'))
    }

    $umask = if ($values.ContainsKey('UMASK')) { $values['UMASK'] } else { '' }
    try {
        $umaskBits = [Convert]::ToInt32($umask, 8)
        if (($umaskBits -band [Convert]::ToInt32('022', 8)) -eq [Convert]::ToInt32('022', 8)) {
            $findings.Add((New-WslFinding -Status Pass -Check 'Default file-creation mask' -Current $umask -Expected 'At least 0022 (no group/other write by default)'))
        }
        else {
            $findings.Add((New-WslFinding -Status Review -Check 'Default file-creation mask' -Current $umask -Expected 'At least 0022 (no group/other write by default)' -Guidance 'Set an appropriate umask in the distribution login configuration.'))
        }
    }
    catch {
        $findings.Add((New-WslFinding -Status Unknown -Check 'Default file-creation mask' -Current 'Could not determine umask' -Expected 'At least 0022'))
    }

    $pending = if ($values.ContainsKey('PENDING_UPDATES')) { $values['PENDING_UPDATES'] } else { 'unknown' }
    $packageSource = if ($values.ContainsKey('PACKAGE_SOURCE')) { $values['PACKAGE_SOURCE'] } else { 'unknown' }
    if ([string]::IsNullOrWhiteSpace($packageSource)) { $packageSource = 'unknown package manager' }
    if ($pending -eq '0') {
        $findings.Add((New-WslFinding -Status Info -Check 'Cached package updates' -Current "No updates shown by $packageSource" -Expected 'No pending updates after refreshing package metadata' -Guidance 'The audit does not refresh package metadata; refresh it regularly with the distribution package manager.'))
    }
    elseif ($pending -match '^\d+$') {
        $findings.Add((New-WslFinding -Status Review -Check 'Cached package updates' -Current "$pending package(s) shown by $packageSource" -Expected 'No pending updates' -Guidance 'Refresh package metadata and apply security/bug-fix updates using the distribution package manager.'))
    }
    else {
        $findings.Add((New-WslFinding -Status Unknown -Check 'Cached package updates' -Current $packageSource -Expected 'No pending updates' -Guidance 'Check for updates using the distribution package manager.'))
    }

    $listeners = if ($values.ContainsKey('LISTENERS')) { $values['LISTENERS'] } else { 'unavailable' }
    if (-not $listeners) { $listeners = 'None detected' }
    $findings.Add((New-WslFinding -Status Info -Check 'Listening network sockets' -Current $listeners -Expected 'Only intentional services listen on the network' -Guidance 'Review exposed services, especially with mirrored networking or port forwarding.'))
    $systemd = if ($values.ContainsKey('SYSTEMD')) { $values['SYSTEMD'] } else { 'default' }
    if ([string]::IsNullOrWhiteSpace($systemd)) { $systemd = 'not configured (default)' }
    $findings.Add((New-WslFinding -Status Info -Check 'systemd configuration' -Current $systemd -Expected 'Intentional for this distribution'))

    [pscustomobject][ordered]@{
        Name = $InventoryItem.Name
        State = $InventoryItem.State
        WslVersion = $InventoryItem.WslVersion
        IsDefault = $InventoryItem.IsDefault
        OsName = if ($values.ContainsKey('OS_NAME') -and $values['OS_NAME']) { $values['OS_NAME'] } else { 'Unknown Linux' }
        OsVersion = if ($values.ContainsKey('OS_VERSION')) { $values['OS_VERSION'] } else { '' }
        Kernel = if ($values.ContainsKey('KERNEL')) { $values['KERNEL'] } else { '' }
        Findings = $findings.ToArray()
    }
}

function Invoke-WslSecurityAudit {
    param([switch]$RunningOnly)

    $hostFindings = New-Object System.Collections.Generic.List[object]
    $command = Get-Command wsl.exe -ErrorAction SilentlyContinue
    if ($null -eq $command) {
        $hostFindings.Add((New-WslFinding -Status Info -Check 'WSL availability' -Current 'wsl.exe is not installed' -Expected 'Not required unless WSL is used'))
        return [pscustomobject][ordered]@{
            AuditedAt = (Get-Date).ToString('o'); WslAvailable = $false; WslVersion = 'Not installed'
            RunningOnly = [bool]$RunningOnly; ConfigurationPath = ''; HostFindings = $hostFindings.ToArray()
            DistributionDiscoveryError = ''; Distributions = @()
        }
    }

    $versionResult = Invoke-WslCommand -Arguments @('--version')
    $wslVersion = 'Unknown'
    if ($versionResult.ExitCode -eq 0 -and $versionResult.Text -match '(?m)(\d+\.\d+\.\d+(?:\.\d+)?)') {
        $wslVersion = $Matches[1]
    }
    $hostFindings.Add((New-WslFinding -Status Info -Check 'WSL installation' -Current "wsl.exe available; version $wslVersion" -Expected 'A supported, regularly updated WSL release'))

    $config = Get-Wsl2Configuration
    if ($config.Error) {
        $hostFindings.Add((New-WslFinding -Status Unknown -Check 'Global WSL configuration' -Current $config.Error -Expected '.wslconfig is readable and valid'))
    }
    else {
        $firewallConfigured = $config.Values.ContainsKey('firewall')
        $firewallValue = if ($firewallConfigured) { [string]$config.Values['firewall'] } else { 'true (default)' }
        if ($firewallConfigured -and $firewallValue -notmatch '^(?i:true|false)$') {
            $hostFindings.Add((New-WslFinding -Status Unknown -Check 'Windows Firewall integration' -Current $firewallValue -Expected 'Enabled (the default)' -Guidance 'Correct the invalid firewall value in .wslconfig or remove it to use the secure default.'))
        }
        elseif ($firewallValue -match '^(?i:false)$') {
            $hostFindings.Add((New-WslFinding -Status Review -Check 'Windows Firewall integration' -Current 'Disabled in .wslconfig' -Expected 'Enabled (the default)' -Guidance 'Remove firewall=false or set it to true, then run wsl --shutdown after saving work.'))
        }
        else {
            $hostFindings.Add((New-WslFinding -Status Pass -Check 'Windows Firewall integration' -Current $firewallValue -Expected 'Enabled (the default)'))
        }

        foreach ($setting in @('kernel', 'kernelModules', 'kernelCommandLine')) {
            if ($config.Values.ContainsKey($setting) -and $config.Values[$setting]) {
                $hostFindings.Add((New-WslFinding -Status Review -Check "Custom WSL $setting" -Current ([string]$config.Values[$setting]) -Expected 'Microsoft-serviced default unless explicitly required' -Guidance 'Verify the custom component source, update process, and security settings.'))
            }
        }
        $networking = if ($config.Values.ContainsKey('networkingMode')) { [string]$config.Values['networkingMode'] } else { 'NAT (default)' }
        $hostFindings.Add((New-WslFinding -Status Info -Check 'WSL networking mode' -Current $networking -Expected 'Intentional; firewall integration remains enabled'))
    }

    $inventory = Get-WslDistributionInventory
    $distributionAudits = New-Object System.Collections.Generic.List[object]
    if ($inventory.Success) {
        foreach ($item in $inventory.Items) {
            if ($RunningOnly -and $item.State -ne 'Running') {
                $skipReason = if ($item.State -eq 'Stopped') { 'Skipped because it was stopped' } else { 'Skipped because its running state could not be determined safely' }
                $distributionAudits.Add([pscustomobject][ordered]@{
                    Name = $item.Name; State = $item.State; WslVersion = $item.WslVersion; IsDefault = $item.IsDefault
                    OsName = 'Not inspected'; OsVersion = ''; Kernel = ''
                    Findings = @((New-WslFinding -Status Info -Check 'Distribution inspection' -Current $skipReason -Expected 'Run without -WslRunningOnly for a deeper audit'))
                })
            }
            else {
                $distributionAudits.Add((Get-WslDistributionAudit -InventoryItem $item))
            }
        }
    }

    [pscustomobject][ordered]@{
        AuditedAt = (Get-Date).ToString('o')
        WslAvailable = $true
        WslVersion = $wslVersion
        RunningOnly = [bool]$RunningOnly
        ConfigurationPath = $config.Path
        HostFindings = $hostFindings.ToArray()
        DistributionDiscoveryError = if ($inventory.Success) { '' } else { $inventory.Error }
        Distributions = $distributionAudits.ToArray()
    }
}

function Get-LocalPasswordPolicy {
    try {
        $computer = [ADSI]("WinNT://{0},computer" -f $env:COMPUTERNAME)
        [pscustomobject]@{
            MinimumLength = [int]$computer.psbase.InvokeGet('MinPasswordLength')
            HistoryLength = [int]$computer.psbase.InvokeGet('PasswordHistoryLength')
        }
    }
    catch {
        $null
    }
}

function Get-AuditPolicyText {
    param([Parameter(Mandatory = $true)][string]$SubcategoryGuid)

    $output = & auditpol.exe /get /subcategory:"$SubcategoryGuid" 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ($output -join ' ')
    }
    ($output -join "`n")
}

function Test-AuditPolicy {
    param(
        [Parameter(Mandatory = $true)][string]$SubcategoryGuid,
        [Parameter(Mandatory = $true)][ValidateSet('Success', 'Failure', 'SuccessAndFailure')][string]$Requirement,
        [Parameter(Mandatory = $true)][string]$ExpectedText
    )

    $text = Get-AuditPolicyText -SubcategoryGuid $SubcategoryGuid
    # auditpol localizes labels. /r is not consistently numeric across Windows builds,
    # so recognize common English output and return Unknown rather than a false result.
    $hasSuccess = $text -match '(?im)Success'
    $hasFailure = $text -match '(?im)Failure'
    $pass = switch ($Requirement) {
        'Success' { $hasSuccess }
        'Failure' { $hasFailure }
        'SuccessAndFailure' { $hasSuccess -and $hasFailure }
    }

    if (-not $hasSuccess -and -not $hasFailure -and $text -notmatch '(?im)No Auditing') {
        return New-CheckResult -Status Unknown -Current 'The localized auditpol output could not be parsed.' -Expected $ExpectedText -Evidence $text.Trim()
    }
    if ($pass) {
        return New-CheckResult -Status Pass -Current $ExpectedText -Expected $ExpectedText -Evidence $text.Trim()
    }
    New-CheckResult -Status Fail -Current 'Required success/failure events are not all enabled.' -Expected $ExpectedText -Evidence $text.Trim()
}

function Set-AuditPolicyValue {
    param(
        [Parameter(Mandatory = $true)][string]$SubcategoryGuid,
        [bool]$Success,
        [bool]$Failure
    )

    $successValue = if ($Success) { 'enable' } else { 'disable' }
    $failureValue = if ($Failure) { 'enable' } else { 'disable' }
    $output = & auditpol.exe /set /subcategory:"$SubcategoryGuid" /success:$successValue /failure:$failureValue 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ($output -join ' ')
    }
}

function Get-SecurityControls {
    $baseline = $script:BaselineUrl
    $controls = New-Object System.Collections.Generic.List[object]

    $controls.Add((New-SecurityControl -Id 'PLAT-001' -Category 'Platform' -Title 'UEFI Secure Boot is enabled' -Severity High `
        -WhyItMatters 'Secure Boot verifies trusted boot components before Windows starts and reduces bootkit and pre-OS tampering risk.' `
        -Affected 'Changing firmware boot mode or keys can prevent the device from booting. BitLocker may request its recovery key after firmware changes.' `
        -Recommendation 'Back up the BitLocker recovery key, suspend BitLocker, then restart into Settings > System > Recovery > Advanced startup > UEFI Firmware Settings. Enable UEFI/Secure Boot using the device vendor instructions.' `
        -Check {
            try {
                $enabled = Confirm-SecureBootUEFI -ErrorAction Stop
                if ($enabled) { New-CheckResult -Status Pass -Current 'Enabled' -Expected 'Enabled' -Evidence 'Confirm-SecureBootUEFI returned True' }
                else { New-CheckResult -Status Fail -Current 'Disabled' -Expected 'Enabled' -Evidence 'Confirm-SecureBootUEFI returned False' }
            }
            catch {
                if ($_.Exception.Message -match 'not supported|BIOS|UEFI') {
                    New-CheckResult -Status NotApplicable -Current 'Secure Boot API is unavailable (legacy BIOS or unsupported platform).' -Expected 'UEFI Secure Boot enabled' -Evidence $_.Exception.Message
                }
                else { throw }
            }
        } -FixRisk Manual -FixImpact 'Requires a firmware change and can affect bootability or trigger BitLocker recovery.' `
        -Rollback 'Restore the previous firmware boot mode/Secure Boot state. Keep the BitLocker recovery key available.' -RestartRequired $true `
        -Source 'Microsoft secured-core and Windows security baseline guidance' -SourceUrl 'https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-highly-secure-11'))

    $controls.Add((New-SecurityControl -Id 'PLAT-002' -Category 'Platform' -Title 'TPM 2.0 is present and ready' -Severity High `
        -WhyItMatters 'TPM 2.0 provides a hardware root of trust used by BitLocker, Windows Hello, measured boot, and credential protection.' `
        -Affected 'Initializing or clearing a TPM can invalidate TPM-protected credentials and may trigger BitLocker recovery.' `
        -Recommendation 'Open Windows Security > Device security > Security processor details. If absent, enable TPM 2.0 (Intel PTT or AMD fTPM) in UEFI firmware. Never clear the TPM without recovery keys and a credential recovery plan.' `
        -Check {
            if (-not (Get-Command Get-Tpm -ErrorAction SilentlyContinue)) {
                return New-CheckResult -Status NotApplicable -Current 'Get-Tpm is unavailable.' -Expected 'TPM 2.0 present and ready'
            }
            $tpm = Get-Tpm -ErrorAction Stop
            if ($null -eq $tpm -or $tpm.PSObject.Properties.Name -notcontains 'TpmPresent') {
                return New-CheckResult -Status Unknown -Current 'TPM state could not be read; run the audit as Administrator.' -Expected 'TPM 2.0 present and ready'
            }
            $version = ''
            try {
                $spec = (Get-CimInstance -Namespace 'root\CIMV2\Security\MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction Stop).SpecVersion
                $version = [string]$spec
            } catch { $version = 'Unknown' }
            $current = "Present=$($tpm.TpmPresent); Ready=$($tpm.TpmReady); Spec=$version"
            if ($tpm.TpmPresent -and $tpm.TpmReady -and $version -match '2\.0') {
                New-CheckResult -Status Pass -Current $current -Expected 'TPM 2.0 present and ready'
            }
            else { New-CheckResult -Status Fail -Current $current -Expected 'TPM 2.0 present and ready' }
        } -FixRisk Manual -FixImpact 'Firmware and TPM ownership changes may affect BitLocker and Windows Hello.' `
        -Rollback 'Restore the prior firmware TPM setting only if your recovery plan requires it. Do not clear the TPM casually.' `
        -RestartRequired $true -Source 'Windows 11 secured-core PC requirements' -SourceUrl 'https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-highly-secure-11'))

    $controls.Add((New-SecurityControl -Id 'PLAT-003' -Category 'Platform' -Title 'Operating-system drive is protected by BitLocker' -Severity High `
        -WhyItMatters 'Full-volume encryption protects offline data if a device or drive is lost, stolen, or removed.' `
        -Affected 'Enabling encryption consumes time and I/O. Firmware, boot, or TPM changes can require the recovery key. A lost recovery key can cause permanent data loss.' `
        -Recommendation 'Back up the recovery key to your Microsoft account and keep a separate protected offline copy, then use Settings > Privacy & security > Device encryption, or Control Panel > BitLocker Drive Encryption.' `
        -Check {
            if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
                return New-CheckResult -Status NotApplicable -Current 'BitLocker PowerShell module is unavailable on this edition.' -Expected 'OS volume fully encrypted with protection on'
            }
            $volume = Get-BitLockerVolume -MountPoint $env:SystemDrive
            $current = "VolumeStatus=$($volume.VolumeStatus); ProtectionStatus=$($volume.ProtectionStatus); Encryption=$($volume.EncryptionPercentage)%"
            if ($volume.VolumeStatus -eq 'FullyEncrypted' -and [string]$volume.ProtectionStatus -eq 'On') {
                New-CheckResult -Status Pass -Current $current -Expected 'FullyEncrypted; Protection On' -Evidence $env:SystemDrive
            }
            else { New-CheckResult -Status Fail -Current $current -Expected 'FullyEncrypted; Protection On' -Evidence $env:SystemDrive }
        } -FixRisk Manual -FixImpact 'Encryption can take time. The TUI will not generate or upload a recovery key automatically because losing every key copy can permanently lock you out of the data.' `
        -Rollback 'Decrypt only after verifying your file backup and recovery key. Use Manage BitLocker > Turn off BitLocker.' `
        -EnterpriseNote 'On a managed PC, recovery keys may need to be escrowed to Microsoft Entra ID or Active Directory instead of a personal Microsoft account.' `
        -RestartRequired $true -Source 'Microsoft BitLocker overview' -SourceUrl 'https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/'))

    $controls.Add((New-SecurityControl -Id 'PLAT-004' -Category 'Platform' -Title 'Virtualization-based security and Memory Integrity are running' -Severity High `
        -WhyItMatters 'Virtualization-based security isolates sensitive Windows components; Memory Integrity uses it to prevent untrusted or malicious kernel-mode code from loading.' `
        -Affected 'Memory Integrity can expose incompatible drivers, affect older virtualization software, and have a small performance cost on some hardware.' `
        -Recommendation 'First install Windows and driver updates. Then open Windows Security > Device security > Core isolation details and enable Memory integrity. Restart and confirm that devices and applications still work.' `
        -Check {
            $dg = Get-DeviceGuardState
            if ($null -eq $dg) { return New-CheckResult -Status Unknown -Current 'Win32_DeviceGuard state unavailable.' -Expected 'VBS running; Memory Integrity running' }
            $vbsRunning = [int]$dg.VirtualizationBasedSecurityStatus -eq 2
            $memoryIntegrityRunning = @($dg.SecurityServicesRunning) -contains 2
            $current = "VBSStatus=$($dg.VirtualizationBasedSecurityStatus); RunningServices=$(@($dg.SecurityServicesRunning) -join ',')"
            if ($vbsRunning -and $memoryIntegrityRunning) { New-CheckResult -Status Pass -Current $current -Expected 'VBS running; Memory Integrity running' }
            else { New-CheckResult -Status Fail -Current $current -Expected 'VBS running; Memory Integrity running' }
        } -FixRisk Manual -FixImpact 'Compatibility-sensitive and requires a restart. Windows Security can list drivers that prevent Memory Integrity from being enabled.' `
        -Rollback 'If a required device stops working, update or remove its incompatible driver. Memory Integrity can be turned off from the same Core isolation screen if necessary.' `
        -EnterpriseNote 'The Microsoft enterprise baseline also enables Credential Guard to protect derived domain credentials. It is not treated as a mandatory personal-PC failure here.' `
        -RestartRequired $true -Source 'Windows 11 25H2 baseline: Device Guard' -SourceUrl $baseline))

    $controls.Add((New-SecurityControl -Id 'DEF-001' -Category 'Microsoft Defender' -Title 'Defender real-time, behavior, script, and download scanning are active' -Severity Critical `
        -WhyItMatters 'These engines inspect files, behavior, scripts, and downloaded content before or while it executes.' `
        -Affected 'Enabling Defender can conflict with a third-party antivirus product, increase scan activity, or reveal previously excluded threats.' `
        -Recommendation 'If Microsoft Defender is your antivirus, enable all four protections. If you intentionally installed a reputable third-party antivirus, confirm it is healthy instead of forcing Defender active mode.' `
        -Check {
            if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
                return New-CheckResult -Status NotApplicable -Current 'Microsoft Defender cmdlets are unavailable.' -Expected 'All real-time scanning layers enabled'
            }
            $status = Get-MpComputerStatus
            $pref = Get-MpPreference
            $values = [ordered]@{
                AntivirusEnabled = $status.AntivirusEnabled
                RealTimeProtection = $status.RealTimeProtectionEnabled
                BehaviorMonitoring = -not [bool]$pref.DisableBehaviorMonitoring
                ScriptScanning = -not [bool]$pref.DisableScriptScanning
                DownloadScanning = -not [bool]$pref.DisableIOAVProtection
            }
            $bad = @($values.GetEnumerator() | Where-Object { -not [bool]$_.Value })
            $current = ($values.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; '
            if ($bad.Count -eq 0) { New-CheckResult -Status Pass -Current $current -Expected 'All enabled' }
            else { New-CheckResult -Status Fail -Current $current -Expected 'All enabled' -Evidence 'A third-party AV may intentionally place Defender in passive mode.' }
        } -Fix {
            Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableScriptScanning $false -DisableIOAVProtection $false
        } -FixRisk Moderate -FixImpact 'May conflict with third-party antivirus and can increase CPU/disk activity while threats are scanned.' `
        -Rollback 'Restore the previous antivirus configuration. Do not leave the device without a working real-time antivirus provider.' `
        -EnterpriseNote 'On a managed system, confirm whether Defender is intentionally in passive mode behind an organization-approved antivirus before changing it.' `
        -Source 'Windows 11 25H2 baseline: Defender scanning protections' -SourceUrl $baseline))

    $controls.Add((New-SecurityControl -Id 'DEF-002' -Category 'Microsoft Defender' -Title 'Defender cloud-delivered protection is enabled' -Severity High `
        -WhyItMatters 'Cloud protection provides rapidly updated verdicts and blocking for new or emerging threats.' `
        -Affected 'File metadata and, depending on separate sample-submission policy, samples may be sent to Microsoft. Connectivity is required for timely verdicts.' `
        -Recommendation 'Enable Microsoft Active Protection Service participation and block-at-first-seen. Review privacy and sample-submission policy separately.' `
        -Check {
            if (-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)) {
                return New-CheckResult -Status NotApplicable -Current 'Microsoft Defender cmdlets are unavailable.' -Expected 'Cloud protection enabled'
            }
            $pref = Get-MpPreference
            $maps = [int]$pref.MAPSReporting
            $firstSeen = -not [bool]$pref.DisableBlockAtFirstSeen
            $current = "MAPSReporting=$maps; BlockAtFirstSeen=$firstSeen"
            if ($maps -gt 0 -and $firstSeen) { New-CheckResult -Status Pass -Current $current -Expected 'MAPS enabled; Block at first sight enabled' }
            else { New-CheckResult -Status Fail -Current $current -Expected 'MAPS enabled; Block at first sight enabled' }
        } -Fix { Set-MpPreference -MAPSReporting Advanced -DisableBlockAtFirstSeen $false } `
        -FixRisk Moderate -FixImpact 'Uses Microsoft cloud lookups; privacy and network policies should be reviewed.' `
        -Rollback 'Restore the prior Defender cloud protection values from the backup or management policy.' `
        -Source 'Windows 11 25H2 baseline: Allow Cloud Protection' -SourceUrl $baseline))

    $controls.Add((New-SecurityControl -Id 'DEF-003' -Category 'Microsoft Defender' -Title 'Potentially unwanted application protection blocks detections' -Severity Medium `
        -WhyItMatters 'PUA protection blocks bundlers, adware, cryptomining software, and other unwanted software that increases attack surface.' `
        -Affected 'Some installers, administrative utilities, or monetized freeware can be blocked and must be reviewed in Protection History.' `
        -Recommendation 'Set PUA protection to Enabled/block mode and handle justified exceptions through managed policy.' `
        -Check {
            if (-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)) {
                return New-CheckResult -Status NotApplicable -Current 'Microsoft Defender cmdlets are unavailable.' -Expected 'PUAProtection=1 (Enabled)'
            }
            $value = [int](Get-MpPreference).PUAProtection
            if ($value -eq 1) { New-CheckResult -Status Pass -Current 'Enabled (block)' -Expected 'Enabled (block)' }
            else { New-CheckResult -Status Fail -Current "PUAProtection=$value" -Expected 'PUAProtection=1 (Enabled/block)' }
        } -Fix { Set-MpPreference -PUAProtection Enabled } -FixRisk Low `
        -FixImpact 'May block unwanted or low-reputation installers and utilities.' -Rollback 'Set PUA protection back to the backed-up value through Defender policy.' `
        -Source 'Windows 11 25H2 baseline: PUA Protection' -SourceUrl $baseline))

    $controls.Add((New-SecurityControl -Id 'DEF-004' -Category 'Microsoft Defender' -Title 'Defender Network Protection is in block mode' -Severity High `
        -WhyItMatters 'Network Protection blocks connections from applications to malicious or low-reputation destinations.' `
        -Affected 'Legacy or line-of-business applications can be blocked from reaching destinations Microsoft classifies as unsafe.' `
        -Recommendation 'Deploy Network Protection in block mode after reviewing audit-mode events for business applications.' `
        -Check {
            if (-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)) {
                return New-CheckResult -Status NotApplicable -Current 'Microsoft Defender cmdlets are unavailable.' -Expected 'EnableNetworkProtection=1 (block)'
            }
            $value = [int](Get-MpPreference).EnableNetworkProtection
            if ($value -eq 1) { New-CheckResult -Status Pass -Current 'Block mode' -Expected 'Block mode' }
            else { New-CheckResult -Status Fail -Current "EnableNetworkProtection=$value" -Expected 'EnableNetworkProtection=1 (block)' }
        } -Fix { Set-MpPreference -EnableNetworkProtection Enabled } -FixRisk Moderate `
        -FixImpact 'May block legacy applications from reaching low-reputation or malicious destinations.' `
        -Rollback 'Use Set-MpPreference -EnableNetworkProtection AuditMode while investigating, or restore managed policy.' `
        -Source 'Windows 11 25H2 baseline: Enable Network Protection' -SourceUrl $baseline))

    $controls.Add((New-SecurityControl -Id 'NET-001' -Category 'Network' -Title 'Windows Firewall is enabled with default inbound blocking on every profile' -Severity Critical `
        -WhyItMatters 'The host firewall limits unsolicited inbound access on domain, private, and public networks.' `
        -Affected 'Applications relying on unsolicited inbound traffic need explicit allow rules. Existing allow rules remain in place.' `
        -Recommendation 'Enable Domain, Private, and Public profiles; block inbound by default and permit only documented services.' `
        -Check {
            if (-not (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
                return New-CheckResult -Status NotApplicable -Current 'NetSecurity module is unavailable.' -Expected 'All profiles enabled; inbound default Block'
            }
            $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
            $bad = @($profiles | Where-Object { -not $_.Enabled -or [string]$_.DefaultInboundAction -ne 'Block' })
            $current = ($profiles | ForEach-Object { "$($_.Name): Enabled=$($_.Enabled), Inbound=$($_.DefaultInboundAction)" }) -join '; '
            if ($bad.Count -eq 0) { New-CheckResult -Status Pass -Current $current -Expected 'All enabled; inbound Block' }
            else { New-CheckResult -Status Fail -Current $current -Expected 'All enabled; inbound Block' }
        } -Fix { Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block } `
        -FixRisk Moderate -FixImpact 'Unsolicited inbound connections without explicit allow rules will stop working.' `
        -Rollback 'Import the saved firewall .wfw backup or restore the prior profile state through policy.' `
        -EnterpriseNote 'The Domain firewall profile is configured defensively but is normally inactive on a personal workgroup PC. It becomes relevant if the device later joins an Active Directory domain.' `
        -Source 'Windows 11 25H2 baseline: Firewall profiles' -SourceUrl $baseline))

    $controls.Add((New-SecurityControl -Id 'NET-002' -Category 'Network' -Title 'Windows Firewall logs allowed and dropped traffic with adequate capacity' -Severity Medium `
        -WhyItMatters 'Firewall logs provide evidence for incident investigation and help identify unexpected inbound or outbound paths.' `
        -Affected 'Successful-connection logging can increase disk writes and log volume. Each profile log can grow to 16 MB.' `
        -Recommendation 'Enable allowed and dropped-packet logging for all profiles and use the 16,384 KB baseline maximum.' `
        -Check {
            if (-not (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
                return New-CheckResult -Status NotApplicable -Current 'NetSecurity module is unavailable.' -Expected 'Allowed/dropped logging on; max size >= 16384 KB'
            }
            $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
            $bad = @($profiles | Where-Object { -not $_.LogAllowed -or -not $_.LogBlocked -or [int]$_.LogMaxSizeKilobytes -lt 16384 })
            $current = ($profiles | ForEach-Object { "$($_.Name): Allowed=$($_.LogAllowed), Dropped=$($_.LogBlocked), KB=$($_.LogMaxSizeKilobytes)" }) -join '; '
            if ($bad.Count -eq 0) { New-CheckResult -Status Pass -Current $current -Expected 'Allowed=True; Dropped=True; KB>=16384' }
            else { New-CheckResult -Status Fail -Current $current -Expected 'Allowed=True; Dropped=True; KB>=16384' }
        } -Fix { Set-NetFirewallProfile -Profile Domain,Private,Public -LogAllowed True -LogBlocked True -LogMaxSizeKilobytes 16384 } `
        -FixRisk Low -FixImpact 'Increases firewall log volume and disk writes; maximum space is bounded per profile.' `
        -Rollback 'Import the saved firewall .wfw backup or restore prior logging settings through policy.' `
        -Source 'Windows 11 25H2 baseline: Firewall logging' -SourceUrl $baseline))

    $controls.Add((New-SecurityControl -Id 'NET-003' -Category 'Network' -Title 'SMB version 1 is disabled' -Severity Critical `
        -WhyItMatters 'SMBv1 is obsolete and lacks modern protections. Its presence enables downgrade and legacy-protocol attack paths.' `
        -Affected 'Very old NAS devices, printers, scanners, and legacy systems that only support SMBv1 will no longer connect.' `
        -Recommendation 'Disable the SMB1 optional feature and server protocol. Upgrade or isolate devices that still require SMBv1.' `
        -Check {
            $signals = @()
            $bad = $false
            if (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue) {
                $feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
                if ($null -ne $feature) {
                    $signals += "OptionalFeature=$($feature.State)"
                    if ([string]$feature.State -notmatch '^Disabled') { $bad = $true }
                }
            }
            if (Get-Command Get-SmbServerConfiguration -ErrorAction SilentlyContinue) {
                $server = Get-SmbServerConfiguration
                $signals += "ServerEnableSMB1=$($server.EnableSMB1Protocol)"
                if ($server.EnableSMB1Protocol) { $bad = $true }
            }
            if ($signals.Count -eq 0) { return New-CheckResult -Status Unknown -Current 'SMB configuration could not be queried.' -Expected 'SMB1 disabled' }
            if ($bad) { New-CheckResult -Status Fail -Current ($signals -join '; ') -Expected 'SMB1 disabled' }
            else { New-CheckResult -Status Pass -Current ($signals -join '; ') -Expected 'SMB1 disabled' }
        } -Fix {
            if (Get-Command Set-SmbServerConfiguration -ErrorAction SilentlyContinue) { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force }
            if (Get-Command Disable-WindowsOptionalFeature -ErrorAction SilentlyContinue) { $null = Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart }
        } -FixRisk Moderate -FixImpact 'Breaks connectivity to devices that only support SMBv1; restart may be required.' `
        -Rollback 'Prefer upgrading the legacy device. If formally accepted, restore only the required SMB1 component from the Windows Features UI.' `
        -RestartRequired $true -Source 'Windows 11 25H2 baseline: SMB v1 client and server' -SourceUrl $baseline))

    $controls.Add((New-SecurityControl -Id 'NET-004' -Category 'Network' -Title 'SMB client and server require signing' -Severity High `
        -WhyItMatters 'SMB signing helps prevent tampering and relay attacks by authenticating SMB messages.' `
        -Affected 'Unsigned legacy SMB servers or clients will fail to connect. Signing can add modest overhead.' `
        -Recommendation 'Require security signatures for both the SMB client and SMB server, after inventorying incompatible legacy systems.' `
        -Check {
            if (-not (Get-Command Get-SmbClientConfiguration -ErrorAction SilentlyContinue) -or -not (Get-Command Get-SmbServerConfiguration -ErrorAction SilentlyContinue)) {
                return New-CheckResult -Status NotApplicable -Current 'SMB cmdlets are unavailable.' -Expected 'Client and server RequireSecuritySignature=True'
            }
            $client = Get-SmbClientConfiguration
            $server = Get-SmbServerConfiguration
            $current = "Client=$($client.RequireSecuritySignature); Server=$($server.RequireSecuritySignature)"
            if ($client.RequireSecuritySignature -and $server.RequireSecuritySignature) { New-CheckResult -Status Pass -Current $current -Expected 'Client=True; Server=True' }
            else { New-CheckResult -Status Fail -Current $current -Expected 'Client=True; Server=True' }
        } -Fix {
            Set-SmbClientConfiguration -RequireSecuritySignature $true -Confirm:$false
            Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
        } -FixRisk Moderate -FixImpact 'Unsigned legacy SMB peers can no longer connect.' `
        -Rollback 'Import the saved registry backup or restore the previous SMB signing policy after documenting the exception.' `
        -Source 'Windows 11 25H2 baseline: Microsoft network client/server signing' -SourceUrl $baseline))

    $controls.Add((New-SecurityControl -Id 'NET-005' -Category 'Network' -Title 'Insecure SMB guest logons are disabled' -Severity High `
        -WhyItMatters 'Guest SMB logons do not provide normal authentication guarantees and can expose users to malicious file servers.' `
        -Affected 'Anonymous access to older NAS devices or shares can stop working.' `
        -Recommendation 'Disable insecure guest logons and configure authenticated accounts on storage devices.' `
        -Check {
            if (-not (Get-Command Get-SmbClientConfiguration -ErrorAction SilentlyContinue)) {
                return New-CheckResult -Status NotApplicable -Current 'SMB client cmdlets are unavailable.' -Expected 'EnableInsecureGuestLogons=False'
            }
            $value = [bool](Get-SmbClientConfiguration).EnableInsecureGuestLogons
            if (-not $value) { New-CheckResult -Status Pass -Current 'Disabled' -Expected 'Disabled' }
            else { New-CheckResult -Status Fail -Current 'Enabled' -Expected 'Disabled' }
        } -Fix { Set-SmbClientConfiguration -EnableInsecureGuestLogons $false -Confirm:$false } `
        -FixRisk Moderate -FixImpact 'Anonymous/guest-only SMB shares will stop working until authentication is configured.' `
        -Rollback 'Restore only as a documented temporary exception; isolate the legacy share and migrate it.' `
        -Source 'Windows 11 25H2 baseline: Enable Insecure Guest Logons' -SourceUrl $baseline))

    $controls.Add((New-SecurityControl -Id 'NET-006' -Category 'Network' -Title 'LLMNR multicast name resolution is disabled' -Severity High `
        -WhyItMatters 'Attackers on a local network can spoof LLMNR responses to capture or relay Windows authentication.' `
        -Affected 'Name resolution for devices that are missing from DNS and depend on LLMNR can stop working.' `
        -Recommendation 'Disable LLMNR and use managed DNS. Validate name resolution for printers and legacy devices first.' `
        -Check { Test-RegistryDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Expected 0 -ExpectedText '0 (LLMNR disabled)' } `
        -Fix { Set-RegistryDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Value 0 } `
        -FixRisk Moderate -FixImpact 'Devices that rely on multicast fallback rather than DNS may no longer resolve by name.' `
        -Rollback 'Import the pre-change registry backup or remove the EnableMulticast policy value.' `
        -Source 'Windows 11 25H2 baseline: Turn off multicast name resolution' -SourceUrl $baseline))

    $controls.Add((New-SecurityControl -Id 'NET-007' -Category 'Network' -Title 'LAN Manager authentication is restricted to NTLMv2' -Severity High `
        -WhyItMatters 'LM and NTLMv1 use weak authentication that is vulnerable to cracking and downgrade attacks.' `
        -Affected 'Legacy devices or applications that cannot use NTLMv2 or Kerberos may fail authentication.' `
        -Recommendation 'Send NTLMv2 responses only and refuse LM/NTLM (LmCompatibilityLevel 5), after testing legacy dependencies.' `
        -Check { Test-RegistryDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Expected 5 -ExpectedText '5 (NTLMv2 only; refuse LM and NTLM)' } `
        -Fix { Set-RegistryDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Value 5 } `
        -FixRisk High -FixImpact 'Legacy applications and older NAS devices may fail authentication.' `
        -Rollback 'Import the saved LSA registry backup or restore the previous authentication level.' `
        -EnterpriseNote 'On a domain-connected PC, old trusts or legacy domain services can also depend on weaker NTLM behavior and must be tested first.' `
        -Source 'Windows 11 25H2 baseline: LAN Manager authentication level' -SourceUrl $baseline))

    $controls.Add((New-SecurityControl -Id 'ID-001' -Category 'Identity' -Title 'User Account Control uses Admin Approval Mode and secure-desktop consent' -Severity High `
        -WhyItMatters 'UAC limits silent elevation and isolates consent prompts from lower-integrity processes.' `
        -Affected 'Administrators will receive consent prompts. Disabling UAC-compatible behavior can affect legacy applications.' `
        -Recommendation 'Enable UAC, Admin Approval Mode, secure-desktop prompting, and consent prompts for administrators.' `
        -Check {
            $path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            $expected = [ordered]@{ EnableLUA = 1; FilterAdministratorToken = 1; ConsentPromptBehaviorAdmin = 2; PromptOnSecureDesktop = 1 }
            $bad = @()
            $current = @()
            foreach ($entry in $expected.GetEnumerator()) {
                $state = Get-RegistryValueState -Path $path -Name $entry.Key
                $valueText = if ($state.Exists) { [string]$state.Value } else { 'missing' }
                $current += "$($entry.Key)=$valueText"
                if (-not $state.Exists -or [int]$state.Value -ne [int]$entry.Value) { $bad += $entry.Key }
            }
            if ($bad.Count -eq 0) { New-CheckResult -Status Pass -Current ($current -join '; ') -Expected 'EnableLUA=1; FilterAdministratorToken=1; Consent=2; SecureDesktop=1' }
            else { New-CheckResult -Status Fail -Current ($current -join '; ') -Expected 'EnableLUA=1; FilterAdministratorToken=1; Consent=2; SecureDesktop=1' -Evidence "Noncompliant: $($bad -join ', ')" }
        } -Fix {
            $path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            Set-RegistryDword -Path $path -Name 'EnableLUA' -Value 1
            Set-RegistryDword -Path $path -Name 'FilterAdministratorToken' -Value 1
            Set-RegistryDword -Path $path -Name 'ConsentPromptBehaviorAdmin' -Value 2
            Set-RegistryDword -Path $path -Name 'PromptOnSecureDesktop' -Value 1
        } -FixRisk Moderate -FixImpact 'Administrators receive secure-desktop consent prompts; restart is required for EnableLUA or built-in Administrator changes.' `
        -Rollback 'Import the saved Policies\System registry backup or restore values through Group Policy.' `
        -RestartRequired $true -Source 'Windows 11 25H2 baseline: User Account Control' -SourceUrl $baseline))

    $controls.Add((New-SecurityControl -Id 'ID-002' -Category 'Identity' -Title 'Built-in Guest account is disabled' -Severity High `
        -WhyItMatters 'A shared guest identity weakens accountability and can provide unintended local or network access.' `
        -Affected 'Workflows that intentionally use the built-in Guest account will stop working.' `
        -Recommendation 'Disable the built-in account with RID 501 and create individually attributable accounts where access is needed.' `
        -Check {
            $guest = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" | Where-Object { $_.SID -match '-501$' } | Select-Object -First 1
            if ($null -eq $guest) { return New-CheckResult -Status Unknown -Current 'Built-in Guest account could not be identified.' -Expected 'Disabled' }
            if ($guest.Disabled) { New-CheckResult -Status Pass -Current "Disabled ($($guest.Name))" -Expected 'Disabled' -Evidence $guest.SID }
            else { New-CheckResult -Status Fail -Current "Enabled ($($guest.Name))" -Expected 'Disabled' -Evidence $guest.SID }
        } -Fix {
            $guest = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" | Where-Object { $_.SID -match '-501$' } | Select-Object -First 1
            if ($null -eq $guest) { throw 'Built-in Guest account could not be identified.' }
            if (Get-Command Disable-LocalUser -ErrorAction SilentlyContinue) { Disable-LocalUser -Name $guest.Name }
            else { $output = & net.exe user "$($guest.Name)" /active:no 2>&1; if ($LASTEXITCODE -ne 0) { throw ($output -join ' ') } }
        } -FixRisk Low -FixImpact 'Any workflow using the shared built-in Guest identity will stop working.' `
        -Rollback 'Re-enable only if a documented exception requires it, then replace it with attributable access.' `
        -Source 'Microsoft security baseline account policy principles' -SourceUrl $script:SctUrl))

    $controls.Add((New-SecurityControl -Id 'ID-003' -Category 'Identity' -Title 'Local password policy requires 14 characters and 24-password history' -Severity Medium `
        -WhyItMatters 'Longer passwords and history reduce guessing risk and discourage immediate password reuse.' `
        -Affected 'The setting applies when users next set local-account passwords. Existing shorter passwords are not automatically changed.' `
        -Recommendation 'Use at least 14 characters and remember 24 passwords. Prefer Windows Hello or passkeys and do not impose routine password expiry without evidence of compromise.' `
        -Check {
            $policy = Get-LocalPasswordPolicy
            if ($null -eq $policy) { return New-CheckResult -Status Unknown -Current 'Local password policy could not be read through the WinNT provider.' -Expected 'MinimumLength>=14; HistoryLength>=24' }
            $current = "MinimumLength=$($policy.MinimumLength); HistoryLength=$($policy.HistoryLength)"
            if ($policy.MinimumLength -ge 14 -and $policy.HistoryLength -ge 24) { New-CheckResult -Status Pass -Current $current -Expected 'MinimumLength>=14; HistoryLength>=24' }
            else { New-CheckResult -Status Fail -Current $current -Expected 'MinimumLength>=14; HistoryLength>=24' }
        } -Fix {
            $output = & net.exe accounts /minpwlen:14 /uniquepw:24 2>&1
            if ($LASTEXITCODE -ne 0) { throw ($output -join ' ') }
        } -FixRisk Moderate -FixImpact 'Future local password changes must satisfy the stronger policy; service or kiosk account procedures may need updates.' `
        -Rollback 'Restore the prior local password policy using Local Security Policy or the captured policy documentation.' `
        -EnterpriseNote 'For a domain-joined PC, domain password policy normally takes precedence for domain accounts. This check covers the computer local-account policy.' `
        -Source 'Windows 11 25H2 baseline: Device password history and minimum length' -SourceUrl $baseline))

    $controls.Add((New-SecurityControl -Id 'ID-004' -Category 'Identity' -Title 'Machine inactivity lock is 15 minutes or less' -Severity Medium `
        -WhyItMatters 'Automatic locking reduces unauthorized access when a signed-in device is left unattended.' `
        -Affected 'Interactive sessions lock after 15 minutes of inactivity and users must sign in again.' `
        -Recommendation 'Set the machine inactivity limit to 900 seconds or less, balancing physical risk and workflow needs.' `
        -Check {
            $state = Get-RegistryValueState -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'InactivityTimeoutSecs'
            if (-not $state.Exists) { return New-CheckResult -Status Fail -Current 'Not configured' -Expected '1-900 seconds' }
            $value = [int]$state.Value
            if ($value -ge 1 -and $value -le 900) { New-CheckResult -Status Pass -Current "$value seconds" -Expected '1-900 seconds' }
            else { New-CheckResult -Status Fail -Current "$value seconds" -Expected '1-900 seconds' }
        } -Fix { Set-RegistryDword -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'InactivityTimeoutSecs' -Value 900 } `
        -FixRisk Low -FixImpact 'The session locks after 15 idle minutes; long-running foreground tasks continue but the user must sign in again.' `
        -Rollback 'Import the saved Policies\System registry backup or choose a different timeout that fits your home environment.' `
        -Source 'Windows 11 25H2 baseline: Interactive logon machine inactivity limit' -SourceUrl $baseline))

    $controls.Add((New-SecurityControl -Id 'ID-005' -Category 'Identity' -Title 'WDigest does not store reusable logon credentials' -Severity High `
        -WhyItMatters 'Allowing WDigest reusable credentials can expose plaintext-equivalent secrets in LSASS memory.' `
        -Affected 'Very old applications that explicitly require WDigest single sign-on may need updated authentication.' `
        -Recommendation 'Keep UseLogonCredential disabled. Missing is treated as the secure default on supported Windows 11 builds.' `
        -Check { Test-RegistryDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Expected 0 -MissingIsExpected $true -ExpectedText '0 or secure default' } `
        -Fix { Set-RegistryDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Value 0 } `
        -FixRisk Low -FixImpact 'Legacy WDigest single sign-on scenarios can require users to reauthenticate.' `
        -Rollback 'Import the saved WDigest key only for a formally accepted legacy requirement.' `
        -Source 'Microsoft security baseline: WDigest authentication' -SourceUrl $baseline))

    $controls.Add((New-SecurityControl -Id 'APP-001' -Category 'Application protection' -Title 'Microsoft Defender SmartScreen is enabled and bypass is blocked' -Severity High `
        -WhyItMatters 'SmartScreen warns or blocks malicious, phishing, and low-reputation files before execution.' `
        -Affected 'You cannot bypass warnings for files classified as unsafe; uncommon utilities may need a signed or better-reputation download source.' `
        -Recommendation 'Enable Explorer SmartScreen and prevent users from overriding file warnings.' `
        -Check {
            $path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
            $enabled = Get-RegistryValueState -Path $path -Name 'EnableSmartScreen'
            $level = Get-RegistryValueState -Path $path -Name 'ShellSmartScreenLevel'
            $override = Get-RegistryValueState -Path $path -Name 'PreventOverrideForFilesInShell'
            $levelValue = if ($level.Exists) { [string]$level.Value } else { 'missing' }
            $current = "Enable=$($enabled.Value); Level=$levelValue; PreventOverride=$($override.Value)"
            if ($enabled.Exists -and [int]$enabled.Value -eq 1 -and $override.Exists -and [int]$override.Value -eq 1) {
                New-CheckResult -Status Pass -Current $current -Expected 'Enable=1; PreventOverride=1'
            }
            else { New-CheckResult -Status Fail -Current $current -Expected 'Enable=1; PreventOverride=1' }
        } -Fix {
            $path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
            Set-RegistryDword -Path $path -Name 'EnableSmartScreen' -Value 1
            if (-not (Test-Path -LiteralPath $path)) { $null = New-Item -Path $path -Force }
            $null = New-ItemProperty -LiteralPath $path -Name 'ShellSmartScreenLevel' -PropertyType String -Value 'Block' -Force
            Set-RegistryDword -Path $path -Name 'PreventOverrideForFilesInShell' -Value 1
        } -FixRisk Moderate -FixImpact 'You cannot bypass SmartScreen file warnings; uncommon utilities may need signing or a more reputable download source.' `
        -Rollback 'Import the saved Windows\System policy key or restore your previous SmartScreen setting.' `
        -Source 'Windows 11 25H2 baseline: SmartScreen in Shell' -SourceUrl $baseline))

    $controls.Add((New-SecurityControl -Id 'APP-002' -Category 'Application protection' -Title 'AutoRun and AutoPlay are disabled for all drives' -Severity Medium `
        -WhyItMatters 'Automatic execution from removable or mounted media can launch malicious content without an intentional user action.' `
        -Affected 'Media and removable drives no longer launch content automatically; users open content manually.' `
        -Recommendation 'Disable AutoPlay and set NoDriveTypeAutoRun to 255 for all drive types.' `
        -Check {
            $path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            $auto = Get-RegistryValueState -Path $path -Name 'NoDriveTypeAutoRun'
            $play = Get-RegistryValueState -Path $path -Name 'NoAutoplayfornonVolume'
            $current = "NoDriveTypeAutoRun=$($auto.Value); NoAutoplayfornonVolume=$($play.Value)"
            if ($auto.Exists -and [int]$auto.Value -eq 255 -and $play.Exists -and [int]$play.Value -eq 1) { New-CheckResult -Status Pass -Current $current -Expected '255; non-volume AutoPlay blocked' }
            else { New-CheckResult -Status Fail -Current $current -Expected 'NoDriveTypeAutoRun=255; NoAutoplayfornonVolume=1' }
        } -Fix {
            $path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            Set-RegistryDword -Path $path -Name 'NoDriveTypeAutoRun' -Value 255
            Set-RegistryDword -Path $path -Name 'NoAutoplayfornonVolume' -Value 1
        } -FixRisk Low -FixImpact 'Removable media and mounted devices will not launch content automatically.' `
        -Rollback 'Import the saved Explorer policy key or remove the two values.' `
        -Source 'Windows 11 25H2 baseline: AutoPlay policies' -SourceUrl $baseline))

    $controls.Add((New-SecurityControl -Id 'APP-003' -Category 'Application protection' -Title 'AlwaysInstallElevated is disabled for computer and user policy' -Severity Critical `
        -WhyItMatters 'If enabled in both scopes, a standard user can install a crafted MSI with SYSTEM privileges.' `
        -Affected 'Managed MSI deployments should use a proper software deployment mechanism rather than user-controlled elevated installation.' `
        -Recommendation 'Keep AlwaysInstallElevated disabled or not configured in both HKLM and HKCU.' `
        -Check {
            $machine = Get-RegistryValueState -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated'
            $user = Get-RegistryValueState -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated'
            $machineUnsafe = $machine.Exists -and [int]$machine.Value -ne 0
            $userUnsafe = $user.Exists -and [int]$user.Value -ne 0
            $current = "Machine=$($machine.Value); CurrentUser=$($user.Value)"
            if (-not $machineUnsafe -and -not $userUnsafe) { New-CheckResult -Status Pass -Current $current -Expected 'Disabled or not configured in both scopes' }
            else { New-CheckResult -Status Fail -Current $current -Expected 'Disabled or not configured in both scopes' }
        } -Fix {
            Set-RegistryDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -Value 0
            Set-RegistryDword -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -Value 0
        } -FixRisk Low -FixImpact 'User-controlled MSI packages can no longer request automatic SYSTEM installation through this policy.' `
        -Rollback 'Import the saved Installer policy keys only if you have confirmed that a trusted installer genuinely depends on this unsafe behavior.' `
        -Source 'Windows 11 25H2 baseline: MSI Always install with elevated privileges' -SourceUrl $baseline))

    $controls.Add((New-SecurityControl -Id 'LOG-001' -Category 'Logging' -Title 'PowerShell Script Block Logging is enabled' -Severity Medium `
        -WhyItMatters 'Script Block Logging records de-obfuscated PowerShell content and provides valuable evidence during investigation.' `
        -Affected 'PowerShell operational logs grow and may contain sensitive command content; log access and retention must be protected.' `
        -Recommendation 'Enable Script Block Logging. Review events in Event Viewer > Applications and Services Logs > Microsoft > Windows > PowerShell > Operational after suspicious activity.' `
        -Check { Test-RegistryDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Expected 1 -ExpectedText '1 (enabled)' } `
        -Fix { Set-RegistryDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Value 1 } `
        -FixRisk Low -FixImpact 'Increases PowerShell event volume and logs command/script content that may contain sensitive data.' `
        -Rollback 'Import the saved PowerShell policy key or restore logging through managed policy.' `
        -Source 'Windows 11 25H2 baseline: Turn on PowerShell Script Block Logging' -SourceUrl $baseline))

    $controls.Add((New-SecurityControl -Id 'LOG-002' -Category 'Logging' -Title 'Key advanced audit policies are enabled' -Severity High `
        -WhyItMatters 'Logon, credential validation, process creation, account management, and system integrity events are core evidence for detecting compromise.' `
        -Affected 'The Security log grows faster. The separate event-log-size control provides enough local capacity for a personal PC.' `
        -Recommendation 'Enable success and failure where the baseline requires both, and success for process creation. The check uses stable subcategory GUIDs.' `
        -Check {
            $requirements = @(
                @{ Name = 'Credential Validation'; Guid = '{0CCE923F-69AE-11D9-BED3-505054503030}'; Mode = 'SuccessAndFailure' },
                @{ Name = 'Logon'; Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}'; Mode = 'SuccessAndFailure' },
                @{ Name = 'User Account Management'; Guid = '{0CCE9235-69AE-11D9-BED3-505054503030}'; Mode = 'SuccessAndFailure' },
                @{ Name = 'Process Creation'; Guid = '{0CCE922B-69AE-11D9-BED3-505054503030}'; Mode = 'Success' },
                @{ Name = 'System Integrity'; Guid = '{0CCE9212-69AE-11D9-BED3-505054503030}'; Mode = 'SuccessAndFailure' }
            )
            $failed = @()
            $unknown = @()
            foreach ($requirement in $requirements) {
                $result = Test-AuditPolicy -SubcategoryGuid $requirement.Guid -Requirement $requirement.Mode -ExpectedText $requirement.Mode
                if ($result.Status -eq 'Fail') { $failed += $requirement.Name }
                if ($result.Status -eq 'Unknown') { $unknown += $requirement.Name }
            }
            if ($unknown.Count -gt 0) { return New-CheckResult -Status Unknown -Current "Could not parse: $($unknown -join ', ')" -Expected 'Five baseline audit subcategories enabled' -Evidence 'auditpol output may be localized.' }
            if ($failed.Count -eq 0) { New-CheckResult -Status Pass -Current 'All five required subcategories are enabled.' -Expected 'All required modes enabled' }
            else { New-CheckResult -Status Fail -Current "Missing required modes: $($failed -join ', ')" -Expected 'All required modes enabled' }
        } -Fix {
            Set-AuditPolicyValue -SubcategoryGuid '{0CCE923F-69AE-11D9-BED3-505054503030}' -Success $true -Failure $true
            Set-AuditPolicyValue -SubcategoryGuid '{0CCE9215-69AE-11D9-BED3-505054503030}' -Success $true -Failure $true
            Set-AuditPolicyValue -SubcategoryGuid '{0CCE9235-69AE-11D9-BED3-505054503030}' -Success $true -Failure $true
            Set-AuditPolicyValue -SubcategoryGuid '{0CCE922B-69AE-11D9-BED3-505054503030}' -Success $true -Failure $false
            Set-AuditPolicyValue -SubcategoryGuid '{0CCE9212-69AE-11D9-BED3-505054503030}' -Success $true -Failure $true
        } -FixRisk Low -FixImpact 'Increases Security event log volume, but provides better local evidence in Event Viewer.' `
        -Rollback 'Restore the saved audit-policy CSV with auditpol /restore.' `
        -EnterpriseNote 'Central event forwarding is an enterprise enhancement. On a personal PC, the immediate benefit is better evidence in Event Viewer after suspicious activity.' `
        -Source 'Windows 11 25H2 baseline: Auditing' -SourceUrl $baseline))

    $controls.Add((New-SecurityControl -Id 'LOG-003' -Category 'Logging' -Title 'Windows event logs meet baseline minimum sizes' -Severity Medium `
        -WhyItMatters 'Adequate log capacity preserves investigation evidence during busy periods or attacks that generate many events.' `
        -Affected 'Maximum reserved log capacity increases: Security 192 MB, System 32 MB, and Application 32 MB.' `
        -Recommendation 'Set Security to at least 196,608 KB and System/Application to at least 32,768 KB. Export relevant events before clearing a log during troubleshooting.' `
        -Check {
            $expected = @{ Security = 201326592L; System = 33554432L; Application = 33554432L }
            $bad = @()
            $current = @()
            foreach ($name in $expected.Keys) {
                $log = Get-WinEvent -ListLog $name
                $current += "$name=$([math]::Round($log.MaximumSizeInBytes / 1MB))MB"
                if ([long]$log.MaximumSizeInBytes -lt [long]$expected[$name]) { $bad += $name }
            }
            if ($bad.Count -eq 0) { New-CheckResult -Status Pass -Current ($current -join '; ') -Expected 'Security>=192MB; System/Application>=32MB' }
            else { New-CheckResult -Status Fail -Current ($current -join '; ') -Expected 'Security>=192MB; System/Application>=32MB' -Evidence "Too small: $($bad -join ', ')" }
        } -Fix {
            $commands = @(
                @{ Name = 'Security'; Size = 201326592 },
                @{ Name = 'System'; Size = 33554432 },
                @{ Name = 'Application'; Size = 33554432 }
            )
            foreach ($item in $commands) {
                $output = & wevtutil.exe sl $item.Name /ms:$($item.Size) 2>&1
                if ($LASTEXITCODE -ne 0) { throw ($output -join ' ') }
            }
        } -FixRisk Low -FixImpact 'Allows the three logs to consume up to approximately 256 MB total before their configured retention behavior applies.' `
        -Rollback 'Use wevtutil sl <log> /ms:<previous-bytes> with the previous sizes shown in the pre-fix audit report.' `
        -Source 'Windows 11 25H2 baseline: Event Log Service sizes' -SourceUrl $baseline))

    $controls.Add((New-SecurityControl -Id 'REMOTE-001' -Category 'Remote access' -Title 'Remote Desktop requires Network Level Authentication when enabled' -Severity High `
        -WhyItMatters 'NLA authenticates users before creating a full Remote Desktop session, reducing pre-authentication exposure and resource use.' `
        -Affected 'Very old RDP clients without NLA support cannot connect.' `
        -Recommendation 'If Remote Desktop is enabled, require NLA. Leave Remote Desktop disabled when it is not needed.' `
        -Check {
            $tsPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
            $rdp = Get-RegistryValueState -Path $tsPath -Name 'fDenyTSConnections'
            if (-not $rdp.Exists -or [int]$rdp.Value -eq 1) { return New-CheckResult -Status NotApplicable -Current 'Remote Desktop is disabled.' -Expected 'NLA required when RDP is enabled' }
            $nla = Get-RegistryValueState -Path "$tsPath\WinStations\RDP-Tcp" -Name 'UserAuthentication'
            if ($nla.Exists -and [int]$nla.Value -eq 1) { New-CheckResult -Status Pass -Current 'RDP enabled; NLA required' -Expected 'NLA required' }
            else { New-CheckResult -Status Fail -Current 'RDP enabled; NLA not explicitly required' -Expected 'UserAuthentication=1' }
        } -Fix { Set-RegistryDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1 } `
        -FixRisk Moderate -FixImpact 'RDP clients that do not support NLA can no longer connect.' `
        -Rollback 'Import the saved Terminal Server registry key or restore the previous Remote Desktop setting.' `
        -Source 'Windows 11 25H2 baseline: Remote Desktop Session Host security' -SourceUrl $baseline))

    $controls.Add((New-SecurityControl -Id 'REMOTE-002' -Category 'Remote access' -Title 'WinRM Basic authentication and unencrypted traffic are disabled' -Severity High `
        -WhyItMatters 'Basic authentication and unencrypted WinRM can expose reusable credentials or management traffic.' `
        -Affected 'Legacy remote-management clients using HTTP Basic or unencrypted transport must move to Kerberos, Negotiate, or HTTPS.' `
        -Recommendation 'Keep Basic authentication and unencrypted traffic disabled for both WinRM client and service.' `
        -Check {
            $locations = @(
                @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'; Name = 'AllowBasic' },
                @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'; Name = 'AllowUnencryptedTraffic' },
                @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'; Name = 'AllowBasic' },
                @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'; Name = 'AllowUnencryptedTraffic' }
            )
            $unsafe = @()
            $current = @()
            foreach ($location in $locations) {
                $state = Get-RegistryValueState -Path $location.Path -Name $location.Name
                $scope = Split-Path $location.Path -Leaf
                $text = if ($state.Exists) { [string]$state.Value } else { 'default-off' }
                $current += "$scope/$($location.Name)=$text"
                if ($state.Exists -and [int]$state.Value -ne 0) { $unsafe += "$scope/$($location.Name)" }
            }
            if ($unsafe.Count -eq 0) { New-CheckResult -Status Pass -Current ($current -join '; ') -Expected 'All disabled or secure default' }
            else { New-CheckResult -Status Fail -Current ($current -join '; ') -Expected 'All disabled' -Evidence "Unsafe: $($unsafe -join ', ')" }
        } -Fix {
            Set-RegistryDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -Name 'AllowBasic' -Value 0
            Set-RegistryDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -Name 'AllowUnencryptedTraffic' -Value 0
            Set-RegistryDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'AllowBasic' -Value 0
            Set-RegistryDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'AllowUnencryptedTraffic' -Value 0
        } -FixRisk Moderate -FixImpact 'Legacy Basic/HTTP WinRM automation may fail until migrated to secure authentication and transport.' `
        -Rollback 'Import the saved WinRM policy key only if a trusted legacy management tool genuinely requires it; prefer fixing the tool configuration.' `
        -EnterpriseNote 'WinRM is most commonly used for enterprise remote administration. If you do not use PowerShell remoting at home, leaving insecure methods disabled has no expected impact.' `
        -Source 'Windows 11 25H2 baseline: WinRM client and service' -SourceUrl $baseline))

    $controls.ToArray()
}

function Invoke-ControlAudit {
    param([Parameter(Mandatory = $true)]$Control)

    $started = Get-Date
    try {
        $checkResult = & $Control.Check
        if ($null -eq $checkResult) { throw 'The check returned no result.' }
        $status = [string]$checkResult.Status
        if (@('Pass', 'Fail', 'NotApplicable', 'Unknown') -notcontains $status) { throw "Invalid check status: $status" }
        [pscustomobject][ordered]@{
            Id = $Control.Id
            Category = $Control.Category
            Title = $Control.Title
            Severity = $Control.Severity
            Status = $status
            Current = [string]$checkResult.Current
            Expected = [string]$checkResult.Expected
            Evidence = [string]$checkResult.Evidence
            CheckedAt = $started.ToString('o')
            Error = ''
        }
    }
    catch {
        [pscustomobject][ordered]@{
            Id = $Control.Id
            Category = $Control.Category
            Title = $Control.Title
            Severity = $Control.Severity
            Status = 'Unknown'
            Current = 'Check failed'
            Expected = ''
            Evidence = ''
            CheckedAt = $started.ToString('o')
            Error = $_.Exception.Message
        }
    }
}

function Invoke-AllAudits {
    param([Parameter(Mandatory = $true)][object[]]$Controls)

    $items = New-Object System.Collections.Generic.List[object]
    $index = 0
    foreach ($control in $Controls) {
        $index++
        if (-not $AuditOnly) {
            Write-Progress -Activity 'Auditing Windows security posture' -Status "$index of $($Controls.Count): $($control.Title)" -PercentComplete (($index / $Controls.Count) * 100)
        }
        $items.Add((Invoke-ControlAudit -Control $control))
    }
    if (-not $AuditOnly) { Write-Progress -Activity 'Auditing Windows security posture' -Completed }
    $script:Results = $items.ToArray()
}

function Get-ResultForControl {
    param([Parameter(Mandatory = $true)][string]$Id)
    @($script:Results | Where-Object { $_.Id -eq $Id }) | Select-Object -First 1
}

function Update-ControlResult {
    param([Parameter(Mandatory = $true)]$Control)
    $replacement = Invoke-ControlAudit -Control $Control
    $updated = New-Object System.Collections.Generic.List[object]
    foreach ($result in $script:Results) {
        if ($result.Id -eq $Control.Id) { $updated.Add($replacement) }
        else { $updated.Add($result) }
    }
    $script:Results = $updated.ToArray()
    $replacement
}

function Save-PreChangeBackup {
    if ($null -ne $script:BackupDirectory) { return $script:BackupDirectory }

    $root = Join-Path $PSScriptRoot 'Backups'
    if (-not (Test-Path -LiteralPath $root)) { $null = New-Item -ItemType Directory -Path $root -Force }
    $script:BackupDirectory = Join-Path $root (Get-Date -Format 'yyyyMMdd-HHmmss')
    $null = New-Item -ItemType Directory -Path $script:BackupDirectory -Force

    $registryKeys = @(
        'HKLM\SOFTWARE\Policies\Microsoft\Windows',
        'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies',
        'HKLM\SYSTEM\CurrentControlSet\Control\Lsa',
        'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest',
        'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer',
        'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation',
        'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server',
        'HKCU\SOFTWARE\Policies\Microsoft\Windows'
    )
    $n = 0
    foreach ($key in $registryKeys) {
        $n++
        $path = Join-Path $script:BackupDirectory ("registry-{0}.reg" -f $n)
        $null = & reg.exe export $key $path /y 2>&1
    }

    if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) {
        try { Get-MpPreference | Export-Clixml -LiteralPath (Join-Path $script:BackupDirectory 'DefenderPreferences.xml') -Force } catch {}
    }
    try { $null = & netsh.exe advfirewall export (Join-Path $script:BackupDirectory 'WindowsFirewall.wfw') 2>&1 } catch {}
    try {
        $auditBackupPath = Join-Path $script:BackupDirectory 'AuditPolicy.csv'
        $null = & auditpol.exe /backup /file:$auditBackupPath 2>&1
    } catch {}

    $metadata = [ordered]@{
        CreatedAt = (Get-Date).ToString('o')
        ComputerName = $env:COMPUTERNAME
        UserName = [Environment]::UserName
        SystemProfile = if ($null -ne $script:SystemContext) { $script:SystemContext.Mode } else { 'Unknown' }
        Baseline = $script:BaselineName
        Note = 'Best-effort pre-change backup. Restore individual settings deliberately; do not bulk-import without review.'
    }
    $metadata | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $script:BackupDirectory 'README.json') -Encoding UTF8
    $script:BackupDirectory
}

function Write-FixLog {
    param(
        [Parameter(Mandatory = $true)]$Control,
        [Parameter(Mandatory = $true)][string]$Outcome,
        [string]$Message = ''
    )
    $entry = [pscustomobject][ordered]@{
        Time = (Get-Date).ToString('o')
        ControlId = $Control.Id
        Title = $Control.Title
        Outcome = $Outcome
        Message = $Message
        BackupDirectory = $script:BackupDirectory
    }
    $script:FixLog += $entry
    if ($null -ne $script:BackupDirectory) {
        $entry | ConvertTo-Json -Compress | Add-Content -LiteralPath (Join-Path $script:BackupDirectory 'FixLog.jsonl') -Encoding UTF8
    }
}

function Invoke-ControlFix {
    param(
        [Parameter(Mandatory = $true)]$Control,
        [switch]$SkipConfirmation
    )

    $result = Get-ResultForControl -Id $Control.Id
    if ($null -eq $result -or $result.Status -ne 'Fail') {
        Write-Host 'This control is not currently in a failed state.' -ForegroundColor Yellow
        return
    }
    if ($Control.FixRisk -eq 'Manual' -or $null -eq $Control.Fix) {
        Write-Host 'This control requires a guided manual change; no automatic fix is offered.' -ForegroundColor Yellow
        Write-Host "Recommended action: $($Control.Recommendation)"
        return
    }
    if (-not $script:IsAdmin) {
        Write-Host 'Remediation requires an elevated PowerShell session. Audit results remain available.' -ForegroundColor Red
        return
    }

    if (-not $SkipConfirmation) {
        Write-Host ''
        Write-Host "Proposed change: $($Control.Recommendation)" -ForegroundColor Cyan
        Write-Host "What may be affected: $($Control.FixImpact)" -ForegroundColor Yellow
        Write-Host "Risk: $($Control.FixRisk) | Restart: $($Control.RestartRequired)"
        Write-Host "Rollback: $($Control.Rollback)"
        $required = if ($Control.FixRisk -eq 'High') { $Control.Id } else { 'APPLY' }
        $answer = Read-Host "Type $required to continue"
        if ($answer -cne $required) {
            Write-Host 'Change cancelled.' -ForegroundColor Yellow
            return
        }
    }

    try {
        $backup = Save-PreChangeBackup
        Write-Host "Pre-change backup: $backup" -ForegroundColor DarkGray
        & $Control.Fix
        $after = Update-ControlResult -Control $Control
        if ($after.Status -eq 'Pass') {
            Write-FixLog -Control $Control -Outcome 'AppliedAndVerified' -Message $after.Current
            Write-Host 'Fix applied and the control now passes.' -ForegroundColor Green
        }
        else {
            Write-FixLog -Control $Control -Outcome 'AppliedButNotVerified' -Message "$($after.Status): $($after.Current) $($after.Error)"
            Write-Host "The change ran, but the control is now $($after.Status). Review policy precedence or restart requirements." -ForegroundColor Yellow
        }
    }
    catch {
        Write-FixLog -Control $Control -Outcome 'Failed' -Message $_.Exception.Message
        Write-Host "Fix failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Get-StatusColor {
    param([string]$Status)
    switch ($Status) {
        'Pass' { 'Green' }
        'Fail' { 'Red' }
        'NotApplicable' { 'DarkGray' }
        default { 'Yellow' }
    }
}

function Get-WslStatusColor {
    param([string]$Status)
    switch ($Status) {
        'Pass' { 'Green' }
        'Review' { 'Yellow' }
        'Info' { 'Cyan' }
        default { 'DarkYellow' }
    }
}

function Show-WslAudit {
    param([Parameter(Mandatory = $true)]$Report)

    Write-Host 'WSL security audit' -ForegroundColor Cyan
    Write-Host "WSL version: $($Report.WslVersion) | Mode: $(if ($Report.RunningOnly) { 'running distributions only' } else { 'all installed distributions' })" -ForegroundColor DarkGray
    if ($Report.ConfigurationPath) { Write-Host "Global configuration: $($Report.ConfigurationPath)" -ForegroundColor DarkGray }
    Write-Host ''
    Write-Host 'Host findings' -ForegroundColor Cyan
    foreach ($finding in @($Report.HostFindings)) {
        Write-Host (' [{0,-7}] ' -f $finding.Status) -NoNewline -ForegroundColor (Get-WslStatusColor $finding.Status)
        Write-Host "$($finding.Check): $($finding.Current)"
        if ($finding.Guidance) { Write-Host "           $($finding.Guidance)" -ForegroundColor DarkGray }
    }

    if ($Report.DistributionDiscoveryError) {
        Write-Host ''
        Write-Host "Could not enumerate installed distributions: $($Report.DistributionDiscoveryError)" -ForegroundColor Yellow
        return
    }
    if (@($Report.Distributions).Count -eq 0) {
        Write-Host ''
        Write-Host 'No WSL distributions are installed.' -ForegroundColor DarkGray
        return
    }

    foreach ($distribution in @($Report.Distributions)) {
        Write-Host ''
        $defaultText = if ($distribution.IsDefault) { ' | default' } else { '' }
        Write-Host "$($distribution.Name) - $($distribution.OsName) | WSL $($distribution.WslVersion) | $($distribution.State)$defaultText" -ForegroundColor Cyan
        if ($distribution.Kernel) { Write-Host " Kernel: $($distribution.Kernel)" -ForegroundColor DarkGray }
        foreach ($finding in @($distribution.Findings)) {
            Write-Host (' [{0,-7}] ' -f $finding.Status) -NoNewline -ForegroundColor (Get-WslStatusColor $finding.Status)
            Write-Host "$($finding.Check): $($finding.Current)"
            if ($finding.Guidance) { Write-Host "           $($finding.Guidance)" -ForegroundColor DarkGray }
        }
    }
    Write-Host ''
    Write-Host "References: $script:WslVersionsUrl | $script:WslConfigUrl" -ForegroundColor DarkGray
}

function Invoke-InteractiveWslAudit {
    Show-Header
    Write-Host 'WSL inspection runs read-only commands inside Linux distributions.' -ForegroundColor Cyan
    Write-Host 'Inspecting a stopped distribution starts it and may run its configured startup services.' -ForegroundColor Yellow
    Write-Host ''
    Write-Host '[A] Inspect all installed distributions'
    Write-Host '[R] Inspect running distributions only (does not start stopped distributions)'
    Write-Host '[B] Back'
    $choice = (Read-Host 'Choose').Trim().ToUpperInvariant()
    if ($choice -eq 'B') { return }
    if (@('A', 'R') -notcontains $choice) {
        Write-Host 'Invalid selection.' -ForegroundColor Yellow
        $null = Read-Host 'Press Enter to continue'
        return
    }

    Write-Host 'Auditing WSL...' -ForegroundColor Cyan
    $script:WslAudit = Invoke-WslSecurityAudit -RunningOnly:($choice -eq 'R')
    Show-Header
    Show-WslAudit -Report $script:WslAudit
    $null = Read-Host 'Press Enter to continue'
}

function Write-Wrapped {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [AllowEmptyString()][string]$Text,
        [ConsoleColor]$LabelColor = 'Cyan'
    )
    Write-Host "${Label}: " -NoNewline -ForegroundColor $LabelColor
    Write-Host $Text
}

function Show-Header {
    if (-not $NoClear) { Clear-Host }
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
    Write-Host " $script:ToolName  v$script:ToolVersion" -ForegroundColor Cyan
    Write-Host " $script:BaselineName" -ForegroundColor DarkGray
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
    if ($null -ne $script:SystemContext) {
        Write-Host " System: $($script:SystemContext.WindowsEdition) $($script:SystemContext.DisplayVersion)" -ForegroundColor DarkGray
        if ($script:SystemContext.ManagedSignals) {
            Write-Host " Context: $($script:SystemContext.Mode) - $($script:SystemContext.ManagedSignals)" -ForegroundColor Yellow
        }
        else {
            Write-Host ' Context: Personal/workgroup PC; enterprise-only requirements are informational.' -ForegroundColor Green
        }
    }
    if (-not $script:IsAdmin) {
        Write-Host ' Limited audit: standard user | Some checks are Unknown; fixes require elevation' -ForegroundColor Yellow
    }
    else {
        Write-Host ' Audit mode: administrator | Fixes remain opt-in and are logged' -ForegroundColor Green
    }
    Write-Host ''
}

function Show-Summary {
    $pass = @($script:Results | Where-Object Status -eq 'Pass').Count
    $fail = @($script:Results | Where-Object Status -eq 'Fail').Count
    $na = @($script:Results | Where-Object Status -eq 'NotApplicable').Count
    $unknown = @($script:Results | Where-Object Status -eq 'Unknown').Count
    $assessed = $pass + $fail
    $score = if ($assessed -gt 0) { [math]::Round(($pass / $assessed) * 100) } else { 0 }

    Write-Host " Posture score: $score%  " -NoNewline -ForegroundColor Cyan
    Write-Host "PASS $pass" -NoNewline -ForegroundColor Green
    Write-Host ' | ' -NoNewline
    Write-Host "FAIL $fail" -NoNewline -ForegroundColor Red
    Write-Host ' | ' -NoNewline
    Write-Host "N/A $na" -NoNewline -ForegroundColor DarkGray
    Write-Host ' | ' -NoNewline
    Write-Host "UNKNOWN $unknown" -ForegroundColor Yellow
    Write-Host ' Score excludes Not Applicable and Unknown controls.' -ForegroundColor DarkGray
    Write-Host ''
}

function Show-ResultsTable {
    param([switch]$FailuresOnly)
    # Wrap the complete conditional expression. Windows PowerShell 5.1 otherwise
    # unwraps a one-item branch into a scalar, which has no Count under StrictMode.
    [object[]]$items = @(
        if ($FailuresOnly) { $script:Results | Where-Object Status -eq 'Fail' }
        else { $script:Results }
    )
    if ($items.Count -eq 0) {
        Write-Host 'No matching results.' -ForegroundColor Green
        return
    }

    $i = 0
    foreach ($item in $items) {
        $i++
        $title = $item.Title
        if ($title.Length -gt 46) { $title = $title.Substring(0, 43) + '...' }
        Write-Host ('{0,2}. ' -f $i) -NoNewline -ForegroundColor DarkGray
        Write-Host ('[{0,-13}] ' -f $item.Status) -NoNewline -ForegroundColor (Get-StatusColor $item.Status)
        Write-Host ('{0,-9} ' -f $item.Severity) -NoNewline
        Write-Host ('{0,-10} ' -f $item.Id) -NoNewline -ForegroundColor Cyan
        Write-Host $title
    }
}

function Show-ControlDetail {
    param([Parameter(Mandatory = $true)]$Control)
    while ($true) {
        Show-Header
        $result = Get-ResultForControl -Id $Control.Id
        Write-Host "[$($result.Status)] $($Control.Id) - $($Control.Title)" -ForegroundColor (Get-StatusColor $result.Status)
        Write-Host ''
        Write-Wrapped -Label 'Severity' -Text $Control.Severity
        Write-Wrapped -Label 'Category' -Text $Control.Category
        Write-Wrapped -Label 'Current state' -Text $result.Current
        Write-Wrapped -Label 'Expected state' -Text $result.Expected
        if ($result.Evidence) { Write-Wrapped -Label 'Evidence' -Text $result.Evidence }
        if ($result.Error) { Write-Wrapped -Label 'Check error' -Text $result.Error -LabelColor Red }
        Write-Host ''
        Write-Wrapped -Label 'Why this matters' -Text $Control.WhyItMatters
        Write-Wrapped -Label 'What is affected' -Text $Control.Affected
        Write-Wrapped -Label 'Best fix' -Text $Control.Recommendation
        Write-Wrapped -Label 'Fix impact' -Text $Control.FixImpact
        Write-Wrapped -Label 'Rollback' -Text $Control.Rollback
        Write-Wrapped -Label 'Fix risk' -Text $Control.FixRisk
        Write-Wrapped -Label 'Restart required' -Text ([string]$Control.RestartRequired)
        if ($Control.EnterpriseNote) { Write-Wrapped -Label 'Enterprise/domain note' -Text $Control.EnterpriseNote -LabelColor Yellow }
        Write-Wrapped -Label 'Microsoft source' -Text "$($Control.Source) - $($Control.SourceUrl)"
        Write-Host ''
        Write-Host '[A] Apply fix   [R] Recheck   [O] Open Microsoft source   [B] Back' -ForegroundColor Cyan
        $choice = (Read-Host 'Choose').Trim().ToUpperInvariant()
        switch ($choice) {
            'A' { Invoke-ControlFix -Control $Control; $null = Read-Host 'Press Enter to continue' }
            'R' { $null = Update-ControlResult -Control $Control }
            'O' {
                try { Start-Process $Control.SourceUrl }
                catch { Write-Host "Could not open the browser: $($_.Exception.Message)" -ForegroundColor Red; $null = Read-Host 'Press Enter to continue' }
            }
            'B' { return }
        }
    }
}

function Select-Control {
    param(
        [Parameter(Mandatory = $true)][object[]]$Controls,
        [switch]$FailuresOnly
    )
    [object[]]$results = @(
        if ($FailuresOnly) { $script:Results | Where-Object Status -eq 'Fail' }
        else { $script:Results }
    )
    if ($results.Count -eq 0) { return $null }
    Show-ResultsTable -FailuresOnly:$FailuresOnly
    $answer = Read-Host 'Enter result number (or B to go back)'
    if ($answer -match '^[Bb]$') { return $null }
    $number = 0
    if (-not [int]::TryParse($answer, [ref]$number) -or $number -lt 1 -or $number -gt $results.Count) {
        Write-Host 'Invalid selection.' -ForegroundColor Yellow
        $null = Read-Host 'Press Enter to continue'
        return $null
    }
    $selectedResult = $results[$number - 1]
    @($Controls | Where-Object Id -eq $selectedResult.Id) | Select-Object -First 1
}

function Export-SecurityReport {
    param(
        [string]$Directory,
        [Parameter(Mandatory = $true)][object[]]$Controls
    )
    if ([string]::IsNullOrWhiteSpace($Directory)) {
        $Directory = Join-Path $PSScriptRoot 'Reports'
    }
    $resolved = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Directory)
    if (-not (Test-Path -LiteralPath $resolved)) { $null = New-Item -ItemType Directory -Path $resolved -Force }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $jsonPath = Join-Path $resolved "WindowsSecurityAudit-$stamp.json"
    $htmlPath = Join-Path $resolved "WindowsSecurityAudit-$stamp.html"

    $details = foreach ($result in $script:Results) {
        $control = @($Controls | Where-Object Id -eq $result.Id) | Select-Object -First 1
        [pscustomobject][ordered]@{
            Id = $result.Id
            Category = $result.Category
            Title = $result.Title
            Severity = $result.Severity
            Status = $result.Status
            Current = $result.Current
            Expected = $result.Expected
            Evidence = $result.Evidence
            Error = $result.Error
            WhyItMatters = $control.WhyItMatters
            Affected = $control.Affected
            Recommendation = $control.Recommendation
            FixRisk = $control.FixRisk
            FixImpact = $control.FixImpact
            Rollback = $control.Rollback
            RestartRequired = $control.RestartRequired
            EnterpriseNote = $control.EnterpriseNote
            Source = $control.Source
            SourceUrl = $control.SourceUrl
            CheckedAt = $result.CheckedAt
        }
    }

    $report = [ordered]@{
        Tool = "$script:ToolName $script:ToolVersion"
        Baseline = $script:BaselineName
        BaselineUrl = $script:BaselineUrl
        GeneratedAt = (Get-Date).ToString('o')
        ComputerName = $env:COMPUTERNAME
        IsAdministrator = $script:IsAdmin
        SystemContext = $script:SystemContext
        Disclaimer = 'Personal Windows 11 posture audit; not a complete enterprise Security Compliance Toolkit compliance attestation.'
        Results = @($details)
        WslAudit = $script:WslAudit
        FixLog = @($script:FixLog)
    }
    $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $jsonPath -Encoding UTF8

    $style = @'
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:32px;color:#1f2937}h1{color:#075985}h2{margin-top:32px}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{border:1px solid #cbd5e1;padding:7px;vertical-align:top}th{background:#e0f2fe;text-align:left}
.note{background:#fff7ed;border-left:4px solid #f97316;padding:12px}.meta{color:#475569}.Pass{color:#15803d;font-weight:bold}.Fail{color:#b91c1c;font-weight:bold}.Review,.Unknown{color:#a16207;font-weight:bold}.Info{color:#0369a1;font-weight:bold}.NotApplicable{color:#64748b;font-weight:bold}
</style>
'@
    $summaryRows = $details | Select-Object Id, Category, Title, Severity, Status, Current, Expected
    $summaryHtml = $summaryRows | ConvertTo-Html -Fragment
    foreach ($status in @('Pass', 'Fail', 'Unknown', 'NotApplicable')) {
        $summaryHtml = $summaryHtml -replace ">($status)<", "><span class='$status'>$status</span><"
    }
    $detailHtml = $details | ConvertTo-Html -Fragment -Property Id,WhyItMatters,Affected,Recommendation,FixRisk,FixImpact,Rollback,RestartRequired,EnterpriseNote,SourceUrl
    $wslHtml = ''
    if ($null -ne $script:WslAudit) {
        $wslRows = New-Object System.Collections.Generic.List[object]
        foreach ($finding in @($script:WslAudit.HostFindings)) {
            $wslRows.Add([pscustomobject]@{ Scope = 'WSL host'; Status = $finding.Status; Check = $finding.Check; Current = $finding.Current; Expected = $finding.Expected; Guidance = $finding.Guidance })
        }
        foreach ($distribution in @($script:WslAudit.Distributions)) {
            foreach ($finding in @($distribution.Findings)) {
                $wslRows.Add([pscustomobject]@{ Scope = $distribution.Name; Status = $finding.Status; Check = $finding.Check; Current = $finding.Current; Expected = $finding.Expected; Guidance = $finding.Guidance })
            }
        }
        if ($wslRows.Count -gt 0) {
            $wslTable = $wslRows.ToArray() | ConvertTo-Html -Fragment
            foreach ($status in @('Pass', 'Review', 'Info', 'Unknown')) {
                $wslTable = $wslTable -replace ">($status)<", "><span class='$status'>$status</span><"
            }
            $wslHtml = "<h2>WSL audit</h2><p class='meta'>WSL $($script:WslAudit.WslVersion); $(if ($script:WslAudit.RunningOnly) { 'running distributions only' } else { 'all installed distributions' })</p>$wslTable"
        }
        if ($script:WslAudit.DistributionDiscoveryError) {
            $encodedError = [System.Net.WebUtility]::HtmlEncode([string]$script:WslAudit.DistributionDiscoveryError)
            $wslHtml += "<p class='note'>Distribution discovery failed: $encodedError</p>"
        }
        elseif (@($script:WslAudit.Distributions).Count -eq 0) {
            $wslHtml += "<p class='meta'>No WSL distributions are installed.</p>"
        }
    }
    $profileText = if ($null -ne $script:SystemContext) { "$($script:SystemContext.Mode); $($script:SystemContext.ManagedSignals)" } else { 'Unknown' }
    $pre = "<h1>$script:ToolName</h1><p class='meta'>$script:BaselineName<br>Computer: $env:COMPUTERNAME<br>System context: $profileText<br>Generated: $(Get-Date -Format 'u')</p><p class='note'>Personal Windows 11 posture audit; not a complete enterprise Security Compliance Toolkit compliance attestation. Enterprise/domain notes are informational unless managed-system signals are detected.</p><h2>Summary</h2>"
    $post = "<h2>Guidance for every control</h2>$detailHtml$wslHtml"
    ConvertTo-Html -Title "$script:ToolName report" -Head $style -Body "$pre$summaryHtml$post" | Set-Content -LiteralPath $htmlPath -Encoding UTF8

    [pscustomobject]@{ Json = $jsonPath; Html = $htmlPath }
}

function Invoke-LowRiskFixes {
    param([Parameter(Mandatory = $true)][object[]]$Controls)
    $targets = @($Controls | Where-Object {
        $_.FixRisk -eq 'Low' -and $null -ne $_.Fix -and (Get-ResultForControl -Id $_.Id).Status -eq 'Fail'
    })
    if ($targets.Count -eq 0) {
        Write-Host 'No failed controls with a low-risk automatic fix were found.' -ForegroundColor Green
        $null = Read-Host 'Press Enter to continue'
        return
    }
    Show-Header
    Write-Host 'The following low-risk changes are proposed:' -ForegroundColor Cyan
    foreach ($target in $targets) {
        Write-Host " - $($target.Id): $($target.Title)"
        Write-Host "   Affects: $($target.FixImpact)" -ForegroundColor Yellow
    }
    Write-Host ''
    Write-Host 'A best-effort registry/firewall/audit backup is created before the first change.' -ForegroundColor DarkGray
    $answer = Read-Host 'Type APPLY LOW RISK to continue'
    if ($answer -cne 'APPLY LOW RISK') { return }
    foreach ($target in $targets) {
        Write-Host "`nApplying $($target.Id)..." -ForegroundColor Cyan
        Invoke-ControlFix -Control $target -SkipConfirmation
    }
    $null = Read-Host 'Press Enter to continue'
}

function Start-SecurityTui {
    param([Parameter(Mandatory = $true)][object[]]$Controls)
    while ($true) {
        Show-Header
        Show-Summary
        Show-ResultsTable -FailuresOnly
        Write-Host ''
        Write-Host '[1] Review a failed control' -ForegroundColor Cyan
        Write-Host '[2] Browse every control'
        Write-Host '[3] Apply low-risk fixes (grouped, opt-in)'
        Write-Host '[4] Run full audit again'
        Write-Host '[5] Export JSON + HTML report'
        Write-Host '[6] Audit WSL and installed Linux distributions'
        Write-Host '[7] About scope and limitations'
        Write-Host '[Q] Quit'
        Write-Host ''
        $choice = (Read-Host 'Choose').Trim().ToUpperInvariant()
        switch ($choice) {
            '1' {
                Show-Header
                $control = Select-Control -Controls $Controls -FailuresOnly
                if ($null -ne $control) { Show-ControlDetail -Control $control }
            }
            '2' {
                Show-Header
                $control = Select-Control -Controls $Controls
                if ($null -ne $control) { Show-ControlDetail -Control $control }
            }
            '3' { Invoke-LowRiskFixes -Controls $Controls }
            '4' { Invoke-AllAudits -Controls $Controls }
            '5' {
                $directory = Read-Host "Export directory (Enter for $PSScriptRoot\Reports)"
                try {
                    $paths = Export-SecurityReport -Directory $directory -Controls $Controls
                    Write-Host "JSON: $($paths.Json)" -ForegroundColor Green
                    Write-Host "HTML: $($paths.Html)" -ForegroundColor Green
                }
                catch { Write-Host "Export failed: $($_.Exception.Message)" -ForegroundColor Red }
                $null = Read-Host 'Press Enter to continue'
            }
            '6' { Invoke-InteractiveWslAudit }
            '7' {
                Show-Header
                Write-Host 'Scope' -ForegroundColor Cyan
                Write-Host 'This profile is designed first for a personal Windows 11 PC. It selects high-value controls from Microsoft''s Windows 11 25H2 baseline and translates enterprise wording into practical local guidance.'
                Write-Host 'It does not claim enterprise compliance, validate every GPO/CSP setting, or replace the complete Security Compliance Toolkit.'
                Write-Host ''
                Write-Host 'Detected system context' -ForegroundColor Cyan
                if ($null -ne $script:SystemContext) {
                    Write-Host "Edition: $($script:SystemContext.WindowsEdition) $($script:SystemContext.DisplayVersion)"
                    Write-Host "Profile: $($script:SystemContext.Mode)"
                    if ($script:SystemContext.ManagedSignals) { Write-Host "Managed signals: $($script:SystemContext.ManagedSignals)" -ForegroundColor Yellow }
                    if ($script:SystemContext.WorkAccountRegistered -and -not $script:SystemContext.ManagedSignals) {
                        Write-Host 'A work/school account is registered, but no domain join or MDM enrollment was detected.' -ForegroundColor Yellow
                    }
                }
                Write-Host ''
                Write-Host 'Enterprise/domain handling' -ForegroundColor Cyan
                Write-Host 'Enterprise-only considerations are shown as highlighted notes. If a domain, Microsoft Entra join, or MDM enrollment is detected, local changes may be overwritten; change the owning Group Policy or Intune policy instead.'
                Write-Host ''
                Write-Host 'Safety model' -ForegroundColor Cyan
                Write-Host 'Auditing is read-only. Every automatic fix is opt-in, shows personal-device impact, creates a best-effort backup, logs its outcome, and rechecks the control. Firmware, BitLocker, and Memory Integrity changes remain manual.'
                Write-Host ''
                Write-Host "Baseline reference: $script:BaselineUrl"
                Write-Host "Security Compliance Toolkit: $script:SctUrl"
                $null = Read-Host 'Press Enter to continue'
            }
            'Q' { return }
        }
    }
}

if (-not $script:RunningOnWindows) {
    throw 'This script can run only on Windows.'
}

try {
    $script:ComputerInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
} catch {}
$script:SystemContext = Get-SystemContext

$allControls = @(Get-SecurityControls)
Invoke-AllAudits -Controls $allControls

if ($AuditOnly) {
    if ($AuditWsl) {
        $script:WslAudit = Invoke-WslSecurityAudit -RunningOnly:$WslRunningOnly
    }
    if ($null -ne $script:SystemContext) {
        Write-Host "System: $($script:SystemContext.WindowsEdition) $($script:SystemContext.DisplayVersion) | Context: $($script:SystemContext.Mode)" -ForegroundColor Cyan
        if ($script:SystemContext.ManagedSignals) { Write-Host "Managed signals: $($script:SystemContext.ManagedSignals)" -ForegroundColor Yellow }
    }
    $script:Results | Select-Object Id, Status, Severity, Category, Title, Current | Format-Table -AutoSize
    $pass = @($script:Results | Where-Object Status -eq 'Pass').Count
    $fail = @($script:Results | Where-Object Status -eq 'Fail').Count
    $unknown = @($script:Results | Where-Object Status -eq 'Unknown').Count
    Write-Host "`nPass=$pass Fail=$fail Unknown=$unknown" -ForegroundColor Cyan
    if ($null -ne $script:WslAudit) {
        Write-Host ''
        Show-WslAudit -Report $script:WslAudit
    }
    if ($PSBoundParameters.ContainsKey('ExportPath')) {
        $paths = Export-SecurityReport -Directory $ExportPath -Controls $allControls
        Write-Host "JSON: $($paths.Json)"
        Write-Host "HTML: $($paths.Html)"
    }
    return
}

Start-SecurityTui -Controls $allControls
