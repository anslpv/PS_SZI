#requires -Version 5.1
<#
.SYNOPSIS
    Имитатор Windows-окружения АРМ для тестирования ПО «СЗИ-Аудит».
.DESCRIPTION
    Определяет глобальные функции-заглушки с именами командлетов и утилит Windows,
    к которым обращается модуль проверок SziAudit.Checks.ps1 (реестр, службы, secedit,
    auditpol, журналы событий, сетевые адаптеры, хранилище сертификатов и т. д.).
    Функции имеют приоритет над командлетами и внешними программами, поэтому модуль
    проверок выполняется без изменений, а получает данные из описания «виртуального АРМ»
    $global:FakeArm. Это позволяет детерминированно воспроизводить состояния АРМ
    (соответствующее эталону и с конкретными нарушениями) как в Windows, так и в Linux.
    Обращения к файловой системе передаются настоящим командлетам.
#>

$global:SziRealTestPath     = Get-Command -Name 'Microsoft.PowerShell.Management\Test-Path' -CommandType Cmdlet
$global:SziRealGetChildItem = Get-Command -Name 'Microsoft.PowerShell.Management\Get-ChildItem' -CommandType Cmdlet
$global:SziRealGetItemProp  = Get-Command -Name 'Microsoft.PowerShell.Management\Get-ItemProperty' -CommandType Cmdlet

# ---------------------------------------------------------------------------
# Описание виртуального АРМ, соответствующего профилю ARM_OPK эталона
# ---------------------------------------------------------------------------
function global:New-FakeArm {
    $now = Get-Date
    @{
        Software = @(
            @{ DisplayName = 'Secure Pack Rus 3.0'; DisplayVersion = '3.0.2.15' }
            @{ DisplayName = 'КриптоПро CSP'; DisplayVersion = '5.0.12000' }
            @{ DisplayName = 'ViPNet Client 4'; DisplayVersion = '4.5.3.65102' }
            @{ DisplayName = 'Kaspersky Endpoint Security для Windows'; DisplayVersion = '11.6.0.394' }
            @{ DisplayName = 'Агент администрирования Kaspersky Security Center'; DisplayVersion = '13.2.0.1511' }
            @{ DisplayName = 'Microsoft Visual C++ 2015-2019 Redistributable (x64)'; DisplayVersion = '14.29.30133' }
            @{ DisplayName = 'Скрытый системный компонент'; DisplayVersion = '1.0'; SystemComponent = 1 }
        )
        Services = @(
            @{ Name = 'ViPNetMonitor'; DisplayName = 'ViPNet Monitor'; Status = 'Running'; StartType = 'Automatic' }
            @{ Name = 'AVP.KES.11.6.0'; DisplayName = 'Kaspersky Endpoint Security'; Status = 'Running'; StartType = 'Automatic' }
            @{ Name = 'klnagent'; DisplayName = 'Агент администрирования Kaspersky Security Center'; Status = 'Running'; StartType = 'Automatic' }
            @{ Name = 'RemoteRegistry'; DisplayName = 'Удалённый реестр'; Status = 'Stopped'; StartType = 'Disabled' }
        )
        SecPolicy = [ordered]@{
            MinimumPasswordLength = 8; PasswordComplexity = 1; MaximumPasswordAge = 90
            LockoutBadCount = 5; EnableGuestAccount = 0
        }
        # Значение подкатегорий аудита: 0 – нет, 1 – успех, 2 – отказ, 3 – успех и отказ
        AuditPolicy = @{
            '{0CCE9215-69AE-11D9-BED3-505054503030}' = 3; '{0CCE9216-69AE-11D9-BED3-505054503030}' = 3
            '{0CCE9217-69AE-11D9-BED3-505054503030}' = 3; '{0CCE9235-69AE-11D9-BED3-505054503030}' = 3
            '{0CCE9237-69AE-11D9-BED3-505054503030}' = 3; '{0CCE922F-69AE-11D9-BED3-505054503030}' = 3
            '{0CCE9228-69AE-11D9-BED3-505054503030}' = 3; '{0CCE9230-69AE-11D9-BED3-505054503030}' = 3
        }
        SeceditFails  = $false
        AuditpolFails = $false
        Admins        = @('ARM-TEST-01\Администратор', 'PTK\Domain Admins')
        AdminsFail    = $false
        Users = @(
            @{ Name = 'Администратор'; Enabled = $true; PasswordExpires = $now.AddDays(60); LastLogon = $now.AddDays(-1) }
            @{ Name = 'Гость'; Enabled = $false; PasswordExpires = $null; LastLogon = $null }
        )
        UsersFail       = $false
        SecurityLogMB   = 128
        LogsPresent     = @('Security', 'Kaspersky Event Log')
        # Журналы событий: имя журнала -> список событий @{ Id; TimeCreated; Message }
        Events = @{
            'Security' = @(
                @{ Id = 4625; TimeCreated = $now.AddDays(-2); Message = 'Учётной записи не удалось выполнить вход в систему.' }
                @{ Id = 4625; TimeCreated = $now.AddDays(-3); Message = 'Учётной записи не удалось выполнить вход в систему.' }
            )
            'Kaspersky Event Log' = @(
                @{ Id = 302; TimeCreated = $now.AddDays(-1); Message = 'Задача обновления баз завершена.' }
            )
        }
        Firewall = @(
            @{ Name = 'Domain'; Enabled = 'True' }; @{ Name = 'Private'; Enabled = 'True' }; @{ Name = 'Public'; Enabled = 'True' }
        )
        DhcpInterfaces = @()
        WifiAdapters   = @()
        Bluetooth      = @()
        Smb1           = $false
        # Произвольные параметры реестра: путь раздела -> значения
        Registry = @{
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' = @{ NoDriveTypeAutoRun = 255 }
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'   = @{ InactivityTimeoutSecs = 600 }
            'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'       = @{ AutoAdminLogon = '0' }
        }
        Usb = @(
            @{ Model = 'Disk&Ven_Kingston&Prod_DataTraveler&Rev_1.00'; Serial = '0401396BBFE2A1B5&0'; FriendlyName = 'Kingston DataTraveler USB Device' }
        )
        # СОС в системных хранилищах: имя хранилища -> список DER-кодов
        StoreCrls    = @{ Root = @(); CA = @() }
        Certificates = @()     # @{ Store; Thumbprint; NotAfter }
        AvProduct    = $null   # @{ displayName; timestamp } – сведения Центра безопасности Windows
    }
}

# Формирование значения Blob раздела реестра SystemCertificates\<Store>\CRLs\<хеш>
function global:New-FakeCrlBlob([byte[]]$Der) {
    $ms = New-Object System.IO.MemoryStream
    $w = New-Object System.IO.BinaryWriter $ms
    # служебное свойство (не СОС), затем свойство 33 – закодированный СОС
    $w.Write([int]20); $w.Write([int]1); $w.Write([int]4); $w.Write([byte[]](1, 2, 3, 4))
    $w.Write([int]33); $w.Write([int]1); $w.Write([int]$Der.Length); $w.Write($Der)
    $w.Flush()
    return , $ms.ToArray()
}

# ---------------------------------------------------------------------------
# Виртуальный реестр
# ---------------------------------------------------------------------------
function global:Get-FakeRegistry {
    $map = @{}
    $i = 0
    foreach ($s in $global:FakeArm.Software) {
        $i++
        $map["HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\App$i"] = $s
    }
    foreach ($u in $global:FakeArm.Usb) {
        $map["HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\$($u.Model)\$($u.Serial)"] = @{ FriendlyName = $u.FriendlyName }
    }
    foreach ($store in $global:FakeArm.StoreCrls.Keys) {
        $n = 0
        foreach ($der in $global:FakeArm.StoreCrls[$store]) {
            $n++
            $map["HKLM:\SOFTWARE\Microsoft\SystemCertificates\$store\CRLs\HASH$n"] = @{ Blob = (New-FakeCrlBlob $der) }
        }
    }
    foreach ($k in $global:FakeArm.Registry.Keys) { $map[$k] = $global:FakeArm.Registry[$k] }
    return $map
}

function global:Test-FakeRegPath([string]$Path) { $Path -match '^(HKLM:|Registry::|Cert:)' }

function global:Test-Path {
    [CmdletBinding()]
    param([Parameter(Position = 0, ValueFromPipeline = $true)][string[]]$Path,
        [string]$LiteralPath, [Microsoft.PowerShell.Commands.TestPathType]$PathType = 'Any')
    if ($Path -and (Test-FakeRegPath $Path[0])) {
        $p = $Path[0].TrimEnd('\').ToUpperInvariant()
        foreach ($k in (Get-FakeRegistry).Keys) {
            $ku = $k.ToUpperInvariant()
            if ($ku -eq $p -or $ku.StartsWith($p + '\')) { return $true }
        }
        return $false
    }
    & $global:SziRealTestPath @PSBoundParameters
}

function global:Get-ChildItem {
    [CmdletBinding()]
    param([Parameter(Position = 0)][string[]]$Path, [switch]$File, [switch]$Recurse, [string]$Filter)
    if ($Path -and $Path[0] -like 'Cert:*') {
        $store = ($Path[0] -split '\\')[-1]
        return @($global:FakeArm.Certificates | Where-Object { $_.Store -eq $store } |
            ForEach-Object { [pscustomobject]@{ Thumbprint = $_.Thumbprint; NotAfter = $_.NotAfter } })
    }
    if ($Path -and (Test-FakeRegPath $Path[0])) {
        $p = $Path[0].TrimEnd('\')
        $children = @{}
        foreach ($k in (Get-FakeRegistry).Keys) {
            if ($k.ToUpperInvariant().StartsWith($p.ToUpperInvariant() + '\')) {
                $name = $k.Substring($p.Length + 1).Split('\')[0]
                $children[$name] = "$p\$name"
            }
        }
        return @($children.Keys | Sort-Object | ForEach-Object {
                [pscustomobject]@{ PSChildName = $_; PSPath = $children[$_]; Name = $_ } })
    }
    & $global:SziRealGetChildItem @PSBoundParameters
}

function global:Get-ItemProperty {
    [CmdletBinding()]
    param([Parameter(Position = 0)][string[]]$Path, [string[]]$Name)
    if (-not ($Path -and (Test-FakeRegPath $Path[0]))) { return & $global:SziRealGetItemProp @PSBoundParameters }
    $reg = Get-FakeRegistry
    foreach ($p in $Path) {
        $keys = if ($p.EndsWith('\*')) {
            $base = $p.Substring(0, $p.Length - 2).ToUpperInvariant()
            @($reg.Keys | Where-Object { $_.ToUpperInvariant().StartsWith($base + '\') -and
                    -not $_.Substring($base.Length + 1).Contains('\') })
        }
        else { @($reg.Keys | Where-Object { $_.ToUpperInvariant() -eq $p.ToUpperInvariant() }) }
        foreach ($k in ($keys | Sort-Object)) { [pscustomobject]$reg[$k] }
    }
}

# ---------------------------------------------------------------------------
# Утилиты secedit.exe и auditpol.exe
# ---------------------------------------------------------------------------
function global:secedit.exe {
    $cfg = $args[([array]::IndexOf($args, '/cfg') + 1)]
    if ($global:FakeArm.SeceditFails) { return 'Задача завершена с ошибкой: отказано в доступе.' }
    $lines = @('[Unicode]', 'Unicode=yes', '[System Access]')
    foreach ($k in $global:FakeArm.SecPolicy.Keys) { $lines += "$k = $($global:FakeArm.SecPolicy[$k])" }
    $lines += '[Version]', 'signature="$CHICAGO$"', 'Revision=1'
    [IO.File]::WriteAllLines($cfg, $lines, [Text.Encoding]::Unicode)
    'Задача успешно завершена.'
}

function global:auditpol.exe {
    $file = ($args | Where-Object { $_ -like '/file:*' } | Select-Object -First 1).Substring(6)
    if ($global:FakeArm.AuditpolFails) { return 'Ошибка 0x00000005: Отказано в доступе.' }
    $lines = @('Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value')
    foreach ($g in $global:FakeArm.AuditPolicy.Keys) {
        $lines += "ARM-TEST-01,System,Подкатегория,$($g.ToLower()),,,$($global:FakeArm.AuditPolicy[$g])"
    }
    [IO.File]::WriteAllLines($file, $lines, (New-Object System.Text.UTF8Encoding($false)))
}

# ---------------------------------------------------------------------------
# Службы, учётные записи, журналы, сеть, WMI/CIM
# ---------------------------------------------------------------------------
function global:Get-Service {
    [CmdletBinding()] param([Parameter(Position = 0)][string]$Name)
    $all = @($global:FakeArm.Services | ForEach-Object { [pscustomobject]$_ })
    if (-not $Name) { return $all }
    $svc = $all | Where-Object { $_.Name -eq $Name }
    if (-not $svc) { Write-Error "Не удаётся найти службу с именем службы '$Name'." ; return }
    $svc
}

function global:Get-LocalGroup {
    [CmdletBinding()] param([string]$SID)
    [pscustomobject]@{ Name = 'Администраторы'; SID = $SID }
}

function global:Get-LocalGroupMember {
    [CmdletBinding()] param($Group)
    if ($global:FakeArm.AdminsFail) { throw 'Не удалось сопоставить элемент группы (осиротевший SID).' }
    $global:FakeArm.Admins | ForEach-Object { [pscustomobject]@{ Name = $_ } }
}

function global:Get-LocalUser {
    [CmdletBinding()] param()
    if ($global:FakeArm.UsersFail) { throw 'Модуль Microsoft.PowerShell.LocalAccounts недоступен.' }
    $global:FakeArm.Users | ForEach-Object { [pscustomobject]$_ }
}

function global:Get-WinEvent {
    [CmdletBinding()]
    param([string]$ListLog, [hashtable]$FilterHashtable, [int]$MaxEvents = [int]::MaxValue)
    if ($ListLog) {
        if ($global:FakeArm.LogsPresent -notcontains $ListLog) { Write-Error "Журнал $ListLog не найден"; return }
        return [pscustomobject]@{
            LogName = $ListLog; LogMode = 'Circular'
            MaximumSizeInBytes = [int64]$global:FakeArm.SecurityLogMB * 1MB
        }
    }
    $log = $FilterHashtable.LogName
    $ev = @($global:FakeArm.Events[$log] | Where-Object { $_ } | ForEach-Object { [pscustomobject]$_ })
    if ($FilterHashtable.ContainsKey('Id')) { $ids = @($FilterHashtable.Id); $ev = @($ev | Where-Object { $ids -contains $_.Id }) }
    if ($FilterHashtable.ContainsKey('StartTime')) { $ev = @($ev | Where-Object { $_.TimeCreated -ge $FilterHashtable.StartTime }) }
    if ($ev.Count -eq 0) { Write-Error 'Не найдено событий, соответствующих указанным условиям выбора.'; return }
    $ev | Sort-Object TimeCreated -Descending | Select-Object -First $MaxEvents
}

function global:Get-NetFirewallProfile { $global:FakeArm.Firewall | ForEach-Object { [pscustomobject]$_ } }

function global:Get-NetIPInterface {
    [CmdletBinding()] param([string]$AddressFamily, [string]$ConnectionState)
    @(@{ InterfaceAlias = 'Ethernet'; Dhcp = 'Disabled' }; @{ InterfaceAlias = 'Loopback Pseudo-Interface 1'; Dhcp = 'Enabled' }) +
    @($global:FakeArm.DhcpInterfaces | ForEach-Object { @{ InterfaceAlias = $_; Dhcp = 'Enabled' } }) |
        ForEach-Object { [pscustomobject]$_ }
}

function global:Get-NetAdapter {
    [CmdletBinding()] param([switch]$Physical)
    @([pscustomobject]@{ Name = 'Ethernet'; InterfaceDescription = 'Intel(R) Ethernet Connection I219-LM'; PhysicalMediaType = '802.3' }) +
    @($global:FakeArm.WifiAdapters | ForEach-Object { [pscustomobject]@{ Name = 'Wi-Fi'; InterfaceDescription = $_; PhysicalMediaType = 'Native 802.11' } })
}

function global:Get-PnpDevice {
    [CmdletBinding()] param([string]$Class, [switch]$PresentOnly)
    $global:FakeArm.Bluetooth | ForEach-Object { [pscustomobject]@{ FriendlyName = $_; Class = 'Bluetooth' } }
}

function global:Get-SmbServerConfiguration { [pscustomobject]@{ EnableSMB1Protocol = [bool]$global:FakeArm.Smb1 } }

function global:Get-NetIPAddress {
    [CmdletBinding()] param([string]$AddressFamily)
    [pscustomobject]@{ IPAddress = '10.10.1.15' }; [pscustomobject]@{ IPAddress = '127.0.0.1' }
}

function global:Get-CimInstance {
    [CmdletBinding()] param([string]$ClassName, [string]$Namespace)
    switch ($ClassName) {
        'Win32_OperatingSystem' {
            [pscustomobject]@{ Caption = 'Microsoft Windows 10 Корпоративная'; Version = '10.0.19045'; LastBootUpTime = (Get-Date).AddHours(-5) }
        }
        'Win32_ComputerSystem' { [pscustomobject]@{ Domain = 'ptk.local' } }
        'AntiVirusProduct' { if ($global:FakeArm.AvProduct) { [pscustomobject]$global:FakeArm.AvProduct } }
    }
}

# Переменные окружения Windows, используемые модулем проверок
if (-not $env:TEMP) { $env:TEMP = [IO.Path]::GetTempPath() }
$env:COMPUTERNAME = 'ARM-TEST-01'
$env:USERDOMAIN = 'PTK'
$env:USERNAME = 'auditor'

$global:FakeArm = New-FakeArm
