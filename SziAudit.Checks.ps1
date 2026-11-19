#requires -Version 5.1
<#
.SYNOPSIS
    ПО «СЗИ-Аудит». Модуль проверок состояния средств защиты информации АРМ.
.DESCRIPTION
    Сценарий выполняется локально (Start-Job) или на удалённом АРМ (Invoke-Command)
    и возвращает объект с общими сведениями об АРМ и списком результатов проверок.
    Каждая проверка сравнивает фактическое состояние АРМ с требованием эталона.
.PARAMETER EtalonXml
    Текст эталонного файла конфигурации (Config\Etalon.xml).
.PARAMETER ProfileId
    Идентификатор профиля АРМ (тип рабочего места) из эталона.
#>
param(
    [Parameter(Mandatory = $true)][string]$EtalonXml,
    [Parameter(Mandatory = $true)][string]$ProfileId
)

$ErrorActionPreference = 'Stop'

# --- Статусы результата проверки --------------------------------------------
$ST_OK   = 'Соответствует'
$ST_FAIL = 'Не соответствует'
$ST_WARN = 'Предупреждение'
$ST_ERR  = 'Ошибка проверки'

[xml]$E = $EtalonXml
$P = $E.SziEtalon.Profiles.Profile | Where-Object { $_.id -eq $ProfileId } | Select-Object -First 1
if (-not $P) { throw "Профиль '$ProfileId' не найден в эталоне" }

$Results = New-Object System.Collections.Generic.List[object]

function Add-Result {
    param(
        [string]$Id, [string]$Category, [string]$Name,
        [string]$Expected, [string]$Actual, [string]$Status,
        [string]$Severity = 'Средняя', [string]$Recommendation = ''
    )
    $Results.Add([pscustomobject]@{
        Computer       = $env:COMPUTERNAME
        CheckId        = $Id
        Category       = $Category
        Name           = $Name
        Expected       = $Expected
        Actual         = $Actual
        Status         = $Status
        Severity       = $Severity
        Recommendation = $Recommendation
        Time           = Get-Date
    })
}

# Обёртка: выполняет тело проверки и фиксирует ошибку, если проверка не удалась
function Invoke-Check {
    param([string]$Id, [string]$Category, [string]$Name, [scriptblock]$Body)
    try { & $Body }
    catch {
        Add-Result $Id $Category $Name '-' $_.Exception.Message $ST_ERR 'Средняя' `
            'Запустите программу от имени администратора и проверьте доступность компонента'
    }
}

function Get-ProfileValue([string]$Name, $Default) {
    $node = $P.SelectSingleNode($Name)
    if ($node -and $node.InnerText) { return $node.InnerText } else { return $Default }
}

function Get-InstalledSoftware {
    $keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    Get-ItemProperty -Path $keys -ErrorAction SilentlyContinue |
        Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName } |
        Where-Object { -not ($_.PSObject.Properties['SystemComponent'] -and $_.SystemComponent -eq 1) } |
        ForEach-Object {
            $ver = ''
            if ($_.PSObject.Properties['DisplayVersion']) { $ver = [string]$_.DisplayVersion }
            [pscustomobject]@{ Name = [string]$_.DisplayName; Version = $ver }
        } | Sort-Object Name -Unique
}

function Test-VersionAtLeast([string]$Actual, [string]$Min) {
    if ([string]::IsNullOrEmpty($Min)) { return $true }
    $a = $null; $m = $null
    $num = [regex]::Match($Actual, '^\d+(\.\d+){0,3}').Value
    if (-not $num) { return $false }
    if ($num -notmatch '\.') { $num = "$num.0" }
    if ($Min -notmatch '\.') { $Min = "$Min.0" }
    if (-not [version]::TryParse($num, [ref]$a)) { return $false }
    if (-not [version]::TryParse($Min, [ref]$m)) { return $true }
    return ($a -ge $m)
}

function Get-SecurityPolicy {
    $tmp = Join-Path $env:TEMP ('szi_sec_{0}.inf' -f [guid]::NewGuid())
    $null = & secedit.exe /export /cfg $tmp /areas SECURITYPOLICY 2>&1
    if (-not (Test-Path $tmp)) { throw 'Не удалось выгрузить локальную политику безопасности (secedit)' }
    $h = @{}
    Get-Content -Path $tmp | ForEach-Object {
        if ($_ -match '^\s*([^=\[\];]+?)\s*=\s*(.*)$') { $h[$matches[1].Trim()] = $matches[2].Trim() }
    }
    Remove-Item -Path $tmp -Force
    return $h
}

function Get-AuditPolicy {
    $tmp = Join-Path $env:TEMP ('szi_aud_{0}.csv' -f [guid]::NewGuid())
    $null = & auditpol.exe /backup /file:$tmp 2>&1
    if (-not (Test-Path $tmp)) { throw 'Не удалось выгрузить политику аудита (auditpol)' }
    $rows = Import-Csv -Path $tmp -Header 'Machine', 'Target', 'Subcategory', 'Guid', 'Incl', 'Excl', 'Value' |
        Select-Object -Skip 1
    Remove-Item -Path $tmp -Force
    $h = @{}
    foreach ($r in $rows) { if ($r.Guid) { $h[$r.Guid.ToUpper()] = $r } }
    return $h
}

function Get-UsbStorageHistory {
    $base = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR'
    if (-not (Test-Path $base)) { return @() }
    Get-ChildItem -Path $base | ForEach-Object {
        $model = $_.PSChildName
        Get-ChildItem -Path $_.PSPath | ForEach-Object {
            $fn = (Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue).FriendlyName
            [pscustomobject]@{
                Serial = ($_.PSChildName -replace '&\d+$', '')
                Model  = $model
                Name   = [string]$fn
            }
        }
    }
}

function Get-LocalAdminMembers {
    try {
        $grp = Get-LocalGroup -SID 'S-1-5-32-544'
        return @(Get-LocalGroupMember -Group $grp | ForEach-Object { $_.Name })
    }
    catch {
        # Запасной вариант через ADSI (Get-LocalGroupMember не работает при «осиротевших» SID)
        $sid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
        $name = $sid.Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1]
        $g = [ADSI]"WinNT://./$name,group"
        return @($g.psbase.Invoke('Members') | ForEach-Object {
            $_.GetType().InvokeMember('AdsPath', 'GetProperty', $null, $_, $null) -replace '^WinNT://', '' -replace '/', '\'
        })
    }
}

# --- Разбор списка отозванных сертификатов (СОС, X.509 CRL, DER или PEM) -------
# Структура: CertificateList ::= SEQUENCE { tbsCertList SEQUENCE { [version INTEGER],
#   signature AlgorithmIdentifier, issuer Name, thisUpdate Time, [nextUpdate Time], ... } ... }
function Read-Asn1Header([byte[]]$Bytes, [int]$Pos) {
    $len = [int]$Bytes[$Pos + 1]; $hl = 2
    if ($len -band 0x80) {
        $n = $len -band 0x7F; $len = 0
        for ($k = 0; $k -lt $n; $k++) { $len = ($len -shl 8) -bor [int]$Bytes[$Pos + 2 + $k] }
        $hl = 2 + $n
    }
    return [pscustomobject]@{ Tag = [int]$Bytes[$Pos]; Len = $len; HL = $hl }
}

function ConvertFrom-Asn1Time([byte[]]$Bytes, $H, [int]$Pos) {
    $s = [Text.Encoding]::ASCII.GetString($Bytes, $Pos + $H.HL, $H.Len)
    if ($H.Tag -eq 0x17) {   # UTCTime ГГММДДччммссZ
        $yy = [int]$s.Substring(0, 2)
        $s = $(if ($yy -lt 50) { '20' } else { '19' }) + $s
    }
    $dt = [datetime]::ParseExact($s.Substring(0, 14), 'yyyyMMddHHmmss', [Globalization.CultureInfo]::InvariantCulture)
    return [datetime]::SpecifyKind($dt, 'Utc').ToLocalTime()
}

function Get-CrlInfo([byte[]]$Bytes) {
    $txt = [Text.Encoding]::ASCII.GetString($Bytes)
    if ($txt -match '-----BEGIN X509 CRL-----([\s\S]+?)-----END') {
        $Bytes = [Convert]::FromBase64String(($matches[1] -replace '\s', ''))
    }
    $h = Read-Asn1Header $Bytes 0; $p = $h.HL             # CertificateList
    $h = Read-Asn1Header $Bytes $p; $p += $h.HL            # tbsCertList
    $h = Read-Asn1Header $Bytes $p
    if ($h.Tag -eq 0x02) { $p += $h.HL + $h.Len; $h = Read-Asn1Header $Bytes $p }   # version
    $p += $h.HL + $h.Len                                   # signature
    $h = Read-Asn1Header $Bytes $p                         # issuer
    $issuerBytes = New-Object byte[] ($h.HL + $h.Len)
    [Array]::Copy($Bytes, $p, $issuerBytes, 0, $issuerBytes.Length)
    $issuer = (New-Object System.Security.Cryptography.X509Certificates.X500DistinguishedName(, $issuerBytes)).Name
    $p += $h.HL + $h.Len
    $h = Read-Asn1Header $Bytes $p
    $thisUpd = ConvertFrom-Asn1Time $Bytes $h $p; $p += $h.HL + $h.Len
    $next = $null
    if ($p -lt $Bytes.Length) {
        $h = Read-Asn1Header $Bytes $p
        if ($h.Tag -eq 0x17 -or $h.Tag -eq 0x18) { $next = ConvertFrom-Asn1Time $Bytes $h $p }
    }
    $cn = $issuer
    if ($issuer -match 'CN=("[^"]+"|[^,]+)') { $cn = $matches[1].Trim('"') }
    return [pscustomobject]@{ Issuer = $issuer; IssuerCN = $cn; ThisUpdate = $thisUpd; NextUpdate = $next }
}

# СОС, установленные в системные хранилища (реестр SystemCertificates\<Store>\CRLs\<хеш>\Blob)
function Get-StoreCrls {
    foreach ($store in 'Root', 'CA') {
        $base = "HKLM:\SOFTWARE\Microsoft\SystemCertificates\$store\CRLs"
        if (-not (Test-Path $base)) { continue }
        foreach ($k in Get-ChildItem -Path $base) {
            $blob = (Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue).Blob
            if (-not $blob) { continue }
            # Blob: последовательность записей {PropId(4), Reserved(4), Length(4), Data}
            $pos = 0
            while ($pos + 12 -le $blob.Length) {
                $len = [BitConverter]::ToInt32($blob, $pos + 8)
                if ($len -le 0 -or $pos + 12 + $len -gt $blob.Length) { break }
                # элемент с идентификатором 33 (CERT_CRL_PROP_ID) содержит закодированный СОС
                if ([BitConverter]::ToInt32($blob, $pos) -eq 33 -and $blob[$pos + 12] -eq 0x30) {
                    $der = New-Object byte[] $len
                    [Array]::Copy($blob, $pos + 12, $der, 0, $len)
                    try { $info = Get-CrlInfo $der; $info | Add-Member -NotePropertyName Source -NotePropertyValue "Хранилище $store"; $info } catch { }
                    break
                }
                $pos += 12 + $len
            }
        }
    }
}

function Get-NodeTexts([string]$XPath) {
    @($E.SelectNodes($XPath) | ForEach-Object { $_.InnerText } | Where-Object { $_ })
}

function Test-LikeAny([string]$Value, $Patterns) {
    foreach ($p in @($Patterns)) { if ($p -and $Value -like [string]$p) { return $true } }
    return $false
}

$Sev = @{ H = 'Высокая'; M = 'Средняя'; L = 'Низкая' }
$Today = Get-Date

# ============================================================================
# 1. Состав, версии, работоспособность и сертификаты СЗИ
# ============================================================================
$Soft = @(Get-InstalledSoftware)
$RequiredIds = @(([string]$P.RequireSzi) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$WarnDays = [int](Get-ProfileValue 'CertWarnDays' 90)

foreach ($sid in $RequiredIds) {
    $s = $E.SziEtalon.SziList.Szi | Where-Object { $_.id -eq $sid } | Select-Object -First 1
    if (-not $s) { continue }

    Invoke-Check "SZI-$sid" 'Состав СЗИ' "Установлено: $($s.GetAttribute('name'))" {
        $found = $Soft | Where-Object { Test-LikeAny $_.Name ([string]$s.productPattern -split '\|') } | Select-Object -First 1
        $exp = "Установлено, версия не ниже $($s.minVersion)"
        if (-not $found) {
            Add-Result $Id $Category $Name $exp 'Не установлено' $ST_FAIL $Sev.H `
                'Установить СЗИ в соответствии с предписанием на эксплуатацию АСЗИ'
        }
        elseif (-not (Test-VersionAtLeast $found.Version $s.minVersion)) {
            Add-Result $Id $Category $Name $exp "$($found.Name), версия $($found.Version)" $ST_FAIL $Sev.H `
                'Обновить СЗИ до версии, указанной в предписании на эксплуатацию'
        }
        else {
            Add-Result $Id $Category $Name $exp "$($found.Name), версия $($found.Version)" $ST_OK $Sev.H
        }
    }

    if ($s.servicePattern) {
        Invoke-Check "SVC-$sid" 'Работоспособность СЗИ' "Служба: $($s.GetAttribute('name'))" {
            $pat = [string]$s.servicePattern -split '\|'
            $svc = @(Get-Service | Where-Object { (Test-LikeAny $_.Name $pat) -or (Test-LikeAny $_.DisplayName $pat) })
            $exp = 'Служба запущена, тип запуска «Автоматически»'
            if ($svc.Count -eq 0) {
                Add-Result $Id $Category $Name $exp 'Служба не найдена' $ST_FAIL $Sev.H 'Переустановить СЗИ'
            }
            else {
                $bad = @($svc | Where-Object { $_.Status -ne 'Running' -or $_.StartType -ne 'Automatic' })
                $act = ($svc | ForEach-Object { "$($_.Name): $($_.Status)/$($_.StartType)" }) -join '; '
                if ($bad.Count -gt 0) {
                    Add-Result $Id $Category $Name $exp $act $ST_FAIL $Sev.H `
                        'Запустить службу, выяснить причину остановки, внести запись в журнал учёта инцидентов ИБ'
                }
                else { Add-Result $Id $Category $Name $exp $act $ST_OK $Sev.H }
            }
        }
    }

    if ($s.certExpires) {
        Invoke-Check "CRT-$sid" 'Сертификаты СЗИ' "Срок сертификата: $($s.GetAttribute('name'))" {
            $d = [datetime]::ParseExact([string]$s.certExpires, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
            $exp = 'Сертификат соответствия действует'
            $act = "№ $($s.certNumber), действует до $($d.ToString('dd.MM.yyyy'))"
            if ($d -lt $Today) {
                Add-Result $Id $Category $Name $exp $act $ST_FAIL $Sev.H `
                    'Эксплуатация СЗИ с истёкшим сертификатом запрещена. Доложить, согласовать порядок действий'
            }
            elseif ($d -lt $Today.AddDays($WarnDays)) {
                Add-Result $Id $Category $Name $exp $act $ST_WARN $Sev.M 'Срок сертификата истекает. Уточнить сведения о продлении'
            }
            else { Add-Result $Id $Category $Name $exp $act $ST_OK $Sev.M }
        }
    }
}

# ============================================================================
# 2. Актуальность баз данных компьютерных вирусов (БДКВ)
# ============================================================================
Invoke-Check 'AV-BASES' 'Антивирусная защита' 'Актуальность БДКВ' {
    $maxAge = [int](Get-ProfileValue 'AvBasesMaxAgeDays' 7)
    $newest = $null
    foreach ($pth in @($E.SziEtalon.Settings.AvBasesPath)) {
        $pp = [Environment]::ExpandEnvironmentVariables([string]$pth)
        if ($pp -and (Test-Path $pp)) {
            $f = Get-ChildItem -Path $pp -File -Recurse -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($f -and ((-not $newest) -or $f.LastWriteTime -gt $newest)) { $newest = $f.LastWriteTime }
        }
    }
    if (-not $newest) {
        $av = Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName 'AntiVirusProduct' -ErrorAction SilentlyContinue |
            Where-Object { $_.displayName -like '*Kaspersky*' } | Select-Object -First 1
        if ($av -and $av.PSObject.Properties['timestamp'] -and $av.timestamp) {
            $newest = [datetime]::Parse($av.timestamp, [Globalization.CultureInfo]::InvariantCulture)
        }
    }
    $exp = "Не старше $maxAge суток"
    if (-not $newest) {
        Add-Result $Id $Category $Name $exp 'Дата обновления не определена' $ST_WARN $Sev.H `
            'Проверить БДКВ в консоли Kaspersky Security Center и путь к базам в эталоне'
    }
    else {
        $age = [math]::Floor(($Today - $newest).TotalDays)
        $act = "Обновлены $($newest.ToString('dd.MM.yyyy HH:mm')) ($age сут.)"
        if ($age -gt $maxAge) {
            Add-Result $Id $Category $Name $exp $act $ST_FAIL $Sev.H 'Выполнить обновление БДКВ в ручном режиме'
        }
        else { Add-Result $Id $Category $Name $exp $act $ST_OK $Sev.H }
    }
}

# ============================================================================
# 3. Политика учётных записей (пароли, блокировка, гостевая запись)
# ============================================================================
$Sec = $null
try { $Sec = Get-SecurityPolicy }
catch {
    Add-Result 'POL-READ' 'Политика учётных записей' 'Чтение локальной политики безопасности' '-' `
        $_.Exception.Message $ST_ERR 'Высокая' 'Запустите программу от имени администратора'
}
if ($Sec) {
    $minLen = [int](Get-ProfileValue 'PasswordMinLength' 8)
    $maxAge = [int](Get-ProfileValue 'PasswordMaxAgeDays' 180)
    $lockMax = [int](Get-ProfileValue 'LockoutThresholdMax' 10)

    Invoke-Check 'PWD-LEN' 'Политика учётных записей' 'Минимальная длина пароля' {
        $v = [int]$Sec['MinimumPasswordLength']
        $st = if ($v -ge $minLen) { $ST_OK } else { $ST_FAIL }
        Add-Result $Id $Category $Name "Не менее $minLen символов" "$v" $st $Sev.H 'Настроить ОГП «Политика паролей»'
    }
    Invoke-Check 'PWD-CPLX' 'Политика учётных записей' 'Требование сложности пароля' {
        $v = [int]$Sec['PasswordComplexity']
        $st = if ($v -eq 1) { $ST_OK } else { $ST_FAIL }
        $act = if ($v -eq 1) { 'Включено' } else { 'Отключено' }
        Add-Result $Id $Category $Name 'Включено' $act $st $Sev.H 'Включить параметр «Пароль должен отвечать требованиям сложности»'
    }
    Invoke-Check 'PWD-AGE' 'Политика учётных записей' 'Максимальный срок действия пароля' {
        $v = [int]$Sec['MaximumPasswordAge']
        $st = if ($v -gt 0 -and $v -le $maxAge) { $ST_OK } else { $ST_FAIL }
        Add-Result $Id $Category $Name "Не более $maxAge суток" "$v сут." $st $Sev.M 'Настроить ОГП «Политика паролей»'
    }
    Invoke-Check 'LOCK-CNT' 'Политика учётных записей' 'Порог блокировки учётной записи' {
        $v = [int]$Sec['LockoutBadCount']
        $st = if ($v -gt 0 -and $v -le $lockMax) { $ST_OK } else { $ST_FAIL }
        Add-Result $Id $Category $Name "От 1 до $lockMax попыток" "$v" $st $Sev.M 'Настроить ОГП «Политика блокировки учётной записи»'
    }
    Invoke-Check 'GUEST' 'Политика учётных записей' 'Учётная запись «Гость»' {
        $v = [int]$Sec['EnableGuestAccount']
        $st = if ($v -eq 0) { $ST_OK } else { $ST_FAIL }
        $act = if ($v -eq 0) { 'Отключена' } else { 'Включена' }
        Add-Result $Id $Category $Name 'Отключена' $act $st $Sev.H 'Отключить учётную запись «Гость»'
    }
}

Invoke-Check 'ADMINS' 'Политика учётных записей' 'Состав группы локальных администраторов' {
    $allowed = @($P.AllowedAdmins.Account)
    $members = @(Get-LocalAdminMembers)
    $extra = @($members | Where-Object { -not (Test-LikeAny $_ $allowed) })
    $act = $members -join '; '
    if ($extra.Count -gt 0) {
        Add-Result $Id $Category $Name ('Только: ' + ($allowed -join '; ')) $act $ST_FAIL $Sev.H `
            ('Исключить из группы: ' + ($extra -join '; ') + '. Сверить с приказом о допуске к АСЗИ')
    }
    else { Add-Result $Id $Category $Name ('Только: ' + ($allowed -join '; ')) $act $ST_OK $Sev.H }
}

# ============================================================================
# 4. Политика аудита событий безопасности и журнал безопасности
# ============================================================================
$Aud = $null
try { $Aud = Get-AuditPolicy }
catch {
    Add-Result 'AUD-READ' 'Аудит событий' 'Чтение политики аудита' '-' `
        $_.Exception.Message $ST_ERR 'Высокая' 'Запустите программу от имени администратора'
}
$AudText = @{ 0 = 'Нет аудита'; 1 = 'Успех'; 2 = 'Отказ'; 3 = 'Успех и отказ' }
if ($Aud) {
    foreach ($a in @($P.AuditPolicy.Item)) {
        $g = ([string]$a.guid).ToUpper()
        $req = [int]$a.GetAttribute('value')
        Invoke-Check "AUD-$($g.Substring(1,8))" 'Аудит событий' "Аудит: $($a.GetAttribute('name'))" {
            $v = 0
            if ($Aud.ContainsKey($g) -and $Aud[$g].Value -match '^\d+$') { $v = [int]$Aud[$g].Value }
            $st = if (($v -band $req) -eq $req) { $ST_OK } else { $ST_FAIL }
            Add-Result $Id $Category $Name $AudText[$req] $AudText[$v] $st $Sev.M `
                'Настроить подкатегорию расширенной политики аудита в ОГП'
        }
    }
}

Invoke-Check 'LOG-SIZE' 'Аудит событий' 'Размер журнала безопасности' {
    $minMb = [int](Get-ProfileValue 'SecurityLogMinMB' 64)
    $log = Get-WinEvent -ListLog 'Security'
    $mb = [math]::Round($log.MaximumSizeInBytes / 1MB)
    $st = if ($mb -ge $minMb) { $ST_OK } else { $ST_FAIL }
    Add-Result $Id $Category $Name "Не менее $minMb МБ" "$mb МБ, режим $($log.LogMode)" $st $Sev.L 'Увеличить максимальный размер журнала'
}

Invoke-Check 'LOG-CLEAR' 'Аудит событий' 'Очистка журнала безопасности (событие 1102)' {
    $days = [int](Get-ProfileValue 'EventLookbackDays' 30)
    $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 1102; StartTime = $Today.AddDays(-$days) } -ErrorAction SilentlyContinue)
    $st = if ($ev.Count -eq 0) { $ST_OK } else { $ST_WARN }
    $act = if ($ev.Count -eq 0) { 'Не выявлено' } else { "Выявлено: $($ev.Count), последнее $($ev[0].TimeCreated.ToString('dd.MM.yyyy HH:mm'))" }
    Add-Result $Id $Category $Name "Отсутствует за $days сут." $act $st $Sev.H 'Установить причину очистки журнала, внести запись в журнал учёта инцидентов ИБ'
}

Invoke-Check 'LOG-FAIL' 'Аудит событий' 'Неудачные попытки входа (событие 4625)' {
    $days = [int](Get-ProfileValue 'EventLookbackDays' 30)
    $lim = [int](Get-ProfileValue 'FailedLogonWarn' 20)
    $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $Today.AddDays(-$days) } -ErrorAction SilentlyContinue)
    $st = if ($ev.Count -le $lim) { $ST_OK } else { $ST_WARN }
    Add-Result $Id $Category $Name "Не более $lim за $days сут." "$($ev.Count)" $st $Sev.M 'Проанализировать журнал на предмет попыток подбора пароля'
}

# ============================================================================
# 5. Сетевые настройки и беспроводные интерфейсы
# ============================================================================
if ((Get-ProfileValue 'RequireFirewall' 'true') -eq 'true') {
    Invoke-Check 'NET-FW' 'Сетевые настройки' 'Межсетевой экран Windows' {
        $prof = @(Get-NetFirewallProfile)
        $off = @($prof | Where-Object { [string]$_.Enabled -ne 'True' })
        $act = ($prof | ForEach-Object { "$($_.Name): $(if ([string]$_.Enabled -eq 'True') { 'вкл' } else { 'выкл' })" }) -join '; '
        $st = if ($off.Count -eq 0) { $ST_OK } else { $ST_FAIL }
        Add-Result $Id $Category $Name 'Включён для всех профилей' $act $st $Sev.M 'Включить межсетевой экран для всех профилей'
    }
}

Invoke-Check 'NET-DHCP' 'Сетевые настройки' 'Статическая IP-адресация' {
    $dyn = @(Get-NetIPInterface -AddressFamily IPv4 -ConnectionState Connected |
        Where-Object { $_.Dhcp -eq 'Enabled' -and $_.InterfaceAlias -notlike 'Loopback*' })
    $st = if ($dyn.Count -eq 0) { $ST_OK } else { $ST_FAIL }
    $act = if ($dyn.Count -eq 0) { 'Статические адреса' } else { 'DHCP: ' + (($dyn | ForEach-Object { $_.InterfaceAlias }) -join '; ') }
    Add-Result $Id $Category $Name 'Только статические адреса' $act $st $Sev.M 'Назначить статический IP-адрес согласно схеме адресации'
}

Invoke-Check 'NET-WLAN' 'Сетевые настройки' 'Беспроводные интерфейсы (Wi-Fi, Bluetooth)' {
    $wifi = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
        Where-Object { $_.PhysicalMediaType -match '802\.11' -or $_.InterfaceDescription -match 'Wi-?Fi|Wireless|WLAN' })
    $bt = @(Get-PnpDevice -Class 'Bluetooth' -PresentOnly -ErrorAction SilentlyContinue)
    $list = @($wifi | ForEach-Object { $_.InterfaceDescription }) + @($bt | ForEach-Object { $_.FriendlyName })
    $st = if ($list.Count -eq 0) { $ST_OK } else { $ST_FAIL }
    $act = if ($list.Count -eq 0) { 'Не обнаружены' } else { $list -join '; ' }
    Add-Result $Id $Category $Name 'Отсутствуют' $act $st $Sev.H 'Извлечь (отключить) беспроводной модуль'
}

# ============================================================================
# 6. Параметры безопасности ОС
# ============================================================================
Invoke-Check 'OS-AUTORUN' 'Параметры ОС' 'Автозапуск со съёмных носителей' {
    $k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    $v = $null
    if (Test-Path $k) { $v = (Get-ItemProperty -Path $k -ErrorAction SilentlyContinue).NoDriveTypeAutoRun }
    $st = if ($v -eq 255) { $ST_OK } else { $ST_FAIL }
    $act = if ($null -eq $v) { 'Не задано' } else { "NoDriveTypeAutoRun = $v" }
    Add-Result $Id $Category $Name 'Запрещён для всех типов (255)' $act $st $Sev.M 'Запретить автозапуск через ОГП'
}

Invoke-Check 'OS-LOCK' 'Параметры ОС' 'Блокировка сеанса при бездействии' {
    $lim = [int](Get-ProfileValue 'InactivityMaxSec' 900)
    $k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $v = $null
    if (Test-Path $k) { $v = (Get-ItemProperty -Path $k -ErrorAction SilentlyContinue).InactivityTimeoutSecs }
    $st = if ($v -and $v -gt 0 -and $v -le $lim) { $ST_OK } else { $ST_WARN }
    $act = if ($null -eq $v) { 'Не задано' } else { "$v с" }
    Add-Result $Id $Category $Name "Не более $lim с" $act $st $Sev.L 'Задать «Интерактивный вход в систему: предел простоя компьютера»'
}

# ============================================================================
# 7. Съёмные машинные носители информации (история подключений USB)
# ============================================================================
Invoke-Check 'USB-READ' 'Съёмные носители' 'История подключения USB-накопителей' {
    $reg = @($E.SziEtalon.Media.Device | ForEach-Object { ([string]$_.serial).ToUpper() })
    $hist = @(Get-UsbStorageHistory)
    if ($hist.Count -eq 0) {
        Add-Result $Id $Category $Name 'Только учтённые МНИ' 'Подключения не выявлены' $ST_OK $Sev.H
    }
    foreach ($d in $hist) {
        $ok = $reg -contains $d.Serial.ToUpper()
        $st = if ($ok) { $ST_OK } else { $ST_FAIL }
        $rec = if ($ok) { '' } else { 'Установить принадлежность носителя, провести служебное разбирательство' }
        Add-Result "USB-$($d.Serial)" $Category "Носитель: $($d.Name)" 'Учтён в журнале МНИ' `
            ("S/N $($d.Serial)" + $(if ($ok) { ' (учтён)' } else { ' (не учтён)' })) $st $Sev.H $rec
    }
}

# ============================================================================
# 8. Сверка установленного ПО с предписанием на эксплуатацию
# ============================================================================
Invoke-Check 'SW-EXTRA' 'Программное обеспечение' 'ПО, не указанное в предписании' {
    $allow = @(@($E.SziEtalon.AllowedSoftware.Pattern) + @($P.AllowedSoftware.Pattern) +
               @($E.SziEtalon.SziList.Szi | ForEach-Object { $_.productPattern }) |
               ForEach-Object { [string]$_ -split '\|' } | Where-Object { $_ })
    $extra = @($Soft | Where-Object { -not (Test-LikeAny $_.Name $allow) })
    if ($extra.Count -eq 0) {
        Add-Result $Id $Category $Name 'Только ПО из предписания' "Установлено программ: $($Soft.Count)" $ST_OK $Sev.H
    }
    else {
        $names = ($extra | Select-Object -First 15 | ForEach-Object { $_.Name }) -join '; '
        if ($extra.Count -gt 15) { $names += " и ещё $($extra.Count - 15)" }
        Add-Result $Id $Category $Name 'Только ПО из предписания' "Лишние ($($extra.Count)): $names" $ST_FAIL $Sev.H `
            'Удалить нештатное ПО либо внести изменения в эталон после согласования'
    }
}

# ============================================================================
# 9. Сертификаты удостоверяющих центров
# ============================================================================
foreach ($c in @($E.SziEtalon.Certificates.Cert)) {
    if (-not $c) { continue }
    Invoke-Check "PKI-$(([string]$c.thumbprint).Substring(0,8))" 'Сертификаты УЦ' "Сертификат: $($c.GetAttribute('name'))" {
        $store = if ($c.store) { [string]$c.store } else { 'Root' }
        $cert = Get-ChildItem -Path "Cert:\LocalMachine\$store" |
            Where-Object { $_.Thumbprint -eq ([string]$c.thumbprint).ToUpper() } | Select-Object -First 1
        if (-not $cert) {
            Add-Result $Id $Category $Name 'Установлен, действует' 'Отсутствует' $ST_FAIL $Sev.M 'Установить сертификат УЦ'
        }
        elseif ($cert.NotAfter -lt $Today) {
            Add-Result $Id $Category $Name 'Установлен, действует' "Истёк $($cert.NotAfter.ToString('dd.MM.yyyy'))" $ST_FAIL $Sev.M 'Установить актуальный сертификат УЦ'
        }
        elseif ($cert.NotAfter -lt $Today.AddDays(30)) {
            Add-Result $Id $Category $Name 'Установлен, действует' "Истекает $($cert.NotAfter.ToString('dd.MM.yyyy'))" $ST_WARN $Sev.M 'Запросить новый сертификат УЦ'
        }
        else {
            Add-Result $Id $Category $Name 'Установлен, действует' "Действует до $($cert.NotAfter.ToString('dd.MM.yyyy'))" $ST_OK $Sev.M
        }
    }
}

# ============================================================================
# 10. Актуальность списков отозванных сертификатов (СОС)
# ============================================================================
$CrlPaths = Get-NodeTexts '/SziEtalon/Crls/Path'
$CrlStore = ([string]$E.SziEtalon.SelectSingleNode('Crls/@includeSystemStore').Value) -eq 'true'
if ($CrlPaths.Count -gt 0 -or $CrlStore) {
    Invoke-Check 'CRL-READ' 'Сертификаты УЦ' 'Списки отозванных сертификатов' {
        $warnH = [int](Get-ProfileValue 'CrlWarnHours' 24)
        $crls = @()
        foreach ($cp in $CrlPaths) {
            $pp = [Environment]::ExpandEnvironmentVariables($cp)
            foreach ($f in @(Get-ChildItem -Path $pp -File -ErrorAction SilentlyContinue)) {
                try {
                    $info = Get-CrlInfo ([IO.File]::ReadAllBytes($f.FullName))
                    $info | Add-Member -NotePropertyName Source -NotePropertyValue $f.Name
                    $crls += $info
                }
                catch {
                    Add-Result "CRL-$($f.Name)" $Category "СОС: $($f.Name)" 'Файл СОС корректен' `
                        "Не удалось разобрать файл: $($_.Exception.Message)" $ST_ERR $Sev.M 'Заменить файл СОС'
                }
            }
        }
        if ($CrlStore) { $crls += @(Get-StoreCrls) }
        if ($crls.Count -eq 0) {
            Add-Result $Id $Category $Name 'СОС установлены' 'СОС не найдены' $ST_WARN $Sev.M `
                'Установить актуальные СОС удостоверяющих центров'
        }
        foreach ($c in $crls) {
            $exp = 'Срок следующего обновления не наступил'
            if (-not $c.NextUpdate) {
                Add-Result "CRL-$($c.IssuerCN)" $Category "СОС: $($c.IssuerCN)" $exp `
                    "Выпущен $($c.ThisUpdate.ToString('dd.MM.yyyy HH:mm')), дата следующего обновления не указана ($($c.Source))" $ST_WARN $Sev.L ''
                continue
            }
            $act = "Действует до $($c.NextUpdate.ToString('dd.MM.yyyy HH:mm')) ($($c.Source))"
            if ($c.NextUpdate -lt $Today) {
                Add-Result "CRL-$($c.IssuerCN)" $Category "СОС: $($c.IssuerCN)" $exp $act $ST_FAIL $Sev.M `
                    'Загрузить и установить актуальный СОС'
            }
            elseif ($c.NextUpdate -lt $Today.AddHours($warnH)) {
                Add-Result "CRL-$($c.IssuerCN)" $Category "СОС: $($c.IssuerCN)" $exp $act $ST_WARN $Sev.M `
                    'Подготовить обновление СОС'
            }
            else { Add-Result "CRL-$($c.IssuerCN)" $Category "СОС: $($c.IssuerCN)" $exp $act $ST_OK $Sev.M }
        }
    }
}

# ============================================================================
# 11. Обнаружения вредоносного ПО в журналах антивирусного средства
# ============================================================================
$AvLogs = @($E.SelectNodes('/SziEtalon/Settings/AvLog'))
if ($AvLogs.Count -gt 0) {
    Invoke-Check 'AV-DETECT' 'Антивирусная защита' 'Обнаружения вредоносного ПО' {
        $days = [int](Get-ProfileValue 'EventLookbackDays' 30)
        $found = @(); $logsSeen = @()
        foreach ($l in $AvLogs) {
            $logName = $l.GetAttribute('name')
            if (-not (Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue)) { continue }
            $logsSeen += $logName
            $filter = @{ LogName = $logName; StartTime = $Today.AddDays(-$days) }
            $ids = @(($l.GetAttribute('eventIds') -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ } | ForEach-Object { [int]$_ })
            if ($ids.Count -gt 0) { $filter['Id'] = $ids }
            $ev = @(Get-WinEvent -FilterHashtable $filter -MaxEvents 5000 -ErrorAction SilentlyContinue)
            $kw = $l.GetAttribute('keywords')
            if ($kw) { $ev = @($ev | Where-Object { $_.Message -match $kw }) }
            $found += $ev
        }
        $exp = "Отсутствуют за $days сут."
        if ($logsSeen.Count -eq 0) {
            Add-Result $Id $Category $Name $exp 'Журналы АВС не найдены' $ST_WARN $Sev.M `
                'Проверить настройки журналов в эталоне и работу АВС'
        }
        elseif ($found.Count -eq 0) {
            Add-Result $Id $Category $Name $exp ('Не выявлено (журналы: ' + ($logsSeen -join ', ') + ')') $ST_OK $Sev.H
        }
        else {
            $last = $found | Sort-Object TimeCreated -Descending | Select-Object -First 1
            $msg = ([string]$last.Message -split "`n")[0].Trim()
            if ($msg.Length -gt 120) { $msg = $msg.Substring(0, 120) + '…' }
            Add-Result $Id $Category $Name $exp ("Выявлено: $($found.Count), последнее $($last.TimeCreated.ToString('dd.MM.yyyy HH:mm')): $msg") `
                $ST_FAIL $Sev.H 'Проанализировать события в консоли АВС, внести запись в журнал учёта инцидентов ИБ'
        }
    }
}

# ============================================================================
# 12. Локальные учётные записи пользователей
# ============================================================================
$Users = $null
try { $Users = @(Get-LocalUser | Where-Object { $_.Enabled }) }
catch {
    Add-Result 'USR-READ' 'Учётные записи' 'Чтение локальных учётных записей' '-' $_.Exception.Message $ST_ERR $Sev.M ''
}
if ($null -ne $Users) {
    $allowedUsers = @($P.SelectNodes('AllowedUsers/Account') | ForEach-Object { $_.InnerText })
    if ($allowedUsers.Count -gt 0) {
        Invoke-Check 'USR-LIST' 'Учётные записи' 'Сверка с приказом о допуске к АСЗИ' {
            $extra = @($Users | Where-Object { -not (Test-LikeAny $_.Name $allowedUsers) } | ForEach-Object { $_.Name })
            $act = 'Активные: ' + (($Users | ForEach-Object { $_.Name }) -join '; ')
            if ($extra.Count -gt 0) {
                Add-Result $Id $Category $Name 'Только лица, допущенные приказом' $act $ST_FAIL $Sev.H `
                    ('Заблокировать учётные записи: ' + ($extra -join '; ') + '. Сверить с приказом о допуске')
            }
            else { Add-Result $Id $Category $Name 'Только лица, допущенные приказом' $act $ST_OK $Sev.H }
        }
    }
    Invoke-Check 'USR-PWDNEVER' 'Учётные записи' 'Учётные записи с бессрочным паролем' {
        $exc = @($P.SelectNodes('PasswordNeverExpiresAllowed/Account') | ForEach-Object { $_.InnerText })
        $bad = @($Users | Where-Object { $null -eq $_.PasswordExpires -and -not (Test-LikeAny $_.Name $exc) } | ForEach-Object { $_.Name })
        $st = if ($bad.Count -eq 0) { $ST_OK } else { $ST_FAIL }
        $act = if ($bad.Count -eq 0) { 'Не выявлены' } else { $bad -join '; ' }
        Add-Result $Id $Category $Name 'Отсутствуют' $act $st $Sev.M 'Снять отметку «Срок действия пароля не ограничен»'
    }
    Invoke-Check 'USR-STALE' 'Учётные записи' 'Неиспользуемые учётные записи' {
        $days = [int](Get-ProfileValue 'InactiveUserDays' 45)
        $stale = @($Users | Where-Object { -not $_.LastLogon -or $_.LastLogon -lt $Today.AddDays(-$days) } | ForEach-Object {
                if ($_.LastLogon) { "$($_.Name) (вход $($_.LastLogon.ToString('dd.MM.yyyy')))" } else { "$($_.Name) (входов не было)" } })
        $st = if ($stale.Count -eq 0) { $ST_OK } else { $ST_WARN }
        $act = if ($stale.Count -eq 0) { 'Не выявлены' } else { $stale -join '; ' }
        Add-Result $Id $Category $Name "Вход не реже 1 раза в $days сут." $act $st $Sev.L `
            'Заблокировать учётные записи, не используемые для работы'
    }
}

# ============================================================================
# 13. Отключение неиспользуемых служб и компонентов
# ============================================================================
foreach ($fs in @($E.SelectNodes('/SziEtalon/ForbiddenServices/Service'))) {
    $svcName = $fs.GetAttribute('name'); $svcTitle = $fs.GetAttribute('title')
    Invoke-Check "SRV-$svcName" 'Неиспользуемые компоненты' "Служба: $svcTitle ($svcName)" {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if (-not $svc) {
            Add-Result $Id $Category $Name 'Отключена или отсутствует' 'Отсутствует' $ST_OK $Sev.L
        }
        elseif ($svc.Status -eq 'Running' -or $svc.StartType -ne 'Disabled') {
            Add-Result $Id $Category $Name 'Отключена или отсутствует' "$($svc.Status)/$($svc.StartType)" $ST_FAIL $Sev.M `
                'Остановить службу и установить тип запуска «Отключена»'
        }
        else { Add-Result $Id $Category $Name 'Отключена или отсутствует' "$($svc.Status)/$($svc.StartType)" $ST_OK $Sev.L }
    }
}

Invoke-Check 'SMB1' 'Неиспользуемые компоненты' 'Протокол SMBv1' {
    $v = (Get-SmbServerConfiguration).EnableSMB1Protocol
    $st = if (-not $v) { $ST_OK } else { $ST_FAIL }
    $act = if (-not $v) { 'Отключён' } else { 'Включён' }
    Add-Result $Id $Category $Name 'Отключён' $act $st $Sev.H 'Set-SmbServerConfiguration -EnableSMB1Protocol $false'
}

Invoke-Check 'OS-AUTOLOGON' 'Параметры ОС' 'Автоматический вход в систему' {
    $k = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $v = [string](Get-ItemProperty -Path $k -ErrorAction SilentlyContinue).AutoAdminLogon
    $st = if ($v -ne '1') { $ST_OK } else { $ST_FAIL }
    $act = if ($v -ne '1') { 'Отключён' } else { 'Включён (AutoAdminLogon = 1)' }
    Add-Result $Id $Category $Name 'Отключён' $act $st $Sev.H 'Отключить автоматический вход, удалить сохранённый пароль DefaultPassword'
}

# ============================================================================
# Общие сведения об АРМ и возврат результата
# ============================================================================
$os = Get-CimInstance -ClassName Win32_OperatingSystem
$cs = Get-CimInstance -ClassName Win32_ComputerSystem
$ip = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -ne '127.0.0.1' } | ForEach-Object { $_.IPAddress }) -join ', '

[pscustomobject]@{
    Computer  = $env:COMPUTERNAME
    ProfileId = $ProfileId
    Profile   = $P.GetAttribute('name')
    Date      = $Today
    OS        = "$($os.Caption) ($($os.Version))"
    Domain    = [string]$cs.Domain
    IP        = $ip
    LastBoot  = $os.LastBootUpTime
    User      = "$env:USERDOMAIN\$env:USERNAME"
    Results   = $Results.ToArray()
}
