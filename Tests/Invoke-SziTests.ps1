#requires -Version 5.1
<#
.SYNOPSIS
    Запуск всех тестов ПО «СЗИ-Аудит» с формированием отчёта NUnit XML.
.DESCRIPTION
    Требуется модуль Pester 5 (Install-Module Pester -MinimumVersion 5.0 -Scope CurrentUser)
    и PSScriptAnalyzer (Install-Module PSScriptAnalyzer -Scope CurrentUser).
    Тесты используют имитатор Windows-окружения и не изменяют настройки компьютера,
    поэтому могут выполняться как в Windows PowerShell 5.1, так и в PowerShell 7 (Windows, Linux).
.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File Tests\Invoke-SziTests.ps1
#>
param([string]$OutputDir = (Join-Path $PSScriptRoot 'TestResults'))

Import-Module Pester -MinimumVersion 5.0 -ErrorAction Stop
if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir | Out-Null }

$cfg = New-PesterConfiguration
$cfg.Run.Path = $PSScriptRoot
$cfg.Run.PassThru = $true
$cfg.Output.Verbosity = 'Detailed'
$cfg.TestResult.Enabled = $true
$cfg.TestResult.OutputFormat = 'NUnitXml'
$cfg.TestResult.OutputPath = Join-Path $OutputDir 'SziAudit.TestResults.xml'

$r = Invoke-Pester -Configuration $cfg
'Итого: тестов {0}, пройдено {1}, не пройдено {2}, пропущено {3}; время {4:mm\:ss}; PowerShell {5} ({6})' -f `
    $r.TotalCount, $r.PassedCount, $r.FailedCount, $r.SkippedCount, $r.Duration, $PSVersionTable.PSVersion, [Environment]::OSVersion.VersionString
exit $r.FailedCount
