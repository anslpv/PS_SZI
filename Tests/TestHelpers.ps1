#requires -Version 5.1
# Общие функции тестов ПО «СЗИ-Аудит»

$global:SziRoot     = Split-Path -Parent $PSScriptRoot
$global:SziChecks   = Join-Path $global:SziRoot 'SziAudit.Checks.ps1'
$global:SziMain     = Join-Path $global:SziRoot 'SziAudit.ps1'
$global:SziTestData = Join-Path $PSScriptRoot 'TestData'

# Тестовый эталон: штатный Config\Etalon.xml, в котором пути к базам АВС и СОС
# перенаправлены во временный каталог теста
function global:New-TestEtalon([string]$WorkDir) {
    $bases = Join-Path $WorkDir 'Bases'
    $crl = Join-Path $WorkDir 'CRL'
    foreach ($d in $bases, $crl) { if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d | Out-Null } }
    $x = New-Object System.Xml.XmlDocument
    $x.Load((Join-Path $global:SziRoot 'Config/Etalon.xml'))
    $settings = $x.SziEtalon.SelectSingleNode('Settings')
    foreach ($n in @($settings.SelectNodes('AvBasesPath'))) { [void]$settings.RemoveChild($n) }
    $p = $x.CreateElement('AvBasesPath'); $p.InnerText = $bases
    [void]$settings.PrependChild($p)
    $x.SziEtalon.SelectSingleNode('Crls/Path').InnerText = (Join-Path $crl '*.crl')
    return [pscustomobject]@{ Xml = $x; Bases = $bases; Crl = $crl }
}

# Свежий файл баз АВС (возраст в сутках)
function global:Set-TestAvBases([string]$Dir, [double]$AgeDays) {
    Get-ChildItem -Path $Dir -File | Remove-Item -Force
    $f = Join-Path $Dir 'kdb.dat'
    Set-Content -Path $f -Value 'bases'
    (Get-Item $f).LastWriteTime = (Get-Date).AddDays(-$AgeDays)
}

# Выполнение модуля проверок на виртуальном АРМ
function global:Invoke-TestAudit($Etalon, [string]$ProfileId = 'ARM_OPK') {
    & $global:SziChecks -EtalonXml $Etalon.OuterXml -ProfileId $ProfileId
}

function global:Get-CheckResult($Run, [string]$CheckId) {
    @($Run.Results | Where-Object { $_.CheckId -eq $CheckId })
}

# Загрузка функций главного модуля SziAudit.ps1 без запуска графического интерфейса:
# тексты функций извлекаются из синтаксического дерева сценария
function global:Get-MainModuleFunctions([string[]]$Names) {
    $tok = $null; $err = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($global:SziMain, [ref]$tok, [ref]$err)
    $defs = $ast.FindAll({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)
    $text = ($defs | Where-Object { -not $Names -or $Names -contains $_.Name } | ForEach-Object { $_.Extent.Text }) -join "`n`n"
    return [scriptblock]::Create($text)
}
