#requires -Version 5.1
#requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }
<#
    Статические проверки исходных текстов и конфигурации ПО «СЗИ-Аудит»:
    синтаксис, кодировка, разметка интерфейса, эталонный файл, файлы запуска,
    анализ PSScriptAnalyzer и совместимость с Windows PowerShell 5.1.
#>

BeforeDiscovery {
    $script:Scripts = @('SziAudit.ps1', 'SziAudit.Checks.ps1')
}

Describe 'Статический анализ ПО «СЗИ-Аудит»' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
        $script:MainText = [IO.File]::ReadAllText($SziMain, [Text.Encoding]::UTF8)
        [xml]$script:Etalon = [IO.File]::ReadAllText((Join-Path $SziRoot 'Config/Etalon.xml'), [Text.Encoding]::UTF8)
    }

    Context 'ТК-25. Синтаксис и кодировка сценариев' {
        It '<_>: синтаксический разбор без ошибок' -ForEach $Scripts {
            $tok = $null; $err = $null
            [void][System.Management.Automation.Language.Parser]::ParseFile((Join-Path $SziRoot $_), [ref]$tok, [ref]$err)
            $err | Should -BeNullOrEmpty
        }
        It '<_>: кодировка UTF-8 с BOM (требуется Windows PowerShell 5.1 для кириллицы)' -ForEach $Scripts {
            $b = [IO.File]::ReadAllBytes((Join-Path $SziRoot $_))
            $b[0..2] | Should -Be @(0xEF, 0xBB, 0xBF)
        }
        It '<_>: указана минимальная версия PowerShell 5.1' -ForEach $Scripts {
            (Get-Content (Join-Path $SziRoot $_) -TotalCount 1 -Encoding UTF8) | Should -Match '#requires -Version 5\.1'
        }
    }

    Context 'ТК-26. Разметка графического интерфейса (XAML)' {
        BeforeAll {
            $script:Xamls = @{}
            foreach ($m in [regex]::Matches($MainText, "(?s)\[xml\]\`$(\w+) = @'\r?\n(.*?)\r?\n'@")) {
                $Xamls[$m.Groups[1].Value] = $m.Groups[2].Value
            }
        }
        It 'главное окно и окно выбора компьютеров – корректный XML' {
            $Xamls.Keys | Should -Contain 'Xaml'
            $Xamls.Keys | Should -Contain 'px'
            foreach ($k in $Xamls.Keys) { { [xml]$Xamls[$k] } | Should -Not -Throw }
        }
        It 'все элементы $Ui.<имя>, используемые в коде, объявлены в разметке (x:Name)' {
            [xml]$x = $Xamls['Xaml']
            $ns = New-Object System.Xml.XmlNamespaceManager $x.NameTable
            $ns.AddNamespace('x', 'http://schemas.microsoft.com/winfx/2006/xaml')
            $declared = @($x.SelectNodes('//*[@x:Name]', $ns) | ForEach-Object { $_.GetAttribute('Name', 'http://schemas.microsoft.com/winfx/2006/xaml') })
            $used = @([regex]::Matches($MainText, '\$Ui\.(\w+)') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
            $used.Count | Should -BeGreaterThan 20
            @($used | Where-Object { $declared -notcontains $_ }) | Should -BeNullOrEmpty
        }
        It 'элементы диалоговых окон, используемые через FindName, объявлены в разметке своего окна' {
            # Каждая функция диалога содержит одну разметку [xml]$px… и обращается к её элементам по имени
            $tok = $null; $err = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($SziMain, [ref]$tok, [ref]$err)
            $funcs = @($ast.FindAll({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
                    Where-Object { $_.Extent.Text -match "\[xml\]\`$px\w* = @'" })
            $funcs.Count | Should -BeGreaterOrEqual 4
            foreach ($fn in $funcs) {
                $m = [regex]::Match($fn.Extent.Text, "(?s)\[xml\]\`$px\w* = @'\r?\n(.*?)\r?\n'@")
                [xml]$x = $m.Groups[1].Value
                $declared = @($x.SelectNodes('//*') | ForEach-Object { $_.GetAttribute('Name', 'http://schemas.microsoft.com/winfx/2006/xaml') } | Where-Object { $_ })
                $names = @([regex]::Matches($fn.Extent.Text, "FindName\('(\w+)'\)") | ForEach-Object { $_.Groups[1].Value })
                $names += @([regex]::Matches($fn.Extent.Text, "foreach \(\`$n in ('[^)]+')\) \{ \`$f\[\`$n\] = \`$w\.FindName") |
                        ForEach-Object { $_.Groups[1].Value -split ',' } | ForEach-Object { $_.Trim().Trim("'") })
                foreach ($n in $names) { "$($fn.Name): $n" | Should -BeIn @($declared | ForEach-Object { "$($fn.Name): $_" }) }
            }
        }
    }

    Context 'ТК-27. Эталонный файл конфигурации Config\Etalon.xml' {
        It 'идентификаторы профилей и СЗИ уникальны' {
            $p = @($Etalon.SziEtalon.Profiles.Profile | ForEach-Object { $_.id })
            $s = @($Etalon.SziEtalon.SziList.Szi | ForEach-Object { $_.id })
            ($p | Sort-Object -Unique).Count | Should -Be $p.Count
            ($s | Sort-Object -Unique).Count | Should -Be $s.Count
        }
        It 'все СЗИ из RequireSzi профилей описаны в справочнике' {
            $s = @($Etalon.SziEtalon.SziList.Szi | ForEach-Object { $_.id })
            foreach ($p in $Etalon.SziEtalon.Profiles.Profile) {
                foreach ($id in ([string]$p.RequireSzi -split ',' | ForEach-Object { $_.Trim() })) { $s | Should -Contain $id -Because "профиль $($p.id)" }
            }
        }
        It 'сроки сертификатов – в формате ГГГГ-ММ-ДД, минимальные версии – числовые' {
            foreach ($z in $Etalon.SziEtalon.SziList.Szi) {
                if ($z.certExpires) { $z.certExpires | Should -Match '^\d{4}-\d{2}-\d{2}$' }
                $z.minVersion | Should -Match '^\d+(\.\d+){0,3}$'
            }
        }
        It 'числовые параметры заданы в каждом профиле' {
            $req = 'AvBasesMaxAgeDays', 'PasswordMinLength', 'PasswordMaxAgeDays', 'LockoutThresholdMax', 'SecurityLogMinMB',
            'EventLookbackDays', 'FailedLogonWarn', 'InactivityMaxSec', 'CertWarnDays', 'CrlWarnHours', 'InactiveUserDays'
            foreach ($p in $Etalon.SziEtalon.Profiles.Profile) {
                foreach ($n in $req) { $p.SelectSingleNode($n).InnerText | Should -Match '^\d+$' -Because "$($p.id)/$n" }
            }
        }
        It 'подкатегории аудита: GUID в фигурных скобках и значение 0–3' {
            foreach ($i in $Etalon.SelectNodes('//AuditPolicy/Item')) {
                $i.guid | Should -Match '^\{[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}\}$'
                $i.GetAttribute('value') | Should -BeIn @('0', '1', '2', '3')
            }
        }
        It 'серийные номера учтённых МНИ заполнены и не повторяются' {
            $sn = @($Etalon.SziEtalon.Media.Device | ForEach-Object { $_.serial })
            $sn | ForEach-Object { $_ | Should -Not -BeNullOrEmpty }
            ($sn | Sort-Object -Unique).Count | Should -Be $sn.Count
        }
    }

    Context 'ТК-28. Файлы запуска' {
        It 'Run-SziAudit.bat запускает SziAudit.ps1 в режиме STA (требование WPF)' {
            $t = Get-Content (Join-Path $SziRoot 'Run-SziAudit.bat') -Raw
            $t | Should -Match '-STA'
            $t | Should -Match '%~dp0SziAudit\.ps1'
        }
        It 'Run-SziAudit-Daily.bat: консольный режим, существующий профиль, передача кода завершения' {
            $t = Get-Content (Join-Path $SziRoot 'Run-SziAudit-Daily.bat') -Raw
            $t | Should -Match '-NoGui'
            $t | Should -Match 'exit /b %ERRORLEVEL%'
            $prof = [regex]::Match($t, 'set PROFILE=(\w+)').Groups[1].Value
            @($Etalon.SziEtalon.Profiles.Profile | ForEach-Object { $_.id }) | Should -Contain $prof
        }
    }

    Context 'ТК-29. Анализ PSScriptAnalyzer' {
        BeforeAll { Import-Module PSScriptAnalyzer -ErrorAction Stop }
        It '<_>: нет замечаний уровня Error' -ForEach $Scripts {
            @(Invoke-ScriptAnalyzer -Path (Join-Path $SziRoot $_) -Severity Error) | Should -BeNullOrEmpty
        }
        It '<_>: синтаксис, команды и типы совместимы с Windows PowerShell 5.1 (Windows 10 / Server 2016)' -ForEach $Scripts {
            $profiles = @('win-48_x64_10.0.17763.0_5.1.17763.316_x64_4.0.30319.42000_framework',
                'win-8_x64_10.0.14393.0_5.1.14393.2791_x64_4.0.30319.42000_framework')
            $settings = @{
                IncludeRules = @('PSUseCompatibleSyntax', 'PSUseCompatibleCommands', 'PSUseCompatibleTypes')
                Rules = @{
                    PSUseCompatibleSyntax = @{ Enable = $true; TargetVersions = @('5.1') }
                    PSUseCompatibleCommands = @{ Enable = $true; TargetProfiles = $profiles }
                    PSUseCompatibleTypes = @{ Enable = $true; TargetProfiles = $profiles }
                }
            }
            # Write-Log – собственная функция программы, а не отсутствующая команда (ложное срабатывание правила)
            $r = @(Invoke-ScriptAnalyzer -Path (Join-Path $SziRoot $_) -Settings $settings |
                Where-Object { -not ($_.RuleName -eq 'PSUseCompatibleCommands' -and $_.Message -like "*'Write-Log'*") })
            $r | ForEach-Object { "$($_.Line): $($_.Message)" } | Should -BeNullOrEmpty
        }
    }
}
