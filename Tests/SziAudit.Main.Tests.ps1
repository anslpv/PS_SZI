#requires -Version 5.1
#requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }
<#
    Модульные и интеграционные тесты главного модуля SziAudit.ps1.
    Функции главного модуля извлекаются из синтаксического дерева сценария и выполняются
    в консольном режиме ($NoGui = $true), без загрузки WPF и проверки прав администратора.
    Интеграционные тесты запускают модуль проверок в фоновых заданиях PowerShell (Start-Job),
    как это делает программа, и проверяют сохранение истории, отчёт и коды завершения.
#>

Describe 'Главный модуль SziAudit.ps1' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
        . (Get-MainModuleFunctions)
        $script:OK = 'Соответствует'; $script:FAIL = 'Не соответствует'
        $script:WARN = 'Предупреждение'; $script:ERR = 'Ошибка проверки'
        $ST_OK = $OK; $ST_FAIL = $FAIL; $ST_WARN = $WARN; $ST_ERR = $ERR
        $NoGui = $true; $OpenReport = $false
        $AppName = 'СЗИ-Аудит'; $AppVersion = '1.0'
        Mock Write-Host { }

        function New-Item2([string]$Id, [string]$Status, [string]$Severity = 'Высокая', [string]$Actual = '') {
            [pscustomobject]@{ CheckId = $Id; Category = 'Кат.'; Name = "Проверка $Id"; Status = $Status; Severity = $Severity; Actual = $Actual }
        }
    }

    BeforeEach {
        $root = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $Paths = @{
            Etalon = Join-Path $root 'Config/Etalon.xml'; Backup = Join-Path $root 'Config/Backup'
            Results = Join-Path $root 'Results'; Reports = Join-Path $root 'Reports'; Logs = Join-Path $root 'Logs'
            Checks = $SziChecks; History = Join-Path $root 'Results/History.csv'
        }
        foreach ($d in 'Backup', 'Results', 'Reports', 'Logs') { New-Item -ItemType Directory -Path $Paths[$d] -Force | Out-Null }
        # ::new() вместо New-Object: в PowerShell 7.x @() над списком, созданным New-Object, вызывает ошибку (см. отчёт)
        $script:AllResults = [System.Collections.Generic.List[object]]::new()
        $script:LastRuns = @{}
        $script:Jobs = @()
    }

    Context 'ТК-19. Расчёт сводных показателей и индекса соответствия' {
        It 'индекс взвешивается по критичности (3/2/1), предупреждение даёт 0,5' {
            $items = @((New-Item2 a $OK 'Высокая'), (New-Item2 b $FAIL 'Высокая'), (New-Item2 c $WARN 'Средняя'), (New-Item2 d $ERR 'Низкая'))
            $s = Get-AuditSummary $items
            $s.Total | Should -Be 4
            $s.Pass | Should -Be 1; $s.Fail | Should -Be 1; $s.Warn | Should -Be 1; $s.Errors | Should -Be 1
            $s.Index | Should -Be 44.4      # (3·1 + 3·0 + 2·0,5 + 1·0) / 9 = 44,4 %
        }
        It 'все проверки соответствуют – 100 %, пустой набор – 0 %' {
            (Get-AuditSummary @((New-Item2 a $OK), (New-Item2 b $OK 'Низкая'))).Index | Should -Be 100
            (Get-AuditSummary @()).Index | Should -Be 0
        }
        It 'неизвестная критичность учитывается с весом 1' {
            (Get-AuditSummary @((New-Item2 a $OK 'Высокая'), (New-Item2 b $FAIL '???'))).Index | Should -Be 75
        }
    }

    Context 'ТК-20. Сравнение результатов двух проверок' {
        It 'определяет улучшение, ухудшение, изменение значения, новую и исчезнувшую проверку' {
            $old = [pscustomobject]@{ Results = @(
                    (New-Item2 A $FAIL -Actual '6'), (New-Item2 B $OK -Actual 'вкл'), (New-Item2 C $WARN -Actual '25'),
                    (New-Item2 D $OK -Actual 'x'), (New-Item2 E $OK -Actual 'без изменений')) }
            $new = [pscustomobject]@{ Results = @(
                    (New-Item2 A $OK -Actual '8'), (New-Item2 B $FAIL -Actual 'выкл'), (New-Item2 C $WARN -Actual '30'),
                    (New-Item2 F $FAIL -Actual 'y'), (New-Item2 E $OK -Actual 'без изменений')) }
            $d = @(Compare-AuditRuns $old $new)
            $d.Count | Should -Be 5
            ($d | Where-Object Name -eq 'Проверка A').Change | Should -Be 'Улучшение: несоответствие устранено'
            ($d | Where-Object Name -eq 'Проверка B').Change | Should -Be 'Ухудшение: выявлено несоответствие'
            ($d | Where-Object Name -eq 'Проверка C').Change | Should -Be 'Изменилось фактическое значение'
            ($d | Where-Object Name -eq 'Проверка D').Change | Should -Be 'Проверка не выполнялась'
            ($d | Where-Object Name -eq 'Проверка F').Change | Should -Be 'Новая проверка'
            ($d | Where-Object Name -eq 'Проверка A').Before | Should -Be "${FAIL}: 6"
        }
        It 'идентичные проверки не дают изменений' {
            $r = [pscustomobject]@{ Results = @((New-Item2 A $OK -Actual '1')) }
            @(Compare-AuditRuns $r $r).Count | Should -Be 0
        }
    }

    Context 'ТК-21. Редактирование и контроль эталона' {
        BeforeEach {
            $x = New-Object System.Xml.XmlDocument
            $x.Load((Join-Path $SziRoot 'Config/Etalon.xml'))
            $script:SziTable = New-TableFromNodes 'Szi' @('id', 'name', 'productPattern', 'minVersion', 'servicePattern',
                'sziClass', 'certNumber', 'certExpires') $x.SziEtalon.SziList.Szi
            $script:MediaTable = New-TableFromNodes 'Media' @('serial', 'owner', 'note') $x.SziEtalon.Media.Device
        }
        It 'таблицы справочника СЗИ и МНИ строятся из эталона' {
            $SziTable.Rows.Count | Should -Be 6
            $SziTable.Rows[0]['id'] | Should -Be 'SPR'
            $MediaTable.Rows.Count | Should -Be 2
            (New-TableFromNodes 'E' @('a') $null).Rows.Count | Should -Be 0
        }
        It 'корректный эталон не содержит ошибок' {
            @(Test-EtalonTables) | Should -BeNullOrEmpty
        }
        It 'выявляются повторяющийся код, пустой шаблон, неверная дата и пустой серийный номер' {
            $SziTable.Rows[1]['id'] = 'SPR'
            $SziTable.Rows[2]['productPattern'] = ' '
            $SziTable.Rows[3]['certExpires'] = '31.12.2028'
            $r = $MediaTable.NewRow(); $r['serial'] = ''; $MediaTable.Rows.Add($r)
            $e = @(Test-EtalonTables)
            $e | Should -Contain 'Повторяющийся код СЗИ: SPR'
            $e | Should -Contain 'СЗИ VIPNET: не задан шаблон имени ПО'
            $e | Should -Contain 'СЗИ KES: дата окончания сертификата должна быть в формате ГГГГ-ММ-ДД'
            $e | Should -Contain 'Не указан серийный номер носителя'
        }
        It 'удалённые строки таблицы не проверяются' {
            $SziTable.Rows[1]['id'] = 'SPR'
            $SziTable.Rows[1].Delete()
            @(Test-EtalonTables) | Should -BeNullOrEmpty
        }
        It 'загрузка эталона: отсутствующий файл вызывает ошибку, существующий – загружается' {
            { Import-Etalon } | Should -Throw '*Не найден эталонный файл*'
            New-Item -ItemType Directory -Path (Split-Path $Paths.Etalon) -Force | Out-Null
            Copy-Item (Join-Path $SziRoot 'Config/Etalon.xml') $Paths.Etalon
            Import-Etalon
            $script:Etalon.SziEtalon.GetAttribute('version') | Should -Be '1.0'
            $script:EtalonText | Should -Match 'SziEtalon'
        }
    }

    Context 'ТК-22. Формирование отчёта HTML' {
        BeforeEach {
            $script:Etalon = New-Object System.Xml.XmlDocument
            $script:Etalon.Load((Join-Path $SziRoot 'Config/Etalon.xml'))
            $script:ReportRun = [pscustomobject]@{
                Computer = 'ARM-01'; Profile = 'АРМ оператора'; OS = 'Windows 10'; Domain = 'ptk.local'; IP = '10.0.0.1'
                Date = Get-Date; User = 'PTK\auditor'
                Results = @((New-Item2 A $OK), (New-Item2 B $FAIL -Actual '<script>alert(1)</script>'), (New-Item2 C $WARN), (New-Item2 D $ERR))
            }
        }
        It 'отчёт сохраняется в каталог Reports в кодировке UTF-8 с BOM' {
            $f = New-HtmlReport @($ReportRun)
            Test-Path $f | Should -BeTrue
            (Split-Path $f -Parent) | Should -Be $Paths.Reports
            $b = [IO.File]::ReadAllBytes($f)
            $b[0..2] | Should -Be @(0xEF, 0xBB, 0xBF)
        }
        It 'отчёт содержит сведения об АРМ, итоги, индекс и раскраску строк по результату' {
            $h = Get-Content (New-HtmlReport @($ReportRun)) -Raw -Encoding UTF8
            $h | Should -Match 'АРМ ARM-01'
            $h | Should -Match 'проверок – 4; соответствует – 1; не соответствует – 1; предупреждений – 1; ошибок – 1'
            $h | Should -Match 'Подразделение пограничного контроля'
            foreach ($cls in 'ok', 'fail', 'warn', 'err') { $h | Should -Match "<tr class=""$cls"">" }
        }
        It 'данные экранируются (защита от внедрения разметки)' {
            $h = Get-Content (New-HtmlReport @($ReportRun)) -Raw -Encoding UTF8
            $h | Should -Not -Match '<script>alert'
            $h | Should -Match '&lt;script&gt;alert\(1\)&lt;/script&gt;'
        }
        It 'отчёт по нескольким АРМ содержит раздел для каждого' {
            $r2 = $ReportRun.PSObject.Copy(); $r2.Computer = 'ARM-02'
            $h = Get-Content (New-HtmlReport @($ReportRun, $r2)) -Raw -Encoding UTF8
            ([regex]::Matches($h, '<h2>АРМ ')).Count | Should -Be 2
        }
    }

    Context 'ТК-23. Обработка результатов фоновых заданий (Start-Job) и ведение истории' {
        BeforeAll {
            # Задание выполняет немодифицированный модуль проверок на виртуальном АРМ
            $script:JobBody = {
                param($Tests, $Checks, $EtalonText, $ProfileId, $Scenario)
                . (Join-Path $Tests 'WindowsStubs.ps1')
                if ($Scenario) { & ([scriptblock]::Create($Scenario)) }
                & $Checks -EtalonXml $EtalonText -ProfileId $ProfileId
            }
            function script:New-TestEtalonFile($Paths) {
                $e = New-TestEtalon (Split-Path $Paths.Results)
                Set-TestAvBases $e.Bases 1
                Copy-Item (Join-Path $SziTestData 'valid_der.crl') $e.Crl
                New-Item -ItemType Directory -Path (Split-Path $Paths.Etalon) -Force | Out-Null
                $e.Xml.Save($Paths.Etalon)
            }
        }
        It 'результат задания сохраняется (XML), добавляется строка истории (CSV)' {
            New-TestEtalonFile $Paths; Import-Etalon
            $job = Start-Job -ScriptBlock $JobBody -ArgumentList $PSScriptRoot, $SziChecks, $script:EtalonText, 'ARM_OPK', ''
            [void](Wait-Job $job -Timeout 300)
            Complete-AuditJob ([pscustomobject]@{ Computer = 'localhost'; Job = $job; Done = $true })
            $script:LastRuns.Keys | Should -Contain 'ARM-TEST-01'
            $files = @(Get-ChildItem $Paths.Results -Filter 'ARM-TEST-01_*.xml')
            $files.Count | Should -Be 1
            $saved = Import-Clixml $files[0].FullName
            @($saved.Results).Count | Should -BeGreaterOrEqual 40
            $h = @(Import-Csv $Paths.History -Delimiter ';' -Encoding UTF8)
            $h.Count | Should -Be 1
            $h[0].Computer | Should -Be 'ARM-TEST-01'
            $h[0].Fail | Should -Be '0'
            [double]$h[0].Index | Should -Be 100
        }
        It 'ошибка задания (АРМ недоступен) даёт результат «Ошибка проверки» с текстом ошибки' {
            $job = Start-Job -ScriptBlock { throw 'Не удаётся подключиться к удалённому серверу ARM-99: WinRM' }
            [void](Wait-Job $job -Timeout 60)
            Complete-AuditJob ([pscustomobject]@{ Computer = 'ARM-99'; Job = $job; Done = $true })
            $r = $script:AllResults[0]
            $r.CheckId | Should -Be 'CONNECT'
            $r.Status | Should -Be $ERR
            $r.Actual | Should -Match 'WinRM'
            Test-Path $Paths.History | Should -BeFalse
        }
    }

    Context 'ТК-24. Консольный режим (Планировщик заданий): перечень АРМ, отчёт, коды завершения' {
        BeforeAll {
            # Подмена способа запуска: локальный АРМ – задание с имитатором, «unreachable*» – недоступный АРМ
            function New-AuditJob([string]$Computer, [string]$ProfileName) {
                $script:StartedFor += $Computer
                if ($Computer -like 'unreachable*') {
                    return Start-Job -ScriptBlock { param($c) throw "Не удаётся подключиться к удалённому серверу ${c}: WinRM" } -ArgumentList $Computer
                }
                Start-Job -ScriptBlock $JobBody -ArgumentList $PSScriptRoot, $SziChecks, $script:EtalonText, $ProfileName, $script:Scenario
            }
        }
        BeforeEach {
            New-TestEtalonFile $Paths
            $script:StartedFor = @(); $script:Scenario = ''
            $ProfileId = 'ARM_OPK'; $Computers = @('localhost'); $ComputersFile = $null; $FromDomain = $false; $SearchBase = $null
        }
        It 'АРМ соответствует эталону – код 0, сформирован отчёт' {
            $code = @(Invoke-ConsoleAudit)
            $code.Count | Should -Be 1      # функция возвращает ровно одно значение
            $code[0] | Should -Be 0
            @(Get-ChildItem $Paths.Reports -Filter 'Report_*.html').Count | Should -Be 1
        }
        It 'выявлены несоответствия – код 1' {
            $script:Scenario = '$global:FakeArm.SecPolicy.EnableGuestAccount = 1'
            Invoke-ConsoleAudit | Should -Be 1
        }
        It 'ошибка выполнения проверок (АРМ недоступен) – код 2' {
            $Computers = @('localhost', 'unreachable-01')
            Invoke-ConsoleAudit | Should -Be 2
        }
        It 'неизвестный профиль – исключение с перечнем доступных профилей' {
            $ProfileId = 'NO_SUCH'
            { Invoke-ConsoleAudit } | Should -Throw '*ARM_OPK, ARM_SPN, ARM_ADM, ARM_SPD, SRV_OHD*'
        }
        It 'файл перечня АРМ: комментарии, пустые строки и повторы пропускаются' {
            $ComputersFile = Join-Path $TestDrive 'arm_list.txt'
            Set-Content -Path $ComputersFile -Encoding UTF8 -Value @('# перечень', '', '  localhost  ', 'localhost', '# unreachable-02')
            [void](Invoke-ConsoleAudit)
            $script:StartedFor | Should -Be @('localhost')
        }
        It 'штатный файл arm.txt разбирается' {
            $ComputersFile = Join-Path $SziRoot 'arm.txt'
            Invoke-ConsoleAudit | Should -Be 0
            $script:StartedFor | Should -Be @('localhost')
        }
    }
}
