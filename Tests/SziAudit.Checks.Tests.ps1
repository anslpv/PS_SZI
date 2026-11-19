#requires -Version 5.1
#requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }
<#
    Модульные и функциональные тесты модуля проверок SziAudit.Checks.ps1.
    Модуль выполняется без изменений на «виртуальном АРМ» (Tests\WindowsStubs.ps1):
    каждое состояние АРМ задаётся явно, после чего сверяется результат конкретной проверки.
    Идентификаторы тестов (ТК-xx) соответствуют таблице тестовых случаев отчёта.
#>

Describe 'Модуль проверок SziAudit.Checks.ps1' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'WindowsStubs.ps1')
        . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
        $script:OK = 'Соответствует'; $script:FAIL = 'Не соответствует'
        $script:WARN = 'Предупреждение'; $script:ERR = 'Ошибка проверки'
    }

    BeforeEach {
        $global:FakeArm = New-FakeArm
        $script:Et = New-TestEtalon $TestDrive
        Set-TestAvBases $Et.Bases 1
        Get-ChildItem -Path $Et.Crl -File | Remove-Item -Force
        Copy-Item -Path (Join-Path $SziTestData 'valid_der.crl'), (Join-Path $SziTestData 'valid_pem.crl') -Destination $Et.Crl
    }

    Context 'ТК-01. АРМ, соответствующий эталону' {
        It 'все проверки профиля ARM_OPK дают результат «Соответствует»' {
            $run = Invoke-TestAudit $Et.Xml
            $bad = @($run.Results | Where-Object { $_.Status -ne $OK } | ForEach-Object { "$($_.CheckId): $($_.Status) – $($_.Actual)" })
            $bad | Should -BeNullOrEmpty
            $run.Results.Count | Should -BeGreaterOrEqual 40
        }
        It 'возвращает общие сведения об АРМ' {
            $run = Invoke-TestAudit $Et.Xml
            $run.Computer | Should -Be 'ARM-TEST-01'
            $run.ProfileId | Should -Be 'ARM_OPK'
            $run.Profile | Should -Be 'АРМ оператора паспортного контроля'
            $run.Domain | Should -Be 'ptk.local'
            $run.IP | Should -Be '10.10.1.15'
            $run.User | Should -Be 'PTK\auditor'
        }
        It 'каждый результат содержит все поля и допустимые значения статуса и критичности' {
            $run = Invoke-TestAudit $Et.Xml
            foreach ($r in $run.Results) {
                foreach ($f in 'Computer', 'CheckId', 'Category', 'Name', 'Expected', 'Actual', 'Status', 'Severity', 'Time') {
                    $r.PSObject.Properties.Name | Should -Contain $f
                }
                $r.Status | Should -BeIn @($OK, $FAIL, $WARN, $ERR)
                $r.Severity | Should -BeIn @('Высокая', 'Средняя', 'Низкая')
            }
        }
    }

    Context 'ТК-02. Входные параметры модуля проверок' {
        It 'несуществующий профиль вызывает ошибку с понятным сообщением' {
            { Invoke-TestAudit $Et.Xml 'NO_SUCH' } | Should -Throw "*Профиль 'NO_SUCH' не найден*"
        }
        It 'для профиля ARM_SPD проверяются только СЗИ из его перечня (KES, KLNAGENT)' {
            $run = Invoke-TestAudit $Et.Xml 'ARM_SPD'
            $ids = @($run.Results | Where-Object { $_.CheckId -like 'SZI-*' } | ForEach-Object { $_.CheckId })
            $ids | Should -Be @('SZI-KES', 'SZI-KLNAGENT')
        }
    }

    Context 'ТК-03. Состав и версии СЗИ' {
        It 'отсутствующее СЗИ – «Не соответствует», «Не установлено»' {
            $FakeArm.Software = @($FakeArm.Software | Where-Object { $_.DisplayName -notlike '*ViPNet*' })
            $r = Get-CheckResult (Invoke-TestAudit $Et.Xml) 'SZI-VIPNET'
            $r.Status | Should -Be $FAIL
            $r.Actual | Should -Be 'Не установлено'
            $r.Severity | Should -Be 'Высокая'
        }
        It 'версия ниже минимальной – «Не соответствует»' {
            ($FakeArm.Software | Where-Object { $_.DisplayName -like 'Kaspersky Endpoint*' }).DisplayVersion = '11.5.0.590'
            (Get-CheckResult (Invoke-TestAudit $Et.Xml) 'SZI-KES').Status | Should -Be $FAIL
        }
        It 'версии сравниваются как числа (11.10 не ниже 11.6)' {
            ($FakeArm.Software | Where-Object { $_.DisplayName -like 'Kaspersky Endpoint*' }).DisplayVersion = '11.10.0.399'
            (Get-CheckResult (Invoke-TestAudit $Et.Xml) 'SZI-KES').Status | Should -Be $OK
        }
        It 'версия без точки («5») и с суффиксом («4.5 R2») разбирается' {
            ($FakeArm.Software | Where-Object { $_.DisplayName -like 'КриптоПро*' }).DisplayVersion = '5'
            ($FakeArm.Software | Where-Object { $_.DisplayName -like 'ViPNet*' }).DisplayVersion = '4.5 R2'
            $run = Invoke-TestAudit $Et.Xml
            (Get-CheckResult $run 'SZI-CSP').Status | Should -Be $OK
            (Get-CheckResult $run 'SZI-VIPNET').Status | Should -Be $OK
        }
        It 'поиск по альтернативному шаблону имени («CryptoPro CSP»)' {
            ($FakeArm.Software | Where-Object { $_.DisplayName -like 'КриптоПро*' }).DisplayName = 'CryptoPro CSP'
            (Get-CheckResult (Invoke-TestAudit $Et.Xml) 'SZI-CSP').Status | Should -Be $OK
        }
        It 'системные компоненты (SystemComponent = 1) не учитываются' {
            $r = Get-CheckResult (Invoke-TestAudit $Et.Xml) 'SW-EXTRA'
            $r.Actual | Should -Be 'Установлено программ: 6'
        }
    }

    Context 'ТК-04. Работоспособность служб СЗИ' {
        It 'остановленная служба СЗИ – «Не соответствует»' {
            ($FakeArm.Services | Where-Object { $_.Name -eq 'klnagent' }).Status = 'Stopped'
            $r = Get-CheckResult (Invoke-TestAudit $Et.Xml) 'SVC-KLNAGENT'
            $r.Status | Should -Be $FAIL
            $r.Actual | Should -Be 'klnagent: Stopped/Automatic'
        }
        It 'тип запуска «Вручную» – «Не соответствует»' {
            ($FakeArm.Services | Where-Object { $_.Name -like 'AVP*' }).StartType = 'Manual'
            (Get-CheckResult (Invoke-TestAudit $Et.Xml) 'SVC-KES').Status | Should -Be $FAIL
        }
        It 'служба не найдена – «Не соответствует»' {
            $FakeArm.Services = @($FakeArm.Services | Where-Object { $_.Name -notlike '*ViPNet*' })
            (Get-CheckResult (Invoke-TestAudit $Et.Xml) 'SVC-VIPNET').Actual | Should -Be 'Служба не найдена'
        }
    }

    Context 'ТК-05. Сроки сертификатов соответствия СЗИ' {
        It 'истёкший сертификат – «Не соответствует»' {
            $Et.Xml.SelectSingleNode("//Szi[@id='SPR']").SetAttribute('certExpires', (Get-Date).AddDays(-1).ToString('yyyy-MM-dd'))
            (Get-CheckResult (Invoke-TestAudit $Et.Xml) 'CRT-SPR').Status | Should -Be $FAIL
        }
        It 'сертификат истекает в течение CertWarnDays (90 сут.) – «Предупреждение»' {
            $Et.Xml.SelectSingleNode("//Szi[@id='SPR']").SetAttribute('certExpires', (Get-Date).AddDays(30).ToString('yyyy-MM-dd'))
            (Get-CheckResult (Invoke-TestAudit $Et.Xml) 'CRT-SPR').Status | Should -Be $WARN
        }
        It 'при пустом сроке проверка не выполняется (агент администрирования)' {
            Get-CheckResult (Invoke-TestAudit $Et.Xml) 'CRT-KLNAGENT' | Should -BeNullOrEmpty
        }
    }

    Context 'ТК-06. Актуальность баз антивирусного средства' {
        It 'базы старше AvBasesMaxAgeDays (7 сут.) – «Не соответствует»' {
            Set-TestAvBases $Et.Bases 10
            $r = Get-CheckResult (Invoke-TestAudit $Et.Xml) 'AV-BASES'
            $r.Status | Should -Be $FAIL
            $r.Actual | Should -Match '\(10 сут\.\)'
        }
        It 'каталог баз не найден, сведений Центра безопасности нет – «Предупреждение»' {
            Remove-Item -Path $Et.Bases -Recurse -Force
            (Get-CheckResult (Invoke-TestAudit $Et.Xml) 'AV-BASES').Status | Should -Be $WARN
        }
        It 'при отсутствии каталога используется дата из Центра безопасности Windows' {
            Remove-Item -Path $Et.Bases -Recurse -Force
            $FakeArm.AvProduct = @{ displayName = 'Kaspersky Endpoint Security'; timestamp = (Get-Date).AddDays(-2).ToString('R') }
            $r = Get-CheckResult (Invoke-TestAudit $Et.Xml) 'AV-BASES'
            $r.Status | Should -Be $OK
            $r.Actual | Should -Match '\(2 сут\.\)'
        }
    }

    Context 'ТК-07. Политика учётных записей' {
        It 'минимальная длина пароля 6 < 8 – «Не соответствует»' {
            $FakeArm.SecPolicy.MinimumPasswordLength = 6
            (Get-CheckResult (Invoke-TestAudit $Et.Xml) 'PWD-LEN').Status | Should -Be $FAIL
        }
        It 'сложность пароля отключена – «Не соответствует»' {
            $FakeArm.SecPolicy.PasswordComplexity = 0
            (Get-CheckResult (Invoke-TestAudit $Et.Xml) 'PWD-CPLX').Actual | Should -Be 'Отключено'
        }
        It 'срок действия пароля 0 (не ограничен) и 365 сут. – «Не соответствует»' {
            foreach ($v in 0, 365) {
                $FakeArm.SecPolicy.MaximumPasswordAge = $v
                (Get-CheckResult (Invoke-TestAudit $Et.Xml) 'PWD-AGE').Status | Should -Be $FAIL
            }
        }
        It 'порог блокировки 0 (не задан) и 20 – «Не соответствует»' {
            foreach ($v in 0, 20) {
                $FakeArm.SecPolicy.LockoutBadCount = $v
                (Get-CheckResult (Invoke-TestAudit $Et.Xml) 'LOCK-CNT').Status | Should -Be $FAIL
            }
        }
        It 'включённая учётная запись «Гость» – «Не соответствует»' {
            $FakeArm.SecPolicy.EnableGuestAccount = 1
            (Get-CheckResult (Invoke-TestAudit $Et.Xml) 'GUEST').Status | Should -Be $FAIL
        }
        It 'ошибка secedit – результат «Ошибка проверки», проверки паролей не выполняются' {
            $FakeArm.SeceditFails = $true
            $run = Invoke-TestAudit $Et.Xml
            (Get-CheckResult $run 'POL-READ').Status | Should -Be $ERR
            Get-CheckResult $run 'PWD-LEN' | Should -BeNullOrEmpty
        }
        It 'лишний член группы администраторов – «Не соответствует» с указанием учётной записи' {
            $FakeArm.Admins += 'ARM-TEST-01\ivanov'
            $r = Get-CheckResult (Invoke-TestAudit $Et.Xml) 'ADMINS'
            $r.Status | Should -Be $FAIL
            $r.Recommendation | Should -Match 'ivanov'
        }
    }

    Context 'ТК-08. Политика аудита и журнал безопасности' {
        It 'подкатегория «Вход в систему» только «Успех» при требовании «Успех и отказ» – «Не соответствует»' {
            $FakeArm.AuditPolicy['{0CCE9215-69AE-11D9-BED3-505054503030}'] = 1
            $r = Get-CheckResult (Invoke-TestAudit $Et.Xml) 'AUD-0CCE9215'
            $r.Status | Should -Be $FAIL
            $r.Actual | Should -Be 'Успех'
        }
        It 'подкатегория отсутствует в выгрузке – «Нет аудита»' {
            $FakeArm.AuditPolicy.Remove('{0CCE9216-69AE-11D9-BED3-505054503030}')
            (Get-CheckResult (Invoke-TestAudit $Et.Xml) 'AUD-0CCE9216').Actual | Should -Be 'Нет аудита'
        }
        It 'требование «Успех» выполняется настройкой «Успех и отказ» (битовая маска)' {
            (Get-CheckResult (Invoke-TestAudit $Et.Xml) 'AUD-0CCE9235').Status | Should -Be $OK
        }
        It 'ошибка auditpol – «Ошибка проверки»' {
            $FakeArm.AuditpolFails = $true
            (Get-CheckResult (Invoke-TestAudit $Et.Xml) 'AUD-READ').Status | Should -Be $ERR
        }
        It 'журнал безопасности 32 МБ < 64 МБ – «Не соответствует»' {
            $FakeArm.SecurityLogMB = 32
            (Get-CheckResult (Invoke-TestAudit $Et.Xml) 'LOG-SIZE').Status | Should -Be $FAIL
        }
        It 'событие очистки журнала 1102 – «Предупреждение»' {
            $FakeArm.Events.Security += @{ Id = 1102; TimeCreated = (Get-Date).AddDays(-5); Message = 'Журнал аудита был очищен.' }
            (Get-CheckResult (Invoke-TestAudit $Et.Xml) 'LOG-CLEAR').Status | Should -Be $WARN
        }
        It 'событие 1102 старше EventLookbackDays (30 сут.) не учитывается' {
            $FakeArm.Events.Security += @{ Id = 1102; TimeCreated = (Get-Date).AddDays(-40); Message = 'Журнал аудита был очищен.' }
            (Get-CheckResult (Invoke-TestAudit $Et.Xml) 'LOG-CLEAR').Status | Should -Be $OK
        }
        It '25 неудачных попыток входа при пороге 20 – «Предупреждение»' {
            $FakeArm.Events.Security = @(1..25 | ForEach-Object { @{ Id = 4625; TimeCreated = (Get-Date).AddHours(-$_); Message = 'Отказ входа' } })
            $r = Get-CheckResult (Invoke-TestAudit $Et.Xml) 'LOG-FAIL'
            $r.Status | Should -Be $WARN
            $r.Actual | Should -Be '25'
        }
    }

    Context 'ТК-09. Сетевые настройки и беспроводные интерфейсы' {
        It 'отключённый профиль межсетевого экрана – «Не соответствует»' {
            $FakeArm.Firewall[2].Enabled = 'False'
            $r = Get-CheckResult (Invoke-TestAudit $Et.Xml) 'NET-FW'
            $r.Status | Should -Be $FAIL
            $r.Actual | Should -Match 'Public: выкл'
        }
        It 'интерфейс с DHCP – «Не соответствует» (петлевой интерфейс не учитывается)' {
            $FakeArm.DhcpInterfaces = @('Ethernet 2')
            $r = Get-CheckResult (Invoke-TestAudit $Et.Xml) 'NET-DHCP'
            $r.Status | Should -Be $FAIL
            $r.Actual | Should -Be 'DHCP: Ethernet 2'
        }
        It 'адаптер Wi-Fi или устройство Bluetooth – «Не соответствует»' {
            $FakeArm.WifiAdapters = @('Intel(R) Wi-Fi 6 AX201 160MHz')
            $FakeArm.Bluetooth = @('Intel(R) Wireless Bluetooth(R)')
            $r = Get-CheckResult (Invoke-TestAudit $Et.Xml) 'NET-WLAN'
            $r.Status | Should -Be $FAIL
            $r.Actual | Should -Match 'Wi-Fi 6'
            $r.Actual | Should -Match 'Bluetooth'
        }
        It 'при RequireFirewall = false проверка межсетевого экрана не выполняется' {
            $Et.Xml.SelectSingleNode("//Profile[@id='ARM_OPK']/RequireFirewall").InnerText = 'false'
            Get-CheckResult (Invoke-TestAudit $Et.Xml) 'NET-FW' | Should -BeNullOrEmpty
        }
    }

    Context 'ТК-10. Параметры безопасности ОС' {
        It 'автозапуск разрешён частично (145) или не задан – «Не соответствует»' {
            $k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            $FakeArm.Registry[$k] = @{ NoDriveTypeAutoRun = 145 }
            (Get-CheckResult (Invoke-TestAudit $Et.Xml) 'OS-AUTORUN').Status | Should -Be $FAIL
            $FakeArm.Registry.Remove($k)
            (Get-CheckResult (Invoke-TestAudit $Et.Xml) 'OS-AUTORUN').Actual | Should -Be 'Не задано'
        }
        It 'предел простоя 1800 с > 900 с или не задан – «Предупреждение»' {
            $k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            $FakeArm.Registry[$k] = @{ InactivityTimeoutSecs = 1800 }
            (Get-CheckResult (Invoke-TestAudit $Et.Xml) 'OS-LOCK').Status | Should -Be $WARN
            $FakeArm.Registry.Remove($k)
            (Get-CheckResult (Invoke-TestAudit $Et.Xml) 'OS-LOCK').Status | Should -Be $WARN
        }
        It 'автоматический вход (AutoAdminLogon = 1) – «Не соответствует»' {
            $FakeArm.Registry['HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'] = @{ AutoAdminLogon = '1' }
            (Get-CheckResult (Invoke-TestAudit $Et.Xml) 'OS-AUTOLOGON').Status | Should -Be $FAIL
        }
        It 'включённый протокол SMBv1 – «Не соответствует»' {
            $FakeArm.Smb1 = $true
            (Get-CheckResult (Invoke-TestAudit $Et.Xml) 'SMB1').Status | Should -Be $FAIL
        }
    }

    Context 'ТК-11. Съёмные машинные носители информации' {
        It 'неучтённый носитель – «Не соответствует», учтённый – «Соответствует»' {
            $FakeArm.Usb += @{ Model = 'Disk&Ven_SanDisk&Prod_Cruzer'; Serial = '4C530001230517&0'; FriendlyName = 'SanDisk Cruzer USB Device' }
            $run = Invoke-TestAudit $Et.Xml
            (Get-CheckResult $run 'USB-4C530001230517').Status | Should -Be $FAIL
            (Get-CheckResult $run 'USB-4C530001230517').Name | Should -Be 'Носитель: SanDisk Cruzer USB Device'
            (Get-CheckResult $run 'USB-0401396BBFE2A1B5').Status | Should -Be $OK
        }
        It 'серийный номер сравнивается без учёта регистра' {
            $FakeArm.Usb[0].Serial = '0401396bbfe2a1b5&0'
            (Get-CheckResult (Invoke-TestAudit $Et.Xml) 'USB-0401396bbfe2a1b5').Status | Should -Be $OK
        }
        It 'подключения не зарегистрированы – «Соответствует»' {
            $FakeArm.Usb = @()
            (Get-CheckResult (Invoke-TestAudit $Et.Xml) 'USB-READ').Actual | Should -Be 'Подключения не выявлены'
        }
    }

    Context 'ТК-12. Сверка установленного ПО с предписанием' {
        It 'нештатное ПО – «Не соответствует» с перечнем программ' {
            $FakeArm.Software += @{ DisplayName = 'Google Chrome'; DisplayVersion = '120.0' }
            $r = Get-CheckResult (Invoke-TestAudit $Et.Xml) 'SW-EXTRA'
            $r.Status | Should -Be $FAIL
            $r.Actual | Should -Be 'Лишние (1): Google Chrome'
        }
        It 'перечень лишнего ПО сокращается после 15 позиций' {
            $FakeArm.Software += @(1..20 | ForEach-Object { @{ DisplayName = ('Program {0:D2}' -f $_); DisplayVersion = '1.0' } })
            (Get-CheckResult (Invoke-TestAudit $Et.Xml) 'SW-EXTRA').Actual | Should -Match 'и ещё 5$'
        }
        It 'ПО, разрешённое для профиля (Microsoft Office для ARM_SPN), не считается лишним' {
            $FakeArm.Software += @{ DisplayName = 'Microsoft Office профессиональный плюс 2016'; DisplayVersion = '16.0' }
            (Get-CheckResult (Invoke-TestAudit $Et.Xml 'ARM_SPN') 'SW-EXTRA').Status | Should -Be $OK
            (Get-CheckResult (Invoke-TestAudit $Et.Xml 'ARM_OPK') 'SW-EXTRA').Status | Should -Be $FAIL
        }
        It 'обновления Windows по шаблону «*(KB*)*» не считаются лишними' {
            $FakeArm.Software += @{ DisplayName = 'Security Update for Windows (KB5034441)'; DisplayVersion = '' }
            (Get-CheckResult (Invoke-TestAudit $Et.Xml) 'SW-EXTRA').Status | Should -Be $OK
        }
        It 'ПО, разрешённое составным шаблоном «*Рутокен*|*Rutoken*», не считается лишним' {
            $FakeArm.Software += @{ DisplayName = 'Драйверы Рутокен'; DisplayVersion = '4.15' }
            $FakeArm.Software += @{ DisplayName = 'Rutoken Drivers'; DisplayVersion = '4.15' }
            (Get-CheckResult (Invoke-TestAudit $Et.Xml) 'SW-EXTRA').Status | Should -Be $OK
        }
    }

    Context 'ТК-13. Сертификаты удостоверяющих центров' {
        BeforeEach {
            $c = $Et.Xml.CreateElement('Cert')
            $c.SetAttribute('name', 'Корневой сертификат тестового УЦ'); $c.SetAttribute('store', 'Root')
            $c.SetAttribute('thumbprint', 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678')
            [void]$Et.Xml.SziEtalon.SelectSingleNode('Certificates').AppendChild($c)
        }
        It 'сертификат отсутствует – «Не соответствует»' {
            (Get-CheckResult (Invoke-TestAudit $Et.Xml) 'PKI-A1B2C3D4').Actual | Should -Be 'Отсутствует'
        }
        It 'действующий / истекающий в 30 сут. / истёкший сертификат' {
            $cases = @(@{ Days = 400; St = $OK }, @{ Days = 10; St = $WARN }, @{ Days = -1; St = $FAIL })
            foreach ($cs in $cases) {
                $FakeArm.Certificates = @(@{ Store = 'Root'; Thumbprint = 'A1B2C3D4E5F60718293A4B5C6D7E8F9012345678'; NotAfter = (Get-Date).AddDays($cs.Days) })
                (Get-CheckResult (Invoke-TestAudit $Et.Xml) 'PKI-A1B2C3D4').Status | Should -Be $cs.St
            }
        }
    }

    Context 'ТК-14. Списки отозванных сертификатов (разбор ASN.1 DER/PEM)' {
        It 'действующие СОС в форматах DER и PEM разбираются, издатель и срок определяются' {
            $run = Invoke-TestAudit $Et.Xml
            $der = Get-CheckResult $run 'CRL-Test UC Valid'
            $der.Status | Should -Be $OK
            $der.Actual | Should -Match '^Действует до 31\.12\.2099'
            (Get-CheckResult $run 'CRL-Test UC Pem').Status | Should -Be $OK
        }
        It 'просроченный СОС – «Не соответствует»' {
            Copy-Item (Join-Path $SziTestData 'expired.crl') $Et.Crl
            (Get-CheckResult (Invoke-TestAudit $Et.Xml) 'CRL-Test UC Expired').Status | Should -Be $FAIL
        }
        It 'повреждённый файл СОС – «Ошибка проверки», остальные СОС проверяются' {
            Copy-Item (Join-Path $SziTestData 'broken.crl') $Et.Crl
            $run = Invoke-TestAudit $Et.Xml
            (Get-CheckResult $run 'CRL-broken.crl').Status | Should -Be $ERR
            (Get-CheckResult $run 'CRL-Test UC Valid').Status | Should -Be $OK
        }
        It 'СОС из системного хранилища (значение Blob реестра) разбирается' {
            Get-ChildItem -Path $Et.Crl -File | Remove-Item -Force
            $FakeArm.StoreCrls.CA = @(, [IO.File]::ReadAllBytes((Join-Path $SziTestData 'expired.crl')))
            $r = Get-CheckResult (Invoke-TestAudit $Et.Xml) 'CRL-Test UC Expired'
            $r.Status | Should -Be $FAIL
            $r.Actual | Should -Match 'Хранилище CA'
        }
        It 'СОС не найдены – «Предупреждение»' {
            Get-ChildItem -Path $Et.Crl -File | Remove-Item -Force
            (Get-CheckResult (Invoke-TestAudit $Et.Xml) 'CRL-READ').Status | Should -Be $WARN
        }
    }

    Context 'ТК-15. Обнаружения вредоносного ПО в журналах АВС' {
        It 'событие с ключевым словом в журнале Kaspersky – «Не соответствует»' {
            $FakeArm.Events['Kaspersky Event Log'] += @{ Id = 302; TimeCreated = (Get-Date).AddDays(-1); Message = "Обнаружен вредоносный объект: EICAR-Test-File`nПуть: C:\Temp" }
            $r = Get-CheckResult (Invoke-TestAudit $Et.Xml) 'AV-DETECT'
            $r.Status | Should -Be $FAIL
            $r.Actual | Should -Match 'Выявлено: 1.*EICAR-Test-File$'
        }
        It 'событие 1116 в журнале Windows Defender – «Не соответствует»' {
            $FakeArm.LogsPresent += 'Microsoft-Windows-Windows Defender/Operational'
            $FakeArm.Events['Microsoft-Windows-Windows Defender/Operational'] = @(@{ Id = 1116; TimeCreated = (Get-Date).AddHours(-3); Message = 'Antimalware platform detected malware' })
            (Get-CheckResult (Invoke-TestAudit $Et.Xml) 'AV-DETECT').Status | Should -Be $FAIL
        }
        It 'журналы АВС отсутствуют – «Предупреждение»' {
            $FakeArm.LogsPresent = @('Security')
            (Get-CheckResult (Invoke-TestAudit $Et.Xml) 'AV-DETECT').Status | Should -Be $WARN
        }
    }

    Context 'ТК-16. Локальные учётные записи' {
        It 'учётная запись, не допущенная приказом, – «Не соответствует»; отключённые не учитываются' {
            $FakeArm.Users += @{ Name = 'petrov'; Enabled = $true; PasswordExpires = (Get-Date).AddDays(30); LastLogon = (Get-Date) }
            $r = Get-CheckResult (Invoke-TestAudit $Et.Xml) 'USR-LIST'
            $r.Status | Should -Be $FAIL
            $r.Recommendation | Should -Match 'petrov'
            $r.Recommendation | Should -Not -Match 'Гость'
        }
        It 'бессрочный пароль – «Не соответствует»' {
            $FakeArm.Users[0].PasswordExpires = $null
            (Get-CheckResult (Invoke-TestAudit $Et.Xml) 'USR-PWDNEVER').Actual | Should -Be 'Администратор'
        }
        It 'вход более InactiveUserDays (45 сут.) назад или входов не было – «Предупреждение»' {
            $FakeArm.Users[0].LastLogon = (Get-Date).AddDays(-60)
            $FakeArm.Users += @{ Name = 'Administrator'; Enabled = $true; PasswordExpires = (Get-Date).AddDays(30); LastLogon = $null }
            $r = Get-CheckResult (Invoke-TestAudit $Et.Xml) 'USR-STALE'
            $r.Status | Should -Be $WARN
            $r.Actual | Should -Match 'Administrator \(входов не было\)'
        }
        It 'для профиля без перечня AllowedUsers сверка не выполняется' {
            Get-CheckResult (Invoke-TestAudit $Et.Xml 'ARM_SPN') 'USR-LIST' | Should -BeNullOrEmpty
        }
        It 'ошибка чтения учётных записей – «Ошибка проверки»' {
            $FakeArm.UsersFail = $true
            (Get-CheckResult (Invoke-TestAudit $Et.Xml) 'USR-READ').Status | Should -Be $ERR
        }
    }

    Context 'ТК-17. Неиспользуемые службы' {
        It 'запрещённая служба запущена или не отключена – «Не соответствует»' {
            $FakeArm.Services += @{ Name = 'Fax'; DisplayName = 'Факс'; Status = 'Stopped'; StartType = 'Manual' }
            ($FakeArm.Services | Where-Object { $_.Name -eq 'RemoteRegistry' }).Status = 'Running'
            $run = Invoke-TestAudit $Et.Xml
            (Get-CheckResult $run 'SRV-Fax').Status | Should -Be $FAIL
            (Get-CheckResult $run 'SRV-RemoteRegistry').Status | Should -Be $FAIL
        }
    }

    Context 'ТК-18. Устойчивость к ошибкам отдельных проверок' {
        It 'исключение в одной проверке фиксируется как «Ошибка проверки», остальные выполняются' {
            function global:Get-NetFirewallProfile { throw 'Служба брандмауэра Защитника Windows недоступна' }
            try {
                $run = Invoke-TestAudit $Et.Xml
                $r = Get-CheckResult $run 'NET-FW'
                $r.Status | Should -Be $ERR
                $r.Actual | Should -Match 'недоступна'
                (Get-CheckResult $run 'NET-DHCP').Status | Should -Be $OK
                (Get-CheckResult $run 'OS-AUTOLOGON').Status | Should -Be $OK
            }
            finally { function global:Get-NetFirewallProfile { $global:FakeArm.Firewall | ForEach-Object { [pscustomobject]$_ } } }
        }
    }
}
