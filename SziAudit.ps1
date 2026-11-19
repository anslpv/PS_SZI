#requires -Version 5.1
<#
.SYNOPSIS
    ПО «СЗИ-Аудит» — аудит средств защиты информации автоматизированных рабочих мест.
.DESCRIPTION
    Главный модуль: графический интерфейс (WPF), управление эталоном, запуск проверок
    на локальном и удалённых АРМ, хранение истории, сравнение результатов, формирование
    отчётов. Проверки выполняются модулем SziAudit.Checks.ps1.
.PARAMETER NoGui
    Консольный режим без графического интерфейса (для Планировщика заданий).
.PARAMETER ProfileId
    Идентификатор профиля АРМ из эталона (обязателен в консольном режиме), например ARM_OPK.
.PARAMETER Computers
    Имена или IP-адреса АРМ через запятую (по умолчанию localhost).
.PARAMETER ComputersFile
    Текстовый файл с перечнем АРМ (одно имя в строке, строки с # игнорируются).
.PARAMETER FromDomain
    Взять перечень АРМ из Active Directory (активные учётные записи компьютеров).
.PARAMETER SearchBase
    Подразделение (OU) Active Directory для отбора компьютеров,
    например "OU=Компьютеры в кабинах ПК,DC=ptk,DC=local".
.PARAMETER OpenReport
    Открыть сформированный отчёт в браузере (консольный режим).
.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File SziAudit.ps1 -NoGui -ProfileId ARM_OPK -ComputersFile arm.txt
.NOTES
    Платформа: Windows PowerShell 5.1, .NET Framework 4.5 и выше.
    Запуск: Run-SziAudit.bat (от имени администратора).
    Коды завершения консольного режима: 0 – несоответствий нет; 1 – выявлены несоответствия;
    2 – ошибки выполнения проверок; 3 – ошибка запуска.
#>
param(
    [switch]$NoGui,
    [string]$ProfileId,
    [string[]]$Computers = @('localhost'),
    [string]$ComputersFile,
    [switch]$OpenReport,
    [switch]$FromDomain,
    [string]$SearchBase
)

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
$ErrorActionPreference = 'Stop'

$AppName    = 'СЗИ-Аудит'
$AppVersion = '1.0'
$Root       = $PSScriptRoot

$Paths = @{
    Etalon  = Join-Path $Root 'Config\Etalon.xml'
    Backup  = Join-Path $Root 'Config\Backup'
    Results = Join-Path $Root 'Results'
    Reports = Join-Path $Root 'Reports'
    Logs    = Join-Path $Root 'Logs'
    Checks  = Join-Path $Root 'SziAudit.Checks.ps1'
    History = Join-Path $Root 'Results\History.csv'
}
foreach ($d in 'Backup', 'Results', 'Reports', 'Logs') {
    if (-not (Test-Path $Paths[$d])) { New-Item -ItemType Directory -Path $Paths[$d] | Out-Null }
}

# --- Проверка прав администратора ------------------------------------------
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$IsAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin -and $NoGui) {
    Write-Warning 'Для выполнения аудита требуются права администратора. Запустите консоль от имени администратора.'
    exit 3
}
if (-not $IsAdmin) {
    $ans = [System.Windows.MessageBox]::Show(
        "Для выполнения аудита требуются права администратора.`nПерезапустить программу с повышением прав?",
        $AppName, 'YesNo', 'Warning')
    if ($ans -eq 'Yes') {
        Start-Process -FilePath 'powershell.exe' -Verb RunAs `
            -ArgumentList "-NoProfile -ExecutionPolicy Bypass -STA -File `"$PSCommandPath`""
        return
    }
}

# ============================================================================
# Разметка интерфейса (XAML)
# ============================================================================
[xml]$Xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="СЗИ-Аудит — аудит средств защиты информации АРМ" Width="1220" Height="780"
        MinWidth="980" MinHeight="600" WindowStartupLocation="CenterScreen"
        FontFamily="Segoe UI" FontSize="13" Background="#F4F6F9">
  <Window.Resources>
    <Style TargetType="Button">
      <Setter Property="Padding" Value="12,4"/>
      <Setter Property="Margin" Value="4,0"/>
      <Setter Property="MinWidth" Value="110"/>
    </Style>
    <Style TargetType="DataGrid">
      <Setter Property="AutoGenerateColumns" Value="False"/>
      <Setter Property="CanUserAddRows" Value="False"/>
      <Setter Property="HeadersVisibility" Value="Column"/>
      <Setter Property="GridLinesVisibility" Value="Horizontal"/>
      <Setter Property="HorizontalGridLinesBrush" Value="#E1E5EB"/>
      <Setter Property="Background" Value="White"/>
      <Setter Property="RowHeight" Value="24"/>
    </Style>
  </Window.Resources>
  <DockPanel>
    <Border DockPanel.Dock="Top" Background="#1F3A5F" Padding="16,10">
      <StackPanel>
        <TextBlock Text="СЗИ-Аудит" Foreground="White" FontSize="20" FontWeight="SemiBold"/>
        <TextBlock Text="Контроль состава, работоспособности и настроек средств защиты информации АРМ" Foreground="#C9D6E8"/>
      </StackPanel>
    </Border>
    <StatusBar DockPanel.Dock="Bottom" Background="#E9EDF2">
      <StatusBarItem><TextBlock x:Name="sbText" Text="Готово"/></StatusBarItem>
      <StatusBarItem HorizontalAlignment="Right"><TextBlock x:Name="sbEtalon"/></StatusBarItem>
    </StatusBar>
    <TabControl Margin="8">
      <!-- ===== Вкладка «Аудит» ===== -->
      <TabItem Header="  Аудит  ">
        <Grid Margin="8">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>
          <GroupBox Header="Параметры аудита" Padding="8">
            <Grid>
              <Grid.ColumnDefinitions>
                <ColumnDefinition Width="Auto"/>
                <ColumnDefinition Width="340"/>
                <ColumnDefinition Width="Auto"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
              </Grid.ColumnDefinitions>
              <TextBlock Text="Тип АРМ (профиль):" VerticalAlignment="Center" Margin="0,0,8,0"/>
              <ComboBox x:Name="cbProfile" Grid.Column="1" Height="26"/>
              <TextBlock Grid.Column="2" Text="Компьютеры:" VerticalAlignment="Center" Margin="16,0,8,0"/>
              <TextBox x:Name="tbComputers" Grid.Column="3" Height="26" Text="localhost" VerticalContentAlignment="Center"
                       ToolTip="Имена или IP-адреса АРМ через запятую. localhost — данный компьютер"/>
              <StackPanel Grid.Column="4" Orientation="Horizontal" Margin="8,0,0,0">
                <Button x:Name="btnDomain" Content="Из домена…"/>
                <Button x:Name="btnLoadList" Content="Из файла…"/>
                <Button x:Name="btnStart" Content="Начать аудит" FontWeight="SemiBold" Background="#2E6BB0" Foreground="White"/>
              </StackPanel>
            </Grid>
          </GroupBox>
          <Grid Grid.Row="1" Margin="0,8">
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="*"/>
              <ColumnDefinition Width="Auto"/>
              <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <ProgressBar x:Name="pbProgress" Height="18" Minimum="0" Maximum="1" Value="0"/>
            <TextBlock x:Name="tbProgress" Grid.Column="1" Margin="10,0" VerticalAlignment="Center" Text="Аудит не выполнялся"/>
            <ComboBox x:Name="cbFilter" Grid.Column="2" Width="280" SelectedIndex="0">
              <ComboBoxItem Content="Все результаты"/>
              <ComboBoxItem Content="Только несоответствия и ошибки"/>
              <ComboBoxItem Content="Несоответствия и предупреждения"/>
            </ComboBox>
          </Grid>
          <DataGrid x:Name="dgResults" Grid.Row="2" IsReadOnly="True">
            <DataGrid.RowStyle>
              <Style TargetType="DataGridRow">
                <Style.Triggers>
                  <DataTrigger Binding="{Binding Status}" Value="Не соответствует"><Setter Property="Background" Value="#F9D6D5"/></DataTrigger>
                  <DataTrigger Binding="{Binding Status}" Value="Предупреждение"><Setter Property="Background" Value="#FCEFC7"/></DataTrigger>
                  <DataTrigger Binding="{Binding Status}" Value="Ошибка проверки"><Setter Property="Background" Value="#E3E3E3"/></DataTrigger>
                </Style.Triggers>
              </Style>
            </DataGrid.RowStyle>
            <DataGrid.Columns>
              <DataGridTextColumn Header="Компьютер" Binding="{Binding Computer}" Width="110"/>
              <DataGridTextColumn Header="Категория" Binding="{Binding Category}" Width="150"/>
              <DataGridTextColumn Header="Проверка" Binding="{Binding Name}" Width="230"/>
              <DataGridTextColumn Header="Требование" Binding="{Binding Expected}" Width="190"/>
              <DataGridTextColumn Header="Фактическое значение" Binding="{Binding Actual}" Width="230"/>
              <DataGridTextColumn Header="Результат" Binding="{Binding Status}" Width="130"/>
              <DataGridTextColumn Header="Критичность" Binding="{Binding Severity}" Width="90"/>
              <DataGridTextColumn Header="Рекомендация" Binding="{Binding Recommendation}" Width="*"/>
            </DataGrid.Columns>
          </DataGrid>
          <DockPanel Grid.Row="3" Margin="0,8,0,0">
            <StackPanel DockPanel.Dock="Right" Orientation="Horizontal">
              <Button x:Name="btnReport" Content="Сформировать отчёт" IsEnabled="False"/>
              <Button x:Name="btnExport" Content="Экспорт в CSV" IsEnabled="False"/>
            </StackPanel>
            <TextBlock x:Name="tbSummary" VerticalAlignment="Center" FontWeight="SemiBold"/>
          </DockPanel>
        </Grid>
      </TabItem>

      <!-- ===== Вкладка «История проверок» ===== -->
      <TabItem Header="  История проверок  ">
        <Grid Margin="8">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
          </Grid.RowDefinitions>
          <StackPanel Orientation="Horizontal" Margin="0,0,0,8">
            <Button x:Name="btnHistRefresh" Content="Обновить"/>
            <Button x:Name="btnHistShow" Content="Показать результаты"/>
            <Button x:Name="btnHistCompare" Content="Сравнить с предыдущей"/>
            <Button x:Name="btnHistReport" Content="Отчёт"/>
          </StackPanel>
          <DataGrid x:Name="dgHistory" Grid.Row="1" IsReadOnly="True" SelectionMode="Single">
            <DataGrid.Columns>
              <DataGridTextColumn Header="Дата и время" Binding="{Binding Date}" Width="140"/>
              <DataGridTextColumn Header="Компьютер" Binding="{Binding Computer}" Width="120"/>
              <DataGridTextColumn Header="Профиль" Binding="{Binding Profile}" Width="260"/>
              <DataGridTextColumn Header="Проверок" Binding="{Binding Total}" Width="80"/>
              <DataGridTextColumn Header="Соответствует" Binding="{Binding Pass}" Width="105"/>
              <DataGridTextColumn Header="Не соответствует" Binding="{Binding Fail}" Width="120"/>
              <DataGridTextColumn Header="Предупреждений" Binding="{Binding Warn}" Width="115"/>
              <DataGridTextColumn Header="Ошибок" Binding="{Binding Errors}" Width="70"/>
              <DataGridTextColumn Header="Индекс, %" Binding="{Binding Index}" Width="80"/>
              <DataGridTextColumn Header="Файл результатов" Binding="{Binding File}" Width="*"/>
            </DataGrid.Columns>
          </DataGrid>
          <TextBlock x:Name="tbDiff" Grid.Row="2" Margin="0,10,0,4" FontWeight="SemiBold" Text="Изменения относительно предыдущей проверки"/>
          <DataGrid x:Name="dgDiff" Grid.Row="3" IsReadOnly="True">
            <DataGrid.Columns>
              <DataGridTextColumn Header="Категория" Binding="{Binding Category}" Width="150"/>
              <DataGridTextColumn Header="Проверка" Binding="{Binding Name}" Width="260"/>
              <DataGridTextColumn Header="Было" Binding="{Binding Before}" Width="220"/>
              <DataGridTextColumn Header="Стало" Binding="{Binding After}" Width="220"/>
              <DataGridTextColumn Header="Характер изменения" Binding="{Binding Change}" Width="*"/>
            </DataGrid.Columns>
          </DataGrid>
        </Grid>
      </TabItem>

      <!-- ===== Вкладка «Эталон» ===== -->
      <TabItem Header="  Эталон  ">
        <Grid Margin="8">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>
          <TextBlock Text="Справочник средств защиты информации" FontWeight="SemiBold" Margin="0,0,0,4"/>
          <DataGrid x:Name="dgSzi" Grid.Row="1" CanUserAddRows="True" CanUserDeleteRows="True">
            <DataGrid.Columns>
              <DataGridTextColumn Header="Код" Binding="{Binding id}" Width="80"/>
              <DataGridTextColumn Header="Наименование СЗИ" Binding="{Binding name}" Width="260"/>
              <DataGridTextColumn Header="Шаблон имени ПО" Binding="{Binding productPattern}" Width="230"/>
              <DataGridTextColumn Header="Мин. версия" Binding="{Binding minVersion}" Width="85"/>
              <DataGridTextColumn Header="Шаблон службы" Binding="{Binding servicePattern}" Width="110"/>
              <DataGridTextColumn Header="Класс" Binding="{Binding sziClass}" Width="80"/>
              <DataGridTextColumn Header="№ сертификата" Binding="{Binding certNumber}" Width="110"/>
              <DataGridTextColumn Header="Действует до (ГГГГ-ММ-ДД)" Binding="{Binding certExpires}" Width="*"/>
            </DataGrid.Columns>
          </DataGrid>
          <TextBlock Grid.Row="2" Text="Учтённые съёмные машинные носители информации" FontWeight="SemiBold" Margin="0,10,0,4"/>
          <DataGrid x:Name="dgMedia" Grid.Row="3" CanUserAddRows="True" CanUserDeleteRows="True">
            <DataGrid.Columns>
              <DataGridTextColumn Header="Серийный номер" Binding="{Binding serial}" Width="220"/>
              <DataGridTextColumn Header="Ответственный" Binding="{Binding owner}" Width="260"/>
              <DataGridTextColumn Header="Примечание (учётный номер)" Binding="{Binding note}" Width="*"/>
            </DataGrid.Columns>
          </DataGrid>
          <StackPanel Grid.Row="4" Orientation="Horizontal" Margin="0,8,0,0">
            <Button x:Name="btnEtalonSave" Content="Сохранить эталон" FontWeight="SemiBold"/>
            <Button x:Name="btnEtalonReload" Content="Отменить изменения"/>
            <Button x:Name="btnAddUsb" Content="Добавить носители этого АРМ"/>
            <Button x:Name="btnEtalonOpen" Content="Открыть XML-файл"/>
          </StackPanel>
        </Grid>
      </TabItem>

      <!-- ===== Вкладка «Журнал работы» ===== -->
      <TabItem Header="  Журнал работы  ">
        <TextBox x:Name="tbLog" Margin="8" IsReadOnly="True" FontFamily="Consolas" FontSize="12"
                 VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto" TextWrapping="NoWrap"/>
      </TabItem>
    </TabControl>
  </DockPanel>
</Window>
'@

$Ui = @{}
if (-not $NoGui) {
    $Window = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $Xaml))
    $nsX = 'http://schemas.microsoft.com/winfx/2006/xaml'
    foreach ($node in $Xaml.SelectNodes('//*')) {
        $n = $node.GetAttribute('Name', $nsX)
        if ($n) { $Ui[$n] = $Window.FindName($n) }
    }
}

# ============================================================================
# Служебные функции
# ============================================================================
$ST_OK = 'Соответствует'; $ST_FAIL = 'Не соответствует'; $ST_WARN = 'Предупреждение'; $ST_ERR = 'Ошибка проверки'

function Write-Log([string]$Message, [string]$Level = 'INFO') {
    $line = '{0:dd.MM.yyyy HH:mm:ss} [{1}] {2}' -f (Get-Date), $Level, $Message
    $file = Join-Path $Paths.Logs ('SziAudit_{0:yyyyMMdd}.log' -f (Get-Date))
    Add-Content -Path $file -Value $line -Encoding UTF8
    if ($NoGui) {
        if ($Level -eq 'ERROR') { Write-Host $line -ForegroundColor Red } else { Write-Host $line }
        return
    }
    $Ui.tbLog.AppendText($line + "`r`n")
    $Ui.tbLog.ScrollToEnd()
    $Ui.sbText.Text = $Message
}

function Show-Message([string]$Text, [string]$Icon = 'Information') {
    if ($NoGui) { Write-Host $Text; return }
    [void][System.Windows.MessageBox]::Show($Text, $AppName, 'OK', $Icon)
}

# Выполнение обработчика с перехватом исключений
function Invoke-Safe([scriptblock]$Action) {
    try { & $Action }
    catch {
        Write-Log $_.Exception.Message 'ERROR'
        Show-Message $_.Exception.Message 'Error'
    }
}

# Сводные показатели и индекс соответствия (взвешенный по критичности)
function Get-AuditSummary($Items) {
    $Items = @($Items)
    $weights = @{ 'Высокая' = 3; 'Средняя' = 2; 'Низкая' = 1 }
    $sumW = 0.0; $sumS = 0.0
    foreach ($i in $Items) {
        $w = $weights[[string]$i.Severity]
        if (-not $w) { $w = 1 }
        $s = switch ([string]$i.Status) { 'Соответствует' { 1.0 } 'Предупреждение' { 0.5 } default { 0.0 } }
        $sumW += $w; $sumS += $w * $s
    }
    $idx = 0
    if ($sumW -gt 0) { $idx = [math]::Round(100 * $sumS / $sumW, 1) }
    [pscustomobject]@{
        Total  = $Items.Count
        Pass   = @($Items | Where-Object { $_.Status -eq $ST_OK }).Count
        Fail   = @($Items | Where-Object { $_.Status -eq $ST_FAIL }).Count
        Warn   = @($Items | Where-Object { $_.Status -eq $ST_WARN }).Count
        Errors = @($Items | Where-Object { $_.Status -eq $ST_ERR }).Count
        Index  = $idx
    }
}

# ============================================================================
# Работа с эталоном
# ============================================================================
function New-TableFromNodes([string]$TableName, [string[]]$Columns, $Nodes) {
    $t = New-Object System.Data.DataTable $TableName
    foreach ($c in $Columns) { [void]$t.Columns.Add($c) }
    foreach ($n in @($Nodes)) {
        if (-not ($n -is [System.Xml.XmlElement])) { continue }
        $r = $t.NewRow()
        foreach ($c in $Columns) { $r[$c] = $n.GetAttribute($c) }
        $t.Rows.Add($r)
    }
    $t.AcceptChanges()
    return , $t
}

function Import-Etalon {
    if (-not (Test-Path $Paths.Etalon)) { throw "Не найден эталонный файл: $($Paths.Etalon)" }
    $script:EtalonText = [IO.File]::ReadAllText($Paths.Etalon, [Text.Encoding]::UTF8)
    $x = New-Object System.Xml.XmlDocument
    $x.LoadXml($script:EtalonText)
    $script:Etalon = $x
    if ($NoGui) { Write-Log 'Эталонный файл конфигурации загружен'; return }

    $Ui.cbProfile.Items.Clear()
    foreach ($p in $x.SziEtalon.Profiles.Profile) {
        $item = New-Object System.Windows.Controls.ComboBoxItem
        $item.Content = $p.GetAttribute('name')
        $item.Tag = $p.GetAttribute('id')
        [void]$Ui.cbProfile.Items.Add($item)
    }
    if ($Ui.cbProfile.Items.Count -gt 0) { $Ui.cbProfile.SelectedIndex = 0 }

    $script:SziTable = New-TableFromNodes 'Szi' @('id', 'name', 'productPattern', 'minVersion', 'servicePattern',
        'sziClass', 'certNumber', 'certExpires') $x.SziEtalon.SziList.Szi
    $script:MediaTable = New-TableFromNodes 'Media' @('serial', 'owner', 'note') $x.SziEtalon.Media.Device
    $Ui.dgSzi.ItemsSource = $script:SziTable.DefaultView
    $Ui.dgMedia.ItemsSource = $script:MediaTable.DefaultView

    $Ui.sbEtalon.Text = 'Эталон от {0}: СЗИ – {1}, профилей – {2}, учтённых МНИ – {3}' -f `
        $x.SziEtalon.GetAttribute('updated'), $script:SziTable.Rows.Count, $Ui.cbProfile.Items.Count, $script:MediaTable.Rows.Count
    Write-Log 'Эталонный файл конфигурации загружен'
}

function Test-EtalonTables {
    $errors = @()
    $ids = @()
    foreach ($r in $script:SziTable.Rows) {
        if ($r.RowState -eq 'Deleted') { continue }
        $id = ([string]$r['id']).Trim()
        if (-not $id) { $errors += 'Не указан код СЗИ'; continue }
        if ($ids -contains $id) { $errors += "Повторяющийся код СЗИ: $id" }
        $ids += $id
        if (-not ([string]$r['productPattern']).Trim()) { $errors += "СЗИ ${id}: не задан шаблон имени ПО" }
        $d = ([string]$r['certExpires']).Trim()
        $tmp = [datetime]::MinValue
        if ($d -and -not [datetime]::TryParseExact($d, 'yyyy-MM-dd', $null, 'None', [ref]$tmp)) {
            $errors += "СЗИ ${id}: дата окончания сертификата должна быть в формате ГГГГ-ММ-ДД"
        }
    }
    foreach ($r in $script:MediaTable.Rows) {
        if ($r.RowState -eq 'Deleted') { continue }
        if (-not ([string]$r['serial']).Trim()) { $errors += 'Не указан серийный номер носителя' }
    }
    return $errors
}

function Save-Etalon {
    $Ui.dgSzi.CommitEdit(); $Ui.dgMedia.CommitEdit()
    $errors = @(Test-EtalonTables)
    if ($errors.Count -gt 0) { throw ("Эталон не сохранён:`n" + ($errors -join "`n")) }

    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    Copy-Item -Path $Paths.Etalon -Destination (Join-Path $Paths.Backup "Etalon_$stamp.xml")

    $x = $script:Etalon
    $root = $x.DocumentElement
    foreach ($spec in @(
            @{ Parent = 'SziList'; Child = 'Szi'; Table = $script:SziTable },
            @{ Parent = 'Media'; Child = 'Device'; Table = $script:MediaTable })) {
        $parent = $root.SelectSingleNode($spec.Parent)
        if (-not $parent) { $parent = $root.AppendChild($x.CreateElement($spec.Parent)) }
        $parent.RemoveAll()
        foreach ($r in $spec.Table.Rows) {
            if ($r.RowState -eq 'Deleted') { continue }
            $el = $x.CreateElement($spec.Child)
            foreach ($c in $spec.Table.Columns) { $el.SetAttribute($c.ColumnName, ([string]$r[$c.ColumnName]).Trim()) }
            [void]$parent.AppendChild($el)
        }
    }
    $root.SetAttribute('updated', (Get-Date -Format 'yyyy-MM-dd'))

    $ws = New-Object System.Xml.XmlWriterSettings
    $ws.Indent = $true
    $ws.Encoding = New-Object System.Text.UTF8Encoding($false)
    $w = [System.Xml.XmlWriter]::Create($Paths.Etalon, $ws)
    try { $x.Save($w) } finally { $w.Close() }
    Write-Log "Эталон сохранён, предыдущая версия: Etalon_$stamp.xml"
    Import-Etalon
}

function Add-LocalUsbToEtalon {
    $base = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR'
    if (-not (Test-Path $base)) { Show-Message 'На данном АРМ подключения USB-накопителей не зарегистрированы'; return }
    $known = @($script:MediaTable.Rows | Where-Object { $_.RowState -ne 'Deleted' } | ForEach-Object { ([string]$_['serial']).ToUpper() })
    $added = 0
    foreach ($m in Get-ChildItem -Path $base) {
        foreach ($d in Get-ChildItem -Path $m.PSPath) {
            $serial = $d.PSChildName -replace '&\d+$', ''
            if ($known -contains $serial.ToUpper()) { continue }
            $fn = (Get-ItemProperty -Path $d.PSPath -ErrorAction SilentlyContinue).FriendlyName
            $r = $script:MediaTable.NewRow()
            $r['serial'] = $serial; $r['owner'] = ''
            $r['note'] = "Добавлен {0:dd.MM.yyyy}: {1}" -f (Get-Date), $fn
            $script:MediaTable.Rows.Add($r)
            $known += $serial.ToUpper(); $added++
        }
    }
    Write-Log "Добавлено носителей в таблицу эталона: $added"
    Show-Message "Добавлено носителей: $added.`nЗаполните графу «Ответственный» и сохраните эталон."
}

# ============================================================================
# Выполнение аудита
# ============================================================================
$script:Jobs = @()
$script:AllResults = New-Object System.Collections.Generic.List[object]
$script:LastRuns = @{}

# Запуск задания проверок: локальный АРМ – фоновое задание, удалённый – через WinRM
function New-AuditJob([string]$Computer, [string]$ProfileName) {
    if ($Computer -in @('localhost', '.', '127.0.0.1', $env:COMPUTERNAME)) {
        return Start-Job -Name "SziAudit_$Computer" -FilePath $Paths.Checks -ArgumentList $script:EtalonText, $ProfileName
    }
    return Invoke-Command -ComputerName $Computer -FilePath $Paths.Checks -ArgumentList $script:EtalonText, $ProfileName `
        -AsJob -JobName "SziAudit_$Computer"
}

function Start-Audit {
    $item = $Ui.cbProfile.SelectedItem
    if (-not $item) { throw 'Не выбран профиль АРМ' }
    $profileId = [string]$item.Tag
    $computers = @($Ui.tbComputers.Text -split '[,;\s]+' | Where-Object { $_ } | Select-Object -Unique)
    if ($computers.Count -eq 0) { $computers = @('localhost') }

    $script:AllResults.Clear()
    $script:LastRuns = @{}
    $script:Jobs = @()
    foreach ($c in $computers) {
        $script:Jobs += [pscustomobject]@{ Computer = $c; Job = (New-AuditJob $c $profileId); Done = $false }
        Write-Log "Запущен аудит АРМ $c (профиль: $($item.Content))"
    }
    $Ui.pbProgress.Maximum = $script:Jobs.Count
    $Ui.pbProgress.Value = 0
    $Ui.btnStart.IsEnabled = $false
    $Ui.btnReport.IsEnabled = $false
    $Ui.btnExport.IsEnabled = $false
    $Ui.dgResults.ItemsSource = $null
    $Timer.Start()
}

function Complete-AuditJob($Task) {
    $jerr = $null
    $out = @(Receive-Job -Job $Task.Job -ErrorAction SilentlyContinue -ErrorVariable jerr)
    Remove-Job -Job $Task.Job -Force
    $run = $out | Where-Object { $_ -and $_.PSObject.Properties['Results'] } | Select-Object -Last 1
    if (-not $run) {
        $msg = 'Результат не получен'
        if ($jerr) { $msg = ($jerr | Select-Object -First 1).ToString() }
        Write-Log "АРМ $($Task.Computer): ошибка выполнения аудита – $msg" 'ERROR'
        $script:AllResults.Add([pscustomobject]@{
            Computer = $Task.Computer; CheckId = 'CONNECT'; Category = 'Выполнение аудита'
            Name = 'Подключение к АРМ'; Expected = 'Аудит выполнен'; Actual = $msg; Status = $ST_ERR
            Severity = 'Высокая'; Recommendation = 'Проверить доступность АРМ и службы WinRM, права учётной записи'
            Time = Get-Date })
        return
    }
    $items = @($run.Results)
    foreach ($i in $items) { $script:AllResults.Add($i) }
    $sum = Get-AuditSummary $items

    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $file = Join-Path $Paths.Results ('{0}_{1}.xml' -f $run.Computer, $stamp)
    $run | Export-Clixml -Path $file -Depth 4
    [pscustomobject]@{
        Date = (Get-Date -Format 'dd.MM.yyyy HH:mm:ss'); Computer = $run.Computer; Profile = $run.Profile
        Total = $sum.Total; Pass = $sum.Pass; Fail = $sum.Fail; Warn = $sum.Warn; Errors = $sum.Errors
        Index = $sum.Index; File = (Split-Path $file -Leaf)
    } | Export-Csv -Path $Paths.History -Append -NoTypeInformation -Encoding UTF8 -Delimiter ';'
    $script:LastRuns[[string]$run.Computer] = $run
    Write-Log ('АРМ {0}: проверок {1}, несоответствий {2}, предупреждений {3}, индекс соответствия {4}%' -f `
            $run.Computer, $sum.Total, $sum.Fail, $sum.Warn, $sum.Index)
}

function Update-ResultView {
    $all = @($script:AllResults)
    switch ($Ui.cbFilter.SelectedIndex) {
        1 { $view = @($all | Where-Object { $_.Status -in $ST_FAIL, $ST_ERR }) }
        2 { $view = @($all | Where-Object { $_.Status -ne $ST_OK }) }
        default { $view = $all }
    }
    $Ui.dgResults.ItemsSource = $view
    if ($all.Count -gt 0) {
        $s = Get-AuditSummary $all
        $Ui.tbSummary.Text = 'Проверок: {0}    Соответствует: {1}    Не соответствует: {2}    Предупреждений: {3}    Ошибок: {4}    Индекс соответствия: {5}%' -f `
            $s.Total, $s.Pass, $s.Fail, $s.Warn, $s.Errors, $s.Index
    }
}

if (-not $NoGui) {
    $Timer = New-Object System.Windows.Threading.DispatcherTimer
    $Timer.Interval = [TimeSpan]::FromMilliseconds(700)
    $Timer.Add_Tick({
        Invoke-Safe {
            foreach ($t in $script:Jobs) {
                if ($t.Done) { continue }
                if ($t.Job.State -in 'Completed', 'Failed', 'Stopped') {
                    $t.Done = $true
                    Complete-AuditJob $t
                }
            }
            $done = @($script:Jobs | Where-Object { $_.Done }).Count
            $Ui.pbProgress.Value = $done
            $Ui.tbProgress.Text = "Обработано АРМ: $done из $($script:Jobs.Count)"
            if ($done -ge $script:Jobs.Count) {
                $Timer.Stop()
                $Ui.btnStart.IsEnabled = $true
                $Ui.btnReport.IsEnabled = ($script:LastRuns.Count -gt 0)
                $Ui.btnExport.IsEnabled = ($script:AllResults.Count -gt 0)
                Update-ResultView
                Import-History
                Write-Log 'Аудит завершён'
            }
        }
    })
}

# ============================================================================
# Отчёты и экспорт
# ============================================================================
function Get-HtmlText([object]$Text) { [System.Net.WebUtility]::HtmlEncode([string]$Text) }

function New-HtmlReport([object[]]$Runs) {
    $css = @'
body{font-family:"Times New Roman",serif;font-size:13pt;margin:24px 40px;color:#000}
h1{font-size:16pt;text-align:center;margin-bottom:4px} h2{font-size:14pt;margin-top:28px;border-bottom:1px solid #444}
table{border-collapse:collapse;width:100%;margin-top:8px;font-size:11pt} th,td{border:1px solid #777;padding:3px 6px;vertical-align:top}
th{background:#E6EAF0} .ok{background:#E3F4E1} .fail{background:#F9D6D5} .warn{background:#FCEFC7} .err{background:#E3E3E3}
.info td:first-child{width:220px;font-weight:bold} .sign{margin-top:40px}
'@
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<!DOCTYPE html><html lang="ru"><head><meta charset="utf-8">')
    [void]$sb.AppendLine("<title>Отчёт о результатах аудита СЗИ</title><style>$css</style></head><body>")
    [void]$sb.AppendLine('<h1>ОТЧЁТ<br>о результатах аудита средств защиты информации</h1>')
    [void]$sb.AppendLine(('<p style="text-align:center">{0}<br>Дата формирования: {1:dd.MM.yyyy HH:mm}. Эталон от {2}</p>' -f `
        (Get-HtmlText $script:Etalon.SziEtalon.GetAttribute('organization')), (Get-Date), $script:Etalon.SziEtalon.GetAttribute('updated')))

    foreach ($r in $Runs) {
        $items = @($r.Results)
        $s = Get-AuditSummary $items
        [void]$sb.AppendLine("<h2>АРМ $(Get-HtmlText $r.Computer)</h2><table class=""info"">")
        $rows = [ordered]@{
            'Профиль (тип АРМ)' = $r.Profile; 'Операционная система' = $r.OS; 'Домен' = $r.Domain
            'IP-адреса' = $r.IP; 'Дата и время аудита' = ('{0:dd.MM.yyyy HH:mm}' -f $r.Date)
            'Аудит выполнил' = $r.User
            'Итоги' = ('проверок – {0}; соответствует – {1}; не соответствует – {2}; предупреждений – {3}; ошибок – {4}' -f `
                    $s.Total, $s.Pass, $s.Fail, $s.Warn, $s.Errors)
            'Индекс соответствия' = "$($s.Index) %"
        }
        foreach ($k in $rows.Keys) { [void]$sb.AppendLine("<tr><td>$k</td><td>$(Get-HtmlText $rows[$k])</td></tr>") }
        [void]$sb.AppendLine('</table><table><tr><th>№</th><th>Категория</th><th>Проверка</th><th>Требование</th><th>Фактическое значение</th><th>Результат</th><th>Рекомендация</th></tr>')
        $n = 0
        foreach ($i in $items) {
            $n++
            $cls = switch ([string]$i.Status) { 'Соответствует' { 'ok' } 'Не соответствует' { 'fail' } 'Предупреждение' { 'warn' } default { 'err' } }
            [void]$sb.AppendLine(("<tr class=""{0}""><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td><td>{6}</td><td>{7}</td></tr>" -f `
                $cls, $n, (Get-HtmlText $i.Category), (Get-HtmlText $i.Name), (Get-HtmlText $i.Expected),
                (Get-HtmlText $i.Actual), (Get-HtmlText $i.Status), (Get-HtmlText $i.Recommendation)))
        }
        [void]$sb.AppendLine('</table>')
    }
    [void]$sb.AppendLine('<p class="sign">Администратор безопасности ______________________ / ______________________ /</p>')
    [void]$sb.AppendLine("<p style=""font-size:10pt;color:#555"">Сформировано ПО «$AppName» версии $AppVersion</p></body></html>")

    $file = Join-Path $Paths.Reports ('Report_{0:yyyyMMdd_HHmmss}.html' -f (Get-Date))
    [IO.File]::WriteAllText($file, $sb.ToString(), (New-Object System.Text.UTF8Encoding($true)))
    Write-Log "Сформирован отчёт: $(Split-Path $file -Leaf)"
    if (-not $NoGui -or $OpenReport) { Start-Process -FilePath $file }
    return $file
}

function Export-ResultsCsv {
    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $dlg.Filter = 'CSV (разделитель «;»)|*.csv'
    $dlg.FileName = 'SziAudit_{0:yyyyMMdd_HHmm}.csv' -f (Get-Date)
    if (-not $dlg.ShowDialog()) { return }
    $script:AllResults | Select-Object @{ n = 'Компьютер'; e = { $_.Computer } }, @{ n = 'Категория'; e = { $_.Category } },
        @{ n = 'Проверка'; e = { $_.Name } }, @{ n = 'Требование'; e = { $_.Expected } },
        @{ n = 'Фактическое значение'; e = { $_.Actual } }, @{ n = 'Результат'; e = { $_.Status } },
        @{ n = 'Критичность'; e = { $_.Severity } }, @{ n = 'Рекомендация'; e = { $_.Recommendation } } |
        Export-Csv -Path $dlg.FileName -NoTypeInformation -Encoding UTF8 -Delimiter ';'
    Write-Log "Результаты выгружены в файл $($dlg.FileName)"
}

# ============================================================================
# История и сравнение результатов
# ============================================================================
function Import-History {
    if (-not (Test-Path $Paths.History)) { $Ui.dgHistory.ItemsSource = $null; return }
    $rows = @(Import-Csv -Path $Paths.History -Delimiter ';' -Encoding UTF8)
    [array]::Reverse($rows)
    $script:HistoryRows = $rows
    $Ui.dgHistory.ItemsSource = $rows
}

function Get-SelectedRun {
    $row = $Ui.dgHistory.SelectedItem
    if (-not $row) { throw 'Выберите запись в таблице истории' }
    $file = Join-Path $Paths.Results $row.File
    if (-not (Test-Path $file)) { throw "Файл результатов не найден: $($row.File)" }
    return [pscustomobject]@{ Row = $row; Run = (Import-Clixml -Path $file) }
}

function Compare-AuditRuns($Old, $New) {
    $o = @{}; foreach ($i in @($Old.Results)) { $o[[string]$i.CheckId] = $i }
    $n = @{}; foreach ($i in @($New.Results)) { $n[[string]$i.CheckId] = $i }
    $keys = @($o.Keys) + @($n.Keys) | Sort-Object -Unique
    foreach ($k in $keys) {
        $a = $o[$k]; $b = $n[$k]
        if ($a -and $b -and $a.Status -eq $b.Status -and $a.Actual -eq $b.Actual) { continue }
        if (-not $a) { $change = 'Новая проверка' }
        elseif (-not $b) { $change = 'Проверка не выполнялась' }
        elseif ($a.Status -ne $ST_OK -and $b.Status -eq $ST_OK) { $change = 'Улучшение: несоответствие устранено' }
        elseif ($a.Status -eq $ST_OK -and $b.Status -ne $ST_OK) { $change = 'Ухудшение: выявлено несоответствие' }
        else { $change = 'Изменилось фактическое значение' }
        $ref = if ($b) { $b } else { $a }
        [pscustomobject]@{
            Category = $ref.Category; Name = $ref.Name; Change = $change
            Before = $(if ($a) { "$($a.Status): $($a.Actual)" } else { '—' })
            After  = $(if ($b) { "$($b.Status): $($b.Actual)" } else { '—' })
        }
    }
}

function Show-RunComparison {
    $sel = Get-SelectedRun
    $prev = $script:HistoryRows | Where-Object {
        $_.Computer -eq $sel.Row.Computer -and $_.File -lt $sel.Row.File } | Select-Object -First 1
    if (-not $prev) { throw "Для АРМ $($sel.Row.Computer) нет более ранних проверок" }
    $old = Import-Clixml -Path (Join-Path $Paths.Results $prev.File)
    $diff = @(Compare-AuditRuns $old $sel.Run)
    $Ui.dgDiff.ItemsSource = $diff
    $Ui.tbDiff.Text = "Изменения на АРМ $($sel.Row.Computer): $($prev.Date) → $($sel.Row.Date). Найдено изменений: $($diff.Count)"
    Write-Log $Ui.tbDiff.Text
}

# ============================================================================
# Получение перечня компьютеров из Active Directory (без модуля RSAT, через LDAP)
# ============================================================================
function Get-DomainComputers([string]$Base) {
    $ds = New-Object System.DirectoryServices.DirectorySearcher
    if ($Base) { $ds.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Base") }
    # только включённые учётные записи компьютеров (бит ACCOUNTDISABLE не установлен)
    $ds.Filter = '(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
    $ds.PageSize = 1000
    foreach ($a in 'name', 'dnshostname', 'operatingsystem', 'lastlogontimestamp', 'distinguishedname') {
        [void]$ds.PropertiesToLoad.Add($a)
    }
    try { $found = $ds.FindAll() }
    catch { throw "Не удалось получить список компьютеров из домена: $($_.Exception.Message)" }
    try {
        foreach ($r in $found) {
            $pr = $r.Properties
            $name = [string]($pr['name'] | Select-Object -First 1)
            $dns = [string]($pr['dnshostname'] | Select-Object -First 1)
            $dn = [string]($pr['distinguishedname'] | Select-Object -First 1)
            $llt = $pr['lastlogontimestamp'] | Select-Object -First 1
            $ou = (($dn -split '(?<!\\),' | Select-Object -Skip 1 | Where-Object { $_ -like 'OU=*' }) |
                ForEach-Object { $_.Substring(3) }) -join ' / '
            [pscustomobject]@{
                Name      = $name
                Host      = $(if ($dns) { $dns } else { $name })
                OS        = [string]($pr['operatingsystem'] | Select-Object -First 1)
                OU        = $(if ($ou) { $ou } else { '(контейнер Computers)' })
                LastLogon = $(if ($llt) { [datetime]::FromFileTime([int64]$llt).ToString('dd.MM.yyyy') } else { '' })
            }
        }
    }
    finally { $found.Dispose() }
}

function Show-DomainPicker {
    $base = [string]$script:Etalon.SziEtalon.SelectSingleNode('Settings/DomainSearchBase').InnerText
    $comps = @(Get-DomainComputers $base | Sort-Object OU, Name)
    if ($comps.Count -eq 0) { throw 'В домене не найдено активных учётных записей компьютеров' }
    $t = New-Object System.Data.DataTable 'Domain'
    [void]$t.Columns.Add('Sel', [bool])
    foreach ($c in 'Name', 'Host', 'OS', 'OU', 'LastLogon') { [void]$t.Columns.Add($c) }
    foreach ($c in $comps) {
        $r = $t.NewRow(); $r['Sel'] = $false
        foreach ($k in 'Name', 'Host', 'OS', 'OU', 'LastLogon') { $r[$k] = $c.$k }
        $t.Rows.Add($r)
    }
    [xml]$px = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Выбор компьютеров из домена" Width="900" Height="560" WindowStartupLocation="CenterOwner"
        FontFamily="Segoe UI" FontSize="13">
  <DockPanel Margin="10">
    <DockPanel DockPanel.Dock="Top" Margin="0,0,0,8">
      <TextBlock Text="Фильтр (имя, ОС или подразделение):" VerticalAlignment="Center" Margin="0,0,8,0"/>
      <TextBox x:Name="tbFilter" Height="26" VerticalContentAlignment="Center"/>
    </DockPanel>
    <DockPanel DockPanel.Dock="Bottom" Margin="0,8,0,0">
      <StackPanel DockPanel.Dock="Right" Orientation="Horizontal">
        <Button x:Name="btnOk" Content="Добавить выбранные" Padding="12,4" Margin="4,0" IsDefault="True"/>
        <Button x:Name="btnCancel" Content="Отмена" Padding="12,4" Margin="4,0" IsCancel="True"/>
      </StackPanel>
      <StackPanel Orientation="Horizontal">
        <Button x:Name="btnAll" Content="Отметить видимые" Padding="12,4" Margin="0,0,4,0"/>
        <Button x:Name="btnNone" Content="Снять отметки" Padding="12,4" Margin="4,0"/>
        <TextBlock x:Name="tbCount" VerticalAlignment="Center" Margin="12,0"/>
      </StackPanel>
    </DockPanel>
    <DataGrid x:Name="dgComp" AutoGenerateColumns="False" CanUserAddRows="False" CanUserDeleteRows="False"
              HeadersVisibility="Column" GridLinesVisibility="Horizontal" HorizontalGridLinesBrush="#E1E5EB">
      <DataGrid.Columns>
        <DataGridCheckBoxColumn Header="✓" Binding="{Binding Sel, UpdateSourceTrigger=PropertyChanged}" Width="40"/>
        <DataGridTextColumn Header="Компьютер" Binding="{Binding Name}" Width="130" IsReadOnly="True"/>
        <DataGridTextColumn Header="Операционная система" Binding="{Binding OS}" Width="230" IsReadOnly="True"/>
        <DataGridTextColumn Header="Подразделение (OU)" Binding="{Binding OU}" Width="*" IsReadOnly="True"/>
        <DataGridTextColumn Header="Последний вход" Binding="{Binding LastLogon}" Width="110" IsReadOnly="True"/>
      </DataGrid.Columns>
    </DataGrid>
  </DockPanel>
</Window>
'@
    $w = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $px))
    $w.Owner = $Window
    $dg = $w.FindName('dgComp'); $tbF = $w.FindName('tbFilter'); $tbC = $w.FindName('tbCount')
    $view = $t.DefaultView
    $dg.ItemsSource = $view
    $updateCount = {
        $tbC.Text = 'Показано: {0} из {1}, отмечено: {2}' -f $view.Count, $t.Rows.Count, @($t.Select('Sel = true')).Count
    }
    & $updateCount
    $tbF.Add_TextChanged({
        $f = $tbF.Text.Replace("'", "''").Replace('[', '[[]').Replace('*', '[*]').Replace('%', '[%]')
        $view.RowFilter = if ($f) { "Name LIKE '%$f%' OR OS LIKE '%$f%' OR OU LIKE '%$f%'" } else { '' }
        & $updateCount
    })
    $t.Add_ColumnChanged({ & $updateCount })
    $w.FindName('btnAll').Add_Click({ foreach ($rv in $view) { $rv.Row['Sel'] = $true }; & $updateCount })
    $w.FindName('btnNone').Add_Click({ foreach ($r in $t.Rows) { $r['Sel'] = $false }; & $updateCount })
    $w.FindName('btnOk').Add_Click({ $w.DialogResult = $true })
    if ($w.ShowDialog()) {
        $dg.CommitEdit()
        $sel = @($t.Select('Sel = true') | ForEach-Object { [string]$_['Host'] })
        if ($sel.Count -gt 0) {
            $Ui.tbComputers.Text = ($sel -join ', ')
            Write-Log "Из домена выбрано компьютеров: $($sel.Count)"
        }
    }
}

# ============================================================================
# Консольный режим (Планировщик заданий)
# ============================================================================
function Invoke-ConsoleAudit {
    Import-Etalon
    $ids = @($script:Etalon.SziEtalon.Profiles.Profile | ForEach-Object { $_.GetAttribute('id') })
    if (-not $ProfileId -or $ids -notcontains $ProfileId) {
        throw ('Укажите профиль параметром -ProfileId. Доступные профили: ' + ($ids -join ', '))
    }
    $list = @($Computers)
    if ($FromDomain) {
        $base = $SearchBase
        if (-not $base) { $base = [string]$script:Etalon.SziEtalon.SelectSingleNode('Settings/DomainSearchBase').InnerText }
        $list = @(Get-DomainComputers $base | ForEach-Object { $_.Host })
        Write-Log "Из домена получено компьютеров: $($list.Count)"
    }
    elseif ($ComputersFile) {
        $list = @(Get-Content -Path $ComputersFile | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -notlike '#*' })
    }
    $list = @($list | ForEach-Object { $_ -split '[,;\s]+' } | Where-Object { $_ } | Select-Object -Unique)
    if ($list.Count -eq 0) { $list = @('localhost') }

    $tasks = @(foreach ($c in $list) {
        Write-Log "Запущен аудит АРМ $c (профиль: $ProfileId)"
        [pscustomobject]@{ Computer = $c; Job = (New-AuditJob $c $ProfileId); Done = $false }
    })
    [void](Wait-Job -Job @($tasks | ForEach-Object { $_.Job }) -Timeout 3600)
    foreach ($t in $tasks) {
        if ($t.Job.State -eq 'Running') { Stop-Job -Job $t.Job }
        Complete-AuditJob $t
    }
    if ($script:LastRuns.Count -gt 0) { [void](New-HtmlReport @($script:LastRuns.Values)) }

    $s = Get-AuditSummary $script:AllResults
    Write-Log ('Итого: АРМ – {0}, проверок – {1}, несоответствий – {2}, предупреждений – {3}, ошибок – {4}, индекс соответствия – {5}%' -f `
        $list.Count, $s.Total, $s.Fail, $s.Warn, $s.Errors, $s.Index)
    foreach ($r in @($script:AllResults | Where-Object { $_.Status -in $ST_FAIL, $ST_ERR })) {
        Write-Host ('  [{0}] {1}: {2} – {3}' -f $r.Computer, $r.Status, $r.Name, $r.Actual) -ForegroundColor Yellow
    }
    if ($s.Errors -gt 0) { return 2 }
    if ($s.Fail -gt 0) { return 1 }
    return 0
}

if ($NoGui) {
    $code = 3
    try { $code = Invoke-ConsoleAudit }
    catch { Write-Log $_.Exception.Message 'ERROR' }
    exit $code
}

# ============================================================================
# Обработчики событий
# ============================================================================
$Ui.btnStart.Add_Click({ Invoke-Safe { Start-Audit } })
$Ui.cbFilter.Add_SelectionChanged({ Invoke-Safe { Update-ResultView } })
$Ui.btnReport.Add_Click({ Invoke-Safe { New-HtmlReport @($script:LastRuns.Values) } })
$Ui.btnExport.Add_Click({ Invoke-Safe { Export-ResultsCsv } })
$Ui.btnDomain.Add_Click({ Invoke-Safe { Show-DomainPicker } })
$Ui.btnLoadList.Add_Click({
    Invoke-Safe {
        $dlg = New-Object Microsoft.Win32.OpenFileDialog
        $dlg.Filter = 'Текстовые файлы|*.txt|Все файлы|*.*'
        if ($dlg.ShowDialog()) {
            $names = Get-Content -Path $dlg.FileName | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -notlike '#*' }
            $Ui.tbComputers.Text = ($names -join ', ')
        }
    }
})
$Ui.btnHistRefresh.Add_Click({ Invoke-Safe { Import-History } })
$Ui.btnHistShow.Add_Click({
    Invoke-Safe {
        $sel = Get-SelectedRun
        $script:AllResults.Clear()
        foreach ($i in @($sel.Run.Results)) { $script:AllResults.Add($i) }
        $script:LastRuns = @{ ([string]$sel.Run.Computer) = $sel.Run }
        $Ui.btnReport.IsEnabled = $true; $Ui.btnExport.IsEnabled = $true
        Update-ResultView
        $Ui.tbProgress.Text = "Результаты от $($sel.Row.Date)"
        [void]$Ui.dgResults.Focus()
    }
})
$Ui.btnHistCompare.Add_Click({ Invoke-Safe { Show-RunComparison } })
$Ui.btnHistReport.Add_Click({ Invoke-Safe { $sel = Get-SelectedRun; New-HtmlReport @($sel.Run) } })
$Ui.btnEtalonSave.Add_Click({ Invoke-Safe { Save-Etalon; Show-Message 'Эталон сохранён' } })
$Ui.btnEtalonReload.Add_Click({ Invoke-Safe { Import-Etalon } })
$Ui.btnAddUsb.Add_Click({ Invoke-Safe { Add-LocalUsbToEtalon } })
$Ui.btnEtalonOpen.Add_Click({ Invoke-Safe { Start-Process -FilePath 'notepad.exe' -ArgumentList "`"$($Paths.Etalon)`"" } })
$Window.Add_Closing({
    $Timer.Stop()
    foreach ($t in $script:Jobs) { if (-not $t.Done) { Remove-Job -Job $t.Job -Force -ErrorAction SilentlyContinue } }
    Write-Log 'Работа программы завершена'
})

# ============================================================================
# Запуск
# ============================================================================
Write-Log "Запуск $AppName $AppVersion, пользователь $env:USERDOMAIN\$env:USERNAME"
Invoke-Safe { Import-Etalon }
Invoke-Safe { Import-History }
[void]$Window.ShowDialog()
