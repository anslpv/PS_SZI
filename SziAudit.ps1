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
                       ToolTip="Имена или IP-адреса АРМ через запятую. localhost — данный компьютер. Другой профиль для АРМ: ИМЯ=КОД_ПРОФИЛЯ (например, ARM-02=ARM_SPN)"/>
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
              <Button x:Name="btnAllowSoft" Content="Разрешить ПО…" IsEnabled="False"
                      ToolTip="Внести ПО, не указанное в предписании, в разрешённое для профиля проверенного АРМ"/>
              <Button x:Name="btnSchedule" Content="Ежедневный аудит…" ToolTip="Задание Планировщика заданий Windows"/>
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
              <DataGridTextColumn Header="Действует до (ГГГГ-ММ-ДД)" Binding="{Binding certExpires}" Width="150"/>
              <DataGridTextColumn Header="Обязательно для профилей (коды через запятую)" Binding="{Binding profiles}" Width="*"/>
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
            <Button x:Name="btnMediaImport" Content="Импорт МНИ из файла…"/>
            <Button x:Name="btnMediaExport" Content="Выгрузить МНИ в CSV…"/>
            <Button x:Name="btnEtalonOpen" Content="Открыть XML-файл"/>
          </StackPanel>
        </Grid>
      </TabItem>

      <!-- ===== Вкладка «Профили АРМ» ===== -->
      <TabItem Header="  Профили АРМ  ">
        <Grid Margin="8">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>
          <StackPanel Orientation="Horizontal" Margin="0,0,0,8">
            <TextBlock Text="Профиль АРМ:" VerticalAlignment="Center" Margin="0,0,8,0" FontWeight="SemiBold"/>
            <ComboBox x:Name="cbEditProfile" Width="420" Height="26"/>
            <TextBlock Text="Наименование:" VerticalAlignment="Center" Margin="16,0,8,0"/>
            <TextBox x:Name="tbProfileName" Width="300" Height="26" VerticalContentAlignment="Center"/>
            <Button x:Name="btnProfileNew" Content="Создать…" MinWidth="90" Margin="16,0,4,0"/>
            <Button x:Name="btnProfileCopy" Content="Копировать…" MinWidth="90"/>
            <Button x:Name="btnProfileDelete" Content="Удалить" MinWidth="90"/>
          </StackPanel>
          <Grid Grid.Row="1">
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="400"/>
              <ColumnDefinition Width="*"/>
            </Grid.ColumnDefinitions>
            <DockPanel Margin="0,0,8,0">
              <TextBlock DockPanel.Dock="Top" Text="Параметры безопасности профиля" FontWeight="SemiBold" Margin="0,0,0,4"/>
              <DataGrid x:Name="dgProfileParams">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="Параметр" Binding="{Binding Title}" Width="*" IsReadOnly="True"/>
                  <DataGridTextColumn Header="Значение" Binding="{Binding Value}" Width="110"/>
                </DataGrid.Columns>
              </DataGrid>
            </DockPanel>
            <TabControl Grid.Column="1">
            <TabItem Header="Разрешённое ПО">
            <Grid Margin="6">
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="*"/>
              <ColumnDefinition Width="*"/>
            </Grid.ColumnDefinitions>
            <DockPanel Grid.Column="0" Margin="0,0,8,0">
              <TextBlock DockPanel.Dock="Top" Text="Разрешённое ПО этого профиля" FontWeight="SemiBold" Margin="0,0,0,4"/>
              <StackPanel DockPanel.Dock="Bottom" Orientation="Horizontal" Margin="0,6,0,0">
                <Button x:Name="btnSoftPickProfile" Content="Выбрать из установленного…" Margin="0,0,4,0"/>
                <Button x:Name="btnSoftDelProfile" Content="Удалить выбранные"/>
              </StackPanel>
              <DataGrid x:Name="dgProfileSoft" CanUserAddRows="True" CanUserDeleteRows="True" SelectionMode="Extended">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="Шаблон имени ПО (* – любые символы, | – варианты)" Binding="{Binding Pattern}" Width="*"/>
                </DataGrid.Columns>
              </DataGrid>
            </DockPanel>
            <DockPanel Grid.Column="1">
              <TextBlock DockPanel.Dock="Top" Text="Общее разрешённое ПО (все профили)" FontWeight="SemiBold" Margin="0,0,0,4"/>
              <StackPanel DockPanel.Dock="Bottom" Orientation="Horizontal" Margin="0,6,0,0">
                <Button x:Name="btnSoftPickCommon" Content="Выбрать из установленного…" Margin="0,0,4,0"/>
                <Button x:Name="btnSoftDelCommon" Content="Удалить выбранные"/>
              </StackPanel>
              <DataGrid x:Name="dgCommonSoft" CanUserAddRows="True" CanUserDeleteRows="True" SelectionMode="Extended">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="Шаблон имени ПО" Binding="{Binding Pattern}" Width="*"/>
                </DataGrid.Columns>
              </DataGrid>
            </DockPanel>
            </Grid>
            </TabItem>
            <TabItem Header="Учётные записи">
              <Grid Margin="6">
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="*"/>
                  <ColumnDefinition Width="*"/>
                  <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>
                <DockPanel Margin="0,0,8,0">
                  <TextBlock DockPanel.Dock="Top" Text="Допущенные к работе (приказ о допуске)" FontWeight="SemiBold"/>
                  <TextBlock DockPanel.Dock="Top" Text="Пусто – сверка не выполняется" Foreground="#555" Margin="0,0,0,4"/>
                  <Button x:Name="btnUsersPick" DockPanel.Dock="Bottom" Content="Добавить учётные записи АРМ…" Margin="0,6,0,0" HorizontalAlignment="Left"/>
                  <DataGrid x:Name="dgAllowedUsers" CanUserAddRows="True" CanUserDeleteRows="True" SelectionMode="Extended">
                    <DataGrid.Columns>
                      <DataGridTextColumn Header="Имя учётной записи (допускается *)" Binding="{Binding Pattern}" Width="*"/>
                    </DataGrid.Columns>
                  </DataGrid>
                </DockPanel>
                <DockPanel Grid.Column="1" Margin="0,0,8,0">
                  <TextBlock DockPanel.Dock="Top" Text="Допустимые члены группы «Администраторы»" FontWeight="SemiBold"/>
                  <TextBlock DockPanel.Dock="Top" Text="Формат: ДОМЕН\имя или *\имя" Foreground="#555" Margin="0,0,0,4"/>
                  <DataGrid x:Name="dgAllowedAdmins" CanUserAddRows="True" CanUserDeleteRows="True" SelectionMode="Extended">
                    <DataGrid.Columns>
                      <DataGridTextColumn Header="Учётная запись или группа" Binding="{Binding Pattern}" Width="*"/>
                    </DataGrid.Columns>
                  </DataGrid>
                </DockPanel>
                <DockPanel Grid.Column="2">
                  <TextBlock DockPanel.Dock="Top" Text="Допускается бессрочный пароль" FontWeight="SemiBold"/>
                  <TextBlock DockPanel.Dock="Top" Text="Например, служебные учётные записи" Foreground="#555" Margin="0,0,0,4"/>
                  <DataGrid x:Name="dgPwdNever" CanUserAddRows="True" CanUserDeleteRows="True" SelectionMode="Extended">
                    <DataGrid.Columns>
                      <DataGridTextColumn Header="Имя учётной записи (допускается *)" Binding="{Binding Pattern}" Width="*"/>
                    </DataGrid.Columns>
                  </DataGrid>
                </DockPanel>
              </Grid>
            </TabItem>
            <TabItem Header="Политика аудита">
              <DockPanel Margin="6">
                <StackPanel DockPanel.Dock="Bottom" Orientation="Horizontal" Margin="0,6,0,0">
                  <TextBlock Text="Подкатегория:" VerticalAlignment="Center" Margin="0,0,8,0"/>
                  <ComboBox x:Name="cbAuditSub" Width="380" Height="26" IsEditable="False"/>
                  <Button x:Name="btnAuditAdd" Content="Добавить"/>
                  <Button x:Name="btnAuditDel" Content="Удалить выбранные"/>
                </StackPanel>
                <TextBlock DockPanel.Dock="Top" Text="Требуемые параметры расширенной политики аудита (auditpol)" FontWeight="SemiBold" Margin="0,0,0,4"/>
                <DataGrid x:Name="dgAuditPolicy" SelectionMode="Extended">
                  <DataGrid.Columns>
                    <DataGridTextColumn Header="Подкатегория" Binding="{Binding Name}" Width="*" IsReadOnly="True"/>
                    <DataGridComboBoxColumn x:Name="colAuditMode" Header="Требуется" SelectedItemBinding="{Binding Mode}" Width="160"/>
                    <DataGridTextColumn Header="GUID" Binding="{Binding Guid}" Width="300" IsReadOnly="True"/>
                  </DataGrid.Columns>
                </DataGrid>
              </DockPanel>
            </TabItem>
            </TabControl>
          </Grid>
          <DockPanel Grid.Row="2" Margin="0,8,0,0">
            <StackPanel Orientation="Horizontal">
              <Button x:Name="btnProfileSave" Content="Сохранить эталон" FontWeight="SemiBold" Margin="0,0,4,0"/>
              <Button x:Name="btnProfileReload" Content="Отменить изменения"/>
            </StackPanel>
            <TextBlock Margin="12,0" VerticalAlignment="Center" Foreground="#555" TextWrapping="Wrap"
                       Text="ПО из справочника СЗИ разрешено автоматически. Обязательные СЗИ профиля задаются на вкладке «Эталон»."/>
          </DockPanel>
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
    $Items = @($Items | Where-Object { $null -ne $_ })
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

# Параметры профиля, редактируемые на вкладке «Профили АРМ»: элемент XML, наименование, тип значения
$ProfileParams = @(
    @{ Key = 'AvBasesMaxAgeDays';   Title = 'Макс. возраст антивирусных баз, сут';           Type = 'int' }
    @{ Key = 'PasswordMinLength';   Title = 'Мин. длина пароля, символов';                   Type = 'int' }
    @{ Key = 'PasswordMaxAgeDays';  Title = 'Макс. срок действия пароля, сут';               Type = 'int' }
    @{ Key = 'LockoutThresholdMax'; Title = 'Порог блокировки учётной записи (не более)';    Type = 'int' }
    @{ Key = 'SecurityLogMinMB';    Title = 'Мин. размер журнала безопасности, МБ';          Type = 'int' }
    @{ Key = 'EventLookbackDays';   Title = 'Глубина анализа журналов событий, сут';         Type = 'int' }
    @{ Key = 'FailedLogonWarn';     Title = 'Неудачных входов до предупреждения';            Type = 'int' }
    @{ Key = 'InactivityMaxSec';    Title = 'Блокировка сеанса при бездействии, не более, с'; Type = 'int' }
    @{ Key = 'CertWarnDays';        Title = 'Предупреждать об окончании сертификата за, сут'; Type = 'int' }
    @{ Key = 'CrlWarnHours';        Title = 'Предупреждать об окончании СОС за, ч';          Type = 'int' }
    @{ Key = 'InactiveUserDays';    Title = 'Неактивная учётная запись, сут';                Type = 'int' }
    @{ Key = 'RequireFirewall';     Title = 'Межсетевой экран обязателен (да/нет)';          Type = 'bool' }
)

function New-PatternTable($Nodes) {
    $t = New-Object System.Data.DataTable 'Soft'
    [void]$t.Columns.Add('Pattern')
    foreach ($n in @($Nodes)) {
        if ($n -is [System.Xml.XmlElement] -and $n.InnerText) { [void]$t.Rows.Add([string]$n.InnerText) }
    }
    $t.AcceptChanges()
    return , $t
}

# Таблицы вкладки «Профили АРМ»: параметры и разрешённое ПО каждого профиля, общее разрешённое ПО
function Import-ProfileTables([System.Xml.XmlDocument]$x) {
    $script:EditProfileId = $null
    $script:ProfileData = [ordered]@{}
    foreach ($p in @($x.SziEtalon.Profiles.Profile)) {
        $pt = New-Object System.Data.DataTable 'Params'
        foreach ($c in 'Key', 'Title', 'Value') { [void]$pt.Columns.Add($c) }
        foreach ($d in $ProfileParams) {
            $node = $p.SelectSingleNode($d.Key)
            $v = if ($node) { [string]$node.InnerText } else { '' }
            if ($d.Type -eq 'bool') { $v = if ($v -eq 'true') { 'да' } elseif ($v -eq 'false') { 'нет' } else { $v } }
            [void]$pt.Rows.Add($d.Key, $d.Title, $v)
        }
        $pt.AcceptChanges()
        $at = New-Object System.Data.DataTable 'Audit'
        foreach ($c in 'Name', 'Guid', 'Mode') { [void]$at.Columns.Add($c) }
        foreach ($a in @($p.SelectNodes('AuditPolicy/Item'))) {
            [void]$at.Rows.Add($a.GetAttribute('name'), $a.GetAttribute('guid'), $AuditModes[[int]('0' + $a.GetAttribute('value'))])
        }
        $at.AcceptChanges()
        $script:ProfileData[$p.GetAttribute('id')] = [pscustomobject]@{
            Name = $p.GetAttribute('name'); Params = $pt
            Soft = (New-PatternTable $p.SelectNodes('AllowedSoftware/Pattern'))
            Users = (New-PatternTable $p.SelectNodes('AllowedUsers/Account'))
            Admins = (New-PatternTable $p.SelectNodes('AllowedAdmins/Account'))
            PwdNever = (New-PatternTable $p.SelectNodes('PasswordNeverExpiresAllowed/Account'))
            Audit = $at
        }
    }
    $script:CommonSoft = New-PatternTable $x.SelectNodes('/SziEtalon/AllowedSoftware/Pattern')
    $Ui.dgCommonSoft.ItemsSource = $script:CommonSoft.DefaultView
    if (-not $script:AuditSubcategories) { Import-AuditSubcategories }

    $prev = if ($Ui.cbEditProfile.SelectedItem) { [string]$Ui.cbEditProfile.SelectedItem.Tag } else { '' }
    $script:ProfileSwitching = $true
    $Ui.cbEditProfile.Items.Clear()
    foreach ($id in $script:ProfileData.Keys) {
        $item = New-Object System.Windows.Controls.ComboBoxItem
        $item.Content = '{0} ({1})' -f $script:ProfileData[$id].Name, $id
        $item.Tag = $id
        [void]$Ui.cbEditProfile.Items.Add($item)
    }
    $script:ProfileSwitching = $false
    $idx = [array]::IndexOf(@($script:ProfileData.Keys), $prev)
    $Ui.cbEditProfile.SelectedIndex = [math]::Max(0, $idx)
}

# Отображение выбранного профиля; наименование предыдущего профиля сохраняется в его таблицах
function Show-EditProfile {
    if ($script:ProfileSwitching) { return }
    Save-ProfileName
    $item = $Ui.cbEditProfile.SelectedItem
    if (-not $item) { return }
    $d = $script:ProfileData[[string]$item.Tag]
    $script:EditProfileId = [string]$item.Tag
    $Ui.tbProfileName.Text = $d.Name
    $Ui.dgProfileParams.ItemsSource = $d.Params.DefaultView
    $Ui.dgProfileSoft.ItemsSource = $d.Soft.DefaultView
    $Ui.dgAllowedUsers.ItemsSource = $d.Users.DefaultView
    $Ui.dgAllowedAdmins.ItemsSource = $d.Admins.DefaultView
    $Ui.dgPwdNever.ItemsSource = $d.PwdNever.DefaultView
    $Ui.dgAuditPolicy.ItemsSource = $d.Audit.DefaultView
}

# Режимы аудита: значение атрибута value в эталоне → текст
$AuditModes = @{ 1 = 'Успех'; 2 = 'Отказ'; 3 = 'Успех и отказ' }

# Перечень подкатегорий расширенной политики аудита данного компьютера (наименование и GUID)
function Import-AuditSubcategories {
    $script:AuditSubcategories = @()
    try {
        $out = & { $ErrorActionPreference = 'Continue'; & auditpol.exe /list /subcategory:* /v 2>$null }
        $script:AuditSubcategories = @($out | ForEach-Object {
                if ($_ -match '^\s+(?<n>\S.*?)\s+(?<g>\{[0-9A-Fa-f-]{36}\})\s*$') {
                    [pscustomobject]@{ Name = $Matches.n.Trim(); Guid = $Matches.g.ToUpper() } } })
    }
    catch { Write-Log "Не удалось получить перечень подкатегорий аудита: $($_.Exception.Message)" 'WARN' }
    $Ui.cbAuditSub.Items.Clear()
    foreach ($s in $script:AuditSubcategories) {
        $item = New-Object System.Windows.Controls.ComboBoxItem
        $item.Content = $s.Name; $item.Tag = $s.Guid
        [void]$Ui.cbAuditSub.Items.Add($item)
    }
    $Ui.dgAuditPolicy.Columns[1].ItemsSource = @($AuditModes[1], $AuditModes[2], $AuditModes[3])
}

function Add-AuditPolicyItem {
    if (-not $script:EditProfileId) { throw 'Выберите профиль АРМ' }
    $item = $Ui.cbAuditSub.SelectedItem
    if (-not $item) { throw 'Выберите подкатегорию аудита' }
    $t = $script:ProfileData[$script:EditProfileId].Audit
    if (@($t.Rows | Where-Object { $_.RowState -ne 'Deleted' -and ([string]$_['Guid']).ToUpper() -eq [string]$item.Tag }).Count -gt 0) {
        throw "Подкатегория «$($item.Content)» уже есть в профиле"
    }
    [void]$t.Rows.Add([string]$item.Content, [string]$item.Tag, $AuditModes[3])
}

# Обновление перечня профилей на вкладке «Аудит»
function Update-AuditProfileList {
    $prev = if ($Ui.cbProfile.SelectedItem) { [string]$Ui.cbProfile.SelectedItem.Tag } else { '' }
    $Ui.cbProfile.Items.Clear()
    foreach ($p in @($script:Etalon.SziEtalon.Profiles.Profile)) {
        $item = New-Object System.Windows.Controls.ComboBoxItem
        $item.Content = $p.GetAttribute('name')
        $item.Tag = $p.GetAttribute('id')
        [void]$Ui.cbProfile.Items.Add($item)
        if ($item.Tag -eq $prev) { $Ui.cbProfile.SelectedItem = $item }
    }
    if (-not $Ui.cbProfile.SelectedItem -and $Ui.cbProfile.Items.Count -gt 0) { $Ui.cbProfile.SelectedIndex = 0 }
}

# Перенос несохранённых правок вкладок «Эталон» и «Профили АРМ» в XML-документ (без записи в файл)
function Sync-ProfilesToXml {
    foreach ($g in 'dgProfileParams', 'dgProfileSoft', 'dgCommonSoft', 'dgAllowedUsers', 'dgAllowedAdmins', 'dgPwdNever', 'dgAuditPolicy', 'dgSzi') {
        [void]$Ui[$g].CommitEdit(); [void]$Ui[$g].CommitEdit()
    }
    Save-ProfileName
    Write-ProfileTables $script:Etalon
    Write-RequireSzi $script:Etalon
}

function Show-InputDialog([string]$Title, [string]$IdValue, [string]$NameValue) {
    [xml]$pxInput = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Width="520" SizeToContent="Height" WindowStartupLocation="CenterOwner" ResizeMode="NoResize"
        FontFamily="Segoe UI" FontSize="13">
  <StackPanel Margin="12">
    <TextBlock Text="Код профиля (латинские буквы, цифры, «_»), например ARM_KPP:"/>
    <TextBox x:Name="tbId" Height="26" Margin="0,4,0,10" VerticalContentAlignment="Center"/>
    <TextBlock Text="Наименование профиля (тип АРМ):"/>
    <TextBox x:Name="tbName" Height="26" Margin="0,4,0,12" VerticalContentAlignment="Center"/>
    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
      <Button x:Name="btnOk" Content="ОК" Padding="16,4" Margin="4,0" IsDefault="True"/>
      <Button Content="Отмена" Padding="16,4" Margin="4,0" IsCancel="True"/>
    </StackPanel>
  </StackPanel>
</Window>
'@
    $w = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $pxInput))
    $w.Owner = $Window; $w.Title = $Title
    $tbId = $w.FindName('tbId'); $tbName = $w.FindName('tbName')
    $tbId.Text = $IdValue; $tbName.Text = $NameValue
    $w.FindName('btnOk').Add_Click({ $w.DialogResult = $true })
    $w.Add_ContentRendered({ [void]$tbId.Focus(); $tbId.SelectAll() })
    if (-not $w.ShowDialog()) { return $null }
    [pscustomobject]@{ Id = $tbId.Text.Trim(); Name = $tbName.Text.Trim() }
}

# Создание (SourceId пуст) или копирование профиля; изменения вступают в силу после сохранения эталона
function New-EtalonProfile([string]$SourceId) {
    Sync-ProfilesToXml
    $x = $script:Etalon
    $profiles = $x.DocumentElement.SelectSingleNode('Profiles')
    $src = $null
    if ($SourceId) { $src = $profiles.SelectSingleNode("Profile[@id='$SourceId']") }
    $ids = @($profiles.SelectNodes('Profile') | ForEach-Object { $_.GetAttribute('id') })
    $suggestId = if ($src) { "${SourceId}_COPY" } else { 'ARM_NEW' }
    $suggestName = if ($src) { $src.GetAttribute('name') + ' (копия)' } else { 'Новый тип АРМ' }
    $title = if ($src) { "Копирование профиля $SourceId" } else { 'Создание профиля АРМ' }
    $ans = Show-InputDialog $title $suggestId $suggestName
    if (-not $ans) { return }
    if ($ans.Id -notmatch '^[A-Za-z][A-Za-z0-9_]*$') { throw 'Код профиля должен начинаться с латинской буквы и содержать только латинские буквы, цифры и «_»' }
    if ($ids -contains $ans.Id) { throw "Профиль с кодом $($ans.Id) уже существует" }
    if (-not $ans.Name) { throw 'Не задано наименование профиля' }

    if ($src) { $node = $src.CloneNode($true) }
    else {
        $node = $x.CreateElement('Profile')
        $defaults = [ordered]@{ RequireSzi = ''; AvBasesMaxAgeDays = 7; PasswordMinLength = 8; PasswordMaxAgeDays = 180
            LockoutThresholdMax = 10; SecurityLogMinMB = 64; EventLookbackDays = 30; FailedLogonWarn = 20
            InactivityMaxSec = 900; CertWarnDays = 90; RequireFirewall = 'true'; CrlWarnHours = 24; InactiveUserDays = 45 }
        foreach ($k in $defaults.Keys) { $e = $x.CreateElement($k); $e.InnerText = [string]$defaults[$k]; [void]$node.AppendChild($e) }
        foreach ($k in 'AllowedUsers', 'PasswordNeverExpiresAllowed') { [void]$node.AppendChild($x.CreateElement($k)) }
        $adm = $node.AppendChild($x.CreateElement('AllowedAdmins'))
        foreach ($a in '*\Администратор*', '*\Administrator') { $e = $x.CreateElement('Account'); $e.InnerText = $a; [void]$adm.AppendChild($e) }
        $aud = $node.AppendChild($x.CreateElement('AuditPolicy'))
        foreach ($i in @(@('Вход в систему', '{0CCE9215-69AE-11D9-BED3-505054503030}', 3),
                @('Выход из системы', '{0CCE9216-69AE-11D9-BED3-505054503030}', 1),
                @('Изменение политики аудита', '{0CCE922F-69AE-11D9-BED3-505054503030}', 1))) {
            $e = $x.CreateElement('Item'); $e.SetAttribute('name', $i[0]); $e.SetAttribute('guid', $i[1]); $e.SetAttribute('value', [string]$i[2])
            [void]$aud.AppendChild($e)
        }
        [void]$node.AppendChild($x.CreateElement('AllowedSoftware'))
    }
    $node.SetAttribute('id', $ans.Id); $node.SetAttribute('name', $ans.Name)
    [void]$profiles.AppendChild($node)
    # Обязательные СЗИ копии – как у исходного профиля
    if ($src) {
        foreach ($r in $script:SziTable.Rows) {
            if ($r.RowState -eq 'Deleted') { continue }
            $list = @(([string]$r['profiles']) -split '[,;\s]+' | Where-Object { $_ })
            if ($list -contains $SourceId) { $r['profiles'] = (@($list) + $ans.Id) -join ', ' }
        }
    }
    Import-ProfileTables $x
    Update-AuditProfileList
    $Ui.cbEditProfile.SelectedIndex = $Ui.cbEditProfile.Items.Count - 1
    Write-Log "Создан профиль $($ans.Id) «$($ans.Name)» (не забудьте сохранить эталон)"
}

function Remove-EtalonProfile {
    $id = $script:EditProfileId
    if (-not $id) { throw 'Выберите профиль АРМ' }
    if ($script:ProfileData.Count -le 1) { throw 'Нельзя удалить единственный профиль' }
    $ans = [System.Windows.MessageBox]::Show(
        "Удалить профиль $id «$($script:ProfileData[$id].Name)»?`n`nАРМ, для которых в перечне (arm.txt) указан этот профиль, перестанут проверяться. " +
        'Профиль будет удалён из файла после сохранения эталона; предыдущая версия эталона сохраняется в каталоге Config\Backup.',
        $AppName, 'YesNo', 'Warning')
    if ($ans -ne 'Yes') { return }
    Sync-ProfilesToXml
    $x = $script:Etalon
    $node = $x.DocumentElement.SelectSingleNode("Profiles/Profile[@id='$id']")
    if ($node) { [void]$node.ParentNode.RemoveChild($node) }
    foreach ($r in $script:SziTable.Rows) {
        if ($r.RowState -eq 'Deleted') { continue }
        $r['profiles'] = (@(([string]$r['profiles']) -split '[,;\s]+' | Where-Object { $_ -and $_ -ne $id })) -join ', '
    }
    Import-ProfileTables $x
    Update-AuditProfileList
    Write-Log "Профиль $id удалён (не забудьте сохранить эталон)"
}

# Выбор учётных записей из локальных пользователей АРМ
function Add-LocalUsersToProfile {
    if (-not $script:EditProfileId) { throw 'Выберите профиль АРМ' }
    $t = $script:ProfileData[$script:EditProfileId].Users
    $have = @($t.Rows | Where-Object { $_.RowState -ne 'Deleted' } | ForEach-Object { ([string]$_['Pattern']).ToUpper() })
    $users = @(Get-LocalUser | Where-Object { $have -notcontains $_.Name.ToUpper() })
    if ($users.Count -eq 0) { Show-Message 'Все локальные учётные записи этого АРМ уже указаны'; return }
    $lines = ($users | ForEach-Object {
            '{0}{1}' -f $_.Name, $(if ($_.Enabled) { '' } else { ' (отключена)' }) }) -join "`n"
    $ans = [System.Windows.MessageBox]::Show("Добавить в перечень допущенных учётные записи этого АРМ?`n`n$lines`n`nОтключённые учётные записи не добавляются.",
        $AppName, 'YesNo', 'Question')
    if ($ans -ne 'Yes') { return }
    $n = 0
    foreach ($u in $users | Where-Object { $_.Enabled }) { [void]$t.Rows.Add($u.Name); $n++ }
    Write-Log "Добавлено учётных записей в перечень допущенных: $n (не забудьте сохранить эталон)"
}

function Save-ProfileName {
    if ($script:EditProfileId -and $script:ProfileData.Contains($script:EditProfileId)) {
        $script:ProfileData[$script:EditProfileId].Name = $Ui.tbProfileName.Text.Trim()
    }
}

function Test-ProfileTables {
    $errors = @()
    foreach ($id in $script:ProfileData.Keys) {
        $d = $script:ProfileData[$id]
        if (-not $d.Name) { $errors += "Профиль ${id}: не задано наименование" }
        foreach ($r in $d.Params.Rows) {
            $v = ([string]$r['Value']).Trim()
            if (-not $v) { continue }
            $def = $ProfileParams | Where-Object { $_.Key -eq $r['Key'] }
            $n = 0
            if ($def.Type -eq 'int' -and -not ([int]::TryParse($v, [ref]$n) -and $n -ge 0)) {
                $errors += "Профиль ${id}: «$($def.Title)» – требуется целое неотрицательное число"
            }
            if ($def.Type -eq 'bool' -and $v -notin 'да', 'нет', 'true', 'false') {
                $errors += "Профиль ${id}: «$($def.Title)» – укажите «да» или «нет»"
            }
        }
    }
    return $errors
}

# Перенос таблиц вкладки «Профили АРМ» в XML-документ эталона
function Write-ProfileTables([System.Xml.XmlDocument]$x) {
    $writeSoft = {
        param($Parent, $Table, $Child = 'Pattern')
        while ($Parent.HasChildNodes) { [void]$Parent.RemoveChild($Parent.FirstChild) }
        foreach ($r in $Table.Rows) {
            if ($r.RowState -eq 'Deleted') { continue }
            $v = ([string]$r['Pattern']).Trim()
            if (-not $v) { continue }
            $el = $x.CreateElement($Child); $el.InnerText = $v
            [void]$Parent.AppendChild($el)
        }
    }
    $getNode = {
        param($P, $Name)
        $n = $P.SelectSingleNode($Name)
        if (-not $n) {
            $n = $x.CreateElement($Name)
            $anchor = $P.SelectSingleNode('AllowedSoftware')
            if ($anchor) { [void]$P.InsertBefore($n, $anchor) } else { [void]$P.AppendChild($n) }
        }
        return $n
    }
    $root = $x.DocumentElement
    foreach ($p in @($root.SelectNodes('Profiles/Profile'))) {
        $d = $script:ProfileData[$p.GetAttribute('id')]
        if (-not $d) { continue }
        $p.SetAttribute('name', $d.Name)
        foreach ($r in $d.Params.Rows) {
            $key = [string]$r['Key']
            $v = ([string]$r['Value']).Trim()
            $def = $ProfileParams | Where-Object { $_.Key -eq $key }
            if ($def.Type -eq 'bool') { $v = if ($v -in 'да', 'true') { 'true' } elseif ($v) { 'false' } else { '' } }
            $node = $p.SelectSingleNode($key)
            if (-not $v) { if ($node) { [void]$p.RemoveChild($node) }; continue }
            if (-not $node) {
                $node = $x.CreateElement($key)
                $anchor = $p.SelectSingleNode('AllowedUsers')
                if ($anchor) { [void]$p.InsertBefore($node, $anchor) } else { [void]$p.AppendChild($node) }
            }
            $node.InnerText = $v
        }
        $soft = $p.SelectSingleNode('AllowedSoftware')
        if (-not $soft) { $soft = $p.AppendChild($x.CreateElement('AllowedSoftware')) }
        & $writeSoft $soft $d.Soft
        & $writeSoft (& $getNode $p 'AllowedUsers') $d.Users 'Account'
        & $writeSoft (& $getNode $p 'PasswordNeverExpiresAllowed') $d.PwdNever 'Account'
        & $writeSoft (& $getNode $p 'AllowedAdmins') $d.Admins 'Account'
        $aud = & $getNode $p 'AuditPolicy'
        while ($aud.HasChildNodes) { [void]$aud.RemoveChild($aud.FirstChild) }
        foreach ($r in $d.Audit.Rows) {
            if ($r.RowState -eq 'Deleted') { continue }
            $val = ($AuditModes.Keys | Where-Object { $AuditModes[$_] -eq [string]$r['Mode'] } | Select-Object -First 1)
            if (-not $val) { $val = 3 }
            $el = $x.CreateElement('Item')
            $el.SetAttribute('name', [string]$r['Name']); $el.SetAttribute('guid', [string]$r['Guid']); $el.SetAttribute('value', [string]$val)
            [void]$aud.AppendChild($el)
        }
    }
    $common = $root.SelectSingleNode('AllowedSoftware')
    if (-not $common) { $common = $root.InsertAfter($x.CreateElement('AllowedSoftware'), $root.SelectSingleNode('SziList')) }
    & $writeSoft $common $script:CommonSoft
}

function Remove-SelectedRows($Grid) {
    $rows = @($Grid.SelectedItems | Where-Object { $_ -is [System.Data.DataRowView] })
    foreach ($rv in $rows) { $rv.Row.Delete() }
}

# Перечень установленного ПО (тот же отбор, что и в модуле проверок)
$GetSoftwareBlock = {
    $keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    Get-ItemProperty -Path $keys -ErrorAction SilentlyContinue |
        Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName } |
        Where-Object { -not ($_.PSObject.Properties['SystemComponent'] -and $_.SystemComponent -eq 1) } |
        ForEach-Object {
            $ver = ''; $pub = ''
            if ($_.PSObject.Properties['DisplayVersion']) { $ver = [string]$_.DisplayVersion }
            if ($_.PSObject.Properties['Publisher']) { $pub = [string]$_.Publisher }
            [pscustomobject]@{ Name = [string]$_.DisplayName; Version = $ver; Publisher = $pub }
        } | Sort-Object Name -Unique
}

# Шаблон по имени программы: номер версии в конце имени заменяется на «*»,
# чтобы шаблон не устаревал при обновлении ПО (например, «7-Zip 26.06 (x64)» → «7-Zip*»)
function ConvertTo-SoftPattern([string]$Name) {
    $p = $Name.Trim() -replace '[\[\]]', '?'
    $p2 = $p -replace '\s*[-–(]?\s*v?\d+([.,]\d+)+.*$', '*'
    if ($p2 -ne $p -and $p2.Trim('*').Trim()) { return $p2 }
    return $p
}

# $Preload – готовый перечень ПО (Name, Version, Publisher) вместо опроса АРМ;
# $Targets – упорядоченный словарь «наименование → таблица шаблонов» для выбора, куда добавить ПО
function Show-SoftwarePicker($Table, [string]$Title, $Preload = $null, $Targets = $null) {
    [xml]$pxSoft = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Выбор разрешённого ПО" Width="980" Height="600" WindowStartupLocation="CenterOwner"
        FontFamily="Segoe UI" FontSize="13">
  <DockPanel Margin="10">
    <TextBlock x:Name="tbHead" DockPanel.Dock="Top" FontWeight="SemiBold" Margin="0,0,0,8"/>
    <StackPanel x:Name="spTarget" DockPanel.Dock="Top" Orientation="Horizontal" Margin="0,0,0,8" Visibility="Collapsed">
      <TextBlock Text="Добавить в:" VerticalAlignment="Center" Margin="0,0,8,0"/>
      <ComboBox x:Name="cbTarget" Width="520" Height="26"/>
    </StackPanel>
    <DockPanel x:Name="dpHost" DockPanel.Dock="Top" Margin="0,0,0,8">
      <TextBlock Text="АРМ:" VerticalAlignment="Center" Margin="0,0,8,0"/>
      <TextBox x:Name="tbHost" Width="200" Height="26" VerticalContentAlignment="Center" Text="localhost"/>
      <Button x:Name="btnLoad" Content="Получить перечень ПО" Padding="12,4" Margin="8,0"/>
      <CheckBox x:Name="cbHideAllowed" Content="Скрыть уже разрешённое" IsChecked="True" VerticalAlignment="Center" Margin="8,0"/>
      <TextBlock Text="Фильтр:" VerticalAlignment="Center" Margin="8,0"/>
      <TextBox x:Name="tbFilter" Height="26" VerticalContentAlignment="Center"/>
    </DockPanel>
    <DockPanel DockPanel.Dock="Bottom" Margin="0,8,0,0">
      <StackPanel DockPanel.Dock="Right" Orientation="Horizontal">
        <Button x:Name="btnOk" Content="Разрешить выбранные" Padding="12,4" Margin="4,0" IsDefault="True"/>
        <Button x:Name="btnCancel" Content="Отмена" Padding="12,4" Margin="4,0" IsCancel="True"/>
      </StackPanel>
      <StackPanel Orientation="Horizontal">
        <Button x:Name="btnAll" Content="Отметить видимые" Padding="12,4" Margin="0,0,4,0"/>
        <Button x:Name="btnNone" Content="Снять отметки" Padding="12,4" Margin="4,0"/>
        <TextBlock x:Name="tbCount" VerticalAlignment="Center" Margin="12,0"/>
      </StackPanel>
    </DockPanel>
    <DataGrid x:Name="dgSoft" AutoGenerateColumns="False" CanUserAddRows="False" CanUserDeleteRows="False"
              HeadersVisibility="Column" GridLinesVisibility="Horizontal" HorizontalGridLinesBrush="#E1E5EB">
      <DataGrid.Columns>
        <DataGridCheckBoxColumn Header="✓" Binding="{Binding Sel, UpdateSourceTrigger=PropertyChanged}" Width="40"/>
        <DataGridTextColumn Header="Программа" Binding="{Binding Name}" Width="300" IsReadOnly="True"/>
        <DataGridTextColumn Header="Версия" Binding="{Binding Version}" Width="110" IsReadOnly="True"/>
        <DataGridTextColumn Header="Издатель" Binding="{Binding Publisher}" Width="170" IsReadOnly="True"/>
        <DataGridTextColumn Header="Шаблон (можно изменить)" Binding="{Binding Pattern}" Width="*"/>
      </DataGrid.Columns>
    </DataGrid>
  </DockPanel>
</Window>
'@
    $w = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $pxSoft))
    $w.Owner = $Window
    $f = @{}; foreach ($n in 'tbHead', 'tbHost', 'btnLoad', 'cbHideAllowed', 'tbFilter', 'tbCount', 'dgSoft', 'spTarget', 'cbTarget', 'dpHost') { $f[$n] = $w.FindName($n) }
    $f.tbHead.Text = $Title
    if ($Preload) {
        foreach ($c in @($f.dpHost.Children)[0], $f.tbHost, $f.btnLoad) { $c.Visibility = 'Collapsed' }
    }
    if ($Targets) {
        $f.spTarget.Visibility = 'Visible'
        foreach ($k in $Targets.Keys) { [void]$f.cbTarget.Items.Add($k) }
        $f.cbTarget.SelectedIndex = 0
        $Table = $Targets[0]
    }
    $t = New-Object System.Data.DataTable 'Installed'
    [void]$t.Columns.Add('Sel', [bool])
    foreach ($c in 'Name', 'Version', 'Publisher', 'Pattern') { [void]$t.Columns.Add($c) }
    [void]$t.Columns.Add('Allowed', [bool])
    $view = $t.DefaultView
    $f.dgSoft.ItemsSource = $view

    # Шаблоны, которые уже разрешают программу: общие, профиля, справочник СЗИ, текущая таблица
    $allowed = @(@($script:CommonSoft.Rows) + @($Table.Rows) | Where-Object { $_.RowState -ne 'Deleted' } |
            ForEach-Object { [string]$_['Pattern'] })
    if ($script:EditProfileId) {
        $allowed += @($script:ProfileData[$script:EditProfileId].Soft.Rows | Where-Object { $_.RowState -ne 'Deleted' } |
                ForEach-Object { [string]$_['Pattern'] })
    }
    $allowed += @($script:SziTable.Rows | Where-Object { $_.RowState -ne 'Deleted' } | ForEach-Object { [string]$_['productPattern'] })
    $allowed = @($allowed | ForEach-Object { $_ -split '\|' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })

    $applyFilter = {
        $q = $f.tbFilter.Text.Replace("'", "''").Replace('[', '[[]').Replace('*', '[*]').Replace('%', '[%]')
        $parts = @()
        if ($q) { $parts += "(Name LIKE '%$q%' OR Publisher LIKE '%$q%')" }
        if ($f.cbHideAllowed.IsChecked) { $parts += 'Allowed = false' }
        $view.RowFilter = ($parts -join ' AND ')
        $f.tbCount.Text = 'Показано: {0} из {1}, отмечено: {2}' -f $view.Count, $t.Rows.Count, @($t.Select('Sel = true')).Count
    }
    $load = {
        $h = $f.tbHost.Text.Trim()
        try {
            $w.Cursor = [System.Windows.Input.Cursors]::Wait
            if ($Preload) { $list = @($Preload) }
            elseif (-not $h -or $h -in @('localhost', '.', '127.0.0.1', $env:COMPUTERNAME)) { $list = @(& $GetSoftwareBlock) }
            else { $list = @(Invoke-Command -ComputerName $h -ScriptBlock $GetSoftwareBlock) }
        }
        catch { Show-Message "Не удалось получить перечень ПО с АРМ ${h}:`n$($_.Exception.Message)" 'Error'; return }
        finally { $w.Cursor = $null }
        $t.Rows.Clear()
        foreach ($s in $list) {
            $ok = $false
            foreach ($a in $allowed) { if ($s.Name -like $a) { $ok = $true; break } }
            [void]$t.Rows.Add($false, $s.Name, $s.Version, $s.Publisher, (ConvertTo-SoftPattern $s.Name), $ok)
        }
        & $applyFilter
    }
    $f.btnLoad.Add_Click($load)
    $f.tbFilter.Add_TextChanged($applyFilter)
    $f.cbHideAllowed.Add_Click($applyFilter)
    $t.Add_ColumnChanged({ $f.tbCount.Text = 'Показано: {0} из {1}, отмечено: {2}' -f $view.Count, $t.Rows.Count, @($t.Select('Sel = true')).Count })
    $w.FindName('btnAll').Add_Click({ foreach ($rv in @($view)) { $rv.Row['Sel'] = $true } })
    $w.FindName('btnNone').Add_Click({ foreach ($r in $t.Rows) { $r['Sel'] = $false } })
    $w.FindName('btnOk').Add_Click({ $f.dgSoft.CommitEdit(); $f.dgSoft.CommitEdit(); $w.DialogResult = $true })
    $w.Add_ContentRendered({ & $load })
    $added = 0
    if ($w.ShowDialog()) {
        if ($Targets) { $Table = $Targets[$f.cbTarget.SelectedIndex] }
        $have = @($Table.Rows | Where-Object { $_.RowState -ne 'Deleted' } | ForEach-Object { ([string]$_['Pattern']).ToUpper() })
        foreach ($r in $t.Select('Sel = true')) {
            $pat = ([string]$r['Pattern']).Trim()
            if (-not $pat -or $have -contains $pat.ToUpper()) { continue }
            [void]$Table.Rows.Add($pat); $have += $pat.ToUpper(); $added++
        }
        Write-Log "Добавлено шаблонов разрешённого ПО: $added (не забудьте сохранить эталон)"
    }
    return $added
}

# ---------------------------------------------------------------------------
# Задание Планировщика заданий Windows для ежедневного аудита
# ---------------------------------------------------------------------------
$TaskPath = '\SZI-Audit\'
$TaskName = 'Ежедневный аудит'
$TaskCodes = @{ 0 = '0 – несоответствий нет'; 1 = '1 – выявлены несоответствия'; 2 = '2 – ошибки выполнения проверок'
    3 = '3 – ошибка запуска'; 267009 = 'выполняется'; 267011 = 'ещё не запускалось' }

function Get-AuditTaskState {
    $task = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $task) { return [pscustomobject]@{ Task = $null; Text = 'Задание не создано' } }
    $info = Get-ScheduledTaskInfo -InputObject $task
    $code = [int64]$info.LastTaskResult
    $codeText = if ($TaskCodes.ContainsKey([int]$code)) { $TaskCodes[[int]$code] } else { '0x{0:X}' -f $code }
    $last = if ($info.LastRunTime -and $info.LastRunTime.Year -gt 2000) { '{0:dd.MM.yyyy HH:mm}, результат: {1}' -f $info.LastRunTime, $codeText } else { 'не запускалось' }
    $next = if ($info.NextRunTime) { '{0:dd.MM.yyyy HH:mm}' -f $info.NextRunTime } else { '—' }
    [pscustomobject]@{
        Task = $task
        Text = "Задание создано ($($task.State)). Учётная запись: $($task.Principal.UserId). Следующий запуск: $next. Последний запуск: $last"
    }
}

function Show-ScheduleDialog {
    [xml]$pxSched = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Ежедневный аудит – Планировщик заданий Windows" Width="720" SizeToContent="Height"
        WindowStartupLocation="CenterOwner" ResizeMode="NoResize" FontFamily="Segoe UI" FontSize="13">
  <StackPanel Margin="14">
    <Border Background="#EEF2F7" Padding="8" Margin="0,0,0,12">
      <TextBlock x:Name="tbState" TextWrapping="Wrap"/>
    </Border>
    <Grid>
      <Grid.ColumnDefinitions><ColumnDefinition Width="200"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
      <Grid.RowDefinitions>
        <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
        <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
      </Grid.RowDefinitions>
      <TextBlock Text="Время запуска (ЧЧ:ММ):" VerticalAlignment="Center"/>
      <StackPanel Grid.Column="1" Orientation="Horizontal" Margin="0,4">
        <TextBox x:Name="tbTime" Width="70" Height="26" VerticalContentAlignment="Center" Text="08:00"/>
        <ComboBox x:Name="cbDays" Width="240" Height="26" Margin="12,0,0,0" SelectedIndex="0">
          <ComboBoxItem Content="Ежедневно"/>
          <ComboBoxItem Content="По рабочим дням (пн–пт)"/>
        </ComboBox>
      </StackPanel>
      <TextBlock Grid.Row="1" Text="Профиль по умолчанию:" VerticalAlignment="Center"/>
      <ComboBox x:Name="cbProf" Grid.Row="1" Grid.Column="1" Height="26" Margin="0,4"/>
      <TextBlock Grid.Row="2" Text="Перечень АРМ:" VerticalAlignment="Center"/>
      <DockPanel Grid.Row="2" Grid.Column="1" Margin="0,4">
        <Button x:Name="btnBrowse" DockPanel.Dock="Right" Content="Обзор…" Padding="10,2" Margin="6,0,0,0"/>
        <TextBox x:Name="tbFile" Height="26" VerticalContentAlignment="Center"/>
      </DockPanel>
      <TextBlock Grid.Row="3" Text="Запускать от имени:" VerticalAlignment="Top" Margin="0,6,0,0"/>
      <StackPanel Grid.Row="3" Grid.Column="1" Margin="0,6">
        <RadioButton x:Name="rbSystem" Content="SYSTEM – без входа пользователя (удалённые АРМ – от учётной записи компьютера)" IsChecked="True"/>
        <RadioButton x:Name="rbUser" Margin="0,4,0,0"/>
      </StackPanel>
      <TextBlock Grid.Row="4" Grid.ColumnSpan="2" Foreground="#555" TextWrapping="Wrap" Margin="0,6,0,0"
                 Text="АРМ без кода профиля в перечне проверяются по профилю по умолчанию. Итоги каждого запуска пишутся в журнал программы и в журнал Windows «Приложение» (источник SZI-Audit): 1000 – аудит выполнен, 1002 – ухудшение, 1003 – аудит не выполнен."/>
    </Grid>
    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,14,0,0">
      <Button x:Name="btnSave" Content="Сохранить задание" FontWeight="SemiBold" Padding="12,4" Margin="4,0"/>
      <Button x:Name="btnRun" Content="Выполнить сейчас" Padding="12,4" Margin="4,0"/>
      <Button x:Name="btnDel" Content="Удалить задание" Padding="12,4" Margin="4,0"/>
      <Button Content="Закрыть" Padding="12,4" Margin="4,0" IsCancel="True"/>
    </StackPanel>
  </StackPanel>
</Window>
'@
    $w = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $pxSched))
    $w.Owner = $Window
    $f = @{}; foreach ($n in 'tbState', 'tbTime', 'cbDays', 'cbProf', 'tbFile', 'btnBrowse', 'rbSystem', 'rbUser', 'btnSave', 'btnRun', 'btnDel') { $f[$n] = $w.FindName($n) }
    $f.rbUser.Content = "$env:USERDOMAIN\$env:USERNAME – только когда пользователь вошёл в систему"
    foreach ($p in @($script:Etalon.SziEtalon.Profiles.Profile)) {
        $item = New-Object System.Windows.Controls.ComboBoxItem
        $item.Content = '{0} ({1})' -f $p.GetAttribute('name'), $p.GetAttribute('id'); $item.Tag = $p.GetAttribute('id')
        [void]$f.cbProf.Items.Add($item)
    }
    $f.cbProf.SelectedIndex = 0
    $f.tbFile.Text = Join-Path $Root 'arm.txt'

    $refresh = {
        $st = Get-AuditTaskState
        $f.tbState.Text = $st.Text
        $f.btnRun.IsEnabled = [bool]$st.Task; $f.btnDel.IsEnabled = [bool]$st.Task
        if ($st.Task) {
            # Текущие параметры задания – в поля формы
            $a = $st.Task.Actions | Select-Object -First 1
            if ($a.Arguments -match '-ProfileId\s+(\S+)') {
                $pid2 = $Matches[1]
                foreach ($it in $f.cbProf.Items) { if ($it.Tag -eq $pid2) { $f.cbProf.SelectedItem = $it } }
            }
            if ($a.Arguments -match '-ComputersFile\s+"([^"]+)"') { $f.tbFile.Text = $Matches[1] }
            $tr = $st.Task.Triggers | Select-Object -First 1
            if ($tr.StartBoundary) { $f.tbTime.Text = ([datetime]$tr.StartBoundary).ToString('HH:mm') }
            $f.cbDays.SelectedIndex = if ($tr.CimClass.CimClassName -eq 'MSFT_TaskWeeklyTrigger') { 1 } else { 0 }
            # Имя SYSTEM локализовано («СИСТЕМА»), поэтому определяется по типу входа
            $f.rbSystem.IsChecked = ([string]$st.Task.Principal.LogonType -eq 'ServiceAccount')
            $f.rbUser.IsChecked = -not $f.rbSystem.IsChecked
        }
    }
    $f.btnBrowse.Add_Click({
        $dlg = New-Object Microsoft.Win32.OpenFileDialog
        $dlg.Filter = 'Текстовые файлы|*.txt|Все файлы|*.*'
        $dlg.FileName = $f.tbFile.Text
        if ($dlg.ShowDialog()) { $f.tbFile.Text = $dlg.FileName }
    })
    $f.btnSave.Add_Click({
        Invoke-Safe {
            $tm = [datetime]::MinValue
            if (-not [datetime]::TryParseExact($f.tbTime.Text.Trim(), 'H:mm', $null, 'None', [ref]$tm)) { throw 'Укажите время запуска в формате ЧЧ:ММ, например 08:00' }
            $file = $f.tbFile.Text.Trim()
            if (-not (Test-Path $file)) { throw "Не найден файл перечня АРМ: $file" }
            # Проверка перечня: все АРМ должны получить профиль
            [void](ConvertTo-AuditTargets @(Get-Content -Path $file -Encoding UTF8) ([string]$f.cbProf.SelectedItem.Tag))
            $args2 = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -NoGui -ProfileId {1} -ComputersFile "{2}"' -f `
                (Join-Path $Root 'SziAudit.ps1'), $f.cbProf.SelectedItem.Tag, $file
            $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $args2 -WorkingDirectory $Root
            $trigger = if ($f.cbDays.SelectedIndex -eq 1) {
                New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday, Tuesday, Wednesday, Thursday, Friday -At $tm
            } else { New-ScheduledTaskTrigger -Daily -At $tm }
            $principal = if ($f.rbSystem.IsChecked) {
                New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
            } else { New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Highest }
            $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew `
                -ExecutionTimeLimit (New-TimeSpan -Hours 3) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
            [void](Register-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -Action $action -Trigger $trigger `
                    -Principal $principal -Settings $settings -Force `
                    -Description 'ПО «СЗИ-Аудит»: ежедневный аудит средств защиты информации АРМ')
            Write-Log "Задание Планировщика «$TaskPath$TaskName» сохранено: $($f.cbDays.Text) в $($tm.ToString('HH:mm')), профиль по умолчанию $($f.cbProf.SelectedItem.Tag)"
            & $refresh
        }
    })
    $f.btnRun.Add_Click({
        Invoke-Safe {
            Start-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName
            Write-Log "Задание «$TaskPath$TaskName» запущено вручную"
            Start-Sleep -Milliseconds 800; & $refresh
        }
    })
    $f.btnDel.Add_Click({
        Invoke-Safe {
            if ([System.Windows.MessageBox]::Show('Удалить задание ежедневного аудита?', $AppName, 'YesNo', 'Question') -ne 'Yes') { return }
            Unregister-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -Confirm:$false
            Write-Log "Задание «$TaskPath$TaskName» удалено"
            & $refresh
        }
    })
    & $refresh
    [void]$w.ShowDialog()
}

# «Разрешить ПО…» на вкладке «Аудит»: лишнее ПО из результатов последнего аудита – в разрешённое профиля или общее
function Show-AllowExtraSoftware {
    $items = @($script:AllResults | Where-Object { $_.CheckId -eq 'SW-EXTRA' -and $_.PSObject.Properties['Details'] -and $_.Details })
    if ($items.Count -eq 0) { throw 'В результатах нет ПО, не указанного в предписании' }
    $soft = @{}
    foreach ($i in $items) {
        foreach ($l in ([string]$i.Details -split "`n" | Where-Object { $_ })) {
            $parts = $l -split "`t", 2
            if (-not $soft.ContainsKey($parts[0])) {
                $soft[$parts[0]] = [pscustomobject]@{ Name = $parts[0]; Version = $(if ($parts.Count -gt 1) { $parts[1] } else { '' }); Publisher = [string]$i.Computer }
            }
        }
    }
    $profIds = @($items | ForEach-Object { $r = $script:LastRuns[[string]$_.Computer]; if ($r -and $r.PSObject.Properties['ProfileId']) { [string]$r.ProfileId } } |
        Where-Object { $script:ProfileData.Contains($_) } | Select-Object -Unique)
    $targets = [ordered]@{}
    foreach ($id in $profIds) { $targets["Разрешённое ПО профиля «$($script:ProfileData[$id].Name)» ($id)"] = $script:ProfileData[$id].Soft }
    $targets['Общее разрешённое ПО (все профили)'] = $script:CommonSoft
    $n = Show-SoftwarePicker $null "ПО, не указанное в предписании (по результатам аудита; в графе «Издатель» – АРМ)" @($soft.Values | Sort-Object Name) $targets
    if ($n -gt 0) {
        $ans = [System.Windows.MessageBox]::Show("Добавлено шаблонов: $n. Сохранить эталон сейчас?`nИзменения учитываются при следующем аудите.", $AppName, 'YesNo', 'Question')
        if ($ans -eq 'Yes') { Save-Etalon; Show-Message 'Эталон сохранён' }
    }
}

function Import-Etalon {
    if (-not (Test-Path $Paths.Etalon)) { throw "Не найден эталонный файл: $($Paths.Etalon)" }
    $script:EtalonText = [IO.File]::ReadAllText($Paths.Etalon, [Text.Encoding]::UTF8)
    $x = New-Object System.Xml.XmlDocument
    $x.LoadXml($script:EtalonText)
    $script:Etalon = $x
    if ($NoGui) { Write-Log 'Эталонный файл конфигурации загружен'; return }

    Update-AuditProfileList

    $script:SziTable = New-TableFromNodes 'Szi' @('id', 'name', 'productPattern', 'minVersion', 'servicePattern',
        'sziClass', 'certNumber', 'certExpires') $x.SziEtalon.SziList.Szi
    # Графа «Обязательно для профилей» – обратное отображение элементов RequireSzi профилей
    [void]$script:SziTable.Columns.Add('profiles')
    foreach ($r in $script:SziTable.Rows) {
        $sid = [string]$r['id']
        $r['profiles'] = (@($x.SziEtalon.Profiles.Profile | Where-Object {
                    @(([string]$_.RequireSzi) -split ',' | ForEach-Object { $_.Trim() }) -contains $sid
                } | ForEach-Object { $_.GetAttribute('id') }) -join ', ')
    }
    $script:SziTable.AcceptChanges()
    Import-ProfileTables $x
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
    $profileIds = @()
    if ($script:Etalon) { $profileIds = @($script:Etalon.SziEtalon.Profiles.Profile | Where-Object { $_ } | ForEach-Object { $_.GetAttribute('id') }) }
    $hasProfiles = $script:SziTable.Columns.Contains('profiles')
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
        if (-not $hasProfiles) { continue }
        foreach ($prof in @(([string]$r['profiles']) -split '[,;\s]+' | Where-Object { $_ })) {
            if ($profileIds -notcontains $prof) {
                $errors += "СЗИ ${id}: неизвестный профиль «$prof». Допустимые коды: $($profileIds -join ', ')"
            }
        }
    }
    foreach ($r in $script:MediaTable.Rows) {
        if ($r.RowState -eq 'Deleted') { continue }
        if (-not ([string]$r['serial']).Trim()) { $errors += 'Не указан серийный номер носителя' }
    }
    return $errors
}

# Перечень обязательных СЗИ каждого профиля (RequireSzi) – из графы «Обязательно для профилей»
function Write-RequireSzi([System.Xml.XmlDocument]$x) {
    foreach ($p in @($x.DocumentElement.SelectNodes('Profiles/Profile'))) {
        $prof = $p.GetAttribute('id')
        $req = @(foreach ($r in $script:SziTable.Rows) {
                if ($r.RowState -eq 'Deleted') { continue }
                if (@(([string]$r['profiles']) -split '[,;\s]+') -contains $prof) { ([string]$r['id']).Trim() }
            })
        $node = $p.SelectSingleNode('RequireSzi')
        if (-not $node) { $node = $p.PrependChild($x.CreateElement('RequireSzi')) }
        $node.InnerText = ($req -join ',')
    }
}

function Save-Etalon {
    foreach ($g in 'dgSzi', 'dgMedia', 'dgProfileParams', 'dgProfileSoft', 'dgCommonSoft', 'dgAllowedUsers', 'dgAllowedAdmins', 'dgPwdNever', 'dgAuditPolicy') {
        [void]$Ui[$g].CommitEdit(); [void]$Ui[$g].CommitEdit()
    }
    Save-ProfileName
    $errors = @(Test-EtalonTables) + @(Test-ProfileTables)
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
            foreach ($c in $spec.Table.Columns) {
                if ($c.ColumnName -eq 'profiles') { continue }
                $el.SetAttribute($c.ColumnName, ([string]$r[$c.ColumnName]).Trim())
            }
            [void]$parent.AppendChild($el)
        }
    }
    Write-RequireSzi $x
    Write-ProfileTables $x
    $root.SetAttribute('updated', (Get-Date -Format 'yyyy-MM-dd'))

    $ws = New-Object System.Xml.XmlWriterSettings
    $ws.Indent = $true
    $ws.Encoding = New-Object System.Text.UTF8Encoding($false)
    $w = [System.Xml.XmlWriter]::Create($Paths.Etalon, $ws)
    try { $x.Save($w) } finally { $w.Close() }
    Write-Log "Эталон сохранён, предыдущая версия: Etalon_$stamp.xml"
    $unused = @($script:SziTable.Rows | Where-Object { $_.RowState -ne 'Deleted' -and -not ([string]$_['profiles']).Trim() } |
        ForEach-Object { ([string]$_['id']).Trim() })
    if ($unused.Count -gt 0) {
        Write-Log ("СЗИ не назначены ни одному профилю и при аудите не проверяются: " + ($unused -join ', ')) 'WARN'
    }
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

# ---------------------------------------------------------------------------
# Импорт и выгрузка журнала учёта МНИ (CSV, Excel)
# ---------------------------------------------------------------------------
# Чтение CSV: кодировка UTF-8 (с BOM или без) либо Windows-1251, разделитель «;», «,» или табуляция
function Read-CsvTable([string]$Path) {
    $bytes = [IO.File]::ReadAllBytes($Path)
    $utf8 = New-Object System.Text.UTF8Encoding($false, $true)
    try { $text = $utf8.GetString($bytes) } catch { $text = [Text.Encoding]::GetEncoding(1251).GetString($bytes) }
    $text = $text.TrimStart([char]0xFEFF)
    $lines = @($text -split "`r?`n" | Where-Object { $_.Trim() })
    if ($lines.Count -eq 0) { return , @() }
    $first = $lines[0]
    $delim = ';'
    $best = 0
    foreach ($d in ';', "`t", ',') {
        $n = ($first.ToCharArray() | Where-Object { $_ -eq $d }).Count
        if ($n -gt $best) { $best = $n; $delim = $d }
    }
    $rows = New-Object System.Collections.ArrayList
    foreach ($l in $lines) {
        # Разбор строки с учётом кавычек
        $cells = New-Object System.Collections.ArrayList
        $sb = New-Object System.Text.StringBuilder
        $q = $false
        for ($i = 0; $i -lt $l.Length; $i++) {
            $ch = $l[$i]
            if ($ch -eq '"') {
                if ($q -and $i + 1 -lt $l.Length -and $l[$i + 1] -eq '"') { [void]$sb.Append('"'); $i++ }
                else { $q = -not $q }
            }
            elseif ($ch -eq $delim -and -not $q) { [void]$cells.Add($sb.ToString()); [void]$sb.Clear() }
            else { [void]$sb.Append($ch) }
        }
        [void]$cells.Add($sb.ToString())
        [void]$rows.Add([string[]]$cells.ToArray())
    }
    return , $rows
}

# Чтение первого листа книги Excel .xlsx без установленного Excel (формат Office Open XML)
function Read-XlsxTable([string]$Path) {
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    # Тип загружается Add-Type – обращение через -as [type] (в PowerShell 5.1 тип не загружен по умолчанию)
    $zip = ('System.IO.Compression.ZipFile' -as [type])::OpenRead($Path)
    try {
        $readXml = {
            param($name)
            $e = $zip.GetEntry($name)
            if (-not $e) { return $null }
            $sr = New-Object IO.StreamReader($e.Open())
            try { $doc = New-Object System.Xml.XmlDocument; $doc.LoadXml($sr.ReadToEnd()); return $doc } finally { $sr.Close() }
        }
        $shared = @()
        $ss = & $readXml 'xl/sharedStrings.xml'
        if ($ss) {
            $ns = New-Object System.Xml.XmlNamespaceManager($ss.NameTable)
            $ns.AddNamespace('m', $ss.DocumentElement.NamespaceURI)
            $shared = @($ss.SelectNodes('/m:sst/m:si', $ns) | ForEach-Object {
                    (@($_.SelectNodes('.//m:t', $ns) | ForEach-Object { $_.InnerText }) -join '') })
        }
        # Путь к первому листу – из описания книги
        $sheetPath = 'xl/worksheets/sheet1.xml'
        $wb = & $readXml 'xl/workbook.xml'; $rels = & $readXml 'xl/_rels/workbook.xml.rels'
        if ($wb -and $rels) {
            $sheet = $wb.GetElementsByTagName('sheet') | Select-Object -First 1
            $rid = $sheet.GetAttribute('id', 'http://schemas.openxmlformats.org/officeDocument/2006/relationships')
            $rel = $rels.GetElementsByTagName('Relationship') | Where-Object { $_.GetAttribute('Id') -eq $rid } | Select-Object -First 1
            if ($rel) {
                $target = $rel.GetAttribute('Target')
                $sheetPath = if ($target.StartsWith('/')) { $target.TrimStart('/') } else { 'xl/' + $target }
            }
        }
        $sh = & $readXml $sheetPath
        if (-not $sh) { throw 'В книге Excel не найден первый лист' }
        $ns = New-Object System.Xml.XmlNamespaceManager($sh.NameTable)
        $ns.AddNamespace('m', $sh.DocumentElement.NamespaceURI)
        $rows = New-Object System.Collections.ArrayList
        foreach ($row in $sh.SelectNodes('//m:sheetData/m:row', $ns)) {
            $cells = @{}; $max = -1
            foreach ($c in $row.SelectNodes('m:c', $ns)) {
                $ref = $c.GetAttribute('r') -replace '\d', ''
                $col = 0; foreach ($ch in $ref.ToCharArray()) { $col = $col * 26 + ([int]$ch - 64) }
                $col--
                $type = $c.GetAttribute('t')
                $v = $c.SelectSingleNode('m:v', $ns)
                $val = if ($type -eq 's' -and $v) { $shared[[int]$v.InnerText] }
                       elseif ($type -eq 'inlineStr') { (@($c.SelectNodes('.//m:t', $ns) | ForEach-Object { $_.InnerText }) -join '') }
                       elseif ($v) { $v.InnerText } else { '' }
                $cells[$col] = [string]$val
                if ($col -gt $max) { $max = $col }
            }
            if ($max -lt 0) { continue }
            [void]$rows.Add([string[]]@(0..$max | ForEach-Object { if ($cells.ContainsKey($_)) { $cells[$_] } else { '' } }))
        }
        return , $rows
    }
    finally { $zip.Dispose() }
}

# Чтение старого формата .xls – через установленный Microsoft Excel
function Read-XlsTable([string]$Path) {
    try { $xl = New-Object -ComObject Excel.Application }
    catch { throw 'Для чтения файлов .xls требуется Microsoft Excel. Сохраните файл в формате .xlsx или .csv' }
    try {
        $xl.DisplayAlerts = $false
        $wb = $xl.Workbooks.Open($Path, 0, $true)
        $data = $wb.Worksheets.Item(1).UsedRange.Value2
        $wb.Close($false)
        $rows = New-Object System.Collections.ArrayList
        if ($data -is [array]) {
            for ($r = 1; $r -le $data.GetLength(0); $r++) {
                [void]$rows.Add([string[]]@(1..$data.GetLength(1) | ForEach-Object { [string]$data[$r, $_] }))
            }
        }
        elseif ($null -ne $data) { [void]$rows.Add([string[]]@([string]$data)) }
        return , $rows
    }
    finally { $xl.Quit(); [void][Runtime.InteropServices.Marshal]::ReleaseComObject($xl) }
}

# Сопоставление граф файла с графами журнала МНИ по заголовкам; без заголовка – графы 1, 2, 3
function ConvertFrom-MediaRows([System.Collections.IList]$Rows) {
    if (-not $Rows -or $Rows.Count -eq 0) { return @() }
    $map = @{ serial = -1; owner = -1; note = -1 }
    $patterns = @{
        serial = 'серийн|serial|s/n|^sn$|заводск'
        owner  = 'ответствен|владел|owner|фио|сотрудник|закреплен'
        note   = 'примечан|учётн|учетн|note|comment|инвентар|номер по журн|уч\.\s*№'
    }
    $head = @($Rows[0] | ForEach-Object { ([string]$_).Trim().ToLower() })
    for ($i = 0; $i -lt $head.Count; $i++) {
        foreach ($k in 'serial', 'owner', 'note') {
            if ($map[$k] -lt 0 -and $head[$i] -match $patterns[$k]) { $map[$k] = $i; break }
        }
    }
    $start = 1
    if ($map.serial -lt 0) {
        # Без заголовка: первая графа первой строки должна выглядеть как серийный номер
        if ([string]$Rows[0][0] -notmatch '^(?=.*\d)[\w\-]{4,}$') { throw 'В файле не найдена графа с серийным номером носителя' }
        $map = @{ serial = 0; owner = 1; note = 2 }; $start = 0
    }
    for ($r = $start; $r -lt $Rows.Count; $r++) {
        $row = @($Rows[$r])
        $get = { param($k) if ($map[$k] -ge 0 -and $map[$k] -lt $row.Count) { ([string]$row[$map[$k]]).Trim() } else { '' } }
        $serial = & $get 'serial'
        if (-not $serial) { continue }
        [pscustomobject]@{ serial = $serial; owner = (& $get 'owner'); note = (& $get 'note') }
    }
}

function Import-MediaFromFile {
    $dlg = New-Object Microsoft.Win32.OpenFileDialog
    $dlg.Filter = 'Журнал учёта МНИ (*.csv;*.xlsx;*.xls;*.txt)|*.csv;*.xlsx;*.xls;*.txt|Все файлы|*.*'
    if (-not $dlg.ShowDialog()) { return }
    $path = $dlg.FileName
    $ext = [IO.Path]::GetExtension($path).ToLower()
    if ($ext -eq '.xlsx') { $rows = Read-XlsxTable $path }
    elseif ($ext -eq '.xls') { $rows = Read-XlsTable $path }
    else { $rows = Read-CsvTable $path }
    $items = @(ConvertFrom-MediaRows $rows)
    if ($items.Count -eq 0) { throw 'В файле не найдено записей о носителях' }
    # Excel хранит длинные числовые серийные номера в экспоненциальной записи – они искажены
    $bad = @($items | Where-Object { $_.serial -match '^\d+([.,]\d+)?E\+\d+$' })
    if ($bad.Count -gt 0) {
        throw ("Серийные номера записаны в Excel как числа и искажены ({0} шт., например {1}).`n" +
            "Задайте для графы серийных номеров текстовый формат ячеек и введите номера заново либо сохраните файл в CSV.") -f `
            $bad.Count, $bad[0].serial
    }

    $ans = [System.Windows.MessageBox]::Show(
        ("В файле найдено носителей: {0}.`n`nДа – добавить к журналу (существующие записи с тем же серийным номером будут обновлены)." +
            "`nНет – заменить журнал содержимым файла.`nОтмена – не загружать.") -f $items.Count,
        $AppName, 'YesNoCancel', 'Question')
    if ($ans -eq 'Cancel') { return }
    if ($ans -eq 'No') { foreach ($r in @($script:MediaTable.Rows)) { if ($r.RowState -ne 'Deleted') { $r.Delete() } } }

    $index = @{}
    foreach ($r in $script:MediaTable.Rows) {
        if ($r.RowState -ne 'Deleted') { $index[([string]$r['serial']).Trim().ToUpper()] = $r }
    }
    $added = 0; $updated = 0
    foreach ($m in $items) {
        $key = $m.serial.ToUpper()
        if ($index.ContainsKey($key)) {
            $r = $index[$key]
            if ($m.owner) { $r['owner'] = $m.owner }
            if ($m.note) { $r['note'] = $m.note }
            $updated++
        }
        else {
            $r = $script:MediaTable.NewRow()
            $r['serial'] = $m.serial; $r['owner'] = $m.owner; $r['note'] = $m.note
            $script:MediaTable.Rows.Add($r)
            $index[$key] = $r; $added++
        }
    }
    Write-Log "Импорт МНИ из файла $(Split-Path $path -Leaf): добавлено $added, обновлено $updated"
    Show-Message "Импорт журнала МНИ: добавлено – $added, обновлено – $updated.`nПроверьте данные и сохраните эталон."
}

function Export-MediaToCsv {
    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $dlg.Filter = 'CSV (разделитель «;»)|*.csv'
    $dlg.FileName = 'Журнал_МНИ_{0:yyyyMMdd}.csv' -f (Get-Date)
    if (-not $dlg.ShowDialog()) { return }
    $script:MediaTable.Rows | Where-Object { $_.RowState -ne 'Deleted' } | ForEach-Object {
        [pscustomobject]@{ 'Серийный номер' = $_['serial']; 'Ответственный' = $_['owner']; 'Примечание (учётный номер)' = $_['note'] }
    } | Export-Csv -Path $dlg.FileName -NoTypeInformation -Encoding UTF8 -Delimiter ';'
    Write-Log "Журнал МНИ выгружен в файл $($dlg.FileName)"
}

# ============================================================================
# Выполнение аудита
# ============================================================================
$script:Jobs = @()
# ArrayList вместо List[object]: в ряде сборок Windows PowerShell 5.1 выражение @(List[object])
# завершается исключением «Типы аргумента не совпадают» (Argument types do not match)
$script:AllResults = New-Object System.Collections.ArrayList
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
    # Каждый элемент поля – отдельная запись: «ARM-01» (выбранный профиль) или «ARM-01=ARM_SPN»
    $entries = @($Ui.tbComputers.Text -split '[,;\s]+' | Where-Object { $_ })
    $targets = ConvertTo-AuditTargets $entries $profileId
    if ($targets.Count -eq 0) { $targets = ConvertTo-AuditTargets @('localhost') $profileId }

    $script:AllResults.Clear()
    $script:LastRuns = @{}
    $script:Jobs = @()
    foreach ($t in $targets) {
        $script:Jobs += [pscustomobject]@{ Computer = $t.Computer; Job = (New-AuditJob $t.Computer $t.ProfileId); Done = $false }
        Write-Log "Запущен аудит АРМ $($t.Computer) (профиль: $($t.ProfileName))"
    }
    $Ui.pbProgress.Maximum = $script:Jobs.Count
    $Ui.pbProgress.Value = 0
    $Ui.btnStart.IsEnabled = $false
    $Ui.btnReport.IsEnabled = $false
    $Ui.btnExport.IsEnabled = $false
    $Ui.dgResults.ItemsSource = $null
    $Timer.Start()
}

# Запись событий в журнал Windows «Приложение» (источник «СЗИ-Аудит»):
#   1000 – аудит выполнен; 1002 – ухудшение по сравнению с предыдущей проверкой; 1003 – аудит не выполнен
$EventSource = 'SZI-Audit'
function Write-AuditEvent([int]$Id, [string]$Type, [string]$Message) {
    try {
        if (-not $script:EventSourceReady) {
            if (-not [Diagnostics.EventLog]::SourceExists($EventSource)) {
                [Diagnostics.EventLog]::CreateEventSource($EventSource, 'Application')
            }
            $script:EventSourceReady = $true
        }
        if ($Message.Length -gt 30000) { $Message = $Message.Substring(0, 30000) + '…' }
        [Diagnostics.EventLog]::WriteEntry($EventSource, $Message, $Type, $Id)
    }
    catch { Add-Content -Path (Join-Path $Paths.Logs ('SziAudit_{0:yyyyMMdd}.log' -f (Get-Date))) -Encoding UTF8 `
            -Value ('{0:dd.MM.yyyy HH:mm:ss} [WARN] Не удалось записать событие в журнал Windows: {1}' -f (Get-Date), $_.Exception.Message) }
}

function Send-AuditEvents($Run, $Sum, $PrevRow) {
    $text = 'АРМ {0} (профиль: {1}): проверок {2}, несоответствий {3}, предупреждений {4}, ошибок {5}, индекс соответствия {6}%' -f `
        $Run.Computer, $Run.Profile, $Sum.Total, $Sum.Fail, $Sum.Warn, $Sum.Errors, $Sum.Index
    Write-AuditEvent 1000 'Information' $text
    if (-not $PrevRow -or $PrevRow.Profile -ne $Run.Profile) { return }
    $prevFile = Join-Path $Paths.Results $PrevRow.File
    if (-not (Test-Path $prevFile)) { return }
    try {
        $old = Import-Clixml -Path $prevFile
        $worse = @(Compare-AuditRuns $old $Run | Where-Object { $_.Change -like 'Ухудшение*' })
        $prevIdx = 0.0
        [void][double]::TryParse(([string]$PrevRow.Index).Replace(',', '.'), [Globalization.NumberStyles]::Float,
            [Globalization.CultureInfo]::InvariantCulture, [ref]$prevIdx)
        if ($worse.Count -eq 0 -and $Sum.Index -ge $prevIdx) { return }
        $lines = @("Ухудшение состояния защиты АРМ $($Run.Computer) по сравнению с проверкой от $($PrevRow.Date).",
            ('Индекс соответствия: {0}% → {1}%.' -f $PrevRow.Index, $Sum.Index))
        if ($worse.Count -gt 0) {
            $lines += "Новые несоответствия ($($worse.Count)):"
            $lines += @($worse | ForEach-Object { " – $($_.Name): $($_.After)" })
        }
        Write-AuditEvent 1002 'Warning' ($lines -join "`r`n")
        Write-Log "АРМ $($Run.Computer): выявлено ухудшение (новых несоответствий: $($worse.Count)), событие записано в журнал Windows" 'WARN'
    }
    catch { Write-Log "Не удалось сравнить с предыдущей проверкой: $($_.Exception.Message)" 'WARN' }
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
        Write-AuditEvent 1003 'Error' "АРМ $($Task.Computer): аудит не выполнен – $msg"
        [void]$script:AllResults.Add([pscustomobject]@{
            Computer = $Task.Computer; CheckId = 'CONNECT'; Category = 'Выполнение аудита'
            Name = 'Подключение к АРМ'; Expected = 'Аудит выполнен'; Actual = $msg; Status = $ST_ERR
            Severity = 'Высокая'; Recommendation = 'Проверить доступность АРМ и службы WinRM, права учётной записи'
            Time = Get-Date })
        return
    }
    $items = @($run.Results)
    foreach ($i in $items) { [void]$script:AllResults.Add($i) }
    $sum = Get-AuditSummary $items

    # Предыдущая проверка этого АРМ – для выявления ухудшений
    $prevRow = $null
    if (Test-Path $Paths.History) {
        $prevRow = @(Import-Csv -Path $Paths.History -Delimiter ';' -Encoding UTF8 |
                Where-Object { $_.Computer -eq $run.Computer }) | Select-Object -Last 1
    }
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $file = Join-Path $Paths.Results ('{0}_{1}.xml' -f $run.Computer, $stamp)
    $run | Export-Clixml -Path $file -Depth 4
    Send-AuditEvents $run $sum $prevRow
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
    $Ui.btnAllowSoft.IsEnabled = (@($all | Where-Object { $_.CheckId -eq 'SW-EXTRA' -and $_.PSObject.Properties['Details'] -and $_.Details }).Count -gt 0)
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
        # Полные перечни (например, ПО, не указанного в предписании)
        foreach ($i in @($items | Where-Object { $_.PSObject.Properties['Details'] -and $_.Details })) {
            $lines = @(([string]$i.Details) -split "`n" | Where-Object { $_ })
            [void]$sb.AppendLine(('<h3 style="font-size:12pt;margin-top:16px">{0} – полный перечень ({1})</h3>' -f (Get-HtmlText $i.Name), $lines.Count))
            [void]$sb.AppendLine('<table><tr><th style="width:40px">№</th><th>Наименование</th><th style="width:180px">Версия</th></tr>')
            $k = 0
            foreach ($l in $lines) {
                $k++; $parts = $l -split "`t", 2
                [void]$sb.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td></tr>' -f $k, (Get-HtmlText $parts[0]), (Get-HtmlText $(if ($parts.Count -gt 1) { $parts[1] } else { '' }))))
            }
            [void]$sb.AppendLine('</table>')
        }
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
        @{ n = 'Критичность'; e = { $_.Severity } }, @{ n = 'Рекомендация'; e = { $_.Recommendation } },
        @{ n = 'Полный перечень'; e = { if ($_.PSObject.Properties['Details']) { ([string]$_.Details).Replace("`t", ' ').Replace("`n", '; ') } } } |
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
# Разбор перечня АРМ с профилями. В строке – имена АРМ и, при необходимости, код профиля:
#   ARM-01;ARM_OPK      ARM-02 ARM_SPN      ARM-03=ARM_ADM      ARM-04 (профиль по умолчанию)
# Токен, совпадающий с кодом профиля, относится ко всем АРМ этой строки; «имя=профиль» – к одному АРМ.
function ConvertTo-AuditTargets([string[]]$Lines, [string]$DefaultProfile) {
    $ids = @($script:Etalon.SziEtalon.Profiles.Profile | ForEach-Object { $_.GetAttribute('id') })
    $seen = @{}
    $targets = New-Object System.Collections.ArrayList
    foreach ($line in @($Lines)) {
        $l = ([string]$line).Trim()
        if (-not $l -or $l.StartsWith('#')) { continue }
        $tokens = @($l -split '[,;\s]+' | Where-Object { $_ })
        $lineProfile = $tokens | Where-Object { $ids -contains $_ } | Select-Object -Last 1
        foreach ($t in $tokens) {
            if ($ids -contains $t) { continue }
            $hostName = $t; $prof = $lineProfile
            if ($t -match '^(?<h>[^=]+)=(?<p>.+)$') {
                $hostName = $Matches.h; $prof = $Matches.p
                if ($ids -notcontains $prof) { throw "АРМ ${hostName}: неизвестный профиль «$prof». Доступные профили: $($ids -join ', ')" }
            }
            if (-not $prof) { $prof = $DefaultProfile }
            if (-not $prof) { throw "Для АРМ $hostName не указан профиль. Укажите его в перечне (например, «$hostName;$($ids[0])») или параметром -ProfileId" }
            if ($ids -notcontains $prof) { throw "Неизвестный профиль «$prof». Доступные профили: $($ids -join ', ')" }
            $key = $hostName.ToUpper()
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true
            $name = [string]($script:Etalon.SziEtalon.Profiles.Profile | Where-Object { $_.GetAttribute('id') -eq $prof } |
                    Select-Object -First 1).GetAttribute('name')
            [void]$targets.Add([pscustomobject]@{ Computer = $hostName; ProfileId = $prof; ProfileName = $name })
        }
    }
    return , $targets
}

function Invoke-ConsoleAudit {
    Import-Etalon
    $ids = @($script:Etalon.SziEtalon.Profiles.Profile | ForEach-Object { $_.GetAttribute('id') })
    if ($ProfileId -and $ids -notcontains $ProfileId) {
        throw ("Неизвестный профиль «$ProfileId». Доступные профили: " + ($ids -join ', '))
    }
    $list = @($Computers)
    if ($FromDomain) {
        $base = $SearchBase
        if (-not $base) { $base = [string]$script:Etalon.SziEtalon.SelectSingleNode('Settings/DomainSearchBase').InnerText }
        $list = @(Get-DomainComputers $base | ForEach-Object { $_.Host })
        Write-Log "Из домена получено компьютеров: $($list.Count)"
    }
    elseif ($ComputersFile) {
        $list = @(Get-Content -Path $ComputersFile -Encoding UTF8)
    }
    $targets = ConvertTo-AuditTargets $list $ProfileId
    if ($targets.Count -eq 0) { $targets = ConvertTo-AuditTargets @('localhost') $ProfileId }

    $tasks = @(foreach ($t in $targets) {
        Write-Log "Запущен аудит АРМ $($t.Computer) (профиль: $($t.ProfileName))"
        [pscustomobject]@{ Computer = $t.Computer; Job = (New-AuditJob $t.Computer $t.ProfileId); Done = $false }
    })
    $list = @($targets)
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
    Write-Log "Запуск $AppName $AppVersion (консольный режим), пользователь $env:USERDOMAIN\$env:USERNAME"
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
            $sel = if ($Ui.cbProfile.SelectedItem) { [string]$Ui.cbProfile.SelectedItem.Tag } else { '' }
            $targets = ConvertTo-AuditTargets @(Get-Content -Path $dlg.FileName -Encoding UTF8) $sel
            $Ui.tbComputers.Text = (@($targets | ForEach-Object {
                        if ($_.ProfileId -eq $sel) { $_.Computer } else { "$($_.Computer)=$($_.ProfileId)" } }) -join ', ')
        }
    }
})
$Ui.btnHistRefresh.Add_Click({ Invoke-Safe { Import-History } })
$Ui.btnHistShow.Add_Click({
    Invoke-Safe {
        $sel = Get-SelectedRun
        $script:AllResults.Clear()
        foreach ($i in @($sel.Run.Results)) { [void]$script:AllResults.Add($i) }
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
$Ui.btnMediaImport.Add_Click({ Invoke-Safe { Import-MediaFromFile } })
$Ui.btnMediaExport.Add_Click({ Invoke-Safe { Export-MediaToCsv } })
$Ui.cbEditProfile.Add_SelectionChanged({ Invoke-Safe { Show-EditProfile } })
$Ui.btnProfileSave.Add_Click({ Invoke-Safe { Save-Etalon; Show-Message 'Эталон сохранён' } })
$Ui.btnProfileReload.Add_Click({ Invoke-Safe { Import-Etalon } })
$Ui.btnSoftPickProfile.Add_Click({
    Invoke-Safe {
        if (-not $script:EditProfileId) { throw 'Выберите профиль АРМ' }
        $d = $script:ProfileData[$script:EditProfileId]
        Show-SoftwarePicker $d.Soft "Разрешённое ПО профиля «$($Ui.tbProfileName.Text)»"
    }
})
$Ui.btnSoftPickCommon.Add_Click({ Invoke-Safe { Show-SoftwarePicker $script:CommonSoft 'Общее разрешённое ПО (для всех профилей)' } })
$Ui.btnSoftDelProfile.Add_Click({ Invoke-Safe { Remove-SelectedRows $Ui.dgProfileSoft } })
$Ui.btnSoftDelCommon.Add_Click({ Invoke-Safe { Remove-SelectedRows $Ui.dgCommonSoft } })
$Ui.btnAllowSoft.Add_Click({ Invoke-Safe { Show-AllowExtraSoftware } })
$Ui.btnSchedule.Add_Click({ Invoke-Safe { Show-ScheduleDialog } })
$Ui.btnProfileNew.Add_Click({ Invoke-Safe { New-EtalonProfile '' } })
$Ui.btnProfileCopy.Add_Click({ Invoke-Safe { if (-not $script:EditProfileId) { throw 'Выберите профиль АРМ' }; New-EtalonProfile $script:EditProfileId } })
$Ui.btnProfileDelete.Add_Click({ Invoke-Safe { Remove-EtalonProfile } })
$Ui.btnUsersPick.Add_Click({ Invoke-Safe { Add-LocalUsersToProfile } })
$Ui.btnAuditAdd.Add_Click({ Invoke-Safe { Add-AuditPolicyItem } })
$Ui.btnAuditDel.Add_Click({ Invoke-Safe { Remove-SelectedRows $Ui.dgAuditPolicy } })
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
