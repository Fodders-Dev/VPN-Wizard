param(
    [Parameter(Position = 0)]
    [string]$Country,
    [Parameter(Position = 1)]
    [string]$NewIp,
    [switch]$CheckOnly
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($Country)) {
    $Country = Read-Host 'Страна nl/fi/us/tr [fi]'
    if ([string]::IsNullOrWhiteSpace($Country)) { $Country = 'fi' }
}
$Country = $Country.Trim().ToLowerInvariant()
if ($Country -notin @('nl', 'fi', 'us', 'tr')) {
    [Console]::Error.WriteLine('Страна должна быть nl, fi, us или tr.')
    exit 2
}

if ([string]::IsNullOrWhiteSpace($NewIp)) {
    $NewIp = Read-Host 'Новый публичный IPv4'
}
if ([string]::IsNullOrWhiteSpace($NewIp)) {
    [Console]::Error.WriteLine('Новый IP не указан.')
    exit 2
}

$Python = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
$Tool = Join-Path $PSScriptRoot 'deploy\scripts\change-exit-ip.py'
if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    [Console]::Error.WriteLine('Не найден Python проекта: ' + $Python)
    exit 2
}
if (-not (Test-Path -LiteralPath $Tool -PathType Leaf)) {
    [Console]::Error.WriteLine('Не найден инструмент смены IP.')
    exit 2
}

if ($CheckOnly) {
    Write-Host 'Проверяю SSH, ключи AWG и план обновления. Изменений не будет.'
} else {
    if ($Country -eq 'nl') {
        Write-Host 'Проверяю и применяю смену публичного IP Нидерландов, сайта и VPN-ссылок.'
    } else {
        Write-Host 'Проверяю и применяю смену IP сервера VPN.'
    }
}
$PythonArgs = @($Tool, '--server', $Country, '--new-ip', $NewIp)
if (-not $CheckOnly) { $PythonArgs += '--apply' }
$OutputLines = @(& $Python @PythonArgs)
$ExitCode = $LASTEXITCODE
$OutputLines | ForEach-Object { Write-Output $_ }
if (-not $CheckOnly -and $Country -eq 'nl') {
    foreach ($Line in $OutputLines) {
        try { $Report = $Line | ConvertFrom-Json -ErrorAction Stop } catch { continue }
        if ($Report.botfather_actions -and $Report.botfather_actions.Count -ge 2) {
            $Domain = (($NewIp.Trim() -replace '\.', '-') + '.nip.io')
            Write-Host ('Сайт: https://' + $Domain + '/connect/join.html')
            Write-Host ('Портал: https://' + $Domain + '/portal/')
            Write-Host ('BotFather вручную: ' + $Report.botfather_actions[0])
            Write-Host ('BotFather вручную: MainAppURL https://' + $Domain + '/portal/')
        }
    }
}
if ($ExitCode -ne 0) {
    [Console]::Error.WriteLine('Операция завершилась ошибкой. Проверьте сообщение выше.')
    exit $ExitCode
}
if ($CheckOnly) {
    Write-Host 'Проверка завершена.'
} else {
    Write-Host 'Операция завершена.'
}
exit 0
