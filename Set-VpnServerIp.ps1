param(
    [Parameter(Position = 0)]
    [string]$Country,
    [Parameter(Position = 1)]
    [string]$NewIp,
    [switch]$CheckOnly
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($Country)) {
    $Country = Read-Host 'Страна fi/us/tr [fi]'
    if ([string]::IsNullOrWhiteSpace($Country)) { $Country = 'fi' }
}
$Country = $Country.Trim().ToLowerInvariant()
if ($Country -notin @('fi', 'us', 'tr')) {
    [Console]::Error.WriteLine('Страна должна быть fi, us или tr.')
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
    Write-Host 'Проверяю и применяю смену IP сервера VPN.'
}
$PythonArgs = @($Tool, '--server', $Country, '--new-ip', $NewIp)
if (-not $CheckOnly) { $PythonArgs += '--apply' }
& $Python @PythonArgs
$ExitCode = $LASTEXITCODE
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
