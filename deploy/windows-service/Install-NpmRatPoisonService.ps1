[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PublishRoot,

    [string]$ServiceName = 'NpmRatPoison',

    [string]$DisplayName = 'NpmRatPoison',

    [string]$Urls = 'http://0.0.0.0:5100',

    [string]$EnvironmentName = 'Production',

    [ValidateSet('postgres', 'sqlite')]
    [string]$DatabaseProvider = 'postgres',

    [Parameter(Mandatory = $true)]
    [string]$ProviderIngressConnectionString,

    [switch]$ApplyProviderIngressMigrations,

    [switch]$StartService
)

$ErrorActionPreference = 'Stop'

$resolvedPublishRoot = (Resolve-Path -LiteralPath $PublishRoot).Path
$exePath = Join-Path $resolvedPublishRoot 'NpmRatPoison.exe'
$productionConfigPath = Join-Path $resolvedPublishRoot 'appsettings.Production.json'

if (-not (Test-Path -LiteralPath $exePath)) {
    throw "Could not find NpmRatPoison.exe under '$resolvedPublishRoot'. Publish the app first."
}

$serviceCommand = "`"$exePath`" --ui --service --urls $Urls"
$serviceRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    throw "Service '$ServiceName' already exists. Remove or rename it before running this script."
}

New-Service -Name $ServiceName -BinaryPathName $serviceCommand -DisplayName $DisplayName -StartupType Automatic | Out-Null

New-ItemProperty -Path $serviceRegistryPath -Name 'Description' -Value 'NpmRatPoison operations dashboard, provider ingress API, and background scan service.' -PropertyType String -Force | Out-Null

$productionConfig = @{
    ConnectionStrings = @{
        ProviderIngress = $ProviderIngressConnectionString
    }
    ProviderIngress = @{
        DatabaseProvider = $DatabaseProvider
    }
} | ConvertTo-Json -Depth 4

Set-Content -LiteralPath $productionConfigPath -Value $productionConfig -Encoding UTF8

if ($ApplyProviderIngressMigrations) {
    & $exePath --apply-provider-ingress-migrations
}

if ($StartService) {
    Start-Service -Name $ServiceName
}

Write-Host "Service '$ServiceName' installed."
Write-Host "Binary: $exePath"
Write-Host "Urls: $Urls"
Write-Host "DatabaseProvider: $DatabaseProvider"
Write-Host "ProductionConfig: $productionConfigPath"
