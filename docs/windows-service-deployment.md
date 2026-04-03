# Windows Service Deployment

## Publish

```powershell
dotnet publish .\NpmRatPoison\NpmRatPoison.csproj /p:PublishProfile=WindowsService
```

The publish profile writes a self-contained single-file build to `.\artifacts\publish\windows-service`.

## Apply Provider Ingress Migrations

For PostgreSQL-backed production deployment:

```powershell
.\artifacts\publish\windows-service\NpmRatPoison.exe --apply-provider-ingress-migrations
```

For SQLite local/dev usage, the same command ensures the local schema exists.

## Install As a Windows Service

Run the install script from an elevated PowerShell session:

```powershell
.\deploy\windows-service\Install-NpmRatPoisonService.ps1 `
  -PublishRoot .\artifacts\publish\windows-service `
  -ProviderIngressConnectionString 'Host=postgres.example;Port=5432;Database=npmratpoison;Username=npmratpoison;Password=<secret>' `
  -ApplyProviderIngressMigrations `
  -StartService
```

The installed service runs:

```text
NpmRatPoison.exe --ui --service --urls http://0.0.0.0:5100
```

That means one service process hosts:

- the Blazor operations dashboard
- the provider ingress API
- the background scan loop

The installer also writes an `appsettings.Production.json` file beside `NpmRatPoison.exe` so the PostgreSQL connection string and provider selection live with the deployed service in a predictable way.

## Config Files

Use [deploy/windows-service/appsettings.Production.template.json](c:/Visual%20Studio%20Projects/NpmRatPoison/deploy/windows-service/appsettings.Production.template.json) as the baseline shape if you manage production configuration outside the install script.

Use a secret store or your normal secure configuration mechanism for the PostgreSQL connection string in production.
