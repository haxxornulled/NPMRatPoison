# Operator Runbook

## Local Triage

```powershell
dotnet run --project .\NpmRatPoison\NpmRatPoison.csproj -- --path <repo> --dry-run --report-dir .\artifacts\manual
```

Use this first when a single repository is in scope.

## Provider Ingress Database

Apply PostgreSQL migrations before enabling a public provider feed:

```powershell
dotnet run --project .\NpmRatPoison\NpmRatPoison.csproj -- --apply-provider-ingress-migrations
```

For SQLite local/dev usage, the same command ensures the schema exists.

## All-Drive Discovery

```powershell
dotnet run --project .\NpmRatPoison\NpmRatPoison.csproj -- --all-drives --report-dir .\artifacts\all-drives
```

Use this for workstation-wide repo discovery and triage.

## Remote GitHub Scan

```powershell
dotnet run --project .\NpmRatPoison\NpmRatPoison.csproj -- --remote-github-scan --remote-github-repo owner/name
```

Use a PAT via prompt, `--github-token`, or `GITHUB_TOKEN`.

## Blazor Dashboard

```powershell
dotnet run --project .\NpmRatPoison\NpmRatPoison.csproj -- --ui
```

The dashboard lets operators:

- launch scoped dry-runs
- launch all-drive dry-runs
- launch remote GitHub scans
- open the latest HTML/JSON/CSV artifacts

## Windows Service Host

Publish and install the combined dashboard + ingress + background service host with the deployment assets in [docs/windows-service-deployment.md](c:/Visual%20Studio%20Projects/NpmRatPoison/docs/windows-service-deployment.md).

## Interpreting Results

- `Critical`: live indicators, quarantined lockfiles, or remediation/removal actions occurred.
- `Warning`: access blockers or scan gaps need to be resolved before the repo can be considered clean.
- `Informational`: git breadcrumbs only.
- `None`: no actionable findings in the scan scope.

## Immediate Next Actions for Critical Results

1. Regenerate dependency lockfiles from a trusted registry.
2. Rotate secrets that may have touched affected workstations or CI runners.
3. Triage impacted hosts separately from repository cleanup.
4. Preserve HTML/JSON artifacts for incident tracking.
