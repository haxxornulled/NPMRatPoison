public sealed class ScanDashboardState
{
    private readonly Lock _sync = new();
    private DashboardLifecycleSnapshot _lifecycle = new("Starting", DateTimeOffset.UtcNow, "Initializing dashboard", null);
    private List<DashboardRunSnapshot> _runs = [];
    private List<DashboardArtifactFile> _artifacts = [];

    public event Action? Changed;

    public DashboardLifecycleSnapshot GetLifecycle()
    {
        lock (_sync)
        {
            return _lifecycle;
        }
    }

    public IReadOnlyList<DashboardRunSnapshot> GetRuns()
    {
        lock (_sync)
        {
            return _runs.ToList();
        }
    }

    public IReadOnlyList<DashboardArtifactFile> GetArtifacts()
    {
        lock (_sync)
        {
            return _artifacts.ToList();
        }
    }

    public void SetLifecycle(string phase, string message, string? baseAddress = null)
    {
        lock (_sync)
        {
            _lifecycle = new DashboardLifecycleSnapshot(phase, DateTimeOffset.UtcNow, message, baseAddress);
        }

        Changed?.Invoke();
    }

    public DashboardRunSnapshot StartRun(string title, string mode)
    {
        DashboardRunSnapshot snapshot;
        lock (_sync)
        {
            snapshot = new DashboardRunSnapshot(
                Guid.NewGuid(),
                title,
                mode,
                "Running",
                DateTimeOffset.UtcNow,
                null,
                null,
                "Scan started",
                []);
            _runs = [snapshot, .. _runs.Take(19)];
        }

        Changed?.Invoke();
        return snapshot;
    }

    public void CompleteRun(Guid id, int exitCode, string summary, IEnumerable<string> reportFiles)
    {
        UpdateRun(id, "Completed", exitCode, summary, reportFiles);
    }

    public void FailRun(Guid id, string summary, IEnumerable<string>? reportFiles = null)
    {
        UpdateRun(id, "Failed", ScanExitCodeEvaluator.ExecutionErrors, summary, reportFiles ?? []);
    }

    public void ReplaceArtifacts(IEnumerable<DashboardArtifactFile> artifacts)
    {
        lock (_sync)
        {
            _artifacts = artifacts.ToList();
        }

        Changed?.Invoke();
    }

    private void UpdateRun(Guid id, string status, int exitCode, string summary, IEnumerable<string> reportFiles)
    {
        lock (_sync)
        {
            _runs = _runs
                .Select(run => run.Id == id
                    ? run with
                    {
                        Status = status,
                        CompletedUtc = DateTimeOffset.UtcNow,
                        ExitCode = exitCode,
                        Summary = summary,
                        ReportFiles = reportFiles.ToList()
                    }
                    : run)
                .ToList();
        }

        Changed?.Invoke();
    }
}

public sealed record DashboardLifecycleSnapshot(
    string Phase,
    DateTimeOffset UpdatedUtc,
    string Message,
    string? BaseAddress);

public sealed record DashboardRunSnapshot(
    Guid Id,
    string Title,
    string Mode,
    string Status,
    DateTimeOffset StartedUtc,
    DateTimeOffset? CompletedUtc,
    int? ExitCode,
    string Summary,
    List<string> ReportFiles);

public sealed record DashboardArtifactFile(
    string Name,
    string Url,
    DateTimeOffset LastWriteTimeUtc);
