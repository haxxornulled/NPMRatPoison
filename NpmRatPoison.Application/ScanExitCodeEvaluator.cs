public static class ScanExitCodeEvaluator
{
    public const int Success = 0;
    public const int InvalidArguments = 2;
    public const int InformationalFindings = 10;
    public const int WarningFindings = 20;
    public const int CriticalFindings = 30;
    public const int ExecutionErrors = 40;

    public static int GetExitCode(object report)
    {
        var severity = report switch
        {
            CleanupReport cleanupReport => cleanupReport.GetSeverity(),
            AllDriveScanReport allDriveScanReport => allDriveScanReport.GetSeverity(),
            AutoTriageReport autoTriageReport => autoTriageReport.GetSeverity(),
            RemoteGitHubScanReport remoteGitHubScanReport => remoteGitHubScanReport.GetSeverity(),
            _ => ScanSeverity.None
        };

        return severity switch
        {
            ScanSeverity.None => Success,
            ScanSeverity.Informational => InformationalFindings,
            ScanSeverity.Warning => WarningFindings,
            ScanSeverity.Critical => CriticalFindings,
            ScanSeverity.Error => ExecutionErrors,
            _ => Success
        };
    }
}
