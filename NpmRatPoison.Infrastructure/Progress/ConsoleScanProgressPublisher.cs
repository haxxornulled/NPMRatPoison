public sealed class ConsoleScanProgressPublisher : IScanProgressPublisher
{
    private static readonly Lock Sync = new();

    public void Publish(string stage, string? drive, string? path, string message)
    {
        var driveText = string.IsNullOrWhiteSpace(drive) ? string.Empty : $" drive={drive}";
        var pathText = string.IsNullOrWhiteSpace(path) ? string.Empty : $" path={path}";

        lock (Sync)
        {
            Console.WriteLine($"[{DateTimeOffset.Now:HH:mm:ss}] [{stage}] {message}{driveText}{pathText}");
        }
    }
}
