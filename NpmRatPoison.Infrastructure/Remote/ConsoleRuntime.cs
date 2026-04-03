public interface IConsoleRuntime
{
    bool IsInputRedirected { get; }

    void WriteLine();

    void WriteLine(string value);

    void Write(string value);

    ConsoleKeyInfo ReadKey(bool intercept);
}

public sealed class SystemConsoleRuntime : IConsoleRuntime
{
    public bool IsInputRedirected => Console.IsInputRedirected;

    public void WriteLine()
    {
        Console.WriteLine();
    }

    public void WriteLine(string value)
    {
        Console.WriteLine(value);
    }

    public void Write(string value)
    {
        Console.Write(value);
    }

    public ConsoleKeyInfo ReadKey(bool intercept)
    {
        return Console.ReadKey(intercept);
    }
}
