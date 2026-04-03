using System.Text;

public sealed class ConsoleGitHubCredentialPrompt : IGitHubCredentialPrompt
{
    private readonly IConsoleRuntime _consoleRuntime;

    public ConsoleGitHubCredentialPrompt(IConsoleRuntime consoleRuntime)
    {
        _consoleRuntime = consoleRuntime;
    }

    public string? PromptForAccessToken()
    {
        if (_consoleRuntime.IsInputRedirected)
        {
            return null;
        }

        _consoleRuntime.WriteLine();
        _consoleRuntime.WriteLine("GitHub authentication");
        _consoleRuntime.WriteLine("Enter a GitHub personal access token to scan private repos or raise API limits.");
        _consoleRuntime.Write("Token (press Enter to continue unauthenticated): ");

        var builder = new StringBuilder();
        while (true)
        {
            var key = _consoleRuntime.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                _consoleRuntime.WriteLine();
                break;
            }

            if (key.Key == ConsoleKey.Backspace)
            {
                if (builder.Length == 0)
                {
                    continue;
                }

                builder.Length--;
                continue;
            }

            if (!char.IsControl(key.KeyChar))
            {
                builder.Append(key.KeyChar);
            }
        }

        var token = builder.ToString().Trim();
        return string.IsNullOrWhiteSpace(token) ? null : token;
    }
}
