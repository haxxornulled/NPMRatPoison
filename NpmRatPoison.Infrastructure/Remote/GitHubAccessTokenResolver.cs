public sealed class GitHubAccessTokenResolver : IGitHubAccessTokenResolver
{
    private readonly IGitHubCredentialPrompt _credentialPrompt;

    public GitHubAccessTokenResolver(IGitHubCredentialPrompt credentialPrompt)
    {
        _credentialPrompt = credentialPrompt;
    }

    public string? ResolveAccessToken(string? configuredAccessToken)
    {
        if (!string.IsNullOrWhiteSpace(configuredAccessToken))
        {
            return configuredAccessToken;
        }

        return _credentialPrompt.PromptForAccessToken();
    }
}
