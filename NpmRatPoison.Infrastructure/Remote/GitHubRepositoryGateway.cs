using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

public sealed class GitHubRepositoryGateway : IGitHubRepositoryGateway
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    private readonly HttpClient _httpClient;

    public GitHubRepositoryGateway(HttpClient httpClient)
    {
        _httpClient = httpClient;
        if (!_httpClient.DefaultRequestHeaders.UserAgent.Any())
        {
            _httpClient.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("NpmRatPoison", "1.0"));
        }

        if (!_httpClient.DefaultRequestHeaders.Accept.Any())
        {
            _httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        }
    }

    public async Task<IReadOnlyList<string>> ResolveRepositoryNamesAsync(RemoteGitHubScanRequest request, CancellationToken cancellationToken = default)
    {
        var repositories = new HashSet<string>(request.RepositoryNames.Where(name => !string.IsNullOrWhiteSpace(name)), StringComparer.OrdinalIgnoreCase);

        if (!string.IsNullOrWhiteSpace(request.Organization))
        {
            await foreach (var repository in EnumerateRepositoriesAsync($"/orgs/{request.Organization}/repos", request.AccessToken, cancellationToken))
            {
                repositories.Add(repository);
            }
        }

        if (!string.IsNullOrWhiteSpace(request.User))
        {
            await foreach (var repository in EnumerateRepositoriesAsync($"/users/{request.User}/repos", request.AccessToken, cancellationToken))
            {
                repositories.Add(repository);
            }
        }

        return repositories.OrderBy(name => name, StringComparer.OrdinalIgnoreCase).ToList();
    }

    public async Task<GitHubRepositoryDescriptor> GetRepositoryAsync(string repositoryFullName, string? accessToken, CancellationToken cancellationToken = default)
    {
        using var response = await SendAsync(HttpMethod.Get, $"/repos/{repositoryFullName}", accessToken, cancellationToken);
        var payload = await DeserializeAsync<GitHubRepositoryResponse>(response, cancellationToken)
                      ?? throw new InvalidOperationException($"GitHub repository payload was empty for '{repositoryFullName}'.");

        return new GitHubRepositoryDescriptor(
            payload.FullName ?? repositoryFullName,
            payload.DefaultBranch ?? "main",
            payload.Private,
            payload.Archived,
            payload.HtmlUrl ?? $"https://github.com/{repositoryFullName}");
    }

    public async Task<GitHubRepositoryTree> GetRepositoryTreeAsync(string repositoryFullName, string gitReference, string? accessToken, CancellationToken cancellationToken = default)
    {
        using var response = await SendAsync(
            HttpMethod.Get,
            $"/repos/{repositoryFullName}/git/trees/{Uri.EscapeDataString(gitReference)}?recursive=1",
            accessToken,
            cancellationToken);

        var payload = await DeserializeAsync<GitHubTreeResponse>(response, cancellationToken)
                      ?? throw new InvalidOperationException($"GitHub tree payload was empty for '{repositoryFullName}'.");

        var files = payload.Tree?
            .Where(item => string.Equals(item.Type, "blob", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(item.Path))
            .Select(item => item.Path!)
            .ToList()
            ?? [];

        return new GitHubRepositoryTree(files, payload.Truncated);
    }

    public async Task<GitHubContentFile?> GetContentFileAsync(string repositoryFullName, string path, string gitReference, string? accessToken, CancellationToken cancellationToken = default)
    {
        var escapedPath = string.Join("/", path.Split('/').Select(Uri.EscapeDataString));
        using var response = await SendAsync(
            HttpMethod.Get,
            $"/repos/{repositoryFullName}/contents/{escapedPath}?ref={Uri.EscapeDataString(gitReference)}",
            accessToken,
            cancellationToken,
            allowNotFound: true);

        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }

        var payload = await DeserializeAsync<GitHubContentResponse>(response, cancellationToken)
                      ?? throw new InvalidOperationException($"GitHub contents payload was empty for '{repositoryFullName}:{path}'.");

        if (!string.Equals(payload.Type, "file", StringComparison.OrdinalIgnoreCase) || string.IsNullOrWhiteSpace(payload.Content))
        {
            return null;
        }

        var normalizedContent = payload.Content.Replace("\n", string.Empty).Replace("\r", string.Empty);
        var bytes = Convert.FromBase64String(normalizedContent);
        return new GitHubContentFile(payload.Path ?? path, Encoding.UTF8.GetString(bytes));
    }

    public async Task<IReadOnlyList<GitHubCommitSummary>> GetRecentDependencyCommitsAsync(string repositoryFullName, string? accessToken, CancellationToken cancellationToken = default)
    {
        var pathQueries = new[]
        {
            "package.json",
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml"
        };

        var commits = new Dictionary<string, GitHubCommitSummary>(StringComparer.OrdinalIgnoreCase);
        foreach (var path in pathQueries)
        {
            using var response = await SendAsync(
                HttpMethod.Get,
                $"/repos/{repositoryFullName}/commits?path={Uri.EscapeDataString(path)}&per_page=25",
                accessToken,
                cancellationToken);

            var payload = await DeserializeAsync<List<GitHubCommitResponse>>(response, cancellationToken) ?? [];
            foreach (var commit in payload)
            {
                if (string.IsNullOrWhiteSpace(commit.Sha)
                    || string.IsNullOrWhiteSpace(commit.Commit?.Committer?.Date))
                {
                    continue;
                }

                if (!DateTimeOffset.TryParse(commit.Commit.Committer.Date, out var parsed))
                {
                    continue;
                }

                commits[commit.Sha] = new GitHubCommitSummary(
                    commit.Sha,
                    parsed.ToUniversalTime(),
                    commit.Commit?.Message ?? string.Empty);
            }
        }

        return commits.Values
            .OrderByDescending(item => item.TimestampUtc)
            .Take(50)
            .ToList();
    }

    public async Task<IReadOnlyList<string>> GetCommitDiffLinesAsync(string repositoryFullName, string commitSha, string? accessToken, CancellationToken cancellationToken = default)
    {
        using var response = await SendAsync(HttpMethod.Get, $"/repos/{repositoryFullName}/commits/{commitSha}", accessToken, cancellationToken);
        var payload = await DeserializeAsync<GitHubCommitDetailResponse>(response, cancellationToken)
                      ?? throw new InvalidOperationException($"GitHub commit payload was empty for '{repositoryFullName}:{commitSha}'.");

        var lines = new List<string>();
        foreach (var file in payload.Files ?? [])
        {
            if (string.IsNullOrWhiteSpace(file.Filename))
            {
                continue;
            }

            if (!IsDependencyFile(file.Filename))
            {
                continue;
            }

            if (string.IsNullOrWhiteSpace(file.Patch))
            {
                continue;
            }

            foreach (var line in file.Patch.Split('\n'))
            {
                lines.Add(line.TrimEnd('\r'));
            }
        }

        return lines;
    }

    private async IAsyncEnumerable<string> EnumerateRepositoriesAsync(string relativePath, string? accessToken, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var page = 1;
        while (true)
        {
            using var response = await SendAsync(HttpMethod.Get, $"{relativePath}?per_page=100&page={page}", accessToken, cancellationToken);
            var payload = await DeserializeAsync<List<GitHubRepositoryResponse>>(response, cancellationToken) ?? [];
            if (payload.Count == 0)
            {
                yield break;
            }

            foreach (var repository in payload)
            {
                if (!string.IsNullOrWhiteSpace(repository.FullName))
                {
                    yield return repository.FullName;
                }
            }

            page++;
        }
    }

    private async Task<HttpResponseMessage> SendAsync(HttpMethod method, string relativePath, string? accessToken, CancellationToken cancellationToken, bool allowNotFound = false)
    {
        using var request = new HttpRequestMessage(method, new Uri(relativePath, UriKind.Relative));
        request.Headers.Add("X-GitHub-Api-Version", "2022-11-28");
        if (!string.IsNullOrWhiteSpace(accessToken))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        }

        var response = await _httpClient.SendAsync(request, cancellationToken);
        if (allowNotFound && response.StatusCode == HttpStatusCode.NotFound)
        {
            return response;
        }

        response.EnsureSuccessStatusCode();
        return response;
    }

    private static async Task<T?> DeserializeAsync<T>(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        return await JsonSerializer.DeserializeAsync<T>(stream, SerializerOptions, cancellationToken);
    }

    private static bool IsDependencyFile(string path)
    {
        var fileName = Path.GetFileName(path);
        return string.Equals(fileName, "package.json", StringComparison.OrdinalIgnoreCase)
               || string.Equals(fileName, "package-lock.json", StringComparison.OrdinalIgnoreCase)
               || string.Equals(fileName, "yarn.lock", StringComparison.OrdinalIgnoreCase)
               || string.Equals(fileName, "pnpm-lock.yaml", StringComparison.OrdinalIgnoreCase);
    }

    private sealed class GitHubRepositoryResponse
    {
        public string? FullName { get; set; }
        public string? DefaultBranch { get; set; }
        public bool Private { get; set; }
        public bool Archived { get; set; }
        public string? HtmlUrl { get; set; }
    }

    private sealed class GitHubTreeResponse
    {
        public bool Truncated { get; set; }
        public List<GitHubTreeItem>? Tree { get; set; }
    }

    private sealed class GitHubTreeItem
    {
        public string? Path { get; set; }
        public string? Type { get; set; }
    }

    private sealed class GitHubContentResponse
    {
        public string? Type { get; set; }
        public string? Path { get; set; }
        public string? Content { get; set; }
    }

    private sealed class GitHubCommitResponse
    {
        public string? Sha { get; set; }
        public GitHubCommitMetadata? Commit { get; set; }
    }

    private sealed class GitHubCommitMetadata
    {
        public string? Message { get; set; }
        public GitHubCommitPerson? Committer { get; set; }
    }

    private sealed class GitHubCommitPerson
    {
        public string? Date { get; set; }
    }

    private sealed class GitHubCommitDetailResponse
    {
        public List<GitHubCommitFile>? Files { get; set; }
    }

    private sealed class GitHubCommitFile
    {
        public string? Filename { get; set; }
        public string? Patch { get; set; }
    }
}
