internal static class GitRepositoryTraversal
{
    public static IEnumerable<string> EnumerateGitRepos(string root)
    {
        var pending = new Stack<string>();
        pending.Push(root);

        while (pending.Count > 0)
        {
            var current = pending.Pop();
            IEnumerable<string> children;

            try
            {
                children = Directory.EnumerateDirectories(current, "*", SearchOption.TopDirectoryOnly);
            }
            catch
            {
                continue;
            }

            var foundGit = false;
            foreach (var child in children)
            {
                if (string.Equals(Path.GetFileName(child), ".git", StringComparison.OrdinalIgnoreCase))
                {
                    foundGit = true;
                    break;
                }
            }

            if (foundGit)
            {
                yield return current;
                continue;
            }

            foreach (var child in children)
            {
                try
                {
                    var attributes = File.GetAttributes(child);
                    if ((attributes & FileAttributes.ReparsePoint) != 0)
                    {
                        continue;
                    }

                    pending.Push(child);
                }
                catch
                {
                }
            }
        }
    }

    public static bool IsGitHubRepo(string repoRoot)
    {
        var config = Path.Combine(repoRoot, ".git", "config");
        if (!File.Exists(config))
        {
            return false;
        }

        try
        {
            var content = File.ReadAllText(config);
            return content.Contains("github.com", StringComparison.OrdinalIgnoreCase)
                   || content.Contains("git@github", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    public static string? ResolveGitRoot(string start)
    {
        var current = new DirectoryInfo(start);
        while (current is not null)
        {
            if (Directory.Exists(Path.Combine(current.FullName, ".git")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        return null;
    }
}
