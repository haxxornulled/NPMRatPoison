internal static class FileSystemTraversal
{
    private static readonly HashSet<string> IgnoredDirectoryNames = new(StringComparer.OrdinalIgnoreCase)
    {
        ".npmratpoison"
    };

    public static IEnumerable<string> EnumerateFiles(string root, string fileName)
    {
        var pending = new Stack<string>();
        pending.Push(root);

        while (pending.Count > 0)
        {
            var current = pending.Pop();
            IEnumerable<string> files = [];
            IEnumerable<string> directories = [];

            try
            {
                files = Directory.EnumerateFiles(current, fileName, SearchOption.TopDirectoryOnly);
            }
            catch
            {
            }

            foreach (var file in files)
            {
                yield return file;
            }

            try
            {
                directories = Directory.EnumerateDirectories(current, "*", SearchOption.TopDirectoryOnly);
            }
            catch
            {
            }

            foreach (var directory in directories)
            {
                try
                {
                    if (ShouldSkipDirectory(directory))
                    {
                        continue;
                    }

                    var attributes = File.GetAttributes(directory);
                    if ((attributes & FileAttributes.ReparsePoint) != 0)
                    {
                        continue;
                    }

                    pending.Push(directory);
                }
                catch
                {
                }
            }
        }
    }

    public static IEnumerable<string> EnumerateDirectoriesByName(string root, string directoryName)
    {
        var pending = new Stack<string>();
        pending.Push(root);

        while (pending.Count > 0)
        {
            var current = pending.Pop();
            IEnumerable<string> directories = [];

            try
            {
                directories = Directory.EnumerateDirectories(current, "*", SearchOption.TopDirectoryOnly);
            }
            catch
            {
            }

            foreach (var directory in directories)
            {
                if (ShouldSkipDirectory(directory))
                {
                    continue;
                }

                if (string.Equals(Path.GetFileName(directory), directoryName, StringComparison.OrdinalIgnoreCase))
                {
                    yield return directory;
                    continue;
                }

                try
                {
                    var attributes = File.GetAttributes(directory);
                    if ((attributes & FileAttributes.ReparsePoint) != 0)
                    {
                        continue;
                    }

                    pending.Push(directory);
                }
                catch
                {
                }
            }
        }
    }

    private static bool ShouldSkipDirectory(string directory)
    {
        return IgnoredDirectoryNames.Contains(Path.GetFileName(directory));
    }
}
