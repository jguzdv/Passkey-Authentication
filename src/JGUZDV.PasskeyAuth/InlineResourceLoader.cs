namespace JGUZDV.PasskeyAuth;

public static class InlineResourceLoader
{
    public static string LoadStyle(string filename) => Load($"css-source.{filename}", "style");

    public static string LoadScript(string filename) => Load(filename, "script");

    private static string Load(string resourceName, string tagName)
    {
        using var stream = typeof(InlineResourceLoader).Assembly.GetManifestResourceStream($"JGUZDV.PasskeyAuth.{resourceName}")
            ?? throw new InvalidOperationException($"The embedded resource '{resourceName}' was not found.");
        using var reader = new StreamReader(stream);
        var content = reader.ReadToEnd();
        if (content.Contains($"</{tagName}", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException($"The embedded resource '{resourceName}' contains an unsafe closing {tagName} tag.");
        }

        return content;
    }
}
