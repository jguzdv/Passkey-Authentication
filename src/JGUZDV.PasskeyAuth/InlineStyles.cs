namespace JGUZDV.PasskeyAuth;

public static class InlineStyles
{
    public static string Bootstrap { get; } = Load("jg-ootstrap.css");
    public static string App { get; } = Load("app.css");

    private static string Load(string name)
    {
        using var stream = typeof(InlineStyles).Assembly.GetManifestResourceStream($"JGUZDV.PasskeyAuth.css-source.{name}")
            ?? throw new InvalidOperationException($"The embedded stylesheet '{name}' was not found.");
        using var reader = new StreamReader(stream);
        var css = reader.ReadToEnd();
        if (css.Contains("</style", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException($"The embedded stylesheet '{name}' contains an unsafe closing style tag.");
        }

        return css;
    }
}
