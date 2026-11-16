using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace JGUZDV.PasskeyAuth.Pages;

public class IndexModel : PageModel
{
    private static readonly string InlinePageScript = LoadPageScript();

    public void OnGet() { }

    public string PageScript => InlinePageScript;

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    private static string LoadPageScript()
    {
        using var stream = typeof(IndexModel).Assembly.GetManifestResourceStream("JGUZDV.PasskeyAuth.Index.inline.js")
            ?? throw new InvalidOperationException("The embedded page script was not found.");
        using var reader = new StreamReader(stream);
        var script = reader.ReadToEnd();
        if (script.Contains("</script", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("The embedded page script contains an unsafe closing script tag.");
        }

        return script;
    }


    /// <summary>
    /// An exisiting return url indicates that the user has been redirected here from another page, and wants to start a session automatically.
    /// If the redirect url is not set, the user has opened this page directly, and most likely wants to start a session for another browser.
    /// </summary>
    public bool AllowOneTimePassword => !string.IsNullOrWhiteSpace(ReturnUrl);

    public bool ClicklessPasskey => !string.IsNullOrWhiteSpace(ReturnUrl);
}
