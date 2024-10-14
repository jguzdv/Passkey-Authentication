using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace JGUZDV.PasskeyAuth.Pages;

public class IndexModel : PageModel
{
    public IndexModel(IHostEnvironment environment)
    {
        AutoInitPasskey = environment.IsProduction();
    }

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }


    public bool AutoInitPasskey { get; }
    public string RedirectUrl => string.IsNullOrWhiteSpace(ReturnUrl)
        ? Url.Page("AboutMe", new { Reason = "emptyRedirect" })!
        : ReturnUrl;
}
