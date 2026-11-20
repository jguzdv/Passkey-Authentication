using System.Diagnostics.CodeAnalysis;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace JGUZDV.PasskeyAuth.Pages;

public class IndexModel : PageModel
{
    public IActionResult OnGet()
    {
        SetCacheControl();
        if(IsUserAuthenticated() && HasRedirectUrl)
        {
            return LocalRedirect(ReturnUrl);
        }

        return Page();
    }

    public IActionResult OnGetSession()
    {
        SetCacheControl();
        return new JsonResult(IsUserAuthenticated());
    }

    private bool IsUserAuthenticated()
    {
        return User.Identity?.IsAuthenticated == true;
    }

    private void SetCacheControl()
    {
        Response.Headers.CacheControl = "no-cache, no-store";
        Response.Headers.Pragma = "no-cache";
    }

    public string PageScript { get; } = InlineResourceLoader.LoadScript("Index.inline.js");

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    /// <summary>
    /// An existing return URL indicates that the user has been redirected here to start a session.
    /// Without a return URL, the user has likely opened this page to start a session for another browser.
    /// </summary>
    [MemberNotNullWhen(true, nameof(ReturnUrl))]
    public bool HasRedirectUrl => !string.IsNullOrWhiteSpace(ReturnUrl);
}
