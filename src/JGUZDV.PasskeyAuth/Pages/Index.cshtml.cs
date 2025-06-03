using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace JGUZDV.PasskeyAuth.Pages;

public class IndexModel : PageModel
{
    public void OnGet() { }

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }


    /// <summary>
    /// An exisiting return url indicates that the user has been redirected here from another page, and wants to start a session automatically.
    /// If the redirect url is not set, the user has opened this page directly, and most likely wants to start a session for another browser.
    /// </summary>
    public bool AllowOneTimePassword => !string.IsNullOrWhiteSpace(ReturnUrl);

    public bool ClicklessPasskey => !string.IsNullOrWhiteSpace(ReturnUrl);
}
