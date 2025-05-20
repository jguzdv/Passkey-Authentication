using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace JGUZDV.PasskeyAuth.Pages;

public class IndexModel : PageModel
{
    public IndexModel(IHostEnvironment environment)
    {
        AutoInitPasskey = environment.IsProduction();
    }

    public IActionResult OnGet()
    {
        if (User.Identities.Any(x => x.IsAuthenticated) && string.IsNullOrWhiteSpace(ReturnUrl))
        {
            return RedirectToPage("Info");
        }

        return Page();
    }

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    public bool AutoInitPasskey { get; }
}
