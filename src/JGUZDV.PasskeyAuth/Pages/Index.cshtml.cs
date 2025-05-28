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
        return Page();
    }

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    public bool AutoInitPasskey { get; }
}
