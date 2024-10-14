using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace JGUZDV.PasskeyAuth.Pages;

public class AboutMeModel : PageModel
{
    [BindProperty(SupportsGet = true)]
    public string? Reason { get; set; }

    public void OnGet()
    {
    }
}
