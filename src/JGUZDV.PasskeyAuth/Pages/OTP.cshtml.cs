using Microsoft.AspNetCore.Mvc.RazorPages;

namespace JGUZDV.PasskeyAuth.Pages;

public class OTPModel : PageModel
{
    public void OnGet()
    {
        OneTimePassword = HttpContext.Session.GetString("otp.value");
    }

    public string? OneTimePassword { get; set; }
}
