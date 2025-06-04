using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace JGUZDV.PasskeyAuth.Pages;

public class OTPModel : PageModel
{
    public IActionResult OnGet()
    {
        OneTimePassword = HttpContext.Session.GetString("otp.value");
        HttpContext.Session.Remove("otp.value");

        if (string.IsNullOrWhiteSpace(OneTimePassword))
        {
            // Redirect to the home page if no OTP is found in the session
            return LocalRedirect("/");
        }

        return Page();
    }

    public string? OneTimePassword { get; set; }
}
