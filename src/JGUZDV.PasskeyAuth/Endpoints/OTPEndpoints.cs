

using System.Security.Claims;

using JGUZDV.PasskeyAuth.Authentication;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;

namespace JGUZDV.PasskeyAuth.Endpoints;

public static class OTPEndpoints
{
    public static void MapOTPEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost("otp/login", ProcessOTP)
            .WithName(EndpointNames.OTPLogin);
    }

    private static async Task<IResult> ProcessOTP(
        [FromQuery] string returnUrl,
        [FromForm] string otpValue,
        HttpContext context,
        OneTimePasswordHandler otpHandler)
    {
        var (identity, error) = await otpHandler.GetIdentityFromPassword(otpValue, context);

        if (error != null)
        {
            return error;
        }

        await context.SignInAsync(new ClaimsPrincipal(identity!));
        return Results.LocalRedirect(returnUrl);
    }
}
