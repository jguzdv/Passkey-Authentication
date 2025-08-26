using System.Text.Json;

using Fido2NetLib;
using Fido2NetLib.Objects;

using JGUZDV.ActiveDirectory.Claims;
using JGUZDV.Passkey.ActiveDirectory;
using JGUZDV.PasskeyAuth.Authentication;
using JGUZDV.PasskeyAuth.OpenTelemetry;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;

namespace JGUZDV.PasskeyAuth.Endpoints;

public static class PasskeyEndpoints
{
    private const string Fido2SessionKey = "fido2.assertionOptions";
    private const string OTPSessionKey = "otp.value";

    public static void MapPasskeyEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var passkey = endpoints.MapGroup("passkey");

        passkey.MapGet("/", InitializeFido2Assertion);
        passkey.MapPost("/", ProcessFido2Assertion)
            .WithName(EndpointNames.PasskeyAssertion);
    }


    internal static IResult InitializeFido2Assertion(
        HttpContext context,
        IFido2 fido2,
        TimeProvider timeProvider,
        MeterContainer meterContainer,
        ILogger<SecurityAudit> auditLogger)
    {
        var assertionOptions = fido2.GetAssertionOptions(
            new()
            {
                AllowedCredentials = [],
                UserVerification = UserVerificationRequirement.Required,
            }
        );

        var jsonFidoAssertionOptions = assertionOptions.ToJson();
        context.Session.SetString(Fido2SessionKey, jsonFidoAssertionOptions);

        meterContainer.CountInitPasskeyAssertion();

        return Results.Content(jsonFidoAssertionOptions, "application/json");
    }


    internal static async Task<IResult> ProcessFido2Assertion(
        [FromQuery] string? returnUrl,
        [FromForm] string webAuthNResponse,
        HttpContext context,
        PasskeyHandler passkeyHandler,
        OneTimePasswordHandler otpHandler,
        ActiveDirectoryService adService,
        IClaimProvider claimProvider,
        ILogger<SecurityAudit> auditLogger,
        CancellationToken ct)
    {
        var assertionResponse = JsonSerializer.Deserialize<AuthenticatorAssertionRawResponse>(webAuthNResponse);
        if (webAuthNResponse == null)
        {
            return Results.BadRequest("Request:WebAuthNAssertionMissing");
        }

        var jsonFidoAssertionOptions = context.Session.GetString(Fido2SessionKey);
        if (jsonFidoAssertionOptions == null)
        {
            return Results.BadRequest("Session:AssertionOptionsMissing");
        }

        context.Session.Remove(Fido2SessionKey);

        var assertionOptions = AssertionOptions.FromJson(jsonFidoAssertionOptions);
        if (assertionOptions == null)
        {
            return Results.BadRequest("Session:AssertionOptionsMissing");
        }

        var (passkeyDescriptor, errorResult) = await passkeyHandler.TryHandleAssertion(adService, assertionResponse, assertionOptions, ct);
        if (errorResult != null)
        {
            return errorResult;
        }

        if (passkeyDescriptor == null)
        {
            throw new InvalidOperationException("No error was returned, but a passkey descriptor still was null");
        }

        auditLogger.LogInformation("A passkey logon was successful. User: {User}, Passkey: {Passkey}", passkeyDescriptor.Owner.ObjectGuid, passkeyDescriptor.DistinguishedName);
        var identity = passkeyHandler.CreateClaimsIdentity(passkeyDescriptor!, claimProvider);


        // If the user has a returnUrl, we redirect them there after signing in.
        if (!string.IsNullOrWhiteSpace(returnUrl))
        {
            await context.SignInAsync(new (identity));
            return Results.LocalRedirect(returnUrl);
        }


        // If the user does not have a returnUrl, we create a one-time-password and redirect them to the display page.
        var oneTimePassword = await otpHandler.CreateOneTimePasswordAsync(context, identity, ct);
        context.Session.SetString(OTPSessionKey, oneTimePassword);

        return Results.Redirect("/OTP");
    }
}
