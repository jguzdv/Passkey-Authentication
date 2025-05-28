using System.Security.Claims;
using System.Text.Json;

using Fido2NetLib;

using JGUZDV.ActiveDirectory.Claims;
using JGUZDV.Passkey.ActiveDirectory;

using Microsoft.AspNetCore.Mvc;

namespace JGUZDV.PasskeyAuth.Endpoints;

public static class PasskeyEndpoints
{
    public static void MapPasskeyEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/passkey", CreateSession);
        endpoints.MapGet("/passkey/{sessionId}", GetPasskeySession);
        endpoints.MapPost("/passkey/authenticate", ValidateAssertion);
    }


    internal static IResult ValidateAssertion(
        [FromForm] WebAuthNResponse response,
        [FromServices] ActiveDirectoryService adService,
        [FromServices] IClaimProvider claimProvider,
        CancellationToken ct)
    {
        var assertionResponse = JsonSerializer.Deserialize<AuthenticatorAssertionRawResponse>(response.WebAuthNAssertionResponseJson);
        if (assertionResponse == null)
        {
            return BadRequest("Request:WebAuthNAssertionMissing");
        }

        var jsonFidoAssertionOptions = HttpContext.Session.GetString("fido2.assertionOptions");
        if (jsonFidoAssertionOptions == null)
        {
            return BadRequest("Session:AssertionOptionsMissing");
        }

        var assertionOptions = AssertionOptions.FromJson(jsonFidoAssertionOptions);
        if (assertionOptions == null)
        {
            return BadRequest("Session:AssertionOptionsMissing");
        }

        var (passkeyDescriptor, errorResult) = await TryHandleAssertion(adService, assertionResponse, assertionOptions, ct);
        if (errorResult != null)
        {
            return errorResult;
        }

        if (passkeyDescriptor == null)
        {
            throw new InvalidOperationException("No error was returned, but a passkey descriptor still was null");
        }

        var identity = CreateClaimsIdentity(passkeyDescriptor!, claimProvider);

        await HttpContext.SignInAsync(
            new ClaimsPrincipal(identity)
        );

        _auditLogger.LogInformation("A passkey logon was successful. User: {User}, Passkey: {Passkey}", passkeyDescriptor.Owner.ObjectGuid, passkeyDescriptor.DistinguishedName);

        if (Url.IsLocalUrl(response.ReturnUrl))
        {
            return Redirect(response.ReturnUrl);
        }

        return RedirectToPage("/Self");
    }
}
