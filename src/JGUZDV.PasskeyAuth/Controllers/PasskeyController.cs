using Fido2NetLib;
using Fido2NetLib.Objects;
using JGUZDV.Passkey.ActiveDirectory;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Text;
using System.Text.Json;

namespace JGUZDV.PasskeyAuth.Controllers;

[ApiController, Route("/passkey")]
public class PasskeyController(
    IFido2 _fido2,
    TimeProvider _timeProvider,
    ILogger<PasskeyController> _logger
    ) : ControllerBase
{
    [HttpGet()]
    public IActionResult InitWebAuthNAssertion()
    {
        var assertionOptions = _fido2.GetAssertionOptions(
            [],
            UserVerificationRequirement.Required
        );

        var jsonFidoAssertionOptions = assertionOptions.ToJson();
        HttpContext.Session.SetString("fido2.assertionOptions", jsonFidoAssertionOptions);

        return new ContentResult()
        {
            Content = jsonFidoAssertionOptions,
            ContentType = "application/json"
        };
    }

    [HttpPost(Name = "passkey-auth")]
    public async Task<IActionResult> AuthenticateUser(
        [FromForm] WebAuthNResponse response,
        [FromServices] ActiveDirectoryService adService,
        CancellationToken ct)
    {
        var assertionResponse = JsonSerializer.Deserialize<AuthenticatorAssertionRawResponse>(response.WebAuthNAssertionResponseJson)
            ?? throw new BadHttpRequestException("Request:WebAuthNAssertionMissing");

        var jsonFidoAssertionOptions = HttpContext.Session.GetString("fido2.assertionOptions");
        var assertionOptions = AssertionOptions.FromJson(jsonFidoAssertionOptions)
            ?? throw new BadHttpRequestException("Session:AssertionOptionsMissing");

        //Read users passkey from active directory
        var passkeyDescriptor = adService.GetPasskeyFromCredentialId(assertionResponse.Id)
            ?? throw new BadHttpRequestException("Passkey:NotFound");

        
        try
        {
            var assertionResult = await _fido2.MakeAssertionAsync(
                assertionResponse,
                assertionOptions,
                passkeyDescriptor.Credential,
                [],
                0,
                (ctx, cancellationToken) => Task.FromResult(ActiveDirectoryService.IsUserOwnerOfPasskey(new Guid(ctx.UserHandle), passkeyDescriptor)),
                ct
            );

            if (!string.IsNullOrWhiteSpace(assertionResult.ErrorMessage))
            {
                _logger.LogError("Passkey Assertion failed: {errorMessage}", assertionResult.ErrorMessage);
                throw new BadHttpRequestException("Passkey:AssertionFailed");
            }
        }
        catch (Exception exc)
        {
            _logger.LogError(exc, "Passkey Assertion failed.");
            throw new BadHttpRequestException("Passkey:AssertionFailed", exc);
        }

        var now = _timeProvider.GetUtcNow();
        if (!adService.IsUserAllowedToLogin(passkeyDescriptor.Owner.DirectoryEntry, now))
        {
            throw new BadHttpRequestException("User:LoginNotAllowed");
        }

        adService.UpdatePasskeyLastUsed(passkeyDescriptor.DistinguishedName, now);
        adService.UpdateUserLastLogin(passkeyDescriptor.Owner.DistinguishedName, now);

        await HttpContext.SignInAsync(
            new ClaimsPrincipal(
                new ClaimsIdentity(
                    [
                        new Claim("sub", passkeyDescriptor.Owner.ObjectGuid.ToString()),
                        new Claim("zdv_upn", passkeyDescriptor.Owner.UserPrincipalName),
                        new Claim("zdv_eppn", passkeyDescriptor.Owner.EduPersonPrincipalName)
                    ],
                    "Fido2",
                    "sub",
                    null
                )
            )
        );

        if (Url.IsLocalUrl(response.ReturnUrl))
        {
            return Redirect(response.ReturnUrl);
        }

        throw new BadHttpRequestException("Request:ReturnUrlInvalid");
    }
}
