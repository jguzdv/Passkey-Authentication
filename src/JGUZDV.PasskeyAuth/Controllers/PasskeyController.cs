using Fido2NetLib;
using Fido2NetLib.Objects;
using JGUZDV.ActiveDirectory.Claims;
using JGUZDV.Passkey.ActiveDirectory;
using JGUZDV.PasskeyAuth.Configuration;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System.Globalization;
using System.Security.Claims;
using System.Text;
using System.Text.Json;

namespace JGUZDV.PasskeyAuth.Controllers;

[ApiController, Route("/passkey")]
public class PasskeyController(
    IFido2 _fido2,
    TimeProvider _timeProvider,
    IOptions<PasskeyAuthOptions> _options,
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

        var identity = CreateClaimsIdentity(passkeyDescriptor!, claimProvider);

        await HttpContext.SignInAsync(
            new ClaimsPrincipal(identity)
        );

        if (Url.IsLocalUrl(response.ReturnUrl))
        {
            return Redirect(response.ReturnUrl);
        }

        throw new BadHttpRequestException("Request:ReturnUrlInvalid");
    }


    private ClaimsIdentity CreateClaimsIdentity(PasskeyDescriptor passkey, IClaimProvider claimProvider)
    {
        var userClaims = claimProvider.GetClaims(passkey.Owner.DirectoryEntry, ["sub", "role", "userSid", "upn" ]).ToList();
        var systemClaims = GetSystemClaims(passkey).ToList();

        return new ClaimsIdentity(
            userClaims.Concat(systemClaims).Select(x => new Claim(x.Type, x.Value)),
            "Fido2",
            "sub",
            "role");
    }

    private IEnumerable<(string Type, string Value)> GetSystemClaims(PasskeyDescriptor passkey)
    {
        var result = new List<(string Type, string Value)>
        {
            ("amr", "FIDO2Passkey"),
        };

        var regardAsMultiFactorAuthentication =
            passkey.IsBackupEligible == false || // We assume non backupable passkeys are hardware-tokens, that are considered 2FA
            _options.Value.MFAWhitelist.Contains(passkey.Aaguid); // If not, we check if the passkey is in the whitelist to be treated as 2FA

        if (regardAsMultiFactorAuthentication)
        {
            result.Add(("amr", "MFA"));
            result.Add(("mfa_auth_time", _timeProvider.GetUtcNow().ToUnixTimeSeconds().ToString("D", CultureInfo.InvariantCulture)));
        }

        return result;
    }

    private async Task<(PasskeyDescriptor? passkeyDescriptor, IActionResult? errorResult)> TryHandleAssertion(
        ActiveDirectoryService adService,
        AuthenticatorAssertionRawResponse assertionResponse,
        AssertionOptions assertionOptions,
        CancellationToken cancellationToken)
    {
        //Read users passkey from active directory
        var passkeyDescriptor = adService.GetPasskeyFromCredentialId(assertionResponse.Id);
        if (passkeyDescriptor == null)
        {
            return (null, BadRequest("Passkey:NotFound"));
        }

        try
        {
            var assertionResult = await _fido2.MakeAssertionAsync(
                new MakeAssertionParams
                {
                    OriginalOptions = assertionOptions,
                    AssertionResponse = assertionResponse,
                    StoredPublicKey = passkeyDescriptor.Credential,

                    StoredSignatureCounter = 0,
                    IsUserHandleOwnerOfCredentialIdCallback = (ctx, _) =>
                    {
                        var userGuid = new Guid(ctx.UserHandle);
                        var result = ActiveDirectoryService.IsUserOwnerOfPasskey(userGuid, passkeyDescriptor);

                        return Task.FromResult(result);
                    }
                },

                cancellationToken
            );
        }
        catch (Exception exc)
        {
            _logger.LogError(exc, "Passkey Assertion failed.");
            return (null, BadRequest("Passkey:AssertionFailed"));
        }

        var now = _timeProvider.GetUtcNow();
        if (!adService.IsUserAllowedToLogin(passkeyDescriptor.Owner.DirectoryEntry, now))
        {
            return (null, BadRequest("User:LoginNotAllowed"));
        }

        adService.UpdatePasskeyLastUsed(passkeyDescriptor.DistinguishedName, now);
        adService.UpdateUserLastLogin(passkeyDescriptor.Owner.DistinguishedName, now);

        return (passkeyDescriptor, null);
    }
}
