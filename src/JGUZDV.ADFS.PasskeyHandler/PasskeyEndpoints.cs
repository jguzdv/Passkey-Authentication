using System.Buffers.Text;
using System.Globalization;
using System.Runtime.Versioning;
using System.Text.Json;

using Fido2NetLib;
using Fido2NetLib.Objects;

using JGUZDV.Passkey.ActiveDirectory;

using Microsoft.AspNetCore.Mvc;

namespace JGUZDV.ADFS.PasskeyHandler;

[SupportedOSPlatform("windows")]
internal class PasskeyEndpoints
{
    public static IResult CreateAssertionOptions(
        [FromQuery(Name = "pci")] string[]? passkeyCredentialIds,
        IFido2 fido2)
    {
        if (passkeyCredentialIds == null || passkeyCredentialIds.Length < 1)
        {
            return Results.BadRequest("No passkey credential ids provided");
        }

        var allowedCredentials = passkeyCredentialIds
            .Select(x => Base64Url.DecodeFromChars(x))
            .Select(x => new PublicKeyCredentialDescriptor(x))
            .ToArray();

        var assertionOptions = fido2.GetAssertionOptions(new() {
            AllowedCredentials = allowedCredentials,
            UserVerification = UserVerificationRequirement.Required
        });

        var jsonFidoAssertionOptions = assertionOptions.ToJson();
        return Results.Content(
            jsonFidoAssertionOptions,
            "application/json"
        );
    }

    public static async Task<IResult> ValidatePasskeyAssertion(
            [FromForm] AssertionRequest request,
            ActiveDirectoryService adService,
            IFido2 fido2,
            TimeProvider timeProvider,
            ILogger<PasskeyEndpoints> logger,
            CancellationToken cancellationToken)
    {
        try
        {
            var assertionOptions = AssertionOptions.FromJson(request.AssertionOptions ?? "");
            var assertionResponse = JsonSerializer.Deserialize<AuthenticatorAssertionRawResponse>(request.AssertionResponse ?? "");

            if (assertionOptions == null || assertionResponse == null)
            {
                return Results.BadRequest("Request:MissingField");
            }

            var passkeyDescriptor = adService.GetPasskeyFromCredentialId(assertionResponse.Id);
            if (passkeyDescriptor == null)
            {
                return Results.BadRequest("Passkey:UnknownCredential");
            }

            var result = await fido2.MakeAssertionAsync(
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
                cancellationToken);

            adService.UpdatePasskeyLastUsed(passkeyDescriptor.DirectoryEntry, timeProvider.GetUtcNow());

            var mfaAuthTime = timeProvider.GetUtcNow().ToUnixTimeSeconds().ToString("D", CultureInfo.InvariantCulture);
            var fido2CredId = Base64Url.EncodeToString(passkeyDescriptor.CredentialId);

            return Results.Ok($"""
                amr=FIDO2Passkey
                amr=MFA
                mfa_auth_time={mfaAuthTime}
                fido2_cred_id={fido2CredId}
                """);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "MakeAssertionAsync threw an exception.");
            return Results.Unauthorized();
        }
    }

    public static IResult GetUserPasskeyIds(
        [FromQuery(Name = "upn")] string userPrincipalName,
        ActiveDirectoryService adService)
    {

        var passkeys = adService.GetUserPasskeyIds(userPrincipalName);
        if (passkeys == null || passkeys.Count == 0)
        {
            return Results.NotFound("No passkeys found for the specified user.");
        }

        var response = string.Join("\n", passkeys.Select(x => Base64Url.EncodeToString(x)));
        return Results.Json(response);
    }

    private record HttpClaim(string Type, string Value);
}
