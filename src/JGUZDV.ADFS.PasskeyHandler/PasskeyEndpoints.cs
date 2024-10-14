using Fido2NetLib;
using Fido2NetLib.Objects;
using JGUZDV.Passkey.ActiveDirectory;
using Microsoft.AspNetCore.Mvc;
using System.Runtime.Versioning;
using System.Text.Json;

namespace JGUZDV.ADFS.PasskeyHandler;

[SupportedOSPlatform("windows")]
internal class PasskeyEndpoints
{
    public static IResult CreateAssertionOptions(
        [FromQuery(Name = "pci")] string[]? passkeyCredentialIds,
        IFido2 fido2)
    {
        if (passkeyCredentialIds == null || passkeyCredentialIds.Length < 1)
            return Results.BadRequest("No passkey credential ids provided");

        var allowedCredentials = passkeyCredentialIds
            .Select(x => Base64Url.Decode(x))
            .Select(x => new PublicKeyCredentialDescriptor(x))
            .ToArray();

        var assertionOptions = fido2.GetAssertionOptions(
            allowedCredentials,
            UserVerificationRequirement.Required
        );

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
            CancellationToken ct)
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
                assertionResponse,
                assertionOptions,
                passkeyDescriptor.Credential,
                [], 0,
                (ctx, _) => {
                    var userGuid = new Guid(ctx.UserHandle);
                    var result = ActiveDirectoryService.IsUserOwnerOfPasskey(userGuid, passkeyDescriptor);

                    return Task.FromResult(result);
                },
                ct);

            if (result.ErrorMessage != null)
            {
                logger.LogWarning("MakeAssertionAsync returned an error message: {errorMessage}", result.ErrorMessage);
                return Results.Unauthorized();
            }

            adService.UpdatePasskeyLastUsed(passkeyDescriptor.DistinguishedName, timeProvider.GetUtcNow());

            return Results.Ok();
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "MakeAssertionAsync threw an exception.");
            return Results.Unauthorized();
        }
    }
}
