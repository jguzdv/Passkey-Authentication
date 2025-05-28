using System;
using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;

using Fido2NetLib;
using Fido2NetLib.Objects;

using JGUZDV.ActiveDirectory.Claims;
using JGUZDV.Passkey.ActiveDirectory;

using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Distributed;

namespace JGUZDV.PasskeyAuth.Authentication;

public class PasskeyHandler(
    IFido2 fido2,
    TimeProvider timeProvider,
    IDistributedCache cache,
    IDataProtectionProvider dataProtectionProvider
    )
{
    private const string ProtectorPurpose = "PasskeyAuth.Session";

    private readonly IFido2 _fido2 = fido2;
    private readonly TimeProvider _timeProvider = timeProvider;
    private readonly IDistributedCache _cache = cache;
    private readonly IDataProtectionProvider _dataProtectionProvider = dataProtectionProvider;

    public async Task<string> CreateLogonSessionAsync(SessionProperties props, CancellationToken ct)
    {
        var sessionId = new Guid(RandomNumberGenerator.GetBytes(16)).ToString("N");

        var sessionKey = $"{sessionId}_{props.UserIpAddress}";
        var assertionOptions = CreateProtectedAssertionOptions();

        var cacheOptions = new DistributedCacheEntryOptions {
            AbsoluteExpirationRelativeToNow = props.ExpirationTimeSpan
        };

        await _cache.SetStringAsync(sessionKey, assertionOptions, cacheOptions, ct);

        return sessionId;
    }



    private string CreateProtectedAssertionOptions()
    {
        var assertionOptions = _fido2.GetAssertionOptions(
            [],
            UserVerificationRequirement.Required
        ).ToJson();

        return _dataProtectionProvider.CreateProtector(ProtectorPurpose).Protect(assertionOptions);
    }



    private ClaimsIdentity CreateClaimsIdentity(PasskeyDescriptor passkey, IClaimProvider claimProvider)
    {
        var userClaims = claimProvider.GetClaims(passkey.Owner.DirectoryEntry, ["sub", "role", "userSid", "upn"]).ToList();
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
            ("amr", "MFA"),
            ("mfa_auth_time", _timeProvider.GetUtcNow().ToUnixTimeSeconds().ToString("D", CultureInfo.InvariantCulture)),
            ("fido2_cred_id", Base64Url.Encode(passkey.CredentialId))
        };

        return result;

        // TODO: This code path has been deactivated on purpose.
        // We'll reconsider the logic behind this eventually.

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
            _auditLogger.LogWarning(exc, "A passkey logon failed. User: {User}, Passkey: {Passkey}", passkeyDescriptor.Owner.ObjectGuid, passkeyDescriptor.DistinguishedName);
            return (null, BadRequest("Passkey:AssertionFailed"));
        }

        var now = _timeProvider.GetUtcNow();
        if (!adService.IsUserAllowedToLogin(passkeyDescriptor.Owner.DirectoryEntry, now))
        {
            return (null, BadRequest("User:LoginNotAllowed"));
        }

        adService.UpdatePasskeyLastUsed(passkeyDescriptor.DistinguishedName, now);

        return (passkeyDescriptor, null);
    }
}

public record SessionProperties(
    string UserIpAddress,
    TimeSpan ExpirationTimeSpan
)
{
    public static SessionProperties FromHttpContext(HttpContext context)
    {
        return new SessionProperties(
            //TODO: Handle null IP address less gracefully
            context.Connection.RemoteIpAddress?.ToString() ?? "No-IP-Address",
            TimeSpan.FromMinutes(3));
    }
}
