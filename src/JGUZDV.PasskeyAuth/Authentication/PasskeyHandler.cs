using System.Globalization;
using System.Security.Claims;

using Fido2NetLib;

using JGUZDV.ActiveDirectory.Claims;
using JGUZDV.Passkey.ActiveDirectory;

namespace JGUZDV.PasskeyAuth.Authentication;

public class PasskeyHandler(
    IFido2 fido2,
    TimeProvider timeProvider,
    ILogger<PasskeyHandler> logger,
    ILogger<SecurityAudit> auditLogger
    )
{
    private readonly IFido2 _fido2 = fido2;
    private readonly TimeProvider _timeProvider = timeProvider;
    private readonly ILogger<PasskeyHandler> _logger = logger;
    private readonly ILogger<SecurityAudit> _auditLogger = auditLogger;


    public async Task<(PasskeyDescriptor? passkeyDescriptor, IResult? errorResult)> TryHandleAssertion(
        ActiveDirectoryService adService,
        AuthenticatorAssertionRawResponse assertionResponse,
        AssertionOptions assertionOptions,
        CancellationToken cancellationToken)
    {
        //Read users passkey from active directory
        var passkeyDescriptor = adService.GetPasskeyFromCredentialId(assertionResponse.Id);
        if (passkeyDescriptor == null)
        {
            _logger.LogDebug("An logon attempt failed, due to an unkown passkey {passkeyId}", Convert.ToBase64String(assertionResponse.Id));
            return (null, Results.Unauthorized());
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
            return (null, Results.Unauthorized());
        }

        var now = _timeProvider.GetUtcNow();
        if (!adService.IsUserAllowedToLogin(passkeyDescriptor.Owner.DirectoryEntry, now))
        {
            _auditLogger.LogWarning("A passkey logon was denied due to a user restriction. User: {User}, Passkey: {Passkey}", passkeyDescriptor.Owner.ObjectGuid, passkeyDescriptor.DistinguishedName);
            return (null, Results.Unauthorized());
        }

        adService.UpdatePasskeyLastUsed(passkeyDescriptor.DirectoryEntry, now);

        return (passkeyDescriptor, null);
    }


    public ClaimsIdentity CreateClaimsIdentity(PasskeyDescriptor passkey, IClaimProvider claimProvider)
    {
        var userClaims = claimProvider.GetClaims(passkey.Owner.DirectoryEntry, ["sub", "role", "userSid", "upn"]).ToList();
        var systemClaims = GetPasskeyClaims(passkey).ToList();

        return new ClaimsIdentity(
            userClaims.Concat(systemClaims).Select(x => new Claim(x.Type, x.Value)),
            "Fido2",
            "sub",
            "role");
    }

    private IEnumerable<(string Type, string Value)> GetPasskeyClaims(PasskeyDescriptor passkey)
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

        //var regardAsMultiFactorAuthentication =
        //    passkey.IsBackupEligible == false || // We assume non backupable passkeys are hardware-tokens, that are considered 2FA
        //    _options.Value.MFAWhitelist.Contains(passkey.Aaguid); // If not, we check if the passkey is in the whitelist to be treated as 2FA

        //if (regardAsMultiFactorAuthentication)
        //{
        //    result.Add(("amr", "MFA"));
        //    result.Add(("mfa_auth_time", _timeProvider.GetUtcNow().ToUnixTimeSeconds().ToString("D", CultureInfo.InvariantCulture)));
        //}

        //return result;
    }
}

