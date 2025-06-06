using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Runtime.Versioning;

using JGUZDV.Passkey.ActiveDirectory.Extensions;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace JGUZDV.Passkey.ActiveDirectory;

[SupportedOSPlatform("windows")]
public class ActiveDirectoryService
{
    private readonly IOptions<ActiveDirectoryOptions> _adOptions;
    private readonly ILogger<ActiveDirectoryService> _logger;

    private readonly string? _ldapServer;

    public ActiveDirectoryService(IOptions<ActiveDirectoryOptions> adOptions, ILogger<ActiveDirectoryService> logger)
    {
        _adOptions = adOptions;
        _logger = logger;

        if(!string.IsNullOrWhiteSpace(_adOptions.Value.DomainName))
        {
            var ctx = new DirectoryContext(DirectoryContextType.Domain, _adOptions.Value.DomainName);
            var domain = Domain.GetDomain(ctx);

            _ldapServer = domain.PdcRoleOwner.Name;
        }
        else
        {
            _ldapServer = _adOptions.Value.LdapServer;
        }
    }

    public PasskeyDescriptor? GetPasskeyFromCredentialId(byte[] credentialId)
    {
        var credentialString = "\\" + BitConverter.ToString(credentialId).Replace("-", "\\");

        using var passkeySearcher = new DirectorySearcher(
            new DirectoryEntry($"LDAP://{_ldapServer}/{_adOptions.Value.BaseOU}"),
            $"(&(objectClass=fIDOAuthenticatorDevice)(fIDOAuthenticatorCredentialId={credentialString}))",
            ["distinguishedName", "userCertificate", "fIDOAuthenticatorAaguid", "flags"],
            SearchScope.Subtree);

        SearchResultCollection? passkeyResults;
        try
        {
            passkeyResults = passkeySearcher.FindAll();
            if (passkeyResults.Count == 0)
            {
                return null;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to search for passkey with credentialId {credentialId}, on {server} in {baseOu}", credentialString, _ldapServer, _adOptions.Value.BaseOU);
            return null;
        }

        if (passkeyResults.Count > 1)
        {
            var base64CredentialId = Convert.ToBase64String(credentialId);
            _logger.LogError("There where mutliple passkeys found for {credentialId} (\\{ldapCredentialString})",
                base64CredentialId, credentialString);
        }

        var passkey = passkeyResults[0];
        var passkeyDN = (string)passkey.Properties["distinguishedName"][0];
        var userDN = passkeyDN.Split(',', 3).Last();

        using var userSearcher = new DirectorySearcher(
            new DirectoryEntry($"LDAP://{_ldapServer}/{userDN}"),
            $"(objectClass=User)",
            ["distinguishedName", "userPrincipalName", "objectGuid", "eduPersonPrincipalName"],
            SearchScope.Base);

        var userResult = userSearcher.FindOne();
        if (userResult == null)
        {
            return null;
        }

        var owner = GetPasskeyOwnerInfo(userResult);

        return GetPasskeyDescriptor(credentialId, passkey, owner);
    }

    private static PasskeyDescriptor GetPasskeyDescriptor(byte[] credentialId, SearchResult passkey, PasskeyOwner owner)
    {
        var distinguishedName = (string)passkey.Properties["distinguishedName"][0];
        var credential = (byte[])passkey.Properties["userCertificate"][0];

        var aaguid = (byte[])passkey.Properties["fIDOAuthenticatorAaguid"][0];

        bool? isBackupEligible = null;
        if(passkey.Properties["flags"].Count > 0)
        {
            if (passkey.Properties["flags"][0] is int i)
            {
                isBackupEligible = (i & 1) == 1;
            }
        }
            

        return new(
            DistinguishedName: distinguishedName,
            CredentialId: credentialId,
            Credential: credential,
            Aaguid: new Guid(aaguid),
            IsBackupEligible: isBackupEligible,
            Owner: owner,
            DirectoryEntry: passkey.GetDirectoryEntry()
        );
    }

    private static PasskeyOwner GetPasskeyOwnerInfo(SearchResult userResult)
    {
        return new PasskeyOwner(
            new Guid((byte[])userResult.Properties["objectGuid"][0]),
            (string)userResult.Properties["distinguishedName"][0],
            (string)userResult.Properties["userPrincipalName"][0],
            (string)userResult.Properties["eduPersonPrincipalName"][0],
            userResult.GetDirectoryEntry()
        );
    }

    public void UpdatePasskeyLastUsed(string passkeyDN, DateTimeOffset lastUsageTime)
    {
        try
        {
            var passkeyEntry = new DirectoryEntry($"LDAP://{_ldapServer}/{passkeyDN}");
            var lastLogon = lastUsageTime.ToFileTime();

            passkeyEntry.Properties["lastLogonTimestamp"].SetLargeInteger(lastLogon);

            passkeyEntry.CommitChanges();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to update lastLogonTimestamp for {passkeyDN}", passkeyDN);
        }
    }


    public static bool IsUserOwnerOfPasskey(Guid ownerHandle, PasskeyDescriptor passkey)
    {
        return ownerHandle == passkey.Owner.ObjectGuid;
    }

    public bool IsUserAllowedToLogin(DirectoryEntry userEntry, DateTimeOffset refDate)
    {
        const int UF_ACCOUNTDISABLE = 0x0002;
        const int UF_NORMAL_ACCOUNT = 0x0200;
        const int UF_SMARTCARD_REQUIRED = 0x40000;

        userEntry.RefreshCache(["userAccountControl", "accountExpires"]);

        if (userEntry.Properties["userAccountControl"]?.Value is not int userAccountControl)
        {
            _logger.LogError("Failed to read userAccountControl for {userDN}", userEntry.Path);
            return false;
        }

        if ((userAccountControl & UF_ACCOUNTDISABLE) == UF_ACCOUNTDISABLE)
        {
            _logger.LogInformation("User {userDN} is disabled", userEntry.Path);
            return false;
        }

        if ((userAccountControl & UF_SMARTCARD_REQUIRED) == UF_SMARTCARD_REQUIRED)
        {
            _logger.LogInformation("User {userDN} requires smartcard", userEntry.Path);
            return false;
        }

        if ((userAccountControl & UF_NORMAL_ACCOUNT) != UF_NORMAL_ACCOUNT)
        {
            _logger.LogInformation("User {userDN} is not a normal account", userEntry.Path);
            return false;
        }


        if (userEntry.Properties["accountExpires"]?.GetLargeInteger() is not long accountExpires)
        {
            _logger.LogError("Failed to read accountExpires for {userDN}", userEntry.Path);
            return false;
        }

        if (accountExpires != 0 && accountExpires <= refDate.ToFileTime())
        {
            _logger.LogInformation("User {userDN} account has expired", userEntry.Path);
            return false;
        }

        return true;
    }
}
