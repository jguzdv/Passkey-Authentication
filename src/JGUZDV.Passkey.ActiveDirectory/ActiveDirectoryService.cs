using System.Buffers.Text;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Runtime.Versioning;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace JGUZDV.Passkey.ActiveDirectory;

[SupportedOSPlatform("windows")]
public class ActiveDirectoryService
{
    private readonly IOptions<ActiveDirectoryOptions> _adOptions;
    private readonly ILogger<ActiveDirectoryService> _logger;

    
    public ActiveDirectoryService(IOptions<ActiveDirectoryOptions> adOptions, ILogger<ActiveDirectoryService> logger)
    {
        _adOptions = adOptions;
        _logger = logger;
    }


    public List<byte[]>? GetUserPasskeyIds(string userPrincipalName)
    {
        var users = PerformSearchWithRetry(
            _adOptions.Value.BaseOU,
            $"(&(userPrincipalName={userPrincipalName})(objectClass=User))",
            ["distinguishedName"],
            SearchScope.Subtree);

        if (users.Count != 1)
        {
            _logger.LogWarning("No or multiple user(s) found with UPN {userPrincipalName} in {baseDN} on {ldapServer}", userPrincipalName, _adOptions.Value.BaseOU, _adOptions.Value.LdapServer);
            return null;
        }

        var passkeys = PerformSearchWithRetry(
            (string)users[0].Properties["distinguishedName"][0]!,
            "(objectClass=fIDOAuthenticatorDevice)",
            ["distinguishedName", "fIDOAuthenticatorCredentialId"],
            SearchScope.Subtree);

        return passkeys.Count == 0
            ? null
            : [.. passkeys.Select(x => (byte[])(x.Properties["fIDOAuthenticatorCredentialId"][0]!))];
    }


    public PasskeyDescriptor? GetPasskeyFromCredentialId(byte[] credentialId)
    {
        var credentialString = "\\" + BitConverter.ToString(credentialId).Replace("-", "\\");

        List<SearchResult> passkeyResults;
        try
        {
            passkeyResults = PerformSearchWithRetry(
                _adOptions.Value.BaseOU,
                $"(&(objectClass=fIDOAuthenticatorDevice)(fIDOAuthenticatorCredentialId={credentialString}))",
                ["distinguishedName", "userCertificate", "fIDOAuthenticatorAaguid", "flags"],
                SearchScope.Subtree);

        
            if (passkeyResults.Count == 0)
            {
                return null;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to search for passkey with credentialId {credentialId}, on {domain} in {baseOu}", credentialString, _adOptions.Value.DomainName, _adOptions.Value.BaseOU);
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

        var userResult = PerformSearchWithRetry(
            userDN,
            $"(objectClass=User)",
            ["distinguishedName", "userPrincipalName", "objectGuid", "eduPersonPrincipalName"],
            SearchScope.Base);

        if (userResult.Count == 0)
        {
            return null;
        }

        var owner = GetPasskeyOwnerInfo(userResult[0]);

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

    public void UpdatePasskeyLastUsed(DirectoryEntry passkeyEntry, DateTimeOffset lastUsageTime)
    {
        try
        {
            var lastLogon = lastUsageTime.ToFileTime();

            passkeyEntry.Properties["lastLogonTimestamp"].SetLargeInteger(lastLogon);

            passkeyEntry.CommitChanges();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to update lastLogonTimestamp for {passkeyPath}", passkeyEntry.Path);
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


    private string? GetPDCEmulator()
    {
        if (_adOptions.Value.DomainName == null)
        {
            _logger.LogWarning("No domain name configured, cannot query PDC emulator.");
            return null;
        }

        var ctx = new DirectoryContext(DirectoryContextType.Domain, _adOptions.Value.DomainName);
        var domain = Domain.GetDomain(ctx);
        return domain.PdcRoleOwner.Name;
    }

    private List<string> GetADServers()
    {
        var directoryContext = _adOptions.Value.DomainName != null
            ? new DirectoryContext(DirectoryContextType.Domain, _adOptions.Value.DomainName)
            : new DirectoryContext(DirectoryContextType.Domain);

        var domainController = _adOptions.Value.DomainSite != null
            ? DomainController.FindOne(directoryContext, _adOptions.Value.DomainSite, LocatorOptions.ForceRediscovery)
            : DomainController.FindOne(directoryContext, LocatorOptions.ForceRediscovery);

        if (domainController.Roles.Contains(ActiveDirectoryRole.PdcRole))
        {
            return [domainController.Name];
        }

        var domain = Domain.GetDomain(directoryContext);
        var pdcRoleOwner = domain.PdcRoleOwner;

        return pdcRoleOwner != null
            ? [domainController.Name, pdcRoleOwner.Name]
            : [domainController.Name];
    }

    private List<SearchResult> PerformSearchWithRetry(string basePath, string ldapFilter, string[] propertiesToLoad, SearchScope scope)
    {
        var ldapServers = GetADServers();

        for (var i = 0; i < ldapServers.Count; i++)
        {
            try
            {
                var result = PerformSearch(ldapServers[i], basePath, ldapFilter, propertiesToLoad, scope);
                if (result.Count > 0)
                {
                    return result;
                }
            }
            catch (DirectoryServicesCOMException ex)
            {
                _logger.LogWarning(ex, "Failed to perform search on {ldapServer} for {basePath} with filter {ldapFilter}. Retrying with next server.", ldapServers[i], basePath, ldapFilter);
            }
        }

        return [];
    }


    private List<SearchResult> PerformSearch(string ldapServer, string basePath, string ldapFilter, string[] propertiesToLoad, SearchScope scope)
    {
        using var searcher = new DirectorySearcher(
            new DirectoryEntry($"LDAP://{ldapServer}:{_adOptions.Value.LdapPort}/{basePath}"),
            ldapFilter, propertiesToLoad, scope);

        return [.. searcher.FindAll().Cast<SearchResult>()];
    }
}
