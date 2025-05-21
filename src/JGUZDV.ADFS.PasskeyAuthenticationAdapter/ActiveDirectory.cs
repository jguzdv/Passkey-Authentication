using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;

namespace JGUZDV.ADFS.PasskeyAuthenticationAdapter
{
    public static class ActiveDirectory
    {
        private static readonly Dictionary<string, string> _pdcEmulators = new();

        public static List<string>? GetUserPasskeyIds(string userPrincipalName, string searchBaseDN, string domainName, int ldapPort)
        {
            if(!_pdcEmulators.TryGetValue(domainName, out var pdcEmulator))
            {
                pdcEmulator = FindPDCEmulator(domainName);
            }

            return GetUserPasskeyIds(userPrincipalName, searchBaseDN, $"{pdcEmulator}:{ldapPort}");
        }

        public static List<string>? GetUserPasskeyIds(string userPrincipalName, string searchBaseDN, string ldapServer)
        {
            using var searcher = new DirectorySearcher(
                new DirectoryEntry($"LDAP://{ldapServer}/{searchBaseDN}"),
                $"(&(userPrincipalName={userPrincipalName})(objectClass=User))",
                new[] { "distinguishedName" },
                SearchScope.Subtree);

            var user = searcher.FindOne();

            using var passkeySearcher = new DirectorySearcher(
                user.GetDirectoryEntry(),
                $"(objectClass=fIDOAuthenticatorDevice)",
                new[] { "distinguishedName", "fIDOAuthenticatorCredentialId" },
                SearchScope.Subtree);

            var result = new List<string>();
            foreach (SearchResult passkey in passkeySearcher.FindAll())
            {
                var credentialId = (byte[])passkey.Properties["fIDOAuthenticatorCredentialId"][0];
                result.Add(Base64Url.Encode(credentialId));
            }

            return result;
        }

        
        private static string FindPDCEmulator(string domainName)
        {
            var ctx = new DirectoryContext(DirectoryContextType.Domain, domainName);
            var domain = Domain.GetDomain(ctx);

            return _pdcEmulators[domainName] = domain.PdcRoleOwner.Name;
        }
    }
}
