using System.Collections.Generic;
using System.DirectoryServices;

namespace JGUZDV.ADFS.PasskeyAuthenticationAdapter
{
    public static class ActiveDirectory
    {
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
    }
}
