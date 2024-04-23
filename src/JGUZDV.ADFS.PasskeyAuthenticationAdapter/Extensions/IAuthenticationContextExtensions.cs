using Microsoft.IdentityServer.Web.Authentication.External;
using System.Collections.Generic;

namespace JGUZDV.ADFS.PasskeyAuthenticationAdapter.Extensions
{
    internal static class IAuthenticationContextExtensions
    {
        private const string PasskeyCredentialIds = nameof(PasskeyCredentialIds);
        private const string AssertionOptions = nameof(AssertionOptions);


        public static void SavePasskeyCredentialIds(this IAuthenticationContext context, IEnumerable<string> base64UrlEncodedPasskeyCredentialIds) 
            => context.Data[PasskeyCredentialIds] = string.Join(";", base64UrlEncodedPasskeyCredentialIds);

        public static bool HasPasskeyCredentialIds(this IAuthenticationContext context)
            => context.Data.ContainsKey(PasskeyCredentialIds) && !string.IsNullOrWhiteSpace(context.Data[PasskeyCredentialIds] as string);

        public static string[] GetPasskeyCredentialIds(this IAuthenticationContext context)
        {
            var storageValue = context.Data[PasskeyCredentialIds] as string;
            return !string.IsNullOrWhiteSpace(storageValue)
                ? storageValue!.Split(';')
                : new string[0];
        }


        public static void SaveAssertionOptions(this IAuthenticationContext context,  string assertionOptions) 
            => context.Data[AssertionOptions] = assertionOptions;

        public static string? GetAssertionOptions(this IAuthenticationContext context)
            => context.Data[AssertionOptions] as string;
    }
}
