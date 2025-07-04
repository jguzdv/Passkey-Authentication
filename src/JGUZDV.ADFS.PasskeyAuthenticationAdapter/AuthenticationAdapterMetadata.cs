using System.Collections.Generic;
using System.Security.Claims;
using Microsoft.IdentityServer.Web.Authentication.External;

namespace JGUZDV.ADFS.PasskeyAuthenticationAdapter;

internal class AuthenticationAdapterMetadata : IAuthenticationAdapterMetadata
{
    public string? AdminName { get; set; }

    public string[]? AuthenticationMethods { get; set; }
    public string[]? IdentityClaims { get; set; }

    //All external providers must return a value of "true" for this property.
    public bool RequiresIdentity => true;


    public int[]? AvailableLcids { get; set; }
    public Dictionary<int, string>? FriendlyNames { get; set; }
    public Dictionary<int, string>? Descriptions { get; set; }


    public static AuthenticationAdapterMetadata Instance { get; } = new AuthenticationAdapterMetadata
    {
        AdminName = "PassKeyAuthProvider",
        AuthenticationMethods = new[] { "FIDO2Passkey" },
        IdentityClaims = new[] { ClaimTypes.Upn },

        AvailableLcids = new[] { 1031, 1033 },
        FriendlyNames = new Dictionary<int, string>
        {
            { 1031, "Anmeldung mit Passkey" },
            { 1033, "Authenticate using Passkey" }
        },
        Descriptions = new Dictionary<int, string>
        {
            { 1031, "Passwortloses Anmeldeverfahren nach FIDO Passkey-Standard" },
            { 1033, "Passwordless authentication proctocol using FIDO Passkeys" }
        }
    };
}
