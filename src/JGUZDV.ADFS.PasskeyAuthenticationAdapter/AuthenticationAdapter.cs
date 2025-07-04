using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.Serialization.Json;
using System.Security.Claims;
using System.Text;
using System.Web;

using JGUZDV.ADFS.PasskeyAuthenticationAdapter.Extensions;

using Microsoft.IdentityServer.Web.Authentication.External;

namespace JGUZDV.ADFS.PasskeyAuthenticationAdapter;

public class AuthenticationAdapter : IAuthenticationAdapter
{
    private ConfigurationData _config = new();

    public IAuthenticationAdapterMetadata Metadata => AuthenticationAdapterMetadata.Instance;


    public void OnAuthenticationPipelineLoad(IAuthenticationMethodConfigData configData)
    {
        if (configData != null && configData.Data != null && configData.Data.Length > 0)
        {
            try
            {
                var jsonContractSerializer = new DataContractJsonSerializer(typeof(ConfigurationData));
                _config = (ConfigurationData)jsonContractSerializer.ReadObject(configData.Data);
            }
            catch (Exception ex)
            {
                throw new InvalidDataException("OnAuthenticationPipelineLoad [PasskeyAuthenticationAdapter]: Error parsing configuration data.", ex);
            }
        }

        if (_config.PasskeyHandlerUrl == null || !Uri.IsWellFormedUriString(_config.PasskeyHandlerUrl, UriKind.Absolute))
        {
            throw new InvalidDataException("OnAuthenticationPipelineLoad [PasskeyAuthenticationAdapter]: BaseUrl was null or invalid");
        }

        if (string.IsNullOrWhiteSpace(_config.LdapServer) && string.IsNullOrWhiteSpace(_config.DomainName))
        {
            throw new InvalidDataException("OnAuthenticationPipelineLoad [PasskeyAuthenticationAdapter]: LdapServer AND DomainName was null or empty");
        }

        if (string.IsNullOrWhiteSpace(_config.SearchBaseDN))
        {
            throw new InvalidDataException("OnAuthenticationPipelineLoad [PasskeyAuthenticationAdapter]: SearchBaseDN was null or empty");
        }
    }

    public void OnAuthenticationPipelineUnload() { }



    public bool IsAvailableForUser(Claim identityClaim, IAuthenticationContext context)
    {
        if (string.IsNullOrWhiteSpace(identityClaim?.Value))
        {
            return false;
        }

        EnsurePasskeysInContext(identityClaim!.Value, context);
        return context.HasPasskeyCredentialIds();
    }



    public IAdapterPresentation? BeginAuthentication(Claim identityClaim, HttpListenerRequest request, IAuthenticationContext context)
    {
        if (context == null)
        {
            throw new InvalidOperationException("BeginAuthentication [PasskeyAuthenticationAdapter]: context was null");
        }

        if (string.IsNullOrWhiteSpace(identityClaim?.Value))
        {
            throw new InvalidOperationException("BeginAuthentication [PasskeyAuthenticationAdapter]: identityClaim was null or empty");
        }

        context.Data["userPrincipalName"] = identityClaim!.Value;

        EnsurePasskeysInContext(identityClaim!.Value, context);
        if (!context.HasPasskeyCredentialIds())
        {
            throw new InvalidOperationException("BeginAuthentication [PasskeyAuthenticationAdapter]: No passkeys where associated with the user identity.");
        }

        var assertionOptions = GetPasskeyAssertionOptions(context);
        context.SaveAssertionOptions(assertionOptions);

        return new PasskeyPresentation(new()
        {
            ShouldAutostartFlow = true,
            AssertionOptions = assertionOptions,
        });
    }


    public IAdapterPresentation? TryEndAuthentication(IAuthenticationContext context, IProofData proofData, HttpListenerRequest request, out Claim[] claims)
    {
        if (context == null)
        {
            throw new InvalidOperationException("TryEndAuthentication [PasskeyAuthenticationAdapter]: context was null");
        }

        if (proofData == null || proofData.Properties == null)
        {
            throw new InvalidOperationException("TryEndAuthentication [PasskeyAuthenticationAdapter]: no proof data received");
        }

        var passkeyValidationResult = ValidatePasskeyAssertion(context, proofData, out var passkeyClaims);
        if (passkeyValidationResult && passkeyClaims != null)
        {
            // Add the authentication method claim mentioned in metadata, indicating the particulate authentication method has been used successfully.
            passkeyClaims.Insert(0, new Claim(ClaimTypes.AuthenticationMethod, Metadata.AuthenticationMethods.First()));
            claims = passkeyClaims.ToArray();

            return null;
        }

        string? userIdentity = context.Data["userPrincipalName"] as string 
            ?? throw new InvalidOperationException("TryEndAuthentication [PasskeyAuthenticationAdapter]: userIdentity has been lost.");

        EnsurePasskeysInContext(userIdentity, context);
        if (!context.HasPasskeyCredentialIds())
        {
            throw new InvalidOperationException("BeginAuthentication [PasskeyAuthenticationAdapter]: No passkeys where associated with the user identity.");
        }

        var assertionOptions = GetPasskeyAssertionOptions(context);
        context.SaveAssertionOptions(assertionOptions);

        claims = Array.Empty<Claim>();
        return new PasskeyPresentation(new()
        {
            ShouldAutostartFlow = false,
            AssertionOptions = assertionOptions,
            ErrorResource = "PasskeyAuthFailed"
        });
    }


    public IAdapterPresentation? OnError(HttpListenerRequest request, ExternalAuthenticationException ex)
    {
        return null; // This will appearantly trigger "default ADFS error handling"
    }


    private void EnsurePasskeysInContext(string userPrincipalName, IAuthenticationContext context)
    {
        if (context.HasPasskeyCredentialIds())
        {
            return;
        }

        var passkeyIds = GetPasskeyCredentialIds(userPrincipalName);

        if (passkeyIds?.Any() == true)
        {
            context.SavePasskeyCredentialIds(passkeyIds);
        }
    }


    private string[]? GetPasskeyCredentialIds(string userPrincipalName)
    {
        var uriBuilder = new UriBuilder(_config.PasskeyHandlerUrl)
        {
            Query = $"upn={userPrincipalName}"
        };

        var httpRequest = WebRequest.CreateHttp(uriBuilder.ToString());
        httpRequest.Accept = "plain/text";

        using var response = (HttpWebResponse)httpRequest.GetResponse();
        if (response.StatusCode != HttpStatusCode.OK)
        {
            throw new InvalidOperationException("GetPasskeyCredentialIds [PasskeyAuthenticationAdapter]: Could not retrieve Passkey CredentialIds from PasskeyHandler.");
        }

        using var stream = response.GetResponseStream();
        using var reader = new StreamReader(stream, Encoding.UTF8);
        {
            var responseString = reader.ReadToEnd();
            return responseString.Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
        }
    }


    private string GetPasskeyAssertionOptions(IAuthenticationContext context)
    {
        var credentialIds = context.GetPasskeyCredentialIds();

        var uriBuilder = new UriBuilder(_config.PasskeyHandlerUrl)
        {
            Query = string.Join("&", credentialIds.Select(x => $"pci={x}"))
        };

        var httpRequest = WebRequest.CreateHttp(uriBuilder.ToString());
        httpRequest.Accept = "application/json";

        using var response = (HttpWebResponse)httpRequest.GetResponse();
        if (response.StatusCode != HttpStatusCode.OK)
        {
            throw new InvalidOperationException("GetPasskeyOptions [PasskeyAuthenticationAdapter]: Could not retrieve Passkey AssertionOptions from PasskeyHandler.");
        }

        using var stream = response.GetResponseStream();
        using var reader = new StreamReader(stream, Encoding.UTF8);
        {
            var responseString = reader.ReadToEnd();
            return responseString;
        }
    }

    private bool ValidatePasskeyAssertion(IAuthenticationContext context, IProofData proofData, out IList<Claim>? passkeyClaims)
    {
        var assertionOptions = context.GetAssertionOptions();
        var assertionResponse = proofData.Properties["assertionResponse"] as string;

        if (string.IsNullOrWhiteSpace(assertionOptions) || string.IsNullOrWhiteSpace(assertionResponse))
        {
            passkeyClaims = null;
            return false;
        }

        var postData = new StringBuilder();
        AppendUrlEncoded(postData, "assertionOptions", assertionOptions!);
        AppendUrlEncoded(postData, "assertionResponse", assertionResponse!);
        var postBytes = Encoding.UTF8.GetBytes(postData.ToString());

        var httpRequest = WebRequest.CreateHttp(_config.PasskeyHandlerUrl);
        httpRequest.Method = "POST";
        httpRequest.ContentType = "application/x-www-form-urlencoded";
        httpRequest.ContentLength = postBytes.Length;

        using (var stream = httpRequest.GetRequestStream())
        {
            stream.Write(postBytes, 0, postBytes.Length);
            stream.Flush();
        }

        using var response = (HttpWebResponse)httpRequest.GetResponse();

        if(response.StatusCode == HttpStatusCode.OK)
        {
            passkeyClaims = new List<Claim>();

            using var stream = response.GetResponseStream();
            using var reader = new StreamReader(stream, Encoding.UTF8);
            
            var responseString = reader.ReadToEnd();
            
            var equalSign = new char[] { '=' };
            var newLines = new char[] { '\r', '\n' };
            foreach (var line in responseString.Split(newLines, StringSplitOptions.RemoveEmptyEntries))
            {
                var elements = line.Trim().Split(equalSign, 2, StringSplitOptions.RemoveEmptyEntries);
                if(elements.Length != 2)
                {
                    continue;
                }

                passkeyClaims.Add(new Claim(elements[0].Trim(), elements[1].Trim()));
            }

            return true;
        }

        passkeyClaims = null;
        return false;
    }

    private static void AppendUrlEncoded(StringBuilder sb, string name, string value)
    {
        if (sb.Length != 0)
        {
            sb.Append("&");
        }

        sb.Append(HttpUtility.UrlEncode(name));
        sb.Append("=");
        sb.Append(HttpUtility.UrlEncode(value));
    }
}
