using System.Diagnostics;
using System.Net;
using System.Security.Claims;
using System.Xml;

using Azure.Core;

using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.MvcCore;
using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;

using JGUZDV.PasskeyAuth.SAML2.CertificateHandling;
using JGUZDV.PasskeyAuth.SAML2.MetadataHandling;

using Microsoft.IdentityModel.Tokens.Saml2;

namespace JGUZDV.PasskeyAuth.Endpoints;

public static class SAMLEndpoints
{
    public static IEndpointRouteBuilder MapSAMLEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var saml = endpoints.MapGroup("saml2/idp");

        saml.MapGet("/metadata", GetMetadata);
        saml.MapGet("/login", PerformSAMlLogin)
            .WithName(nameof(PerformSAMlLogin))
            .RequireAuthorization();

        return endpoints;
    }


    internal static IResult GetMetadata(
        HttpContext context,
        LinkGenerator linkGenerator,
        Saml2Configuration samlConfig,
        CertificateContainer certificateContainer,
        MetadataContainer metadataContainer)
    {
        var entityDescriptor = new EntityDescriptor(samlConfig)
        {
            ValidUntil = 7,
            IdPSsoDescriptor = new IdPSsoDescriptor
            {
                WantAuthnRequestsSigned = samlConfig.SignAuthnRequest,

                // We'll always announce all certificates in metadata
                SigningCertificates = certificateContainer.GetCertificates(),
                EncryptionCertificates = certificateContainer.GetCertificates(),

                SingleSignOnServices =
                [
                    new()
                    {
                        Binding = ProtocolBindings.HttpRedirect,
                        Location = new Uri(linkGenerator.GetUriByName(context, nameof(PerformSAMlLogin), null, scheme: "https")!)
                    }
                ],
                //SingleLogoutServices =
                //[
                //    new()
                //    {
                //        Binding = ProtocolBindings.HttpPost,
                //        Location = new Uri(new Uri($"{Request.Scheme}://{Request.Host}"), Url.Content("~/saml2/idp/logout"))
                //    }
                //],
                NameIDFormats = [
                    NameIdentifierFormats.Unspecified,
                ],
                Attributes =
                [
                    new("role", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"),
                    new("sub", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"),
                    new("userSid", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"),
                    new("upn", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic")
                ]
            },
            //Organization = new Organization("ZDV", "Zentrum für Datenverarbeitung", "https://www.zdv.uni-mainz.de"),
            ContactPersons = [
                new ContactPerson(ContactTypes.Administrative)
                {
                    Company = "Johannes Gutenberg-Universität Mainz",
                    GivenName = "Thomas",
                    SurName = "Ottenhus",
                    EmailAddress = "zdv-dev@uni-mainz.de",
                    TelephoneNumber = "+4961313926487",
                },
                new ContactPerson(ContactTypes.Technical)
                {
                    Company = "Johannes Gutenberg-Universität Mainz",
                    GivenName = "Thomas",
                    SurName = "Ottenhus",
                    EmailAddress = "zdv-dev@uni-mainz.de",
                    TelephoneNumber = "+4961313926487",
                }
            ]
        };

        var metadata = new Saml2Metadata(entityDescriptor).CreateMetadata();
        return Results.Content(metadata.ToXml(), "text/xml");
    }


    internal static async Task<IResult> PerformSAMlLogin(
        HttpContext context,
        Saml2Configuration samlConfig,
        CertificateContainer certificateContainer,
        MetadataContainer metadataContainer,
        ILogger<SecurityAudit> auditLogger)
    {
        var httpRequest = context.Request.ToGenericHttpRequest(validate: true);
        var samlRequest = httpRequest.Binding.ReadSamlRequest(httpRequest, new Saml2AuthnRequest(samlConfig));

        EntityDescriptor relyingParty;

        try
        {
            // Get an existing reylingParty entry from the metadataContainer, or fetch it if it is not present.
            relyingParty = await metadataContainer.GetByEntityId(samlRequest.Issuer);
        }
        catch (MetadataLoaderException)
        {
            throw new BadHttpRequestException("SAML2:RelyingPartyNotLoaded");
        }
        catch (InvalidOperationException)
        {
            throw new BadHttpRequestException("SAML2:InvalidEntityId");
        }

        var rpConfig = GetRpSaml2Configuration(relyingParty, samlConfig);
        var saml2AuthnRequest = new Saml2AuthnRequest(rpConfig);

        var responseBinding = new Saml2PostBinding
        {
            RelayState = httpRequest.Binding.RelayState
        };

        Saml2AuthnResponse saml2AuthnResponse;

        try
        {
            httpRequest.Binding.Unbind(httpRequest, saml2AuthnRequest);

            var claims = context.User.Claims;
            saml2AuthnResponse = new Saml2AuthnResponse(rpConfig)
            {
                InResponseTo = saml2AuthnRequest.Id,
                Status = Saml2StatusCodes.Success,
                Destination = relyingParty.SPSsoDescriptor.AssertionConsumerServices.First(x => x.IsDefault).Location,

                ClaimsIdentity = new ClaimsIdentity(claims, "FIDO2", "sub", "role"),
                NameId = new Saml2NameIdentifier(claims.First(x => x.Type == "sub").Value, NameIdentifierFormats.Unspecified),
            };

            var token = saml2AuthnResponse.CreateSecurityToken(
                relyingParty.EntityId,
                subjectConfirmationLifetime: 5,
                // TODO: there seems to be no ac:class for FIDO2 currently, so we made one up
                authnContext: new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:FIDO2Passkey"),
                issuedTokenLifetime: 60
                );

            auditLogger.LogInformation("A SAML2 token was created for {NameId}.", saml2AuthnResponse.NameId.Value);
        }
        catch (Exception exc)
        {
            Debug.WriteLine($"Saml 2.0 Authn Request error: {exc.ToString()}\nSaml Auth Request: '{saml2AuthnRequest.XmlDocument?.OuterXml}'\nQuery String: {context.Request.QueryString}");
            saml2AuthnResponse = new Saml2AuthnResponse(rpConfig)
            {
                InResponseTo = saml2AuthnRequest.Id,
                Status = Saml2StatusCodes.Responder,
                Destination = relyingParty.SPSsoDescriptor.AssertionConsumerServices.First(x => x.IsDefault).Location,
            };
        }

        responseBinding.Bind(saml2AuthnResponse);
        return Results.Content(responseBinding.PostContent, "text/html");
    }


    private static Saml2Configuration GetRpSaml2Configuration(EntityDescriptor relyingParty, Saml2Configuration samlConfig)
    {
        var rpConfig = new Saml2Configuration()
        {
            Issuer = samlConfig.Issuer,
            SignAuthnRequest = samlConfig.SignAuthnRequest,
            SingleSignOnDestination = samlConfig.SingleSignOnDestination,
            SingleLogoutDestination = samlConfig.SingleLogoutDestination,
            ArtifactResolutionService = samlConfig.ArtifactResolutionService,
            SigningCertificate = samlConfig.SigningCertificate,
            SignatureAlgorithm = samlConfig.SignatureAlgorithm,
            CertificateValidationMode = samlConfig.CertificateValidationMode,
            RevocationMode = samlConfig.RevocationMode
        };

        rpConfig.AllowedAudienceUris.AddRange(samlConfig.AllowedAudienceUris);

        if (relyingParty != null)
        {
            rpConfig.SignatureValidationCertificates.AddRange(relyingParty.SPSsoDescriptor.SigningCertificates);
            if (relyingParty.SPSsoDescriptor.EncryptionCertificates?.Count() > 0)
            {
                rpConfig.EncryptionCertificate = relyingParty.SPSsoDescriptor.EncryptionCertificates
                    .Where(x => x.IsValidLocalTime())
                    .LastOrDefault();
            }
        }

        return rpConfig;
    }
}
