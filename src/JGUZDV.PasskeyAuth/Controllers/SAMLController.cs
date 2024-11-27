using System.Diagnostics;
using System.Net;
using System.Security.Claims;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.MvcCore;
using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using JGUZDV.PasskeyAuth.SAML2.CertificateHandling;
using JGUZDV.PasskeyAuth.SAML2.MetadataHandling;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens.Saml2;

namespace JGUZDV.PasskeyAuth.Controllers;

[Route("saml2/idp")]
public class SAMLController(
        Saml2Configuration samlConfig,
        CertificateContainer certificateContainer,
        MetadataContainer metadataContainer,
        ILogger<SAMLController> logger
    ) : ControllerBase
{
    private readonly Saml2Configuration _samlConfig = samlConfig;
    private readonly CertificateContainer _certificateContainer = certificateContainer;
    private readonly MetadataContainer _metadataContainer = metadataContainer;

    private readonly ILogger<SAMLController> _logger = logger;


    [HttpGet("metadata")]
    public IActionResult GetMetadata()
    {
        var entityDescriptor = new EntityDescriptor(_samlConfig)
        {
            ValidUntil = 7,
            IdPSsoDescriptor = new IdPSsoDescriptor
            {
                WantAuthnRequestsSigned = _samlConfig.SignAuthnRequest,

                // We'll always announce all certificates in metadata
                SigningCertificates = _certificateContainer.GetCertificates(),
                EncryptionCertificates = _certificateContainer.GetCertificates(),

                SingleSignOnServices =
                [
                    new()
                    {
                        Binding = ProtocolBindings.HttpRedirect,
                        Location = new Uri(new Uri($"{Request.Scheme}://{Request.Host}"), Url.Content("~/saml2/idp/login"))
                    }
                ],
                SingleLogoutServices =
                [
                    new()
                    {
                        Binding = ProtocolBindings.HttpPost,
                        Location = new Uri(new Uri($"{Request.Scheme}://{Request.Host}"), Url.Content("~/saml2/idp/logout"))
                    }
                ],
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
        return metadata.ToActionResult();
    }


    [HttpGet("status")]
    public IActionResult Status()
    {
        // TODO: Write out metadata that has been loaded
        return Ok("Statuspage");
    }


    [HttpGet("login")]
    public async Task<IActionResult> Login()
    {
        var authResult = await HttpContext.AuthenticateAsync();

        if(!authResult.Succeeded) // We are not authenticated yet
        {
            var returnUrl = WebUtility.UrlEncode(Request.GetEncodedPathAndQuery());
            return Redirect("~/?returnUrl=" + returnUrl);
        }

        return await CreateSamlResponse(authResult.Principal);
    }


    private async Task<IActionResult> CreateSamlResponse(ClaimsPrincipal principal)
    {
        var httpRequest = Request.ToGenericHttpRequest(validate: true);
        var samlRequest = httpRequest.Binding.ReadSamlRequest(httpRequest, new Saml2AuthnRequest(_samlConfig));

        EntityDescriptor relyingParty;

        try
        {
            // Get an existing reylingParty entry from the metadataContainer, or fetch it if it is not present.
            relyingParty = await _metadataContainer.GetByEntityId(samlRequest.Issuer);
        }
        catch (MetadataLoaderException)
        {
            throw new BadHttpRequestException("SAML2:RelyingPartyNotLoaded");
        }
        catch (InvalidOperationException)
        {
            throw new BadHttpRequestException("SAML2:InvalidEntityId");
        }

        var rpConfig = GetRpSaml2Configuration(relyingParty);
        var saml2AuthnRequest = new Saml2AuthnRequest(rpConfig);

        try
        {
            httpRequest.Binding.Unbind(httpRequest, saml2AuthnRequest);

            return LoginPostResponse(saml2AuthnRequest.Id, Saml2StatusCodes.Success, httpRequest.Binding.RelayState, relyingParty, rpConfig, principal.Claims);
        }
        catch (Exception exc)
        {
            Debug.WriteLine($"Saml 2.0 Authn Request error: {exc.ToString()}\nSaml Auth Request: '{saml2AuthnRequest.XmlDocument?.OuterXml}'\nQuery String: {Request.QueryString}");
            return LoginPostResponse(saml2AuthnRequest.Id, Saml2StatusCodes.Responder, httpRequest.Binding.RelayState, relyingParty, rpConfig, null);
        }
    }

    private static IActionResult LoginPostResponse(Saml2Id inResponseTo, Saml2StatusCodes status, string relayState, EntityDescriptor relyingParty, Saml2Configuration rpConfig, IEnumerable<Claim>? claims)
    {
        var responsebinding = new Saml2PostBinding
        {
            RelayState = relayState
        };

        var saml2AuthnResponse = new Saml2AuthnResponse(rpConfig)
        {
            InResponseTo = inResponseTo,
            Status = status,
            Destination = relyingParty.SPSsoDescriptor.AssertionConsumerServices.First(x => x.IsDefault).Location,
        };

        if (status == Saml2StatusCodes.Success && claims != null)
        {
            saml2AuthnResponse.ClaimsIdentity = new ClaimsIdentity(claims, "FIDO2", "sub", "role");
            saml2AuthnResponse.NameId = new Saml2NameIdentifier(claims.First(x => x.Type == "sub").Value, NameIdentifierFormats.Unspecified);

            var token = saml2AuthnResponse.CreateSecurityToken(
                relyingParty.EntityId,
                subjectConfirmationLifetime: 5,
                // TODO: there seems to be no ac:class for FIDO2 currently, so we made one up
                authnContext: new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:FIDO2Passkey"),
                issuedTokenLifetime: 60
                );
        }

        return responsebinding.Bind(saml2AuthnResponse).ToActionResult();
    }

    private Saml2Configuration GetRpSaml2Configuration(EntityDescriptor relyingParty)
    {
        var rpConfig = new Saml2Configuration()
        {
            Issuer = _samlConfig.Issuer,
            SignAuthnRequest = _samlConfig.SignAuthnRequest,
            SingleSignOnDestination = _samlConfig.SingleSignOnDestination,
            SingleLogoutDestination = _samlConfig.SingleLogoutDestination,
            ArtifactResolutionService = _samlConfig.ArtifactResolutionService,
            SigningCertificate = _samlConfig.SigningCertificate,
            SignatureAlgorithm = _samlConfig.SignatureAlgorithm,
            CertificateValidationMode = _samlConfig.CertificateValidationMode,
            RevocationMode = _samlConfig.RevocationMode
        };

        rpConfig.AllowedAudienceUris.AddRange(_samlConfig.AllowedAudienceUris);

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
