using System.Diagnostics;
using System.Net;
using System.Security.Claims;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.MvcCore;
using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using JGUZDV.PasskeyAuth.SAML2;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens.Saml2;

namespace JGUZDV.PasskeyAuth.Controllers;

[Route("saml2/idp")]
public class SAMLController(
    Saml2Configuration samlConfig,
    [FromKeyedServices("Saml2:SP")] RelyingPartyMetadata rpMetadata
    )
    : ControllerBase
{
    private readonly Saml2Configuration _samlConfig = samlConfig;
    private readonly RelyingPartyMetadata _rpMetadata = rpMetadata;

    [HttpGet("metadata")]
    public IActionResult GetMetadata()
    {
        var entityDescriptor = new EntityDescriptor(_samlConfig)
        {
            ValidUntil = 7,
            IdPSsoDescriptor = new IdPSsoDescriptor
            {
                WantAuthnRequestsSigned = _samlConfig.SignAuthnRequest,
                SigningCertificates = [_samlConfig.SigningCertificate],

                //EncryptionCertificates = config.DecryptionCertificates,
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
                //ArtifactResolutionServices =
                //[
                //    new()
                //    {
                //        Binding = ProtocolBindings.ArtifactSoap,
                //        Index = _samlConfig.ArtifactResolutionService.Index,
                //        Location = _samlConfig.ArtifactResolutionService.Location
                //    }
                //],
                NameIDFormats = [
                    NameIdentifierFormats.Unspecified,
                ],
                Attributes =
                [
                    new("urn:oid:1.3.6.1.4.1.5923.1.1.1.6", friendlyName: "eduPersonPrincipalName")
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
    public async Task<IActionResult> Status()
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

        return CreateSamlResponse();
    }


    private IActionResult CreateSamlResponse()
    {
        var httpRequest = Request.ToGenericHttpRequest(validate: true);
        var samlRequest = httpRequest.Binding.ReadSamlRequest(httpRequest, new Saml2AuthnRequest(_samlConfig));

        if (!_rpMetadata.RelyingParties.TryGetValue(samlRequest.Issuer, out var relyingParty))
        {
            throw new BadHttpRequestException("SAML2:RelyingPartyNotFound");
        }

        var rpConfig = GetRpSaml2Configuration(relyingParty);
        var saml2AuthnRequest = new Saml2AuthnRequest(rpConfig);

        try
        {
            httpRequest.Binding.Unbind(httpRequest, saml2AuthnRequest);
            var claims = new List<Claim>(HttpContext.User.Claims);

            //TODO: Add more claims from AD (JGUZDV.ActiveDirectory should help)
            // - GroupSIDs
            // - SID of user
            // - GUID of user
            // - MFA claim, if AAGuid is applicable
            // - AMR claim
            // - UPN

            return LoginPostResponse(saml2AuthnRequest.Id, Saml2StatusCodes.Success, httpRequest.Binding.RelayState, relyingParty, rpConfig, claims);
        }
        catch (Exception exc)
        {
            Debug.WriteLine($"Saml 2.0 Authn Request error: {exc.ToString()}\nSaml Auth Request: '{saml2AuthnRequest.XmlDocument?.OuterXml}'\nQuery String: {Request.QueryString}");
            return LoginPostResponse(saml2AuthnRequest.Id, Saml2StatusCodes.Responder, httpRequest.Binding.RelayState, relyingParty, rpConfig, null);
        }
    }

    private IActionResult LoginPostResponse(Saml2Id inResponseTo, Saml2StatusCodes status, string relayState, EntityDescriptor relyingParty, Saml2Configuration rpConfig, IEnumerable<Claim>? claims)
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
            //var claimsIdentity = new ClaimsIdentity(claims);
            //saml2AuthnResponse.NameId = new Saml2NameIdentifier(claimsIdentity.Claims.Where(c => c.Type == ClaimTypes.NameIdentifier).Select(c => c.Value).Single(), NameIdentifierFormats.Persistent);
            //saml2AuthnResponse.NameId = new Saml2NameIdentifier(claimsIdentity.Claims.Where(c => c.Type == ClaimTypes.NameIdentifier).Select(c => c.Value).Single());
            saml2AuthnResponse.ClaimsIdentity = (ClaimsIdentity)HttpContext.User.Identity!;

            // TODO: Declare some more claims, like AMR
            var token = saml2AuthnResponse.CreateSecurityToken(
                relyingParty.EntityId,
                /*authnContext: new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"),*/
                /*declAuthnContext: new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified"),*/
                subjectConfirmationLifetime: 5,
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
                rpConfig.EncryptionCertificate = relyingParty.SPSsoDescriptor.EncryptionCertificates.LastOrDefault();
            }
        }

        return rpConfig;
    }
}
