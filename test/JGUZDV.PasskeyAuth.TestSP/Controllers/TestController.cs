using System.Security.Authentication;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.MvcCore;
using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JGUZDV.PasskeyAuth.TestSP.Controllers;

public class SAMLTestController(
    IConfiguration config
    ) : ControllerBase
{
    private const string _relayStateReturnUrl = "returnUrl";
    private readonly IConfiguration _config = config;

    [Route("/"), HttpGet, Authorize]
    public IActionResult Index()
    {
        var user = HttpContext.User.Claims.Select(x => $"{x.Type}: {x.Value}").Aggregate("", (c, s) => c + "\r\n" + s);

        return Content($"<pre>Hello World\r\n{user}</pre>");
    }


    [Route("/saml2/metadata"), HttpGet]
    public IActionResult GetMetadata()
    {
        var entityDescriptor = new EntityDescriptor(new Saml2Configuration { Issuer = GetEntityId() })
        {
            ValidUntil = 7,

            SPSsoDescriptor = new SPSsoDescriptor
            {
                AssertionConsumerServices = [
                    new() {
                        Binding = ProtocolBindings.HttpPost,
                        Location = new Uri(new Uri($"{Request.Scheme}://{Request.Host}"), Url.Content("~/saml2/redirect/post"))
                    }
                ]
            },

            Organization = new Organization("ZDV", "Zentrum für Datenverarbeitung", "https://www.zdv.uni-mainz.de"),
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

        return new Saml2Metadata(entityDescriptor).CreateMetadata().ToActionResult();
    }

    [Route("/saml2/login"), HttpGet]
    public IActionResult Login(string? returnUrl,
        [FromServices] Saml2Configuration samlConfig)
    {
        var binding = new Saml2RedirectBinding();
        binding.SetRelayStateQuery(
            new Dictionary<string, string>
            {
                { _relayStateReturnUrl, returnUrl ?? Url.Content("~/") }
            }
        );

        var samlAuthnRequest = new Saml2AuthnRequest(samlConfig);
        samlAuthnRequest.Issuer = GetEntityId();
        return binding.Bind(samlAuthnRequest).ToActionResult();
    }

    [Route("/saml2/redirect/post"), HttpPost]
    public async Task<IActionResult> PostBinding(
        [FromServices] Saml2Configuration samlConfig)
    {
        var httpRequest = Request.ToGenericHttpRequest(validate: true);
        var saml2AuthnResponse = new Saml2AuthnResponse(samlConfig);

        httpRequest.Binding.ReadSamlResponse(httpRequest, saml2AuthnResponse);
        if (saml2AuthnResponse.Status != Saml2StatusCodes.Success)
        {
            throw new AuthenticationException($"SAML Response status: {saml2AuthnResponse.Status}");
        }
        httpRequest.Binding.Unbind(httpRequest, saml2AuthnResponse);
        await saml2AuthnResponse.CreateSession(HttpContext, claimsTransform: ClaimsTransform.Transform);

        var relayStateQuery = httpRequest.Binding.GetRelayStateQuery();
        relayStateQuery.TryGetValue(_relayStateReturnUrl, out var returnUrl);
        returnUrl ??= Url.Content("~/");

        return Redirect(returnUrl);
    }


    private string GetEntityId()
    {
        return _config["Saml2:SP:EntityId"]!;
    }
}
