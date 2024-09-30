using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Configuration;
using JGUZDV.ActiveDirectory;
using JGUZDV.Passkey.ActiveDirectory.Extensions;
using JGUZDV.PasskeyAuth.SAML2;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;
using System.Security.Cryptography.X509Certificates;


var builder = WebApplication.CreateBuilder(args);
var services = builder.Services;

builder.UseJGUZDVLogging();

if (builder.Environment.IsProduction())
{
    services.AddDistributedSqlServerCache(opt =>
    {
        builder.Configuration.Bind("DistributedCache", opt);
    });
    builder.AddJGUZDVDataProtection();
}

//TODO: Replace with a merge mechanism as in OIDC-Server
services.AddPropertyReader(opt => builder.Configuration.GetRequiredSection("PropertyReader").Bind(opt));
services.AddClaimProvider(opt => builder.Configuration.GetRequiredSection("ClaimProvider").Bind(opt));

services.AddHttpClient();
services.AddTransient((sp) => TimeProvider.System);
services.AddLocalization();
services.AddRequestLocalization(opt =>
{
    opt.SupportedCultures = [new("de-de"), new("en-US")];
    opt.SupportedUICultures = [.. opt.SupportedCultures];
    opt.DefaultRequestCulture = new(opt.SupportedCultures.First());
});

services.AddControllers();
services.AddRazorPages();
services.AddSession();

services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(opt =>
    {
        opt.SlidingExpiration = false;
        // TODO: make this configurable
        opt.ExpireTimeSpan = TimeSpan.FromHours(8);
    });

services.AddFido2(builder.Configuration.GetSection("Fido2"));
services.AddPasskeyActiveDirectoryServices("ActiveDirectory");

services.AddKeyedSingleton("Saml2:SP", new RelyingPartyMetadata());
services.AddHostedService<SPMetadataLoader>();

services.AddScoped(sp => sp.GetRequiredService<IOptionsSnapshot<Saml2Configuration>>().Value);
services.AddOptions<Saml2Configuration>()
    .Bind(builder.Configuration.GetSection("Saml2:IDP"))
    .PostConfigure<IConfiguration>((saml2, config) =>
    {
        var certifiates = Directory.GetFiles(config["SAML2:CertificatesPath"]!, "*.pfx")
            .Select(x => new X509Certificate2(x, config["SAML2:CertificatePassword"]))
            .ToList();

        saml2.DecryptionCertificates.AddRange(certifiates);

        // Take the oldest certificate that is still valid
        saml2.SigningCertificate = certifiates
            .Where(x => x.IsValidLocalTime())
            .OrderBy(x => x.NotAfter)
            .First();

        if (saml2.SigningCertificate?.IsValidLocalTime() != true)
        {
            throw new Saml2ConfigurationException("The IdP signing certificates has expired.");
        }
        saml2.AllowedAudienceUris.Add(saml2.Issuer);
    });



var app = builder.Build();

if (app.Environment.IsDevelopment() && false)
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/Error");
    //app.UseStatusCodePagesWithReExecute("/Error/{0}");
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseStaticFiles();
app.UseSession();

app.UseRequestLocalization();
app.UseRouting();

app.UseAntiforgery();

app.MapRazorPages();
app.MapControllers();

app.Run();

