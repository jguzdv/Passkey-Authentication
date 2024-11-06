using ITfoxtec.Identity.Saml2;
using JGUZDV.ActiveDirectory;
using JGUZDV.ActiveDirectory.Configuration;
using JGUZDV.Passkey.ActiveDirectory;
using JGUZDV.Passkey.ActiveDirectory.Extensions;
using JGUZDV.PasskeyAuth.Configuration;
using JGUZDV.PasskeyAuth.SAML2;
using JGUZDV.PasskeyAuth.SAML2.CertificateHandling;
using JGUZDV.PasskeyAuth.SAML2.MetadataHandling;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;


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

services.AddOptions<PasskeyAuthOptions>()
    .BindConfiguration("PasskeyAuth")
    .ValidateDataAnnotations()
    .ValidateOnStart();

services.AddOptions<ActiveDirectoryOptions>()
    .Configure<IOptions<PasskeyAuthOptions>>((opt, pkauth) =>
    {
        opt.Server = pkauth.Value.ActiveDirectory.Server;
        opt.BaseOU = pkauth.Value.ActiveDirectory.BaseOU;
    })
    .ValidateDataAnnotations()
    .ValidateOnStart();

services.AddScoped<ActiveDirectoryService>();

services.AddPropertyReader();
services.AddClaimProvider();

// Add property reader options for the properties we want to read from the AD.
services.AddOptions<PropertyReaderOptions>()
    .PostConfigure<IOptions<PasskeyAuthOptions>>((readerOptions, serverOptions) =>
    {
        foreach (var prop in serverOptions.Value.Properties)
        {
            readerOptions.PropertyInfos.Add(
                prop.Key,
                new(
                    prop.Key,
                    prop.Value switch
                    {
                        "int" => typeof(int),
                        "long" => typeof(long),
                        "DateTime" => typeof(DateTime),
                        "byte[]" => typeof(byte[]),
                        _ => typeof(string)
                    }
                )
            );
        }
    });

// Same, but for claims.
services.AddOptions<ClaimProviderOptions>()
    .PostConfigure<IOptions<PasskeyAuthOptions>>((cpOptions, serverOptions) =>
    {
        foreach (var src in serverOptions.Value.ClaimSources)
        {
            cpOptions.ClaimSources.RemoveAll(c => c.ClaimType.Equals(src.ClaimType, StringComparison.OrdinalIgnoreCase));
            cpOptions.ClaimSources.Add(src);
        }
    });


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
    })
    .AddCookieDistributedTicketStore();

services.AddFido2(builder.Configuration.GetSection("Fido2"));

services.AddOptions<CertificateOptions>()
    .Bind(builder.Configuration.GetSection("Saml2"))
    .ValidateDataAnnotations()
    .ValidateOnStart();

// Certificate management
services.AddSingleton<CertificateContainer>();
services.AddHostedService<CertificateManager>();

// Creates options e.g. for "/metadata". Creation and post configuration (PostConfigure) happens scoped on every request!
services.AddScoped(sp => sp.GetRequiredService<IOptionsSnapshot<Saml2Configuration>>().Value);
services.AddOptions<Saml2Configuration>()
    .Bind(builder.Configuration.GetSection("Saml2:IDP"))
    .PostConfigure<CertificateContainer>((saml2, certificateContainer) =>
    {
        saml2.AllowedAudienceUris.Add(saml2.Issuer);

        saml2.DecryptionCertificates.AddRange(certificateContainer.GetCertificates());
        saml2.SigningCertificate = certificateContainer.GetSignatureCertificate();
    });

// Metadata management
services.AddSingleton<MetadataContainer>();
services.AddHostedService<MetadataManager>();

services.AddOptions<RelyingPartyOptions>()
    .Bind(builder.Configuration.GetSection("Saml2"));       // Binds appsettings->Saml2->RelyingParties


var app = builder.Build();

if (app.Environment.IsDevelopment())
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

