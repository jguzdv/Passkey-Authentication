using ITfoxtec.Identity.Saml2;

using JGUZDV.ActiveDirectory;
using JGUZDV.ActiveDirectory.Configuration;
using JGUZDV.AspNetCore.Hosting;
using JGUZDV.Passkey.ActiveDirectory;
using JGUZDV.PasskeyAuth.Authentication;
using JGUZDV.PasskeyAuth.Configuration;
using JGUZDV.PasskeyAuth.Endpoints;
using JGUZDV.PasskeyAuth.SAML2.CertificateHandling;
using JGUZDV.PasskeyAuth.SAML2.MetadataHandling;

using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;

using BlazorInteractivityModes = JGUZDV.AspNetCore.Hosting.Components.BlazorInteractivityModes;


var builder = JGUZDVHostApplicationBuilder.CreateWebHost(args, BlazorInteractivityModes.DisableBlazor);
var services = builder.Services;

services.AddOptions<PasskeyAuthOptions>()
    .BindConfiguration("PasskeyAuth")
    .ValidateDataAnnotations()
    .ValidateOnStart();

// Copy settings from PasskeyAuthOptions to ActiveDirectoryOptions
services.AddOptions<ActiveDirectoryOptions>()
    .BindConfiguration("PasskeyAuth:ActiveDirectory")
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

//TODO: This is a redo, since it's missing from the HostBuilder
services.AddRazorPages()
    .AddViewLocalization();

services.Configure<RazorPagesOptions>(opt =>
{
    opt.Conventions.AuthorizePage("/Info");
});


services.AddSession();

services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(opt =>
    {
        opt.SlidingExpiration = false;
        // TODO: make this configurable
        opt.ExpireTimeSpan = TimeSpan.FromHours(8);
        opt.LoginPath = "/";
    })
    .AddCookieDistributedTicketStore();
services.AddAuthorizationCore();

services.AddFido2(builder.Configuration.GetSection("Fido2"));

services.AddScoped<PasskeyHandler>();
services.AddScoped<OneTimePasswordHandler>();

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

app.UseAuthentication();
app.UseAuthorization();

app.UseAntiforgery();

app.MapRazorPages();
app.MapSAMLEndpoints();
app.MapPasskeyEndpoints();
app.MapOTPEndpoints();

app.Run();
