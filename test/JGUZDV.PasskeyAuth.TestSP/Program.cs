using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.MvcCore.Configuration;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);
var services = builder.Services;

services.AddHttpClient();
services.AddControllers();

services.AddKeyedSingleton("Saml2:IDP", new EntityDescriptor());

services.AddScoped(sp => sp.GetRequiredService<IOptionsSnapshot<Saml2Configuration>>().Value);
services.AddOptions<Saml2Configuration>()
    .Bind(builder.Configuration.GetSection("Saml2:SP"));
services.ConfigureOptions<IDPMetadataConfiguration>();

services.AddSaml2(
    loginPath: "/saml2/login"
    );

services.AddHostedService<IDPMetadataLoader>();

var app = builder.Build();

app.MapControllers();

app.Run();


public class IDPMetadataConfiguration : IConfigureOptions<Saml2Configuration>
{
    private readonly EntityDescriptor _idpDescriptor;

    public IDPMetadataConfiguration([FromKeyedServices("Saml2:IDP")] EntityDescriptor idpDescriptor)
    {
        _idpDescriptor = idpDescriptor;
    }

    public void Configure(Saml2Configuration saml2)
    {
        saml2.SingleSignOnDestination = _idpDescriptor.IdPSsoDescriptor.SingleSignOnServices.First().Location;
        saml2.SingleLogoutDestination = _idpDescriptor.IdPSsoDescriptor.SingleLogoutServices.First().Location;
        saml2.SignatureValidationCertificates.AddRange(_idpDescriptor.IdPSsoDescriptor.SigningCertificates);

        saml2.AllowedAudienceUris.Add("https://localhost:7002/saml2/");
        saml2.CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.None;
    }
}

public class IDPMetadataLoader : IHostedService
{
    private readonly IConfiguration _configuration;
    private readonly IHttpClientFactory _httpClientFactory;

    private readonly EntityDescriptor _idpDescriptor;
    private Timer? _timer;

    public IDPMetadataLoader(
        IConfiguration configuration,
        IHttpClientFactory httpClientFactory,
        [FromKeyedServices("Saml2:IDP")] EntityDescriptor idpDescriptor)
    {
        _configuration = configuration;
        _httpClientFactory = httpClientFactory;
        _idpDescriptor = idpDescriptor;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await _idpDescriptor.ReadIdPSsoDescriptorFromUrlAsync(_httpClientFactory, new Uri(_configuration["Saml2:IdPMetadataUrl"]!));

        _timer = new Timer((ctx) => _ = LoadIdpMetadata(), null, TimeSpan.FromSeconds(60), TimeSpan.FromSeconds(60));
    }

    private async Task LoadIdpMetadata()
    {
        await _idpDescriptor.ReadIdPSsoDescriptorFromUrlAsync(_httpClientFactory, new Uri(_configuration["Saml2:IdPMetadataUrl"]!));
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _timer?.Dispose();
        return Task.CompletedTask;
    }
}
