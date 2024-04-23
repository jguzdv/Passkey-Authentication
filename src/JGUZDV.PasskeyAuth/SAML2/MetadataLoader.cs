using ITfoxtec.Identity.Saml2.Schemas.Metadata;

namespace JGUZDV.PasskeyAuth.SAML2;

public class SPMetadataLoader : IHostedService
{
    private readonly IConfiguration _configuration;
    private readonly IHttpClientFactory _httpClientFactory;

    private readonly RelyingPartyMetadata _metadata;
    private Timer? _timer;

    public SPMetadataLoader(
        IConfiguration configuration,
        IHttpClientFactory httpClientFactory,
        [FromKeyedServices("Saml2:SP")] RelyingPartyMetadata metadata)
    {
        _configuration = configuration;
        _httpClientFactory = httpClientFactory;
        _metadata = metadata;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        // await LoadMetadata();

        _timer = new Timer((ctx) => _ = LoadMetadata(), null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(60));
    }

    private async Task LoadMetadata()
    {
        foreach(var metadataUrl in _configuration.GetSection("Saml2:RelyingParties").Get<string[]>() ?? [])
        {
            var entityDescriptor = new EntityDescriptor();
            await entityDescriptor.ReadSPSsoDescriptorFromUrlAsync(_httpClientFactory, new Uri(metadataUrl));
            _metadata.RelyingParties.Add(entityDescriptor.EntityId, entityDescriptor);
        }
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _timer?.Dispose();
        return Task.CompletedTask;
    }
}
