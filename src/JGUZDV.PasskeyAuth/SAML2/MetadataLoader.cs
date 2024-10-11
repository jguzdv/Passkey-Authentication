using ITfoxtec.Identity.Saml2.Schemas.Metadata;

namespace JGUZDV.PasskeyAuth.SAML2;

public class SPMetadataLoader : IHostedService
{
    private readonly IConfiguration _configuration;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<SPMetadataLoader> _logger;
    private readonly RelyingPartyMetadata _metadata;
    private readonly Dictionary<string, Timer> _timers = [];

    public SPMetadataLoader(
        IConfiguration configuration,
        IHttpClientFactory httpClientFactory,
        ILogger<SPMetadataLoader> logger,
        [FromKeyedServices("Saml2:SP")] RelyingPartyMetadata metadata)
    {
        _configuration = configuration;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
        _metadata = metadata;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        foreach (var metadataUrl in _configuration.GetSection("Saml2:RelyingParties").Get<string[]>() ?? [])
        {
            // Create a timer foreach url
            _timers[metadataUrl] = new Timer((ctx) => _ = LoadMetadata(metadataUrl), null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(60));
        }

        return Task.CompletedTask;
    }

    private async Task LoadMetadata(string metadataUrl)
    {
        _logger.LogInformation("Loading metadata from {metadataUrl}", metadataUrl);

        try
        {
            var entityDescriptor = new EntityDescriptor();
            await entityDescriptor.ReadSPSsoDescriptorFromUrlAsync(_httpClientFactory, new Uri(metadataUrl));

            //Add or update the entity descriptor
            if (!_metadata.RelyingParties.TryAdd(entityDescriptor.EntityId, entityDescriptor))
            {
                _metadata.RelyingParties[entityDescriptor.EntityId] = entityDescriptor;
            }

            //If we've successfully loaded the matadata, stop the timer
            _timers[metadataUrl].Dispose();

            //Create a new timer, that loads once every hour
            _timers[metadataUrl] = new Timer((ctx) => _ = LoadMetadata(metadataUrl), null, TimeSpan.FromHours(1), TimeSpan.FromHours(1));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load metadata from {metadataUrl}", metadataUrl);
        }
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        //Dispose all timers
        foreach (var timer in _timers.Values)
        {
            timer.Dispose();
        }

        return Task.CompletedTask;
    }
}
