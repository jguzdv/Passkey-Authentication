
using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using System.Net.Http;
using Microsoft.Extensions.Options;

namespace JGUZDV.PasskeyAuth.SAML2.MetadataHandling;

public class MetadataManager : IHostedService
{
    private readonly Dictionary<string, Timer> _timers = [];

    private readonly MetadataContainer _metadataContainer;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IOptions<RelyingPartyOptions> _options;
    private readonly ILogger<MetadataManager> _logger;

    public MetadataManager(MetadataContainer metadataContainer,
        IHttpClientFactory httpClientFactory,
        IOptions<RelyingPartyOptions> options,
        ILogger<MetadataManager> logger)
    {
        _metadataContainer = metadataContainer;
        _httpClientFactory = httpClientFactory;
        _options = options;
        _logger = logger;
    }


    public Task StartAsync(CancellationToken cancellationToken)
    {
        foreach (var option in _options.Value.RelyingParties)
        {
            _timers[option.EntityId] = new Timer(
                async ctx => await ReloadMetadataEntry(option),
                null,
                TimeSpan.FromHours(1),
                TimeSpan.FromHours(1)
            );
        }

        return Task.CompletedTask;
    }

    private async Task ReloadMetadataEntry(RelyingPartyEntry option)
    {
        var entityDescriptor = new EntityDescriptor();

        try
        {
            await entityDescriptor.ReadSPSsoDescriptorFromUrlAsync(_httpClientFactory, new Uri(option.MetadataUrl));
            _ = _metadataContainer.AddOrReplace(option.EntityId, Task.FromResult(entityDescriptor));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unable to load and exchange metadata for entry {entityId}", option.EntityId);
        }
    }


    public Task StopAsync(CancellationToken cancellationToken)
    {
        foreach (var timer in _timers.Values)
        {
            timer.Dispose();
        }

        return Task.CompletedTask;
    }
}
