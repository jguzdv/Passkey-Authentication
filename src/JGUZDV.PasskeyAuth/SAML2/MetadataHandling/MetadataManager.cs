
using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using Microsoft.Extensions.Options;

namespace JGUZDV.PasskeyAuth.SAML2.MetadataHandling;


/// <summary>
/// This manager/hosted service is used to update the EntityDescriptor's for all
/// known/configured RelyingParties every hour. A table of timers (scheduled executors)
/// is used to repeat the fetch process for every known EntityId.
/// </summary>
public class MetadataManager : IHostedService
{
    // EntityId -> Timer (scheduled executors)
    private readonly Dictionary<string, Timer> _timers = [];

    // Our metadata container where we need to replace the entries every hour.
    private readonly MetadataContainer _metadataContainer;

    // The options contain the list of known relying parties to update.
    private readonly IOptions<RelyingPartyOptions> _options;

    private readonly IHttpClientFactory _httpClientFactory;
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


    /// <summary>
    /// Start timers (scheduled executors) to update metadata for all known relying parties regularly.
    /// </summary>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
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

    /// <summary>
    /// Reload and set/replace an EntityDescriptor in the MetadataContainer.
    /// Note: We do not reuse the asynchronous mechanic from the MetadataContainer built around
    /// GetByEntityId(...) and LoadMetadataAsync:
    /// 1) We want to catch read errors here, and do nothing further than log the error, but do not replace the current entry.
    /// 2) We must run into the LoadMetadataAsync exception handling block that remove's our current EntityDescriptor entry.
    /// </summary>
    /// <param name="option"></param>
    /// <returns></returns>
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
