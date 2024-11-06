using System.Net.Http;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using Microsoft.Extensions.Options;

namespace JGUZDV.PasskeyAuth.SAML2.MetadataHandling;

public class MetadataContainer
{
    private readonly Dictionary<string, Task<EntityDescriptor>> _metadata = [];
    private readonly IOptions<RelyingPartyOptions> _options;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<MetadataContainer> _logger;

    public MetadataContainer(IOptions<RelyingPartyOptions> options,
        IHttpClientFactory httpClientFactory,
        ILogger<MetadataContainer> logger)
    {
        _options = options;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }


    public Task<EntityDescriptor> AddOrReplace(string entityId, Task<EntityDescriptor> descriptor)
    {
        _metadata[entityId] = descriptor;
        return descriptor;
    }


    public Task<EntityDescriptor> GetByEntityId(string entityId)
    {
        var entry = _options.Value.RelyingParties.FirstOrDefault(x => x.EntityId == entityId)
            ?? throw new InvalidOperationException($"Unknown entityId {entityId}");

        if (!_metadata.TryGetValue(entityId, out var value))
        {
            value = AddOrReplace(entityId, LoadMetadataAsync(entityId, entry));
        }

        return value;
    }


    private async Task<EntityDescriptor> LoadMetadataAsync(string entityId, RelyingPartyEntry entry)
    {
        var entityDescriptor = new EntityDescriptor();

        try
        {
            await entityDescriptor.ReadSPSsoDescriptorFromUrlAsync(_httpClientFactory, new Uri(entry.MetadataUrl));

            if (entityDescriptor.EntityId != entityId)
            {
                _logger.LogError("The configured entityId is not equal to the entity id in EntityDescriptor. " +
                    "Given EntityId: {entityId}, MetadataUrl: {metadataUrl}", entityId, entry.MetadataUrl);

                throw new MetadataLoaderException("Configuration error...");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected exception when loading metadata.");
            _metadata.Remove(entityId);
            throw new MetadataLoaderException("Unexpected exception when loading metadata.", ex);
        }

        return entityDescriptor;
    }

}
