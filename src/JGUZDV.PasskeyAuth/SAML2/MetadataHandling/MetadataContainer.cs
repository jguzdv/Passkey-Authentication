using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using Microsoft.Extensions.Options;

namespace JGUZDV.PasskeyAuth.SAML2.MetadataHandling;

/// <summary>
/// Encapsulates logic/data to handle EntityDescriptor's. An EntityDescriptor describes a
/// SAML IdP or Saml ServiceProvider/RelyingParty. @see https://en.wikipedia.org/wiki/SAML_metadata
/// The property _metadata is used to store EntityDescriptor's. The dictionary uses EntityId's as
/// keys, and takes a Task that determines an EntityDescriptor. We do not store the EntityDescriptor
/// directly, but store the Task that runs asynchronously, so if GetByEntityId(...) is called multiple
/// times, and fetching an EntityDescriptor is not yet completed, all threads wait for the same Task.
/// </summary>
public class MetadataContainer
{
    // Stores EntityId -> Task. The Task tries to fetch an EntityDescriptor for the given EntityId.
    private readonly Dictionary<string, Task<EntityDescriptor>> _metadata = [];

    // All relying parties we know, needed to validate the saml authn request.
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

    /// <summary>
    /// Creates a task to either fetch the currently stored EntityDescriptor, or otherwise to load it.
    /// This mechanic ensures that we try to load an EntityDescriptor before we continue processing
    /// the current authentication request.
    /// </summary>
    /// <param name="entityId">A given entityId (from a saml authentication request)</param>
    /// <returns></returns>
    /// <exception cref="InvalidOperationException">When the given entityId is unknown.</exception>
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

    /// <summary>
    /// This runs asynchronously on the thread pool. Note: It is essential to remove the
    /// Task<EntityDescriptor> in case of an Exception, otherwise every call on GetByEntityId(...)
    /// will get the Task's exception result.
    /// </summary>
    /// <param name="entityId"></param>
    /// <param name="entry"></param>
    /// <returns></returns>
    /// <exception cref="MetadataLoaderException"></exception>
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

            // This is essential, so on a new request a new Task will be created. If we miss this,
            // every call on GetByEntityId(...) will get the Task with this error/exception result.
            _metadata.Remove(entityId);

            throw new MetadataLoaderException("Unexpected exception when loading metadata.", ex);
        }

        return entityDescriptor;
    }

}
