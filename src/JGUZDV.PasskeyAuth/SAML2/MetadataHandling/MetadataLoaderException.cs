
namespace JGUZDV.PasskeyAuth.SAML2.MetadataHandling;

/// <summary>
/// Exception to indicate that metadata loading (fetching an EntityDescriptor) went wrong.
/// </summary>
[Serializable]
internal class MetadataLoaderException : Exception
{
    public MetadataLoaderException(string? message) : base(message)
    {
    }

    public MetadataLoaderException(string? message, Exception? innerException) : base(message, innerException)
    {
    }
}
