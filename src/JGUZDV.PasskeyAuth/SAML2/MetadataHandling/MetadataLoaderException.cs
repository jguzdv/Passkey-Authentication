
namespace JGUZDV.PasskeyAuth.SAML2.MetadataHandling;

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
