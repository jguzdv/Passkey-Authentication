using ITfoxtec.Identity.Saml2.Schemas.Metadata;

namespace JGUZDV.PasskeyAuth.SAML2;

public class RelyingPartyMetadata
{
    public Dictionary<string, EntityDescriptor> RelyingParties { get; set; } = new();
}
