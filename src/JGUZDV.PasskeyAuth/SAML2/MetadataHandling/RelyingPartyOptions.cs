namespace JGUZDV.PasskeyAuth.SAML2.MetadataHandling;


public class RelyingPartyOptions
{
    public required List<RelyingPartyEntry> RelyingParties { get; set; } = [];
}


public class RelyingPartyEntry
{
    public required string EntityId { get; set; }
    public required string MetadataUrl { get; set; }
}
