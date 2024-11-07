namespace JGUZDV.PasskeyAuth.SAML2.MetadataHandling;


/// <summary>
/// Represents the entry RelyingParties in our appsettings.
/// </summary>
public class RelyingPartyOptions
{
    public required List<RelyingPartyEntry> RelyingParties { get; set; } = [];
}


/// <summary>
/// Represents an entry in our RelyingParties list.
/// </summary>
public class RelyingPartyEntry
{
    public required string EntityId { get; set; }
    public required string MetadataUrl { get; set; }
}
