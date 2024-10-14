namespace JGUZDV.PasskeyAuth.SAML2.CertificateHandling;

internal class CertificateOptions
{
    public required string CertificatePath { get; internal set; }
    public string? CertificatePassword { get; internal set; }

    public TimeSpan CertificateRenewThreshold { get; internal set; } = TimeSpan.FromDays(15);
}
