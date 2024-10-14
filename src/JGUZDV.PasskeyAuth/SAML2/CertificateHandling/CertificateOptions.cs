namespace JGUZDV.PasskeyAuth.SAML2.CertificateHandling;

public class CertificateOptions
{
    public required string CertificatesPath { get; set; }
    public string? CertificatePassword { get; set; }

    public TimeSpan CertificateRenewThreshold { get; set; } = TimeSpan.FromDays(15);
}
