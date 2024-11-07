using System.Security.Cryptography.X509Certificates;
using ITfoxtec.Identity.Saml2;

namespace JGUZDV.PasskeyAuth.SAML2.CertificateHandling;

public class CertificateContainer(ILogger<CertificateContainer> logger)
{
    private readonly List<X509Certificate2> _certificates = [];
    private readonly ILogger<CertificateContainer> _logger = logger;

    public void AddCertificate(X509Certificate2 certificate)
    {
        // Do not add expired certificates
        if (certificate.NotAfter < DateTime.UtcNow)
        {
            _logger.LogInformation("Certificate {CertificateThumbprint} is expired and will not be added to the container", certificate.Thumbprint);
            return;
        }

        _certificates.Add(certificate);
    }

    /// <summary>
    /// Gets all currently loaded certificates
    /// </summary>
    public X509Certificate2[] GetCertificates()
    {
        return _certificates.ToArray();
    }

    /// <summary>
    /// Returns the certificate with the closest expiration date to be used as signature certificate
    /// </summary>
    /// <exception cref="InvalidOperationException">Will throw if there's no certificate available</exception>
    public X509Certificate2 GetSignatureCertificate()
    {
        if (!HasAnyValidCertificate())
        {
            throw new InvalidOperationException("No valid certificates are available in the container");
        }

        return _certificates
            .Where(x => x.IsValidLocalTime())
            .OrderBy(x => x.NotAfter)
            .First();
    }

    /// <summary>
    /// Checks if there's any valid certificate in the container
    /// </summary>
    /// <returns></returns>
    public bool HasAnyValidCertificate()
    {
        return _certificates.Any(x => x.IsValidLocalTime());
    }
}
