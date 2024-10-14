
using ITfoxtec.Identity.Saml2.Configuration;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;

namespace JGUZDV.PasskeyAuth.SAML2.CertificateHandling;

internal class CertificateManager(
    CertificateContainer container,
    TimeProvider timeProvider,
    IOptions<CertificateOptions> options,
    ILogger<CertificateManager> logger) : IHostedService
{
    private readonly CertificateContainer _container = container;
    private readonly TimeProvider _timeProvider = timeProvider;
    private readonly IOptions<CertificateOptions> _options = options;
    private readonly ILogger<CertificateManager> _logger = logger;

    private Timer? _timer;

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await EnsureUsableCertificate();
        _timer = new Timer(async _ => await CreateCertificateIfNecessary(), null, TimeSpan.FromMinutes(10), TimeSpan.FromHours(8));
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _timer?.Dispose();
        return Task.CompletedTask;
    }

    private async Task EnsureUsableCertificate()
    {
        LoadCertificatesIntoContainer();
        if (!_container.HasAnyValidCertificate())
        {
            _logger.LogInformation("No valid certificates found in the container. Creating a new one.");
            var certificate = await CreateAndStoreCertificate();
            _container.AddCertificate(certificate);
        }

        if (!_container.HasAnyValidCertificate())
        {
            throw new Saml2ConfigurationException("No valid certificates found in the container and certificate creation failed.");
        }
    }

    private async Task CreateCertificateIfNecessary()
    {
        //Create a new certificate if all certificates will expire in less than the renew threshold
        var notAfterThreshold = _timeProvider.GetUtcNow().Add(_options.Value.CertificateRenewThreshold);
        if (!_container.GetCertificates().Any(x => x.NotAfter > notAfterThreshold))
        {
            _logger.LogInformation("All certificates will expire soon. Creating a new one.");
            var certificate = await CreateAndStoreCertificate();
            _container.AddCertificate(certificate);
        }
    }


    private async Task<X509Certificate2> CreateAndStoreCertificate()
    {
        // Create a self-signed certificate
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=Passkey-Auth-", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Add extensions to the certificate
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.DataEncipherment, false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        // Create the self-signed certificate
        var certificate = request.CreateSelfSigned(
            _timeProvider.GetUtcNow(), _timeProvider.GetUtcNow().AddYears(1).Add(_options.Value.CertificateRenewThreshold));

        // Export the certificate to a file
        var certPath = Path.Combine(_options.Value.CertificatesPath, $"{certificate.Thumbprint}.pfx");
        var certPassword = _options.Value.CertificatePassword;
        await File.WriteAllBytesAsync(certPath, certificate.Export(X509ContentType.Pfx, certPassword));

        _logger.LogInformation("Self-signed certificate created and stored at {certPath}.", certPath);

        return certificate;
    }

    private void LoadCertificatesIntoContainer()
    {
        var certificateFiles = Directory.GetFiles(_options.Value.CertificatesPath, "*.pfx");
        if (certificateFiles.Length == 0)
        {
            throw new Saml2ConfigurationException("No certificates found in the configured path.");
        }

        foreach (var certFile in certificateFiles)
        {
            try
            {
                var pfx = new X509Certificate2(certFile, _options.Value.CertificatePassword);
                _container.AddCertificate(pfx);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to load certificate {certFile}.", certFile);
                continue;
            }
        }
    }
}
