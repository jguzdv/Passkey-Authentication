using System.Diagnostics.Metrics;
using JGUZDV.AspNetCore.Extensions.OpenTelemetry;
using Microsoft.Extensions.Options;

namespace JGUZDV.PasskeyAuth.OpenTelemetry;


/// <summary>
/// Currently just counts passkey init assertions. What statistics are we interested in?
/// </summary>
public class MeterContainer : AbstractJguZdvMeter
{
    private readonly Counter<int> _passkeyInitAssertionCounter;


    public MeterContainer(IOptions<AspNetCoreOpenTelemetryOptions> options) : base(options)
    {
        _passkeyInitAssertionCounter = Meter.CreateCounter<int>(
            name: "passkey.server.init.assertion.count",
            description: "Counter for init passkey assertion.");
    }

    /// <summary>
    /// Count passkey init assertions.
    /// </summary>
    public void CountInitPasskeyAssertion()
    {
        _passkeyInitAssertionCounter.Add(1);
            // KeyValuePair.Create("key", value));
    }
}

