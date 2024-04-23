#pragma warning disable CA1416 // Validate platform compatibility
using JGUZDV.ADFS.PasskeyHandler;
using JGUZDV.Passkey.ActiveDirectory.Extensions;

var builder = WebApplication.CreateBuilder(args);
builder.Logging.AddEventLog(opt =>
{
    opt.LogName = "Application";
    opt.SourceName = "ADFSPasskeyHandler";
});

builder.Services.AddWindowsService();
builder.Services.AddFido2(builder.Configuration.GetSection("Fido2"));
builder.Services.AddPasskeyActiveDirectoryServices("ActiveDirectory");

var app = builder.Build();

// Creates the FIDO2 Options object and returns it as JSON
app.MapGet("/", PasskeyEndpoints.CreateAssertionOptions);

app.MapPost("/", PasskeyEndpoints.ValidatePasskeyAssertion)
    .DisableAntiforgery();

app.Run();

public class AssertionRequest
{
    public string? AssertionOptions { get; set; }
    public string? AssertionResponse { get; set; }
}