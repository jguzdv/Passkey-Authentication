using System.ComponentModel.DataAnnotations;
using JGUZDV.ActiveDirectory.Configuration;
using JGUZDV.Passkey.ActiveDirectory;

namespace JGUZDV.PasskeyAuth.Configuration;

public class PasskeyAuthOptions : IValidatableObject
{
    public required ActiveDirectoryOptions ActiveDirectory { get; set; }

    public List<Guid> MFAWhitelist { get; set;} = [];

    public Dictionary<string, string> Properties { get; set; } = [];
    public List<ClaimSource> ClaimSources { get; set; } = [];

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (ActiveDirectory == null)
        {
            yield return new ValidationResult("ActiveDirectory configuration is required", [nameof(ActiveDirectory)]);
        }
    }
}
