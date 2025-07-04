using System.ComponentModel.DataAnnotations;

using JGUZDV.ActiveDirectory.Configuration;

namespace JGUZDV.PasskeyAuth.Configuration;

public class PasskeyAuthOptions : IValidatableObject
{
    public List<Guid> MFAWhitelist { get; set;} = [];

    public Dictionary<string, string> Properties { get; set; } = [];
    public List<ClaimSource> ClaimSources { get; set; } = [];

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        return [];
    }
}
