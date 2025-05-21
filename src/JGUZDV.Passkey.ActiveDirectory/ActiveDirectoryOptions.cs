using System.ComponentModel.DataAnnotations;

namespace JGUZDV.Passkey.ActiveDirectory;

public class ActiveDirectoryOptions : IValidatableObject
{
    public required string BaseOU { get; set; }

    public string? LdapServer { get; set; }

    public string? DomainName { get; set; }

    public int LdapPort { get; set; } = 636;

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (string.IsNullOrWhiteSpace(LdapServer) && string.IsNullOrWhiteSpace(DomainName))
        {
            yield return new ValidationResult("LdapServer or DomainName is required", [nameof(LdapServer), nameof(DomainName)]);
        }

        if (string.IsNullOrWhiteSpace(BaseOU))
        {
            yield return new ValidationResult("BaseOU is required", [nameof(BaseOU)]);
        }
    }
}
