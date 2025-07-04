using System.ComponentModel.DataAnnotations;

namespace JGUZDV.Passkey.ActiveDirectory;

public class ActiveDirectoryOptions : IValidatableObject
{
    public required string BaseOU { get; set; }

    public required string LdapServer { get; set; }

    public string? DomainName { get; set; }

    public int LdapPort { get; set; } = 636;

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if(string.IsNullOrWhiteSpace(LdapServer))
        {
            yield return new ValidationResult("LdapServer is required ", [nameof(LdapServer)]);
        }

        if (string.IsNullOrWhiteSpace(BaseOU))
        {
            yield return new ValidationResult("BaseOU is required", [nameof(BaseOU)]);
        }
    }
}
