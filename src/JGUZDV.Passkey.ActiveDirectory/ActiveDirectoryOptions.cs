using System.ComponentModel.DataAnnotations;

namespace JGUZDV.Passkey.ActiveDirectory;

public class ActiveDirectoryOptions : IValidatableObject
{
    public required string BaseOU { get; set; }
    public required string Server { get; set; }

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (string.IsNullOrWhiteSpace(Server))
        {
            yield return new ValidationResult("Server is required", [nameof(Server)]);
        }

        if (string.IsNullOrWhiteSpace(BaseOU))
        {
            yield return new ValidationResult("BaseOU is required", [nameof(BaseOU)]);
        }
    }
}
