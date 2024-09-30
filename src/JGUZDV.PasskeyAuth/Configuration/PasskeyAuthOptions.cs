using JGUZDV.ActiveDirectory.Configuration;
using JGUZDV.Passkey.ActiveDirectory;

namespace JGUZDV.PasskeyAuth.Configuration;

public class PasskeyAuthOptions
{
    public required ActiveDirectoryOptions ActiveDirectory { get; set; }

    public Dictionary<string, string> Properties { get; set; } = [];
    public List<ClaimSource> ClaimSources { get; set; } = [];
}
