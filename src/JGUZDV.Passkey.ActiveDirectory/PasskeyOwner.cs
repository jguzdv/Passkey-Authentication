using System.DirectoryServices;

namespace JGUZDV.Passkey.ActiveDirectory;

public record PasskeyOwner(
    Guid ObjectGuid,
    string DistinguishedName,
    string UserPrincipalName,
    string EduPersonPrincipalName,
    DirectoryEntry DirectoryEntry
);
