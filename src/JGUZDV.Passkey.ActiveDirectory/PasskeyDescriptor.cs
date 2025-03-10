using System.DirectoryServices;

namespace JGUZDV.Passkey.ActiveDirectory;

public record PasskeyDescriptor(
    string DistinguishedName,
    byte[] CredentialId,
    byte[] Credential,
    Guid Aaguid,
    bool? IsBackupEligible,
    PasskeyOwner Owner,
    DirectoryEntry DirectoryEntry
);
