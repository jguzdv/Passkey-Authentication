using System.DirectoryServices;

namespace JGUZDV.Passkey.ActiveDirectory;

public record PasskeyDescriptor(
    byte[] Credential,
    string DistinguishedName,
    PasskeyOwner Owner,
    DirectoryEntry DirectoryEntry
);
