title Passkey Authentication Adapter

ADFS -> AuthenticationAdapter: IsAvailableForUser
AuthenticationAdapter -> ActiveDirectory: Query for User Passkeys
ActiveDirectory --> AuthenticationAdapter: Passkey CredentialIds
AuthenticationAdapter -> AuthenticationAdapter: Save CredentialIds to Context
AuthenticationAdapter --> ADFS: return count(CredentialIds) > 0
ADFS -> AuthenticationAdapter: BeginAuthentication
AuthenticationAdapter -> AuthenticationAdapter: Load CredentialIds from Context
AuthenticationAdapter -> Passkey Handler: Query for Assertion Options (/w CredentialIds)
Passkey Handler --> AuthenticationAdapter: return WebAuthN Assertion Options
AuthenticationAdapter -> AuthenticationAdapter: Save Options to Context
AuthenticationAdapter --> ADFS: return FormPresentation
ADFS -> User Agent: Send logon form 
User Agent -> User Agent: Handle Passkey Assertion
User Agent --> ADFS: return FormData
ADFS -> AuthenticationAdapter: TryEndAuthentication
AuthenticationAdapter -> AuthenticationAdapter: Load Options from Context
AuthenticationAdapter -> Passkey Handler: Send Assertion Options and Assertion Response
Passkey Handler -> Passkey Handler: Validate Assertion
Passkey Handler --> AuthenticationAdapter: return 200 (valid) or 401 (unauthorized)
AuthenticationAdapter --> ADFS: Signal success or failure