namespace JGUZDV.PasskeyAuth;

public record WebAuthNResponse(
    string WebAuthNAssertionResponseJson,
    string ReturnUrl = "/");
