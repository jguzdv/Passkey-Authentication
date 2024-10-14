import * as Passkeys from "./PasskeyAuth.js";
async function handlePasskeyAuth(passkeyOptionsUrl) {
    const publicKeyOptionsResponse = await fetch(passkeyOptionsUrl);
    const publicKeyOptionsJson = await publicKeyOptionsResponse.text();
    const publicKeyCredentialJson = await Passkeys.getNavigatorCredentialAsJsonFromJson(publicKeyOptionsJson);
    document.getElementById("assertion-response").value = publicKeyCredentialJson;
    document.getElementById("auth-form").submit();
}
const passkeyUrl = document.body.getAttribute("data-passkey-initiator-url") ?? "/passkey";
const autostartPasskey = !!document.body.getAttribute("data-passkey-autostart");
if (autostartPasskey) {
    await handlePasskeyAuth(passkeyUrl);
}
else {
    document.getElementById("passkey-initiator").addEventListener("click", () => {
        handlePasskeyAuth(passkeyUrl);
    });
}
//# sourceMappingURL=app.js.map
