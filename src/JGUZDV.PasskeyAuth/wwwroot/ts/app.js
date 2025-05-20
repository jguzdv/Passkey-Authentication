import * as Passkeys from "./PasskeyAuth.js";
async function handlePasskeyAuth(passkeyOptionsUrl, statusCallback) {
    statusCallback("FetchAssertionOptions");
    const publicKeyOptionsResponse = await fetch(passkeyOptionsUrl);
    const publicKeyOptionsJson = await publicKeyOptionsResponse.text();
    const publicKeyCredentialJson = await Passkeys.getNavigatorCredentialAsJsonFromJson(publicKeyOptionsJson, statusCallback);
    document.getElementById("assertion-response").value = publicKeyCredentialJson;
    document.getElementById("auth-form").submit();
    statusCallback("SubmitAssertionResponse");
}
async function loadLanguageResources() {
    let lang = navigator.language.split("-")[0];
    if (lang !== "en") {
        lang = "default";
    }
    const response = await fetch(`lang/${lang}.json`);
    return await response.json();
}
async function updateStatusMessage(key) {
    if (!document.i18n) {
        document.i18n = await loadLanguageResources();
    }
    const statusElement = document.getElementById("status-message");
    if (key) {
        statusElement.innerText = ((document.i18n && document.i18n[key]) || key);
    }
}
if (Passkeys.isBrowserCapable()) {
    const passkeyUrl = document.body.getAttribute("data-passkey-initiator-url") ?? "/passkey";
    const autostartPasskey = !!document.body.getAttribute("data-passkey-autostart");
    if (autostartPasskey) {
        await handlePasskeyAuth(passkeyUrl, updateStatusMessage);
    }
    document.getElementById("passkey-initiator").addEventListener("click", () => {
        handlePasskeyAuth(passkeyUrl, updateStatusMessage);
    });
}
else {
    document.getElementById("passkey-initiator").remove();
    updateStatusMessage("CapabilityMissing");
}
//# sourceMappingURL=app.js.map