import * as Passkeys from "./PasskeyAuth.js";
import * as Components from "./Components.js";
async function handlePasskeyAuth(passkeyOptionsUrl) {
    updateStatusMessage("FetchAssertionOptions");
    const publicKeyOptionsResponse = await fetch(passkeyOptionsUrl);
    const publicKeyOptionsJson = await publicKeyOptionsResponse.text();
    const startTime = performance.now();
    try {
        const publicKeyCredentialJson = await Passkeys.getNavigatorCredentialAsJsonFromJson(publicKeyOptionsJson, updateStatusMessage);
        document.getElementById("assertion-response").value = publicKeyCredentialJson;
    }
    catch {
        const duration = performance.now() - startTime;
        if (duration < 500) {
            console.debug("Detected very small runtime for passkey authentication. Assuming browser refused to allow passkey usage.");
            document.body.setAttribute("data-passkey-capable", "false");
        }
        return;
    }
    updateStatusMessage("SubmitAssertionResponse");
    document.getElementById("auth-form").submit();
}
function updateStatusMessage(key) {
    document.getElementById("status-message")?.setAttribute("message-key", key);
}
async function handlePasskeyButtonClick(event) {
    const buttons = document.getElementsByClassName("action-buttons");
    buttons[0].classList.add("d-none");
    await handlePasskeyAuth("passkey");
}
async function executePage() {
    const isPasskeyCapable = await Passkeys.isBrowserCapable();
    document.body.setAttribute("data-passkey-capable", isPasskeyCapable ? "true" : "false");
    if (isPasskeyCapable) {
        customElements.define("status-message", Components.StatusMessage);
        if (document.body.getAttribute("clickless") === "true") {
            await handlePasskeyAuth("passkey");
        }
        else {
            const buttons = document.querySelectorAll("button[passkey-auth]");
            buttons.forEach((button) => {
                button.addEventListener("click", handlePasskeyButtonClick);
            });
        }
    }
}
executePage();
