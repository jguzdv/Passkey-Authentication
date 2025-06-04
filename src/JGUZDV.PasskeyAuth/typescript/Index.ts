import * as Passkeys from "./PasskeyAuth.js";
import * as Components from "./Components.js";

declare global {
    interface Document {
        i18n?: { [key: string]: string };
    }
}

async function handlePasskeyAuth(passkeyOptionsUrl: string) {
    updateStatusMessage("FetchAssertionOptions");
    const publicKeyOptionsResponse = await fetch(passkeyOptionsUrl);
    const publicKeyOptionsJson = await publicKeyOptionsResponse.text();

    const publicKeyCredentialJson = await Passkeys.getNavigatorCredentialAsJsonFromJson(publicKeyOptionsJson, updateStatusMessage);
    (<HTMLInputElement>document.getElementById("assertion-response")).value = publicKeyCredentialJson;

    updateStatusMessage("SubmitAssertionResponse");
    (<HTMLFormElement>document.getElementById("auth-form")).submit();
}

function updateStatusMessage(key: string) {
    document.getElementById("status-message")?.setAttribute("message-key", key);
}

async function handlePasskeyButtonClick(event: Event) {
    const buttons = document.getElementsByClassName("action-buttons");
    buttons[0].classList.add("d-none");

    await handlePasskeyAuth("passkey");
}

async function executePage() {
    const isPasskeyCapable = Passkeys.isBrowserCapable();
    document.body.setAttribute("data-passkey-capable", isPasskeyCapable ? "true" : "false");

    if (isPasskeyCapable) {
        customElements.define("status-message", Components.StatusMessage);

        if (document.body.getAttribute("clickless") === "true") {
            await handlePasskeyAuth("passkey");
        }
        else
        {
            const buttons = document.querySelectorAll("button[passkey-auth]");
            buttons.forEach((button) => {
                button.addEventListener("click", handlePasskeyButtonClick);
            });
        }
    }
}

executePage();
