import * as Passkeys from "./PasskeyAuth.js";
import * as Components from "./Components.js";

declare global {
    interface Document {
        i18n?: { [key: string]: string };
    }
}

async function handlePasskeyAuth(passkeyOptionsUrl: string, statusCallback: (key: string) => void) {
    statusCallback("FetchAssertionOptions");
    const publicKeyOptionsResponse = await fetch(passkeyOptionsUrl);
    const publicKeyOptionsJson = await publicKeyOptionsResponse.text();

    const publicKeyCredentialJson = await Passkeys.getNavigatorCredentialAsJsonFromJson(publicKeyOptionsJson, statusCallback);
    (<HTMLInputElement>document.getElementById("assertion-response")).value = publicKeyCredentialJson;
    (<HTMLFormElement>document.getElementById("auth-form")).submit();

    statusCallback("SubmitAssertionResponse");
}

async function updateStatusMessage(key: string) {
    const statusElement = document.getElementById("status-message") as HTMLElement;
    statusElement.setAttribute("message-key", key);
}

Components.registerCustomElements();

if (Passkeys.isBrowserCapable()) {
    const passkeyUrl = document.body.getAttribute("data-passkey-initiator-url") ?? "/passkey";
    const autostartPasskey = !!document.body.getAttribute("data-passkey-autostart");

    if (autostartPasskey) {
        await handlePasskeyAuth(passkeyUrl, updateStatusMessage);
    }

    document.getElementById("passkey-initiator")!.addEventListener("click", () => {
        handlePasskeyAuth(passkeyUrl, updateStatusMessage);
    });
}
else {
    document.getElementById("passkey-initiator")!.remove();
    updateStatusMessage("CapabilityMissing");
}
