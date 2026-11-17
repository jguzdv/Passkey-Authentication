import * as Passkeys from "./PasskeyAuth.js";
import * as Components from "./Components.js";

declare global {
    interface Document {
        i18n?: { [key: string]: string };
    }
}

const promptLockName = "passkey-assertion";
let assertionPending = false;
let assertionHasBeenTried = false;

async function handlePasskeyAuth() {
    updateStatusMessage("TryReuseSession");
    if (await TryReuseSession()) {
        return;
    }

    if (!isPageActive()) {
        updateStatusMessage("");
        return;
    }

    updateStatusMessage("FetchAssertionOptions");
    const publicKeyOptionsResponse = await fetch("passkey", { cache: "no-store" });
    if (!publicKeyOptionsResponse.ok) {
        throw new Error(`Fetching assertion options failed: ${publicKeyOptionsResponse.status}`);
    }

    const publicKeyOptionsJson = await publicKeyOptionsResponse.text();

    assertionHasBeenTried = true;
    const credentialJson = await Passkeys.getNavigatorCredentialAsJsonFromJson(publicKeyOptionsJson, updateStatusMessage);
    (<HTMLInputElement>document.getElementById("assertion-response")).value = credentialJson;

    updateStatusMessage("SubmitAssertionResponse");
    // Keep the lock until the POST response commits navigation (and its cookie).
    const navigating = new Promise<void>((resolve) => window.addEventListener("pagehide", () => resolve(), { once: true }));
    (<HTMLFormElement>document.getElementById("auth-form")).submit();
    await navigating;
}

async function requestPasskeyAuth() {
    if (assertionPending) {
        return;
    }

    updateStatusMessage("TryReuseSession");
    if (await TryReuseSession()) {
        return;
    }

    assertionPending = true;
    const buttons = document.querySelector<HTMLElement>(".action-buttons");
    buttons?.classList.add("d-none");
    try {
        if (navigator.locks) {
            updateStatusMessage("WaitingForOtherWindow");
            await navigator.locks.request(promptLockName, () => handlePasskeyAuth());
        }
        else {
            await handlePasskeyAuth();
        }
    }
    catch (error) {
        console.error("Passkey authentication failed.", error);
        updateStatusMessage("GetAssertionError");
    }
    finally {
        buttons?.classList.remove("d-none");
        assertionPending = false;
    }
}

function isPageActive(): boolean {
    console.log("Page visibility state:", document.visibilityState, "Has focus:", document.hasFocus());
    return document.visibilityState === "visible" && document.hasFocus();
}

async function TryReuseSession(): Promise<boolean> {
    if (document.body.getAttribute("data-automatic-sign-in") !== "true") {
        return false;
    }

    let authenticated: unknown;
    try {
        const sessionResponse = await fetch("?handler=Session", { cache: "no-store" });
        if (sessionResponse.ok) {
            authenticated = await sessionResponse.json();
            if (typeof authenticated !== "boolean") {
                console.warn("Invalid authentication session response. Continuing with passkey login.");
            }
        }
        else {
            console.warn(`Checking the authentication session failed: ${sessionResponse.status}. Continuing with passkey login.`);
        }
    }
    catch (error) {
        console.warn("Could not check the authentication session. Continuing with passkey login.", error);
    }

    if (authenticated !== true) {
        return false;
    }

    // Reload lets the server validate the return URL and reuse the shared cookie.
    const navigating = new Promise<void>((resolve) => window.addEventListener("pagehide", () => resolve(), { once: true }));
    window.location.reload();
    await navigating;
    return true;
}

function updateStatusMessage(key: string) {
    document.getElementById("status-message")?.setAttribute("message-key", key);
}


async function handlePasskeyButtonClick() {
    requestPasskeyAuth();
}

async function tryAutomatically() {
    if (assertionHasBeenTried) {
        return;
    }

    requestPasskeyAuth();
}

async function executePage() {
    const isPasskeyCapable = await Passkeys.isBrowserCapable();
    document.body.setAttribute("data-passkey-capable", isPasskeyCapable ? "true" : "false");

    if (isPasskeyCapable) {
        customElements.define("status-message", Components.StatusMessage);
        document.querySelectorAll("button[passkey-auth]").forEach((button) => {
            button.addEventListener("click", handlePasskeyButtonClick);
        });

        if (document.body.getAttribute("data-automatic-sign-in") === "true") {
            document.addEventListener("visibilitychange", tryAutomatically);
            window.addEventListener("focus", tryAutomatically);
            tryAutomatically();
        }
    }
}

executePage();
