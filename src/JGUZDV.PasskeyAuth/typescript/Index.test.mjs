import assert from "node:assert/strict";
import { setImmediate } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import test from "node:test";
import { buildSync } from "esbuild";

const script = new vm.Script(buildSync({
    entryPoints: [fileURLToPath(new URL("./Index.ts", import.meta.url))],
    bundle: true,
    format: "iife",
    target: "es2022",
    write: false
}).outputFiles[0].text);

function deferred() {
    let resolve;
    let reject;
    const promise = new Promise((resolvePromise, rejectPromise) => {
        resolve = resolvePromise;
        reject = rejectPromise;
    });
    return { promise, resolve, reject };
}

function createBrowser() {
    let tail = Promise.resolve();
    return {
        authenticated: false,
        locks: {
            request(name, callback) {
                const result = tail.then(() => callback({ name }));
                tail = result.catch(() => {});
                return result;
            }
        }
    };
}

function createPage(browser, options = {}) {
    const attributes = new Map([["data-automatic-sign-in", options.automaticSignIn === false ? "false" : "true"]]);
    const classes = new Set();
    const statusAttributes = new Map();
    const button = new EventTarget();
    const page = {
        focused: options.focused ?? true,
        requests: [],
        prompts: [],
        errors: [],
        warnings: [],
        debugs: [],
        submitted: 0,
        reloaded: 0,
        response: { value: "" },
        classes,
        attributes,
        statusAttributes,
        button
    };
    const document = Object.assign(new EventTarget(), {
        visibilityState: options.visibility ?? "visible",
        hasFocus: () => page.focused,
        body: {
            getAttribute: (name) => attributes.get(name),
            setAttribute: (name, value) => attributes.set(name, value)
        },
        querySelectorAll: () => [button],
        querySelector: () => ({ classList: {
            add: (value) => classes.add(value),
            remove: (value) => classes.delete(value)
        } }),
        getElementById: (id) => ({
            "status-message": { setAttribute: (name, value) => statusAttributes.set(name, value) },
            "assertion-response": page.response,
            "auth-form": { submit: () => page.submitted++ }
        })[id]
    });
    const window = Object.assign(new EventTarget(), {
        PublicKeyCredential: class {},
        location: { reload: () => page.reloaded++ }
    });
    const context = vm.createContext({
        document,
        window,
        HTMLElement: class {},
        customElements: { define() {} },
        navigator: {
            locks: options.noLocks ? undefined : browser.locks,
            credentials: { get: async (request) => {
                page.prompts.push(request);
                if (options.credential) {
                    return options.credential();
                }
                throw new Error("User cancelled the prompt");
            } }
        },
        fetch: async (url, init) => {
            page.requests.push({ url, init });
            if (options.fetch) {
                return options.fetch(url);
            }
            return new Response(JSON.stringify(url === "?handler=Session"
                ? browser.authenticated
                : { challenge: "AQ", rpId: "localhost", userVerification: "required" }));
        },
        localStorage: options.storage,
        atob,
        btoa,
        performance: options.performance ?? { now: () => 0 },
        console: {
            log() {},
            debug: (...args) => page.debugs.push(args),
            error: (...args) => page.errors.push(args),
            warn: (...args) => page.warnings.push(args)
        }
    });
    page.document = document;
    page.window = window;
    page.click = () => button.dispatchEvent(new Event("click"));
    page.focus = () => window.dispatchEvent(new Event("focus"));
    page.hide = () => window.dispatchEvent(new Event("pagehide"));
    script.runInContext(context);
    return page;
}

function credential() {
    const bytes = () => new Uint8Array([1, 2, 3]).buffer;
    return {
        id: "credential-id",
        type: "public-key",
        rawId: bytes(),
        response: {
            authenticatorData: bytes(),
            clientDataJSON: bytes(),
            signature: bytes(),
            userHandle: null
        }
    };
}

test("automatic prompts wait until the document is both visible and focused", async () => {
    const page = createPage(createBrowser(), { visibility: "hidden", focused: false });
    await setImmediate();
    assert.deepEqual(page.requests.map(({ url }) => url), ["?handler=Session"]);
    assert.equal(page.prompts.length, 0);
    page.document.visibilityState = "visible";
    page.document.dispatchEvent(new Event("visibilitychange"));
    await setImmediate();
    assert.deepEqual(page.requests.map(({ url }) => url), ["?handler=Session", "?handler=Session"]);
    assert.equal(page.prompts.length, 0);
    page.focused = true;
    page.focus();
    await setImmediate();
    assert.equal(page.prompts.length, 1);
    assert.equal(page.prompts[0].publicKey.userVerification, "required");
    assert.deepEqual(page.requests.map(({ url }) => url), ["?handler=Session", "?handler=Session", "?handler=Session", "passkey"]);
    assert.ok(page.requests.every(({ init }) => init.cache === "no-store"));
});

test("an attempt started while active continues after option retrieval without rechecking focus", async () => {
    const session = deferred();
    const options = deferred();
    const page = createPage(createBrowser(), { fetch: (url) => {
        if (url === "?handler=Session") return session.promise;
        return options.promise;
    } });
    await setImmediate();
    assert.deepEqual(page.requests.map(({ url }) => url), ["?handler=Session"]);
    assert.equal(page.statusAttributes.get("message-key"), "TryReuseSession");
    session.resolve(new Response("false"));
    await setImmediate();
    assert.equal(page.statusAttributes.get("message-key"), "FetchAssertionOptions");
    assert.deepEqual(page.requests.map(({ url }) => url), ["?handler=Session", "passkey"]);
    assert.equal(page.prompts.length, 0);
    assert.equal(page.classes.has("d-none"), true);
    page.focused = false;
    options.resolve(new Response('{"challenge":"AQ"}'));
    await setImmediate();
    assert.equal(page.prompts.length, 1);
    page.focused = true;
    page.focus();
    await setImmediate();
    assert.equal(page.prompts.length, 1);
    assert.equal(page.requests.length, 2);
});

test("concurrent windows serialize prompts without a cooldown after cancellation", async () => {
    const browser = createBrowser();
    const pending = deferred();
    const first = createPage(browser, { credential: () => pending.promise });
    const second = createPage(browser);
    await setImmediate();
    assert.equal(first.prompts.length, 1);
    assert.equal(second.requests.length, 0);
    assert.equal(second.statusAttributes.get("message-key"), "WaitingForOtherWindow");
    assert.equal(second.classes.has("d-none"), true);
    pending.reject(new Error("Cancelled"));
    await setImmediate();
    assert.equal(second.prompts.length, 1);
    assert.deepEqual(second.requests.map(({ url }) => url), ["?handler=Session", "passkey"]);
    assert.equal(first.classes.has("d-none"), false);
    assert.equal(first.attributes.get("data-passkey-capable"), "true");
});

test("the lock covers POST navigation and waiting windows reuse the resulting cookie", async () => {
    const browser = createBrowser();
    const first = createPage(browser, { credential });
    const second = createPage(browser);
    await setImmediate();
    assert.equal(first.submitted, 1);
    assert.equal(JSON.parse(first.response.value).id, "credential-id");
    assert.equal(second.requests.length, 0);
    browser.authenticated = true;
    first.hide();
    await setImmediate();
    assert.equal(second.reloaded, 1);
    assert.equal(second.prompts.length, 0);
    assert.deepEqual(second.requests.map(({ url }) => url), ["?handler=Session"]);
    second.hide();
});

test("a queued page that loses focus does not fetch options or prompt", async () => {
    const browser = createBrowser();
    const pending = deferred();
    createPage(browser, { credential: () => pending.promise });
    const second = createPage(browser);
    await setImmediate();
    second.focused = false;
    pending.reject(new Error("Cancelled"));
    await setImmediate();
    assert.deepEqual(second.requests.map(({ url }) => url), ["?handler=Session"]);
    assert.equal(second.prompts.length, 0);
    assert.equal(second.statusAttributes.get("message-key"), "");
});

test("hidden unfocused pages reuse an authenticated session without prompting", async () => {
    const browser = createBrowser();
    browser.authenticated = true;
    const page = createPage(browser, { visibility: "hidden", focused: false });
    await setImmediate();
    assert.deepEqual(page.requests.map(({ url }) => url), ["?handler=Session"]);
    assert.equal(page.reloaded, 1);
    assert.equal(page.prompts.length, 0);
    page.hide();
});

test("cancellation prevents further automatic prompts on the same page", async () => {
    const page = createPage(createBrowser());
    await setImmediate();
    assert.equal(page.prompts.length, 1);
    assert.equal(page.errors.length, 1);
    page.focus();
    page.document.dispatchEvent(new Event("visibilitychange"));
    await setImmediate();
    assert.equal(page.prompts.length, 1);
    assert.equal(page.requests.length, 2);
});

test("fast cancellation marks the browser incapable and reports the authentication error", async () => {
    const page = createPage(createBrowser());
    await setImmediate();
    assert.equal(page.prompts.length, 1);
    assert.equal(page.statusAttributes.get("message-key"), "GetAssertionError");
    assert.equal(page.classes.has("d-none"), false);
    assert.equal(page.attributes.get("data-passkey-capable"), "false");
    assert.equal(page.debugs.length, 1);
});

test("slow cancellation leaves passkey capability enabled", async () => {
    let now = 0;
    const page = createPage(createBrowser(), {
        credential: async () => { throw new Error("Cancelled"); },
        performance: { now: () => (now += 501) }
    });
    await setImmediate();
    assert.equal(page.prompts.length, 1);
    assert.equal(page.statusAttributes.get("message-key"), "GetAssertionError");
    assert.equal(page.attributes.get("data-passkey-capable"), "true");
    assert.equal(page.debugs.length, 0);
});

test("direct OTP visits never prompt automatically or reuse the sign-in session", async () => {
    const browser = createBrowser();
    browser.authenticated = true;
    const page = createPage(browser, { automaticSignIn: false, credential });
    await setImmediate();
    assert.equal(page.requests.length, 0);
    page.click();
    await setImmediate();
    assert.deepEqual(page.requests.map(({ url }) => url), ["passkey"]);
    assert.equal(page.submitted, 1);
    assert.equal(page.reloaded, 0);
    page.hide();
});

test("unavailable local storage does not prevent automatic or manual login", async () => {
    const page = createPage(createBrowser(), { storage: {
        getItem() { throw new Error("Storage blocked"); },
        setItem() { throw new Error("Storage blocked"); }
    } });
    await setImmediate();
    assert.equal(page.prompts.length, 1);
    assert.equal(page.warnings.length, 0);
    page.click();
    await setImmediate();
    assert.equal(page.prompts.length, 2);
    assert.equal(page.warnings.length, 0);
});

test("missing Web Locks disables automatic prompts but preserves explicit sign-in", async () => {
    const page = createPage(createBrowser(), { noLocks: true });
    await setImmediate();
    assert.equal(page.requests.length, 0);
    assert.equal(page.warnings.length, 1);
    page.click();
    await setImmediate();
    assert.equal(page.prompts.length, 1);
});

test("session check failures warn and allow normal passkey login", async (t) => {
    const cases = [
        ["HTTP failure", () => new Response("Failure", { status: 500 })],
        ["invalid object", () => new Response('{}')],
        ["truthy string", () => new Response('"true"')],
        ["invalid JSON", () => new Response('<html>Error</html>')],
        ["network failure", () => { throw new TypeError("Network unavailable"); }]
    ];
    for (const [name, sessionResponse] of cases) {
        await t.test(name, async () => {
            const page = createPage(createBrowser(), {
                credential,
                fetch: (url) => url === "?handler=Session"
                    ? sessionResponse()
                    : new Response('{"challenge":"AQ"}')
            });
            await setImmediate();
            assert.deepEqual(page.requests.map(({ url }) => url), ["?handler=Session", "passkey"]);
            assert.equal(page.warnings.length, 1);
            assert.equal(page.errors.length, 0);
            assert.equal(page.prompts.length, 1);
            assert.equal(page.submitted, 1);
            assert.equal(JSON.parse(page.response.value).id, "credential-id");
            assert.equal(page.reloaded, 0);
            page.hide();
        });
    }
});

test("assertion option HTTP failures still surface without prompting", async () => {
    const page = createPage(createBrowser(), { fetch: (url) => url === "?handler=Session"
        ? new Response("false")
        : new Response("Failure", { status: 500 })
    });
    await setImmediate();
    assert.equal(page.prompts.length, 0);
    assert.equal(page.errors.length, 1);
    assert.equal(page.statusAttributes.get("message-key"), "GetAssertionError");
    assert.equal(page.classes.has("d-none"), false);
});

test("repeated visibility and focus events cannot start duplicate requests", async () => {
    const page = createPage(createBrowser(), { credential: () => deferred().promise });
    page.focus();
    page.document.dispatchEvent(new Event("visibilitychange"));
    await setImmediate();
    page.focus();
    await setImmediate();
    assert.equal(page.prompts.length, 1);
    assert.equal(page.requests.length, 2);
});
