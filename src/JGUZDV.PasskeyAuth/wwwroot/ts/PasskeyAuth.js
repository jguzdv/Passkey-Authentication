function base64UrlToUint8Array(base64Url) {
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(base64);
    const array = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        array[i] = binary.charCodeAt(i);
    }
    return array;
}
;
function arrayBufferToBase64Url(arrayBuffer) {
    const binary = String.fromCharCode(...new Uint8Array(arrayBuffer));
    const base64 = btoa(binary);
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
;
function getNavigatorCredential(publicKeyOptions) {
    return new Promise((resolve, reject) => {
        navigator.credentials
            .get({
            publicKey: publicKeyOptions
        })
            .then((credential) => {
            if (!credential) {
                reject(new Error('No credential returned'));
            }
            resolve(credential);
        })
            .catch((error) => {
            reject(error);
        });
    });
}
;
function jsonToPublicKeyCredentialRequestOptions(publicKeyOptionsJson) {
    let publicKeyOptions = JSON.parse(publicKeyOptionsJson);
    let assertionOptions = {
        challenge: base64UrlToUint8Array(publicKeyOptions.challenge),
        rpId: publicKeyOptions.rpId,
        timeout: publicKeyOptions.timeout,
        userVerification: publicKeyOptions.userVerification
    };
    if (publicKeyOptions.allowCredentials && publicKeyOptions.allowCredentials.length > 0) {
        assertionOptions.allowCredentials = publicKeyOptions.allowCredentials.map((ec) => {
            return {
                id: base64UrlToUint8Array(ec.id),
                type: ec.type
            };
        });
    }
    else {
        assertionOptions.allowCredentials = [];
    }
    return assertionOptions;
}
;
function convertPublicKeyCredentialToJson(publicKeyCredential) {
    const response = publicKeyCredential.response;
    let publicKeyCredentialJson = {
        id: publicKeyCredential.id,
        type: publicKeyCredential.type,
        rawId: arrayBufferToBase64Url(publicKeyCredential.rawId),
        response: {
            authenticatorData: arrayBufferToBase64Url(response.authenticatorData),
            clientDataJSON: arrayBufferToBase64Url(response.clientDataJSON),
            signature: arrayBufferToBase64Url(response.signature),
            userHandle: response.userHandle && arrayBufferToBase64Url(response.userHandle)
        }
    };
    return JSON.stringify(publicKeyCredentialJson);
}
;
export async function getNavigatorCredentialAsJsonFromJson(publicKeyOptionsJson) {
    let publicKeyOptions = jsonToPublicKeyCredentialRequestOptions(publicKeyOptionsJson);
    let publicKeyCredential = await getNavigatorCredential(publicKeyOptions);
    return convertPublicKeyCredentialToJson(publicKeyCredential);
}
;
export function isBrowserCapable() {
    return !!navigator.credentials;
}
//# sourceMappingURL=PasskeyAuth.js.map