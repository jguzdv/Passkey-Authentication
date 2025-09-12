function base64UrlToUint8Array(base64Url: string): Uint8Array {
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(base64);
    const array = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
        array[i] = binary.charCodeAt(i);
    }

    return array;
};

function arrayBufferToBase64Url(arrayBuffer: ArrayBuffer): string {
    const binary = String.fromCharCode(...new Uint8Array(arrayBuffer));
    const base64 = btoa(binary);

    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

function getNavigatorCredential(publicKeyOptions: PublicKeyCredentialRequestOptions, statusCallback: (key: string) => void): Promise<PublicKeyCredential> {
    statusCallback("GetAssertion");
    return new Promise((resolve, reject) => {
        navigator.credentials
            .get({
                publicKey: publicKeyOptions
            })
            .then((credential) => {
                if (!credential) {
                    reject(new Error('No credential returned'));
                }

                resolve(credential as PublicKeyCredential);
            })
            .catch((error: Error) => {
                statusCallback("GetAssertionError")
                reject(error);
            });
        });
};


function jsonToPublicKeyCredentialRequestOptions(publicKeyOptionsJson: string, statusCallback: (key: string) => void): PublicKeyCredentialRequestOptions {
    statusCallback("ParseAssertionOptions");
    let publicKeyOptions = JSON.parse(publicKeyOptionsJson)
    let assertionOptions = {
        challenge: base64UrlToUint8Array(publicKeyOptions.challenge),
        rpId: publicKeyOptions.rpId,
        timeout: publicKeyOptions.timeout,
        userVerification: publicKeyOptions.userVerification
    } as PublicKeyCredentialRequestOptions;


    if (publicKeyOptions.allowCredentials && publicKeyOptions.allowCredentials.length > 0) {
        assertionOptions.allowCredentials = publicKeyOptions.allowCredentials.map((ec: any) => {
            return {
                id: base64UrlToUint8Array(ec.id),
                type: ec.type
            };
        });
    } else {
        assertionOptions.allowCredentials = [];
    }

    return assertionOptions;
};



function convertPublicKeyCredentialToJson(publicKeyCredential: PublicKeyCredential, statusCallback: (key: string) => void): string {
    const response = publicKeyCredential.response as AuthenticatorAssertionResponse;

    statusCallback("ConvertAssertionResponse");
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
};

export async function getNavigatorCredentialAsJsonFromJson(publicKeyOptionsJson: string, statusCallback: (key: string) => void): Promise<string> {
    let publicKeyOptions = jsonToPublicKeyCredentialRequestOptions(publicKeyOptionsJson, statusCallback);
    let publicKeyCredential = await getNavigatorCredential(publicKeyOptions, statusCallback);

    return convertPublicKeyCredentialToJson(publicKeyCredential, statusCallback);
};

export async function isBrowserCapable(): Promise<boolean> {
    // Test for 'PublicKeyCredential' availability seems to be the best currently available compromise for
    // testing whether the browser can handle passkeys.
    let checkIsAvailable = window.PublicKeyCredential !== undefined;
    let checkIsFunction = typeof window.PublicKeyCredential === 'function';
    return checkIsAvailable && checkIsFunction;
}
