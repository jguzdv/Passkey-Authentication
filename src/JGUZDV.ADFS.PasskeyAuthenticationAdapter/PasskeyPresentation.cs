using Microsoft.IdentityServer.Web.Authentication.External;
using System;
using System.Text;

namespace JGUZDV.ADFS.PasskeyAuthenticationAdapter
{
    internal class PasskeyPresentation : IAdapterPresentationForm
    {
        private readonly PresentationData _presentationData;

        public PasskeyPresentation(PresentationData presentationData)
        {
            _presentationData = presentationData;
        }

        public string GetPageTitle(int lcid)
            => Utility.GetStringResource(nameof(Resources.Label_PasskeyAuthentication), lcid);

        public string GetFormHtml(int lcid)
        {
            return $""""""
                <div id="loginArea">
                    <form method="post" id="loginForm" autocomplete="off" 
                        data-passkey-autostart="{(_presentationData.ShouldAutostartFlow ? "okay" : "")}"
                        data-passkey-options="{_presentationData.Base64AssertionOptions}">
                        <!-- These inputs are required by the presentation framework.  Do not modify or remove -->
                        <input id="authMethod" type="hidden" name="AuthMethod" value="%AuthMethod%"/>
                        <input id="context" type="hidden" name="Context" value="%Context%"/>
                        <!-- End inputs are required by the presentation framework. -->

                        <input type="hidden" name="assertionResponse" id="assertion-response" />

                        <div>
                            <svg id="passkey-logo" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
                                <g id="icon-passkey" fill="#000">
                                    <circle id="icon-passkey-head" cx="10.5" cy="6" r="4.5" />
                                    <path id="icon-passkey-key" d="M22.5,10.5a3.5,3.5,0,1,0-5,3.15V19L19,20.5,21.5,18,20,16.5,21.5,15l-1.24-1.24A3.5,3.5,0,0,0,22.5,10.5Zm-3.5,0a1,1,0,1,1,1-1A1,1,0,0,1,19,10.5Z" />
                                    <path id="icon-passkey-body" d="M14.44,12.52A6,6,0,0,0,12,12H9a6,6,0,0,0-6,6v2H16V14.49A5.16,5.16,0,0,1,14.44,12.52Z" />
                                </g>
                            </svg>

                            <span role="button" id="passkey-button" class="submit">{Utility.GetStringResource(nameof(Resources.Label_PasskeyButton), lcid)}</button>
                        </div>

                        <div id="passkey-error" class="smallTopSpacing mediumBottomSpacing error" role="alert" aria-live="assertive">
                            <p>{(_presentationData.HasError ? Utility.GetStringResource(_presentationData.ErrorResource!, lcid) : "")}</p>
                        </div>
                    </form>
                </div>
            """""";
        }

        public string? GetFormPreRenderHtml(int lcid)
        {
            return $$""""""
                <style>
                    #passkey-logo {
                        display: block;
                        max-height: 100px;
                        
                        margin-left: auto;
                        margin-right: auto;
                    }

                    #passkey-error {
                        display: {{(_presentationData.HasError ? "block":"none")}}
                    }
                </style>
                <script type="module" defer>
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

                    export async function handlePasskeyAuth() {
                        const loginForm = document.getElementById("loginForm");
                        const publicKeyOptionsJson = atob(loginForm.getAttribute("data-passkey-options"));
                        
                        const publicKeyCredentialJson = await getNavigatorCredentialAsJsonFromJson(publicKeyOptionsJson);
                        
                        document.getElementById("assertion-response").value = publicKeyCredentialJson;
                        document.getElementById("loginForm").submit();
                    }
                    
                    const autostartPasskey = !!document.getElementById("loginForm").getAttribute("data-passkey-autostart");
                    
                    const passkeyButton = document.getElementById("passkey-button");
                    passkeyButton.addEventListener("click", handlePasskeyAuth);

                    if (autostartPasskey) {
                        passkeyButton.disabled = true;
                        await handlePasskeyAuth();
                        passkeyButton.disabled = false;
                    }
                </script>
                """""";
        }


        public class PresentationData
        {
            public bool ShouldAutostartFlow { get; set; }

            public string? AssertionOptions { get; set; }
            public string Base64AssertionOptions => Convert.ToBase64String(Encoding.UTF8.GetBytes(AssertionOptions ?? ""));

            public bool HasError => !string.IsNullOrWhiteSpace(ErrorResource);
            public string? ErrorResource { get; set; }
        }
    }
}
