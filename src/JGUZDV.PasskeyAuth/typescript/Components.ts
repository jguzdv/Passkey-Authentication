export class StatusMessage extends HTMLElement {
    static observedAttributes = ["message-key"];

    private _messages: Promise<any>;

    constructor() {
        super();

        this._messages = this.loadMessages();
    }

    async loadMessages() {
        let lang = navigator.language.split("-")[0];
        if (lang !== "en") {
            lang = "default";
        }

        const response = await fetch(`lang/${lang}.json`);
        return response.json();
    }

    connectedCallback() {
        console.log("Custom element added to page.");

        this.updateMessage(this.getAttribute("message-key"));
    }


    attributeChangedCallback(name: any, _: any, newValue: any) {
        console.log(`Attribute ${name} has changed.`);

        if (name === "message-key") {
            this.updateMessage(newValue);
        };
    }


    updateMessage(key: string | null) {
        this._messages.then(messages => {
            if (!!key) {
                this.innerText = messages[key] || key || "";
            }
            else {
                this.innerText = "";
            }
        }).catch(() => {
            // Fallback to key if messages fail to load
            this.innerText = key || "";
        });
    }
}
