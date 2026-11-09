// Passkeys (WebAuthn) for sign-in, enrollment and "Confirm it's you". Bound through data attributes, no inline handlers (CSP).
(function () {
    "use strict";

    function token() {
        var meta = document.querySelector('meta[name="vaulty-antiforgery"]');
        return meta ? meta.getAttribute("content") : "";
    }

    async function post(url, body) {
        return fetch(url, {
            method: "POST",
            credentials: "same-origin",
            headers: { "Content-Type": "application/json", "X-Vaulty-Antiforgery": token() },
            body: body === undefined ? undefined : JSON.stringify(body)
        });
    }

    function show(element, message) {
        var target = document.getElementById(element.getAttribute("data-passkey-error") || "passkey-error");
        if (target) { target.textContent = message; target.hidden = false; }
    }

    async function run(element) {
        var mode = element.getAttribute("data-passkey");
        if (!window.PublicKeyCredential || !PublicKeyCredential.parseRequestOptionsFromJSON) {
            show(element, "This browser does not support passkeys. Use the authenticator app instead.");
            return;
        }
        try {
            if (mode === "register") {
                var optionsResponse = await post("/account/passkey/creation-options");
                var creation = PublicKeyCredential.parseCreationOptionsFromJSON(await optionsResponse.json());
                var created = await navigator.credentials.create({ publicKey: creation });
                var nameInput = document.getElementById("passkey-name");
                var saved = await post("/account/passkey/register", {
                    credential: JSON.stringify(created.toJSON()),
                    name: nameInput ? nameInput.value : "Passkey"
                });
                if (!saved.ok) { show(element, "The passkey could not be saved."); return; }
                window.location.assign(element.getAttribute("data-passkey-next") || "/");
                return;
            }
            var requestResponse = await post("/account/passkey/request-options");
            var request = PublicKeyCredential.parseRequestOptionsFromJSON(await requestResponse.json());
            var assertion = await navigator.credentials.get({ publicKey: request });
            var url = mode === "stepup" ? "/account/stepup/passkey" : "/account/passkey/login";
            var result = await post(url, { credential: JSON.stringify(assertion.toJSON()) });
            if (!result.ok) { show(element, "The passkey was not accepted."); return; }
            window.location.assign(element.getAttribute("data-passkey-next") || "/");
        } catch (error) {
            show(element, "The passkey request was cancelled or failed.");
        }
    }

    document.addEventListener("click", function (event) {
        var element = event.target.closest("[data-passkey]");
        if (!element) { return; }
        event.preventDefault();
        run(element);
    });
})();
