import { Utils } from '../utils.js';
import { E2ECrypto } from '../crypto-module.js';

document.addEventListener("DOMContentLoaded", () => {
    const crypto = new E2ECrypto();
    const form = document.getElementById('registerForm');
    const statusMsg = document.getElementById('statusMessage');
    const submitBtn = document.getElementById('submitBtn');

    // password strength bar
    const passInput = document.getElementById('password_raw');
    const bar = document.getElementById('password-strength-bar');
    const text = document.getElementById('password-strength-text');

    passInput.addEventListener('input', () => {
        const val = passInput.value;
        const score = Utils.calculatePasswordStrength(val);
        const colors = ["#dc3545", "#dc3545", "#ffc107", "#198754", "#20c997"];
        const widths = ["0%", "25%", "50%", "75%", "100%"];
        
        bar.style.width = widths[score];
        bar.style.backgroundColor = colors[score];
        
        if (score < 2 && val.length > 0) {
            submitBtn.disabled = true;
            text.innerText = "Too weak!";
        } else {
            submitBtn.disabled = false;
            text.innerText = "Password strength";
        }
    });

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        submitBtn.disabled = true;
        statusMsg.innerText = "Generating keys...";

        try {
            const username = document.getElementById('username').value;
            const email = document.getElementById('email').value;
            const password = document.getElementById('password_raw').value;
            const confirm = document.getElementById('password_second_raw').value;

            if (password !== confirm) throw new Error("Passwords do not match");
            if (Utils.calculatePasswordStrength(password).score < 2) throw new Error("Password too weak");
            if (!Utils.isValidUsername(username)) throw new Error("Invalid username");

            // Get encryption key and logging hash
            const salt = await window.crypto.getRandomValues(new Uint8Array(16));
            const secrets = await crypto.deriveSecretsFromPassword(password, salt);

            // key generation
            const encKP = await crypto.generateKeyPair('encryption');
            const signKP = await crypto.generateKeyPair('signing');

            // saving keys to session
            const expEncPriv = await crypto.exportKey(encKP.privateKey);
            const expSignPriv = await crypto.exportKey(signKP.privateKey);
            sessionStorage.setItem("dec_enc_key", JSON.stringify(expEncPriv));
            sessionStorage.setItem("dec_sign_key", JSON.stringify(expSignPriv));

            // wrap and export keys
            const wrappedEnc = await crypto.wrapKey(encKP.privateKey, secrets.encryptionKey);
            const wrappedSign = await crypto.wrapKey(signKP.privateKey, secrets.encryptionKey);
            const pubEnc = await crypto.exportKey(encKP.publicKey, 'spki');
            const pubSign = await crypto.exportKey(signKP.publicKey, 'spki');

            document.getElementById('public_key').value = Utils.arrayBufferToBase64(pubEnc);
            document.getElementById('encrypted_private_key').value = Utils.arrayBufferToBase64(wrappedEnc.wrappedData);
            document.getElementById('private_key_iv').value = Utils.arrayBufferToBase64(wrappedEnc.iv);

            document.getElementById('signing_public_key').value = Utils.arrayBufferToBase64(pubSign);
            document.getElementById('encrypted_signing_private_key').value = Utils.arrayBufferToBase64(wrappedSign.wrappedData);
            document.getElementById('signing_private_key_iv').value = Utils.arrayBufferToBase64(wrappedSign.iv);

            document.getElementById('password_verifier').value = secrets.loginToken;
            document.getElementById('password_salt').value = Utils.arrayBufferToBase64(salt);

            document.getElementById('password_raw').value = "";
            document.getElementById('password_second_raw').value = "";

            HTMLFormElement.prototype.submit.call(form);

        } catch (err) {
            console.error(err);
            statusMsg.innerText = "Error: " + err.message;
            statusMsg.style.color = "red";
            submitBtn.disabled = false;
        }
    });
});