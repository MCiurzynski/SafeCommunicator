import { Utils } from '../utils.js';
import { E2ECrypto } from '../crypto-module.js';

document.addEventListener("DOMContentLoaded", () => {
    const crypto = new E2ECrypto();
    const form = document.getElementById('resetForm');
    const submitBtn = document.getElementById('submitBtn');
    const statusMsg = document.getElementById('statusMessage');

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const password = document.getElementById('new_password').value;
        const confirm = document.getElementById('confirm_password').value;
        
        if (password !== confirm) {
            alert("Passwords must be equal!");
            return;
        }

        if (Utils.calculatePasswordStrength(password) < 2) {
            alert("Password is too weak!");
            return;
        }

        submitBtn.disabled = true;
        statusMsg.innerText = "Generowanie nowych kluczy kryptograficznych...";

        try {
            const salt = await window.crypto.getRandomValues(new Uint8Array(16));
            const secrets = await crypto.deriveSecretsFromPassword(password, salt);

            const encKP = await crypto.generateKeyPair('encryption');
            const signKP = await crypto.generateKeyPair('signing');

            const wrappedEnc = await crypto.wrapKey(encKP.privateKey, secrets.encryptionKey);
            const wrappedSign = await crypto.wrapKey(signKP.privateKey, secrets.encryptionKey);

            const pubEnc = await crypto.exportKey(encKP.publicKey, 'spki');
            const pubSign = await crypto.exportKey(signKP.publicKey, 'spki');

            document.getElementById('password_verifier').value = secrets.loginToken;
            document.getElementById('password_salt').value = Utils.arrayBufferToBase64(salt);

            document.getElementById('public_key').value = Utils.arrayBufferToBase64(pubEnc);
            document.getElementById('encrypted_private_key').value = Utils.arrayBufferToBase64(wrappedEnc.wrappedData);
            document.getElementById('private_key_iv').value = Utils.arrayBufferToBase64(wrappedEnc.iv);

            document.getElementById('signing_public_key').value = Utils.arrayBufferToBase64(pubSign);
            document.getElementById('encrypted_signing_private_key').value = Utils.arrayBufferToBase64(wrappedSign.wrappedData);
            document.getElementById('signing_private_key_iv').value = Utils.arrayBufferToBase64(wrappedSign.iv);

            HTMLFormElement.prototype.submit.call(form);

        } catch (err) {
            console.error(err);
            statusMsg.innerText = err.message;
            submitBtn.disabled = false;
        }
    });
});