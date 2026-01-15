import { Utils } from '../utils.js';
import { E2ECrypto } from '../crypto-module.js';

document.addEventListener("DOMContentLoaded", () => {
    const crypto = new E2ECrypto();
    const form = document.getElementById('loginForm');
    const statusMsg = document.getElementById('statusMessage');
    const submitBtn = document.getElementById('submitBtn');

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        statusMsg.innerText = "Verifying credentials...";
        submitBtn.disabled = true;

        try {
            const username = document.getElementById('username').value;
            const password = document.getElementById('password_raw').value;
            const totp = document.getElementById('totp_code').value;

            if (!username || !password || !totp) throw new Error("All fields required");

            // Get encryption key and logging hash
            const salt = await crypto.sha256(Utils.strToUint8(username));
            const secrets = await crypto.deriveSecretsFromPassword(password, salt);

            // logging to server
            const formData = new FormData(form);
            formData.set('password_verifier', secrets.loginToken);
            
            const response = await fetch(form.action, {
                method: 'POST',
                body: formData
            });

            const result = await response.json();

            if (!result.success) {
                throw new Error(result.message || "Login failed");
            }

            // private key unwrap
            const keys = result.keys;
            
            // Encryption private Key
            const encPrivKeyObj = await crypto.unwrapKey(
                Utils.base64ToArrayBuffer(keys.encrypted_private_key),
                secrets.encryptionKey,
                Utils.base64ToArrayBuffer(keys.private_key_iv),
                'encryption'
            );
            
            // Signing private Key
            const signPrivKeyObj = await crypto.unwrapKey(
                Utils.base64ToArrayBuffer(keys.encrypted_signing_private_key),
                secrets.encryptionKey,
                Utils.base64ToArrayBuffer(keys.signing_private_key_iv),
                'signing'
            );

            // storing keys in session
            const expEnc = await crypto.exportKey(encPrivKeyObj);
            const expSign = await crypto.exportKey(signPrivKeyObj);
            
            sessionStorage.setItem("dec_enc_key", JSON.stringify(expEnc));
            sessionStorage.setItem("dec_sign_key", JSON.stringify(expSign));

            window.location.href = result.redirect_url;

        } catch (err) {
            console.error(err);
            statusMsg.innerText = "Error: " + err.message;
            statusMsg.style.color = "red";
            submitBtn.disabled = false;
        }
    });
});