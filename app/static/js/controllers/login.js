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
            const res = await fetch(`/api/user/salt/${username}`);
            if (!res.ok) throw new Error("Username not found");
            const saltJson = await res.json();
            const salt = Utils.base64ToArrayBuffer(await saltJson.password_salt);

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
                window.location.reload();
                submitBtn.disabled = true;
                return;
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
            submitBtn.disabled = false;
            statusMsg.innerText = err;
        }
    });
});