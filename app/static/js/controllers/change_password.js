import { Utils } from '../utils.js';
import { E2ECrypto } from '../crypto-module.js';

document.addEventListener("DOMContentLoaded", () => {
    const crypto = new E2ECrypto();
    const form = document.getElementById('changePasswordForm');
    const submitBtn = document.getElementById('submitBtn');
    const statusMsg = document.getElementById('statusMessage');

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const currentPass = document.getElementById('current_password').value;
        const newPass = document.getElementById('new_password').value;
        const confirmPass = document.getElementById('confirm_password').value;

        if (newPass !== confirmPass) {
            alert("Passwords must be equal!");
            return;
        }

        submitBtn.disabled = true;
        statusMsg.innerText = "Verification";

        try {
            const currentData = document.getElementById('currentData').dataset;
            const oldSalt = Utils.base64ToArrayBuffer(currentData.salt);
            
            const oldSecrets = await crypto.deriveSecretsFromPassword(currentPass, oldSalt);

            const encPrivKeyObj = await crypto.unwrapKey(
                Utils.base64ToArrayBuffer(currentData.encKey),
                oldSecrets.encryptionKey,
                Utils.base64ToArrayBuffer(currentData.encIv),
                'encryption'
            );
            
            const signPrivKeyObj = await crypto.unwrapKey(
                Utils.base64ToArrayBuffer(currentData.signKey),
                oldSecrets.encryptionKey,
                Utils.base64ToArrayBuffer(currentData.signIv),
                'signing'
            );

            const newSalt = await window.crypto.getRandomValues(new Uint8Array(16));
            const newSecrets = await crypto.deriveSecretsFromPassword(newPass, newSalt);

            const newWrappedEnc = await crypto.wrapKey(encPrivKeyObj, newSecrets.encryptionKey);
            const newWrappedSign = await crypto.wrapKey(signPrivKeyObj, newSecrets.encryptionKey);

            document.getElementById('password_verifier').value = newSecrets.loginToken;
            document.getElementById('password_salt').value = Utils.arrayBufferToBase64(newSalt);

            document.getElementById('encrypted_private_key').value = Utils.arrayBufferToBase64(newWrappedEnc.wrappedData);
            document.getElementById('private_key_iv').value = Utils.arrayBufferToBase64(newWrappedEnc.iv);

            document.getElementById('encrypted_signing_private_key').value = Utils.arrayBufferToBase64(newWrappedSign.wrappedData);
            document.getElementById('signing_private_key_iv').value = Utils.arrayBufferToBase64(newWrappedSign.iv);

            HTMLFormElement.prototype.submit.call(form);

        } catch (err) {
            console.error(err);
            statusMsg.innerText = err;
            statusMsg.style.color = "red";
            submitBtn.disabled = false;
        }
    });
});