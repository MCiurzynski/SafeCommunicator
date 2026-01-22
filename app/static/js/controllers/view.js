import { Utils } from '../utils.js';
import { E2ECrypto } from '../crypto-module.js';

const attachmentCache = new Map();

document.addEventListener("DOMContentLoaded", async () => {
    const crypto = new E2ECrypto();
    
    try {
        // checking if key in session
        const privKeyStr = sessionStorage.getItem('dec_enc_key');
        if (!privKeyStr) throw new Error("Private key absent. Please relog.");
        
        // get data from html
        const senderUsername = document.getElementById('sender').value;
        const signature = Utils.base64ToArrayBuffer(document.getElementById('signature').value);
        const ephemeralKeyRaw = Utils.base64ToArrayBuffer(document.getElementById('ephemeral_key').value);
        const subjRaw = Utils.base64ToArrayBuffer(document.getElementById('encrypted_subject').value);
        const contRaw = Utils.base64ToArrayBuffer(document.getElementById('encrypted_content').value);
        
        const keyForRecipientB64 = document.getElementById('key_for_recipient').value;
        const keyForSenderB64 = document.getElementById('key_for_sender').value;

        // get current user
        const meRes = await fetch('/api/me');
        if (!meRes.ok) throw new Error("Failed to fetch user info");
        const me = await meRes.json();
        const currentUsername = me.username;

        // get sender public key
        const keyRes = await fetch(`/api/get_public_key/${senderUsername}`);
        const keyData = await keyRes.json();
        if (keyData.error) throw new Error("Sender public key not found");
        
        const senderVerifyKey = await crypto.importKey(
            Utils.base64ToArrayBuffer(keyData.signing_public_key), 
            'signing', 
            true
        );

        // get attachments
        const partsToVerify = [subjRaw, contRaw];
        const rows = document.querySelectorAll('.attachment-row');
        
        document.getElementById('sig_badge').innerText = "Downloading attachments...";

        for (let row of rows) {
            const attId = row.dataset.id;
            // fetch blob
            const res = await fetch(`/api/attachment/${attId}`);
            if (!res.ok) throw new Error("Attachment fetch failed");
            const blob = await res.blob();
            const buffer = await blob.arrayBuffer();
            
            // cache blob
            attachmentCache.set(attId, buffer);

            // metadata
            const span = row.querySelector('.encrypted-filename');
            const encName = Utils.base64ToArrayBuffer(span.dataset.encName);
            const encMime = Utils.base64ToArrayBuffer(span.dataset.encMime);

            // add to verification
            partsToVerify.push(buffer);
            partsToVerify.push(encName);
            partsToVerify.push(encMime);
        }

        // verify signature
        const isValid = await crypto.verify(senderVerifyKey, signature, ...partsToVerify);
        
        const badge = document.getElementById('sig_badge');
        let proceed = true;
        
        if (isValid) {
            badge.innerText = "Signature Verified";
            badge.style.backgroundColor = "#d4edda";
            badge.style.color = "#155724";
        } else {
            badge.innerText = "Signature INVALID";
            badge.style.backgroundColor = "#f8d7da";
            badge.style.color = "#721c24";
            proceed = confirm("Warning: Integrity check failed. Proceed?");
        }

        if (proceed) {
            // decrypt session key
            let targetEnvelopeB64;

            if (currentUsername === senderUsername) {
                // sender envelope
                targetEnvelopeB64 = keyForSenderB64;
            } else {
                // recipient envelope
                targetEnvelopeB64 = keyForRecipientB64;
            }

            if (!targetEnvelopeB64 || targetEnvelopeB64 === "None" || targetEnvelopeB64 === "") {
                throw new Error("Cannot decrypt");
            }

            // import keys
            const myPrivKey = await crypto.importKey(JSON.parse(privKeyStr), 'encryption');
            const ephemeralKey = await crypto.importKey(ephemeralKeyRaw, 'encryption', true);
            
            // derive wrapping key
            const wrappingKey = await crypto.deriveSharedKey(myPrivKey, ephemeralKey);

            // decrypt aes key
            const rawSessionKey = await crypto.decryptData(wrappingKey, Utils.base64ToArrayBuffer(targetEnvelopeB64));
            
            // import aes key
            const sessionAesKey = await window.crypto.subtle.importKey(
                "raw", rawSessionKey, { name: "AES-GCM" }, false, ["decrypt"]
            );

            // decrypt content
            const subjDec = await crypto.decryptData(sessionAesKey, subjRaw);
            const contDec = await crypto.decryptData(sessionAesKey, contRaw);
            
            document.getElementById('subject_display').innerText = Utils.uint8ToStr(subjDec);
            document.getElementById('content_display').innerText = Utils.uint8ToStr(contDec);
            document.getElementById('message_container').style.display = 'block';

            // decrypt attachments
            const attSection = document.getElementById('attachments_section');
            if (rows.length > 0 && attSection) attSection.style.display = 'block';

            for (let row of rows) {
                const attId = row.dataset.id;
                const span = row.querySelector('.encrypted-filename');
                const btn = row.querySelector('.btn-download');

                try {
                    const encName = Utils.base64ToArrayBuffer(span.dataset.encName);
                    const encMime = Utils.base64ToArrayBuffer(span.dataset.encMime);

                    const nameDec = await crypto.decryptData(sessionAesKey, encName);
                    const mimeDec = await crypto.decryptData(sessionAesKey, encMime);
                    
                    const fileName = Utils.uint8ToStr(nameDec);
                    const mimeType = Utils.uint8ToStr(mimeDec);

                    span.innerText = fileName;
                    btn.disabled = false;

                    // download handler
                    btn.onclick = async () => {
                        const fileBuf = attachmentCache.get(attId);
                        const fileDec = await crypto.decryptData(sessionAesKey, fileBuf);
                        
                        const blob = new Blob([fileDec], { type: mimeType });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = fileName;
                        document.body.appendChild(a);
                        a.click();
                        document.body.removeChild(a);
                        URL.revokeObjectURL(url);
                    };

                } catch (e) {
                    span.innerText = "[Decryption Error]";
                    span.style.color = "red";
                    console.error(e);
                }
            }
        }

    } catch (err) {
        console.error(err);
        const errorPanel = document.getElementById('error_panel');
        errorPanel.style.display = 'block';
        
        if (err.message.includes("Cannot decrypt") || err.message.includes("operation failed")) {
             document.getElementById('error_msg').innerText = 
                "The message could not be decrypted. The password may have been reset or the private key may not match.";
        } else {
             document.getElementById('error_msg').innerText = err.message;
        }
    }
});