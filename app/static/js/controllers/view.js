import { Utils } from '../utils.js';
import { E2ECrypto } from '../crypto-module.js';

const attachmentCache = new Map();

document.addEventListener("DOMContentLoaded", async () => {
    const crypto = new E2ECrypto();
    
    try {
        // checking if key in session
        const privKeyStr = sessionStorage.getItem('dec_enc_key');
        if (!privKeyStr) throw new Error("Private key absent. Please relog.");
        
        const senderUsername = document.getElementById('sender').value;
        const signature = Utils.base64ToArrayBuffer(document.getElementById('signature').value);
        const ephemeralKeyRaw = Utils.base64ToArrayBuffer(document.getElementById('ephemeral_key').value);
        const subjRaw = Utils.base64ToArrayBuffer(document.getElementById('encrypted_subject').value);
        const contRaw = Utils.base64ToArrayBuffer(document.getElementById('encrypted_content').value);

        // getting sender public key
        const keyRes = await fetch(`/api/get_public_key/${senderUsername}`);
        const keyData = await keyRes.json();
        if (keyData.error) throw new Error("Sender public key not found");
        
        const senderVerifyKey = await crypto.importKey(
            Utils.base64ToArrayBuffer(keyData.signing_public_key), 
            'signing', 
            true
        );

        // getting attachments
        const partsToVerify = [subjRaw, contRaw];
        const rows = document.querySelectorAll('.attachment-row');
        
        document.getElementById('sig_badge').innerText = "Downloading attachments...";

        for (let row of rows) {
            const attId = row.dataset.id;
            // Fetch blob
            const res = await fetch(`/api/attachment/${attId}`);
            if (!res.ok) throw new Error("Attachment fetch failed");
            const blob = await res.blob();
            const buffer = await blob.arrayBuffer();
            
            // Cache
            attachmentCache.set(attId, buffer);

            // metadata
            const span = row.querySelector('.encrypted-filename');
            const encName = Utils.base64ToArrayBuffer(span.dataset.encName);
            const encMime = Utils.base64ToArrayBuffer(span.dataset.encMime);

            // adding to check sign
            partsToVerify.push(buffer);
            partsToVerify.push(encName);
            partsToVerify.push(encMime);
        }

        // sing verification
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
            // getting AES key
            const myPrivKey = await crypto.importKey(JSON.parse(privKeyStr), 'encryption');
            const ephemKey = await crypto.importKey(ephemeralKeyRaw, 'encryption', true);
            const aesKey = await crypto.deriveSharedKey(myPrivKey, ephemKey);

            // decrypting subject and content
            const subjDec = await crypto.decryptData(aesKey, subjRaw);
            const contDec = await crypto.decryptData(aesKey, contRaw);
            
            document.getElementById('subject_display').innerText = Utils.uint8ToStr(subjDec);
            document.getElementById('content_display').innerText = Utils.uint8ToStr(contDec);
            document.getElementById('message_container').style.display = 'block';

            // decrypting filename
            const attSection = document.getElementById('attachments_section');
            if (attSection) attSection.style.display = 'block';

            for (let row of rows) {
                const attId = row.dataset.id;
                const span = row.querySelector('.encrypted-filename');
                const btn = row.querySelector('.btn-download');

                try {
                    const encName = Utils.base64ToArrayBuffer(span.dataset.encName);
                    const encMime = Utils.base64ToArrayBuffer(span.dataset.encMime);

                    const nameDec = await crypto.decryptData(aesKey, encName);
                    const mimeDec = await crypto.decryptData(aesKey, encMime);
                    
                    const fileName = Utils.uint8ToStr(nameDec);
                    const mimeType = Utils.uint8ToStr(mimeDec);

                    span.innerText = fileName;
                    btn.disabled = false;

                    btn.onclick = async () => {
                        const fileBuf = attachmentCache.get(attId);
                        const fileDec = await crypto.decryptData(aesKey, fileBuf);
                        
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
        document.getElementById('error_panel').style.display = 'block';
        document.getElementById('error_msg').innerText = err.message;
    }
});