import { Utils } from '../utils.js';
import { E2ECrypto } from '../crypto-module.js';

const MAX_SIZE = 100 * 1024 * 1024;

const fileInput = document.getElementById('file_input');

fileInput.addEventListener('change', (event) => {
    const files = event.target.files; 
    
    if (files.length > 10) {
        alert("Too many files. Maximum is 10.");
        fileInput.value = ""; 
    }

    let totalSize = 0;

    for (const file of files) {
        totalSize += file.size;
    }

    if (totalSize > MAX_SIZE) {
        alert("Total file size is too big. Max size is 100MB.");
        fileInput.value = ""; 
    }
});

document.addEventListener("DOMContentLoaded", () => {
    // checking if key in session
    if (!sessionStorage.getItem("dec_enc_key") || !sessionStorage.getItem("dec_sign_key")) {
        document.getElementById("sendForm").style.display = "none";
        document.getElementById("key-error").style.display = "block";
        return;
    }

    const crypto = new E2ECrypto();
    const form = document.getElementById('sendForm');
    const submitBtn = document.getElementById('submitBtn');
    const status = document.getElementById('status');

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        submitBtn.disabled = true;
        status.innerText = "Encrypting and signing...";

        try {
            const recipientName = document.getElementById('recipient').value;
            const subject = document.getElementById('subject').value;
            const content = document.getElementById('content').value;

            // get recipient public key
            const res = await fetch(`/api/get_public_key/${encodeURIComponent(recipientName)}`);
            const data = await res.json();
            if (data.error) throw new Error("Recipient not found");
            
            const reciPubKey = await crypto.importKey(
                Utils.base64ToArrayBuffer(data.public_key), 
                'encryption', 
                true
            );

            // import sign key
            const myPrivSignKey = await crypto.importKey(
                JSON.parse(sessionStorage.getItem("dec_sign_key")), 'signing'
            );

            // generating ephemeral Key and aes key
            const ephemeralKP = await crypto.generateKeyPair('encryption');
            const aesKey = await crypto.deriveSharedKey(ephemeralKP.privateKey, reciPubKey);

            // encrypt subject and content
            const subjectBlob = await crypto.encryptData(aesKey, Utils.strToUint8(subject));
            const contentBlob = await crypto.encryptData(aesKey, Utils.strToUint8(content));

            // files
            const fileInput = document.getElementById('file_input');
            const attachmentsMetadata = [];
            const encryptedFileBlobs = [];
            
            const partsToSign = [subjectBlob, contentBlob];

            for (let i = 0; i < fileInput.files.length; i++) {
                const file = fileInput.files[i];
                
                // encrypt content of file
                const fileBuf = await file.arrayBuffer();
                const encFile = await crypto.encryptData(aesKey, fileBuf);
                
                // encrypt metadata
                const encName = await crypto.encryptData(aesKey, Utils.strToUint8(file.name));
                const encMime = await crypto.encryptData(aesKey, Utils.strToUint8(file.type || 'application/octet-stream'));

                // add to signing
                partsToSign.push(encFile);
                partsToSign.push(encName);
                partsToSign.push(encMime);

                attachmentsMetadata.push({
                    encrypted_filename: Utils.arrayBufferToBase64(encName),
                    encrypted_mime: Utils.arrayBufferToBase64(encMime),
                    file_size_hint: file.size
                });

                encryptedFileBlobs.push(new Blob([encFile]));
            }

            // sing
            const signature = await crypto.sign(myPrivSignKey, ...partsToSign);

            const ephemPubExp = await crypto.exportKey(ephemeralKP.publicKey, 'spki');
            
            document.getElementById('subject_encrypted').value = Utils.arrayBufferToBase64(subjectBlob);
            document.getElementById('content_encrypted').value = Utils.arrayBufferToBase64(contentBlob);
            document.getElementById('ephemeral_public_key').value = Utils.arrayBufferToBase64(ephemPubExp);
            document.getElementById('signature').value = Utils.arrayBufferToBase64(signature);
            document.getElementById('attachments_metadata_json').value = JSON.stringify(attachmentsMetadata);

            // sending formdata
            const formData = new FormData(form);
            formData.delete('attachment_blob');
            if (formData.has('subject')) formData.delete('subject');
            if (formData.has('content')) formData.delete('content');

            encryptedFileBlobs.forEach((blob, idx) => {
                formData.append('attachment_blob', blob, `enc_file_${idx}`);
            });

            const resp = await fetch(form.action, { method: 'POST', body: formData });
            if (resp.ok) {
                window.location.href = "/";
            } else {
                throw new Error(await resp.text());
            }

        } catch (err) {
            console.error(err);
            status.innerText = "Error: " + err.message;
            submitBtn.disabled = false;
        }
    });
});