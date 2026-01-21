import { Utils } from '../utils.js';
import { E2ECrypto } from '../crypto-module.js';

document.addEventListener("DOMContentLoaded", async () => {
    const privKeyStr = sessionStorage.getItem("dec_enc_key");
    if (!privKeyStr) {
        document.getElementById('key-status-missing').style.display = 'block';
        return;
    }

    const crypto = new E2ECrypto();
    const rows = document.querySelectorAll('.message-row');

    try {
        const myPrivKey = await crypto.importKey(JSON.parse(privKeyStr), 'encryption');

        const decryptionPromises = Array.from(rows).map(async (row) => {
            try {
                const subjectCell = row.querySelector('.subject-cell');
                const ephemB64 = row.dataset.ephemeral;
                const subjB64 = row.dataset.subject;

                // Derive AES
                const ephemKey = await crypto.importKey(Utils.base64ToArrayBuffer(ephemB64), 'encryption', true);
                const aesKey = await crypto.deriveSharedKey(myPrivKey, ephemKey);

                // Decrypt
                const subjDec = await crypto.decryptData(aesKey, Utils.base64ToArrayBuffer(subjB64));
                
                subjectCell.innerText = Utils.uint8ToStr(subjDec);
                subjectCell.style.fontStyle = "normal";
                subjectCell.style.color = "black";

            } catch (e) {
                console.error("Row decryption failed", e);
                row.querySelector('.subject-cell').innerText = "[Error]";
            }
        });
        await Promise.all(decryptionPromises);
    } catch (e) {
        console.error("Index error", e);
    }
});