import { Utils } from './utils.js';

const CFG = {
    encAlgo: "AES-GCM",
    encLen: 256,
    hashAlgo: "SHA-256",
    signAlgo: "Ed25519",
    ecdhAlgo: "X25519",
    ivLen: 12
};

export class E2ECrypto {
    
    async sha256(dataUint8) {
        return await window.crypto.subtle.digest(CFG.hashAlgo, dataUint8);
    }

    async deriveSecretsFromPassword(password, saltUint8) {
        if (saltUint8 instanceof ArrayBuffer) {
            saltUint8 = new Uint8Array(saltUint8);
        }

        const enc = new TextEncoder();
        
        const passwordKey = await window.crypto.subtle.importKey(
            "raw",
            enc.encode(password),
            { name: "PBKDF2" },
            false,
            ["deriveBits", "deriveKey"]
        );

        const masterKeyBits = await window.crypto.subtle.deriveBits(
            {
                name: "PBKDF2",
                salt: saltUint8,
                iterations: 500000, 
                hash: "SHA-256"
            },
            passwordKey,
            256
        );

        const masterKey = await window.crypto.subtle.importKey(
            "raw",
            masterKeyBits,
            { name: "HKDF" },
            false,
            ["deriveKey"]
        );

        const encKey = await window.crypto.subtle.deriveKey(
            { name: "HKDF", hash: CFG.hashAlgo, salt: new Uint8Array(), info: Utils.strToUint8("enc") },
            masterKey,
            { name: CFG.encAlgo, length: CFG.encLen },
            false, ["wrapKey", "unwrapKey"]
        );

        const authKey = await window.crypto.subtle.deriveKey(
            { name: "HKDF", hash: CFG.hashAlgo, salt: new Uint8Array(), info: Utils.strToUint8("auth") },
            masterKey,
            { name: "HMAC", hash: CFG.hashAlgo },
            true, ["sign"]
        );
        const loginTokenRaw = await window.crypto.subtle.exportKey("raw", authKey);

        return { encryptionKey: encKey, loginToken: Utils.arrayBufferToBase64(loginTokenRaw) };
    }

    async generateKeyPair(type) {
        const algo = type === 'signing' ? CFG.signAlgo : CFG.ecdhAlgo;
        const usages = type === 'signing' ? ["sign", "verify"] : ["deriveKey", "deriveBits"];
        return await window.crypto.subtle.generateKey({ name: algo }, true, usages);
    }

    async wrapKey(keyToWrap, wrappingKey) {
        const iv = window.crypto.getRandomValues(new Uint8Array(CFG.ivLen));
        const wrapped = await window.crypto.subtle.wrapKey(
            "pkcs8", keyToWrap, wrappingKey, { name: CFG.encAlgo, iv: iv }
        );
        return { wrappedData: wrapped, iv: iv };
    }

    async unwrapKey(wrappedData, unwrappingKey, iv, type) {
        const algo = type === 'signing' ? CFG.signAlgo : CFG.ecdhAlgo;
        const usages = type === 'signing' ? ["sign"] : ["deriveKey", "deriveBits"];
        return await window.crypto.subtle.unwrapKey(
            "pkcs8", wrappedData, unwrappingKey,
            { name: CFG.encAlgo, iv: iv },
            { name: algo },
            true, usages
        );
    }

    async exportKey(key, format = 'jwk') {
        return await window.crypto.subtle.exportKey(format, key);
    }
    
    async importKey(keyData, type, isPublic = false) {
        const algo = type === 'signing' ? CFG.signAlgo : CFG.ecdhAlgo;
        const format = isPublic ? 'spki' : 'jwk';
        const usages = [];
        
        if (type === 'signing') usages.push(isPublic ? 'verify' : 'sign');
        else usages.push(isPublic ? [] : 'deriveKey');

        const finalUsages = (type !== 'signing' && isPublic) ? [] : usages;

        return await window.crypto.subtle.importKey(format, keyData, { name: algo }, false, finalUsages);
    }

    async encryptData(aesKey, dataBuffer) {
        const iv = window.crypto.getRandomValues(new Uint8Array(CFG.ivLen));
        const encrypted = await window.crypto.subtle.encrypt(
            { name: CFG.encAlgo, iv: iv }, aesKey, dataBuffer
        );
        const result = new Uint8Array(encrypted.byteLength + CFG.ivLen);
        result.set(new Uint8Array(encrypted), 0);
        result.set(iv, encrypted.byteLength);
        return result.buffer;
    }

    async decryptData(aesKey, blobWithIV) {
        const { cipherText, nonce } = Utils.splitCipherIV(blobWithIV);
        return await window.crypto.subtle.decrypt(
            { name: CFG.encAlgo, iv: nonce }, aesKey, cipherText
        );
    }

    async sign(signKey, ...buffers) {
        const data = Utils.concatBuffers(...buffers);
        return await window.crypto.subtle.sign({ name: CFG.signAlgo }, signKey, data);
    }

    async verify(verifyKey, signature, ...buffers) {
        const data = Utils.concatBuffers(...buffers);
        return await window.crypto.subtle.verify({ name: CFG.signAlgo }, verifyKey, signature, data);
    }

    async deriveSharedKey(privKey, pubKey) {
        return await window.crypto.subtle.deriveKey(
            { name: CFG.ecdhAlgo, public: pubKey },
            privKey,
            { name: CFG.encAlgo, length: CFG.encLen },
            false, ["encrypt", "decrypt"]
        );
    }
}