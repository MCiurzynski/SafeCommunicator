/*
Konwertuje ArrayBuffer (dane binarne) na ciąg Base64.
*/
function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    return bytes.toBase64();
}

/*
Konwertuje ciąg Base64 na ArrayBuffer (dane binarne).
*/
function base64ToArrayBuffer(base64) {
    const bytes = Uint8Array.fromBase64(base64);
    return bytes.buffer;
}

/*
Pomocnicza funkcja do zamiany zwykłego tekstu na ArrayBuffer (UTF-8).
*/
function str2ab(str) {
    const enc = new TextEncoder();
    return enc.encode(str);
}

function base64ToUint8Array(base64) {
    var binary_string = window.atob(base64);
    var len = binary_string.length;
    var bytes = new Uint8Array(len);
    for (var i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }

    return bytes;
}

async function getSaltFromUsername(username) {
    const encoder = new TextEncoder();
    const data = encoder.encode(username); 

    const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
    
    return new Uint8Array(hashBuffer);
}


async function deriveSecrets(password, salt) {
    const enc = new TextEncoder();

    let hashResult;
    try {
        hashResult = await argon2.hash({
            pass: password,
            salt: salt,       
            time: 2,
            mem: 16 * 1024,
            hashLen: 32, 
            parallelism: 1,
            type: argon2.ArgonType.Argon2id 
        });
    } catch (e) {
        console.error("Argon2 Error:", e);
        throw new Error("Błąd kryptograficzny Argon2");
    }

    const masterKey = await window.crypto.subtle.importKey(
        "raw",
        hashResult.hash,
        { name: "HKDF" },
        false,
        ["deriveKey"]
    );

    const encryptionKey = await window.crypto.subtle.deriveKey(
        {
            name: "HKDF",
            hash: "SHA-256",
            salt: new Uint8Array(),
            info: enc.encode("enc")
        },
        masterKey,
        { name: "AES-GCM", length: 256 },
        false, 
        ["wrapKey", "unwrapKey"]
    );

    const loginTokenKey = await window.crypto.subtle.deriveKey(
        {
            name: "HKDF",
            hash: "SHA-256",
            salt: new Uint8Array(),
            info: enc.encode("auth")
        },
        masterKey,
        { name: "HMAC", hash: "SHA-256" },
        true, 
        ["sign"]
    );
    
    const loginTokenRaw = await window.crypto.subtle.exportKey("raw", loginTokenKey);

    return {
        loginToken: arrayBufferToBase64(loginTokenRaw),
        encryptionKey: encryptionKey
    };
}

function isValidUsername(username) {
    const regex = /^[a-zA-Z0-9_-]+$/;
    return regex.test(username);
}

function isValidEmail(email) {
    const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return regex.test(email);
}

async function signData(signKey, ...args) {
    const enc = new TextEncoder();
    let signData = '';
    for (let arg of args) signData += arg;
    const sign = await window.crypto.subtle.sign({name: 'Ed25519'}, signKey, enc.encode(signData));
    return sign;
}

async function verifySignature(senderVerifyKey, signature, ...args) {
    const enc = new TextEncoder();
    let signData = '';
    for (let arg of args) signData += arg;
    const isValid = await window.crypto.subtle.verify(
        { name: 'Ed25519'},
        senderVerifyKey,
        signature,
        enc.encode(signData)
    );
    return isValid;
}