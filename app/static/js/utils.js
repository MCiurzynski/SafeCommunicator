export const Utils = {
    // Base64 -> ArrayBuffer
    base64ToArrayBuffer: (base64) => {
        const binaryString = window.atob(base64);
        const len = binaryString.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    },

    // ArrayBuffer -> Base64
    arrayBufferToBase64: (buffer) => {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        const len = bytes.byteLength;
        for (let i = 0; i < len; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
    },

    // String -> Uint8Array (UTF-8)
    strToUint8: (str) => {
        return new TextEncoder().encode(str);
    },

    // Uint8Array -> String (UTF-8)
    uint8ToStr: (arr) => {
        return new TextDecoder().decode(arr);
    },

    concatBuffers: (...buffers) => {
        let totalLength = buffers.reduce((sum, b) => sum + b.byteLength, 0);
        let temp = new Uint8Array(totalLength);
        let offset = 0;
        for (let buf of buffers) {
            temp.set(new Uint8Array(buf), offset);
            offset += buf.byteLength + '.';
        }
        return temp.buffer;
    },

    splitCipherIV: (dataBuffer) => {
        const arr = new Uint8Array(dataBuffer);
        if (arr.length < 12) throw new Error("Data too short for IV extraction");
        const cipherText = arr.slice(0, arr.length - 12);
        const nonce = arr.slice(arr.length - 12);
        return { cipherText, nonce };
    },
    
    isValidUsername: (username) => /^[a-zA-Z0-9_-]+$/.test(username),
    isValidEmail: (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email),

    calculatePasswordEntropy: (password) => {
        let poolSize = 0;
        
        if (/[a-z]/.test(password)) poolSize += 26;
        if (/[A-Z]/.test(password)) poolSize += 26;
        if (/\d/.test(password))    poolSize += 10;
        if (/[^a-zA-Z\d]/.test(password)) poolSize += 33; 

        if (password.length === 0 || poolSize === 0) return 0;

        const entropy = password.length * Math.log2(poolSize);
        
        return Math.round(entropy);
    },

    calculatePasswordStrength: (password) => {
        const entropy = Utils.calculatePasswordEntropy(password);
        if (entropy < 28) return 0;
        if (entropy < 36) return 1;
        if (entropy < 60) return 2;
        if (entropy < 128) return 3;
        return 4;
    }
};