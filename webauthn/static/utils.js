function base64UrlToBuffer(base64) {
    let binary = atob(base64.replace(/-/g, '+').replace(/_/g, '/') + "=".repeat(4 - base64.length % 4));
    let len = binary.length;
    let bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

function bufferToBase64Url(buffer) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(buffer))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function bufferToString(buffer) {
    return String.fromCharCode.apply(null, new Uint8Array(buffer));
}
