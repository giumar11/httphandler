// Cloudflare Worker – WhatsApp Flow Integrity Endpoint
// Funziona con body:
// { "encrypted_aes_key": "<base64>", "challenge": "Accepted", "iv": "<base64 opzionale>" }
// Risponde: base64( IV || CIPHERTEXT || TAG ) cifrato AES-256-GCM

export default {
  async fetch(req) {
    if (req.method === 'POST') {
      const txt = await req.text();
      return new Response(txt || 'pong', { status: 200, headers: { 'Content-Type': 'text/plain' } });
    }
    return new Response('ok', { status: 200 });
  }
},
  
  function base64ToBytes(b64) {
    const bin = atob(b64);
    const buf = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    return buf;
  }
  function bytesToBase64(arr) {
    let s = '';
    for (let i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i]);
    return btoa(s);
  }
  function concat(a, b) {
    const out = new Uint8Array(a.length + b.length);
    out.set(a, 0); out.set(b, a.length);
    return out;
  }
  async function importPrivateKey(pem) {
    const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
    const der = base64ToBytes(b64);
    return crypto.subtle.importKey(
      'pkcs8', der.buffer,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false, ['decrypt']
    );
  }
