// Cloudflare Worker – WhatsApp Flow Integrity Endpoint
// Funziona con body:
// { "encrypted_aes_key": "<base64>", "challenge": "Accepted", "iv": "<base64 opzionale>" }
// Risponde: base64( IV || CIPHERTEXT || TAG ) cifrato AES-256-GCM

export default {
    async fetch(req, env) {
      try {
        const json = await req.json();
  
        // 1) importa chiave privata RSA-OAEP (PKCS#8 PEM in secret PRIVATE_KEY_PEM)
        const rsaKey = await importPrivateKey(env.PRIVATE_KEY_PEM);
  
        // 2) prendi AES key cifrata e decifrala con la private RSA
        const encKey = base64ToBytes(json.encrypted_aes_key);
        const aesKeyRaw = await crypto.subtle.decrypt(
          { name: 'RSA-OAEP' }, rsaKey, encKey
        );
        const aesKey = await crypto.subtle.importKey(
          'raw', aesKeyRaw, { name: 'AES-GCM' }, false, ['encrypt']
        );
  
        // 3) plaintext: usa json.challenge se presente, altrimenti "Accepted"
        const plaintext = new TextEncoder().encode(json.challenge || 'Accepted');
  
        // IV: usa quello passato o generane uno (12 byte per GCM)
        const iv = json.iv ? base64ToBytes(json.iv) : crypto.getRandomValues(new Uint8Array(12));
  
        // 4) cifra con AES-GCM
        const ct = new Uint8Array(await crypto.subtle.encrypt(
          { name: 'AES-GCM', iv }, aesKey, plaintext
        ));
        // In WebCrypto il tag è in coda al ciphertext; molti esperimenti passano così
        // Meta in genere accetta IV || CIPHERTEXT (tag incluso) in base64.
        const out = bytesToBase64(concat(iv, ct));
  
        return new Response(out, {
          status: 200,
          headers: { 'Content-Type': 'text/plain' }
        });
      } catch (e) {
        return new Response('error', { status: 500 });
      }
    }
  };
  
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