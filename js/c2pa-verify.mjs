// c2pa-verify.mjs — native JS C2PA verifier for WAV (no c2pa-rs). The twin of
// c2pa.mjs: parses the RIFF C2PA chunk + JUMBF tree, decodes the CBOR claim /
// assertions / COSE_Sign1, verifies the ES256 signature against the embedded
// certificate's public key (WebCrypto), and recomputes the hard-binding data
// hash + assertion hashedURIs. Pure WebCrypto — runs in browsers, Node, Deno,
// Workers.
//
// c2paVerifyWav(wavBytes) -> {
//   valid,            // signature + all hash bindings check out
//   signatureValid,   // COSE ES256 verified against the embedded cert
//   dataHashValid,    // hard binding matches the audio
//   assertionsValid,  // every claimed assertion hash matches
//   trusted,          // false for self-signed (no trust-anchor checking here)
//   errors: [string], // human-readable failures
//   manifest: { generatorName, instanceID, actions:[...], alg },
// }
const crypto = globalThis.crypto;
const td = new TextDecoder();

// ------------------------------------------------------------- minimal CBOR decode
function cborDecode(bytes) {
  let pos = 0;
  function u(n) { let v = 0; for (let i = 0; i < n; i++) v = v * 256 + bytes[pos++]; return v; }
  function head() {
    const ib = bytes[pos++];
    const major = ib >> 5, ai = ib & 0x1f;
    let len;
    if (ai < 24) len = ai;
    else if (ai === 24) len = bytes[pos++];
    else if (ai === 25) len = u(2);
    else if (ai === 26) len = u(4);
    else if (ai === 27) len = u(8);
    else len = ai; // 31 = indefinite (unused here)
    return { major, ai, len };
  }
  function value() {
    const h = head();
    switch (h.major) {
      case 0: return h.len;                 // uint
      case 1: return -1 - h.len;            // negative
      case 2: { const b = bytes.slice(pos, pos + h.len); pos += h.len; return b; } // bstr
      case 3: { const b = bytes.slice(pos, pos + h.len); pos += h.len; return td.decode(b); } // tstr
      case 4: { const a = []; for (let i = 0; i < h.len; i++) a.push(value()); return a; }     // array
      case 5: { const m = new Map(); for (let i = 0; i < h.len; i++) { const k = value(); m.set(typeof k === 'string' || typeof k === 'number' ? k : JSON.stringify(k), value()); } return m; } // map
      case 6: return { __tag: h.len, value: value() };  // tag
      case 7:
        if (h.ai === 20) return false;
        if (h.ai === 21) return true;
        if (h.ai === 22) return null;
        return undefined;
      default: throw new Error('cbor: bad major ' + h.major);
    }
  }
  const v = value();
  return v;
}

// -------------------------------------------------------------------- RIFF + JUMBF
function findC2paChunk(wav) {
  const dv = new DataView(wav.buffer, wav.byteOffset, wav.byteLength);
  let off = 12;
  while (off + 8 <= wav.length) {
    const id = String.fromCharCode(wav[off], wav[off + 1], wav[off + 2], wav[off + 3]);
    const sz = dv.getUint32(off + 4, true);
    if (id === 'C2PA') return { start: off, size: sz, body: wav.subarray(off + 8, off + 8 + sz) };
    off += 8 + sz + (sz & 1);
  }
  return null;
}
function rd32be(b, o) { return ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0; }
// Walk the JUMBF tree; collect { label -> {box, contentCbor} }.
function walkJumbf(body) {
  const boxes = {};
  function walk(b) {
    let o = 0;
    while (o + 8 <= b.length) {
      const sz = rd32be(b, o);
      const typ = String.fromCharCode(b[o + 4], b[o + 5], b[o + 6], b[o + 7]);
      if (sz < 8 || o + sz > b.length) break;
      if (typ === 'jumb') {
        const payload = b.subarray(o + 8, o + sz);
        const jsz = rd32be(payload, 0);
        const lblStart = 8 + 16 + 1; // jumd hdr + type uuid + toggles
        let e = lblStart; while (e < jsz && payload[e] !== 0) e++;
        const label = String.fromCharCode(...payload.subarray(lblStart, e));
        // find a cbor content box (first level under the jumd)
        let content = null, po = jsz;
        while (po + 8 <= payload.length) {
          const psz = rd32be(payload, po);
          const pt = String.fromCharCode(payload[po + 4], payload[po + 5], payload[po + 6], payload[po + 7]);
          if (psz < 8 || po + psz > payload.length) break;
          if (pt === 'cbor') content = payload.subarray(po + 8, po + psz);
          po += psz;
        }
        boxes[label] = { box: b.subarray(o, o + sz), content };
        walk(payload);
      }
      o += sz;
    }
  }
  walk(body);
  return boxes;
}

// ------------------------------------------------------------------- crypto helpers
async function sha256(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)); }
function eq(a, b) { if (a.length !== b.length) return false; for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false; return true; }
function concat(a, b) { const o = new Uint8Array(a.length + b.length); o.set(a, 0); o.set(b, a.length); return o; }
// Extract the 65-byte uncompressed EC point (04||x||y) from an X.509 P-256 cert
// DER: locate the SubjectPublicKeyInfo BIT STRING `03 42 00 04 <64>`.
function extractEcPoint(certDer) {
  for (let i = 0; i + 4 + 65 <= certDer.length; i++) {
    if (certDer[i] === 0x03 && certDer[i + 1] === 0x42 && certDer[i + 2] === 0x00 && certDer[i + 3] === 0x04) {
      return certDer.slice(i + 3, i + 3 + 65); // 04 || x || y
    }
  }
  return null;
}
// Re-encode canonical CBOR bstr/tstr/array head + payload for the Sig_structure.
function cborHead(major, n) {
  if (n < 24) return Uint8Array.of((major << 5) | n);
  if (n < 0x100) return Uint8Array.of((major << 5) | 24, n);
  if (n < 0x10000) return Uint8Array.of((major << 5) | 25, n >> 8, n & 255);
  return Uint8Array.of((major << 5) | 26, (n >>> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255);
}
function bstr(b) { return concat(cborHead(2, b.length), b); }
function tstr(s) { const b = new TextEncoder().encode(s); return concat(cborHead(3, b.length), b); }

// ------------------------------------------------------------------------ verify
export async function c2paVerifyWav(wavBytes) {
  const errors = [];
  const res = { valid: false, signatureValid: false, dataHashValid: false, assertionsValid: false, trusted: false, errors, manifest: null };
  try {
    const chunk = findC2paChunk(wavBytes);
    if (!chunk) { errors.push('no C2PA chunk in RIFF'); return res; }
    const boxes = walkJumbf(chunk.body);
    for (const need of ['c2pa.claim.v2', 'c2pa.signature', 'c2pa.hash.data', 'c2pa.actions.v2']) {
      if (!boxes[need]) { errors.push('missing JUMBF box: ' + need); return res; }
    }

    // --- decode claim + signature ---
    const claimBytes = boxes['c2pa.claim.v2'].content;
    const claim = cborDecode(claimBytes);
    const cget = (k) => (claim instanceof Map ? claim.get(k) : claim[k]);
    const cose = cborDecode(boxes['c2pa.signature'].content); // tag(18,[protected,unprotected,payload,sig])
    const coseArr = cose.__tag !== undefined ? cose.value : cose;
    const protectedBstr = coseArr[0];       // serialized protected header (bytes)
    const signature = coseArr[3];           // raw r||s (64)
    const protMap = cborDecode(protectedBstr);
    const certChain = protMap.get(33) || protMap.get('33');
    const certDer = Array.isArray(certChain) ? certChain[0] : certChain;
    if (!certDer) { errors.push('no certificate in COSE protected header'); return res; }

    // --- verify COSE_Sign1 ES256 ---
    const point = extractEcPoint(certDer);
    if (!point) { errors.push('could not extract EC public key from certificate'); return res; }
    const key = await crypto.subtle.importKey('raw', point, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    // Sig_structure = ["Signature1", protected, external_aad(empty), payload(claim)]
    const sigStructure = concat(cborHead(4, 4), concat(concat(tstr('Signature1'), bstr(protectedBstr)), concat(bstr(new Uint8Array(0)), bstr(claimBytes))));
    res.signatureValid = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, signature, sigStructure);
    if (!res.signatureValid) errors.push('COSE ES256 signature does not verify');

    // --- verify assertion hashedURIs (hash = sha256(box without 8-byte header)) ---
    const created = cget('created_assertions') || [];
    const gathered = cget('gathered_assertions') || [];
    let assertionsOk = true;
    for (const a of [...created, ...gathered]) {
      const url = a instanceof Map ? a.get('url') : a.url;
      const storedHash = a instanceof Map ? a.get('hash') : a.hash;
      const label = String(url).split('/').pop();
      const bx = boxes[label];
      if (!bx) { errors.push('assertion box not found: ' + label); assertionsOk = false; continue; }
      const h = await sha256(bx.box.subarray(8));
      if (!eq(h, storedHash)) { errors.push('assertion hash mismatch: ' + label); assertionsOk = false; }
    }
    res.assertionsValid = assertionsOk;

    // --- verify hard binding (data hash over file minus the C2PA chunk region) ---
    const hd = cborDecode(boxes['c2pa.hash.data'].content);
    const hget = (k) => (hd instanceof Map ? hd.get(k) : hd[k]);
    const excl = (hget('exclusions') || [])[0];
    const exStart = excl ? (excl instanceof Map ? excl.get('start') : excl.start) : chunk.start;
    const exLen = excl ? (excl instanceof Map ? excl.get('length') : excl.length) : (8 + chunk.size + (chunk.size & 1));
    const storedFileHash = hget('hash');
    const before = wavBytes.subarray(0, exStart);
    const after = wavBytes.subarray(exStart + exLen);
    const fileHash = await sha256(concat(before, after));
    res.dataHashValid = eq(fileHash, storedFileHash);
    if (!res.dataHashValid) errors.push('data hash (hard binding) mismatch');

    // --- surface manifest content ---
    const actionsCbor = cborDecode(boxes['c2pa.actions.v2'].content);
    const actions = (actionsCbor instanceof Map ? actionsCbor.get('actions') : actionsCbor.actions) || [];
    const gen = cget('claim_generator_info');
    res.manifest = {
      generatorName: gen ? (gen instanceof Map ? gen.get('name') : gen.name) : undefined,
      instanceID: cget('instanceID'),
      alg: cget('alg'),
      actions: actions.map((ac) => ({
        action: ac instanceof Map ? ac.get('action') : ac.action,
        digitalSourceType: ac instanceof Map ? ac.get('digitalSourceType') : ac.digitalSourceType,
        softwareAgent: ac instanceof Map ? ac.get('softwareAgent') : ac.softwareAgent,
      })),
    };

    res.valid = res.signatureValid && res.dataHashValid && res.assertionsValid;
    res.trusted = false; // self-signed: no trust-anchor evaluation here
    return res;
  } catch (e) {
    errors.push('verify exception: ' + (e && e.message ? e.message : String(e)));
    return res;
  }
}
