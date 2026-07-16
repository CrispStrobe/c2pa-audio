// c2pa.mjs — native JS C2PA signer for WAV (no c2pa-rs / no ~9 MB Rust wasm).
// Pure WebCrypto: ECDSA P-256 (ES256) + SHA-256; hand-built canonical CBOR,
// JUMBF box tree, COSE_Sign1, and RIFF chunk embedding. The output is a
// standard C2PA v2 manifest with a c2pa.actions.v2 (c2pa.created,
// trainedAlgorithmicMedia) assertion and a c2pa.hash.data hard binding — it
// validates against the c2pa-rs reference reader (only status:
// signingCredential.untrusted, expected for a self-signed cert).
//
// Runs anywhere WebCrypto exists: browsers, Node ≥16, Deno, Cloudflare
// Workers, and (crucially) the emscripten wasm build — replacing the c2pa-rs
// dependency there entirely.
const crypto = globalThis.crypto;
const te = new TextEncoder();

// ---- minimal canonical CBOR encoder (RFC 8949 deterministic) ----
function cborHead(major, n) {
  if (n < 24) return Uint8Array.of((major << 5) | n);
  if (n < 0x100) return Uint8Array.of((major << 5) | 24, n);
  if (n < 0x10000) return Uint8Array.of((major << 5) | 25, n >> 8, n & 255);
  // 32-bit
  return Uint8Array.of((major << 5) | 26, (n >>> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255);
}
function cat(arrs) {
  let len = 0; for (const a of arrs) len += a.length;
  const out = new Uint8Array(len); let o = 0; for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}
function cbor(v) {
  if (v === null) return Uint8Array.of(0xf6);
  if (typeof v === 'boolean') return Uint8Array.of(v ? 0xf5 : 0xf4);
  if (typeof v === 'number' && Number.isInteger(v)) {
    if (v >= 0) return cborHead(0, v);
    return cborHead(1, -v - 1);
  }
  if (typeof v === 'string') { const b = te.encode(v); return cat([cborHead(3, b.length), b]); }
  if (v instanceof Uint8Array) return cat([cborHead(2, v.length), v]);
  if (Array.isArray(v)) return cat([cborHead(4, v.length), ...v.map(cbor)]);
  if (v && v.__tag !== undefined) return cat([cborHead(6, v.__tag), cbor(v.value)]);
  if (v && typeof v === 'object') {
    // canonical: sort keys by encoded-key bytes (length then lexicographic)
    const entries = Object.entries(v).map(([k, val]) => [cbor(isNaN(+k) || k === '' ? k : (v.__intKeys ? +k : k)), cbor(val), k]);
    // (keys here are always strings for our maps except COSE header which uses intKey())
    entries.sort((a, b) => a[0].length - b[0].length || cmp(a[0], b[0]));
    return cat([cborHead(5, entries.length), ...entries.flatMap(e => [e[0], e[1]])]);
  }
  throw new Error('cbor: unsupported ' + typeof v);
}
function cmp(a, b) { const n = Math.min(a.length, b.length); for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i]; return a.length - b.length; }
// COSE protected header uses integer keys — encode directly
function coseProtected(certDer) {
  // { 1: -7 (ES256), 33: [certDer] }  (canonical: key 1 before key 33)
  return cat([cborHead(5, 2),
    cbor(1), cbor(-7),
    cbor(33), cat([cborHead(4, 1), cat([cborHead(2, certDer.length), certDer])])]);
}
function tag(t, value) { return { __tag: t, value }; }

// ---- JUMBF boxes ----
const UUID_SUFFIX = hexToBytes('00110010800000aa00389b71');
function boxType(ascii) { return cat([te.encode(ascii), UUID_SUFFIX]); } // 16-byte JUMBF type UUID
function u32be(n) { return Uint8Array.of((n >>> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255); }
function box(type4, payload) { const sz = 8 + payload.length; return cat([u32be(sz), te.encode(type4), payload]); }
// jumd description box: [16-byte type-uuid][toggles=0x03][label\0]
function jumd(typeUuid, label) {
  return box('jumd', cat([typeUuid, Uint8Array.of(0x03), te.encode(label), Uint8Array.of(0)]));
}
// a jumb superbox: jumd(desc) + content boxes
function jumb(typeAscii, label, contentBoxes) {
  return box('jumb', cat([jumd(boxType(typeAscii), label), ...contentBoxes]));
}
function cborBox(cborBytes) { return box('cbor', cborBytes); }

function hexToBytes(h) { const a = new Uint8Array(h.length / 2); for (let i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16); return a; }
function bytesToHex(b) { return [...b].map(x => x.toString(16).padStart(2, '0')).join(''); }
async function sha256(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)); }

// Parse PEM cert -> DER bytes; PEM EC private key -> CryptoKey (PKCS8).
function pemToDer(pem, kind) {
  const re = new RegExp(`-----BEGIN ${kind}-----([\\s\\S]*?)-----END ${kind}-----`);
  const m = pem.match(re); if (!m) throw new Error('no ' + kind + ' in PEM');
  return Uint8Array.from(atob(m[1].replace(/\s+/g, '')), c => c.charCodeAt(0));
}

// Sign PCM-derived WAV bytes (already a WAV container) with a C2PA manifest.
// certPem/keyPem: PEM strings. Returns signed WAV Uint8Array.
export async function c2paSignWav(wavBytes, certPem, keyPem, opts = {}) {
  const gen = opts.generator || { name: 'CrispASR', version: '0.6' };
  const manifestUrn = 'urn:c2pa:' + crypto.randomUUID();
  const instanceID = 'xmp:iid:' + crypto.randomUUID();

  // --- assertions ---
  const actionsCbor = cbor({ actions: [{ action: 'c2pa.created', softwareAgent: opts.softwareAgent || 'CrispASR TTS', digitalSourceType: 'http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia' }] });
  const actionsBox = jumb('cbor', 'c2pa.actions.v2', [cborBox(actionsCbor)]);
  // c2pa hashed-URI: hash of the assertion JUMBF box WITHOUT its 8-byte outer
  // header (i.e. over jumd + content boxes). Verified against c2pa-rs output.
  const assertionHash = (box) => sha256(box.subarray(8));
  const actionsHash = await assertionHash(actionsBox);

  // hash.data assertion: hash + exclusions filled after layout is known. Build
  // with a zero placeholder hash first (its box SIZE is fixed).
  const ZERO = new Uint8Array(32);
  function hashDataCbor(fileHash, exclStart, exclLen) {
    return cbor({ exclusions: [{ start: exclStart, length: exclLen }], name: 'jumbf manifest', alg: 'sha256', hash: fileHash, pad: new Uint8Array(8) });
  }
  // --- claim (sizes fixed; hashes/signature filled later, all same length) ---
  function buildClaim(hashDataAssnHash) {
    return cbor({
      instanceID,
      claim_generator_info: gen,
      signature: `self#jumbf=/c2pa/${manifestUrn}/c2pa.signature`,
      created_assertions: [{ url: 'self#jumbf=c2pa.assertions/c2pa.hash.data', hash: hashDataAssnHash }],
      gathered_assertions: [{ url: 'self#jumbf=c2pa.assertions/c2pa.actions.v2', hash: actionsHash }],
      alg: 'sha256',
    });
  }
  // --- COSE signature box (size fixed: 64-byte sig placeholder) ---
  const certDer = pemToDer(certPem, 'CERTIFICATE');
  const key = await crypto.subtle.importKey('pkcs8', pemToDer(keyPem, 'PRIVATE KEY'), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const protectedHdr = coseProtected(certDer);
  async function buildCoseBox(claimBytes) {
    const sigStructure = cbor(['Signature1', protectedHdr, new Uint8Array(0), claimBytes]);
    const sig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, sigStructure));
    const cose = tag(18, [protectedHdr, {}, null, sig]); // COSE_Sign1
    return jumb('c2cs', 'c2pa.signature', [cborBox(cbor(cose))]);
  }

  // --- Two-pass layout: assemble with placeholders to learn sizes/offsets ---
  async function assemble(fileHash, exclStart, exclLen, hashDataAssnHash) {
    const hashDataBox = jumb('cbor', 'c2pa.hash.data', [cborBox(hashDataCbor(fileHash, exclStart, exclLen))]);
    const assertionsBox = jumb('c2as', 'c2pa.assertions', [actionsBox, hashDataBox]);
    const claimBytes = buildClaim(hashDataAssnHash);
    const claimBox = jumb('c2cl', 'c2pa.claim.v2', [cborBox(claimBytes)]);
    const sigBox = await buildCoseBox(claimBytes);
    const manifestBox = jumb('c2ma', manifestUrn, [assertionsBox, claimBox, sigBox]);
    const store = jumb('c2pa', 'c2pa', [manifestBox]); // top c2pa superbox
    return { store, hashDataBox, claimBytes };
  }
  // Where does the C2PA chunk go? After all existing RIFF chunks (append).
  const chunkStart = wavBytes.length; // append at end
  const exclStart = chunkStart;
  // The chunk length (exclLen) is embedded INSIDE the hash.data exclusion, and
  // its CBOR integer width changes the store size — so iterate to a fixed point.
  let exclLen = 0;
  for (let i = 0; i < 6; i++) {
    const st = (await assemble(ZERO, exclStart, exclLen, ZERO)).store;
    const n = 8 + st.length + (st.length & 1); // RIFF 'C2PA' + size + pad
    if (n === exclLen) break;
    exclLen = n;
  }
  let a;
  // build final file layout with the chunk region present (zeros) so the file
  // hash is over everything EXCEPT [exclStart, exclLen].
  function withChunk(store) {
    const pad = (store.length & 1) ? Uint8Array.of(0) : new Uint8Array(0);
    const chunk = cat([te.encode('C2PA'), u32beLE(store.length), store, pad]);
    const out = cat([wavBytes.subarray(0, chunkStart), chunk]);
    // fix RIFF size (bytes 4..8) = total - 8
    new DataView(out.buffer).setUint32(4, out.length - 8, true);
    return out;
  }
  // compute file hash excluding the chunk region
  async function fileHashExcluding(fullFile) {
    const before = fullFile.subarray(0, exclStart);
    const after = fullFile.subarray(exclStart + exclLen);
    return await sha256(cat([before, after]));
  }
  // pass 2: real file hash
  let tmp = withChunk((await assemble(ZERO, exclStart, exclLen, ZERO)).store);
  const fileHash = await fileHashExcluding(tmp);
  // pass 3: hash.data box now has real hash -> its box hash -> claim created_assertions
  a = await assemble(fileHash, exclStart, exclLen, ZERO);
  const hashDataAssnHash = await assertionHash(a.hashDataBox);
  // pass 4: final assemble with real assertion hash (claim now final -> re-sign)
  a = await assemble(fileHash, exclStart, exclLen, hashDataAssnHash);
  return withChunk(a.store);
}
function u32beLE(n) { return Uint8Array.of(n & 255, (n >> 8) & 255, (n >> 16) & 255, (n >>> 24) & 255); } // little-endian for RIFF

// Internals exported for unit tests / advanced callers. Not part of the stable
// public API — use c2paSignWav().
export const _internal = { cbor, cborHead, coseProtected, boxType, jumb, jumd, cborBox, sha256, pemToDer, cat, hexToBytes, bytesToHex };
