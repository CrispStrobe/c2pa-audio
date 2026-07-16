// c2pa_audio_native.cpp — implementation of c2pa_audio_native.h.
//
// Compiled at C++17. All C++14/17-only constructs (generic lambdas,
// multi-statement lambda return deduction, micro-ecc) live in this TU so the
// C++11 crispasr-lib headers that include c2pa_audio_native.h stay clean.
// See the header for the design overview.
#include "c2pa_native.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <random>

#include "sha256.h"

extern "C" {
#include "uECC.h"
}

namespace crispasr {
namespace c2pa_native {

// ------------------------------------------------------------------ utilities
inline void put(Bytes& b, std::initializer_list<uint8_t> v) {
    b.insert(b.end(), v);
}
inline void put(Bytes& b, const Bytes& v) {
    b.insert(b.end(), v.begin(), v.end());
}
inline void put(Bytes& b, const uint8_t* p, size_t n) {
    b.insert(b.end(), p, p + n);
}
inline void put_str(Bytes& b, const std::string& s) {
    b.insert(b.end(), s.begin(), s.end());
}

// ------------------------------------------------------------- canonical CBOR
namespace cbor {
inline Bytes head(uint8_t major, uint64_t n) {
    Bytes o;
    uint8_t m = uint8_t(major << 5);
    if (n < 24) {
        o = {uint8_t(m | n)};
    } else if (n < 0x100) {
        o = {uint8_t(m | 24), uint8_t(n)};
    } else if (n < 0x10000) {
        o = {uint8_t(m | 25), uint8_t(n >> 8), uint8_t(n)};
    } else if (n < 0x100000000ULL) {
        o = {uint8_t(m | 26), uint8_t(n >> 24), uint8_t(n >> 16), uint8_t(n >> 8), uint8_t(n)};
    } else {
        o = {uint8_t(m | 27),  uint8_t(n >> 56), uint8_t(n >> 48), uint8_t(n >> 40), uint8_t(n >> 32),
             uint8_t(n >> 24), uint8_t(n >> 16), uint8_t(n >> 8),  uint8_t(n)};
    }
    return o;
}
inline Bytes uint_(uint64_t n) {
    return head(0, n);
}
inline Bytes nint(int64_t n) {
    return head(1, uint64_t(-1 - n));
} // n < 0
inline Bytes tstr(const std::string& s) {
    Bytes o = head(3, s.size());
    put_str(o, s);
    return o;
}
inline Bytes bstr(const Bytes& v) {
    Bytes o = head(2, v.size());
    put(o, v);
    return o;
}
inline Bytes null_() {
    return {0xf6};
}
inline Bytes arr(const std::vector<Bytes>& items) {
    Bytes o = head(4, items.size());
    for (auto& it : items)
        put(o, it);
    return o;
}
inline Bytes tag(uint64_t t, const Bytes& v) {
    Bytes o = head(6, t);
    put(o, v);
    return o;
}
// map with pre-encoded (key, value) pairs, sorted canonically (length then bytes)
inline Bytes map_raw(std::vector<std::pair<Bytes, Bytes>> kv) {
    std::sort(kv.begin(), kv.end(), [](const auto& a, const auto& b) {
        if (a.first.size() != b.first.size())
            return a.first.size() < b.first.size();
        return std::lexicographical_compare(a.first.begin(), a.first.end(), b.first.begin(), b.first.end());
    });
    Bytes o = head(5, kv.size());
    for (auto& p : kv) {
        put(o, p.first);
        put(o, p.second);
    }
    return o;
}
// convenience: string-keyed map
inline Bytes map(std::vector<std::pair<std::string, Bytes>> kv) {
    std::vector<std::pair<Bytes, Bytes>> raw;
    for (auto& p : kv)
        raw.emplace_back(tstr(p.first), p.second);
    return map_raw(std::move(raw));
}
} // namespace cbor

// ------------------------------------------------------------------ JUMBF box
inline const uint8_t* uuid_suffix() {
    static const uint8_t s[12] = {0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71};
    return s;
}
inline Bytes box_type(const char ascii[5]) { // 4 ASCII chars + 12-byte suffix
    Bytes t;
    t.insert(t.end(), ascii, ascii + 4);
    put(t, uuid_suffix(), 12);
    return t;
}
inline void u32be(Bytes& b, uint32_t n) {
    put(b, {uint8_t(n >> 24), uint8_t(n >> 16), uint8_t(n >> 8), uint8_t(n)});
}
inline Bytes box(const char type4[5], const Bytes& payload) {
    Bytes o;
    u32be(o, uint32_t(8 + payload.size()));
    o.insert(o.end(), type4, type4 + 4);
    put(o, payload);
    return o;
}
// jumd description box: [16-byte type-uuid][toggles=0x03][label\0]
inline Bytes jumd(const Bytes& type_uuid, const std::string& label) {
    Bytes p;
    put(p, type_uuid);
    p.push_back(0x03);
    put_str(p, label);
    p.push_back(0x00);
    return box("jumd", p);
}
// jumb superbox: jumd(desc) + content boxes
inline Bytes jumb(const char type_ascii[5], const std::string& label, const std::vector<Bytes>& content) {
    Bytes p = jumd(box_type(type_ascii), label);
    for (auto& c : content)
        put(p, c);
    return box("jumb", p);
}
inline Bytes cbor_box(const Bytes& cbor_bytes) {
    return box("cbor", cbor_bytes);
}

// ---------------------------------------------------------------- PEM parsing
inline int b64val(char c) {
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    return -1;
}
inline Bytes b64decode(const std::string& s) {
    Bytes out;
    int buf = 0, bits = 0;
    for (char c : s) {
        if (c == '=' || c == '\n' || c == '\r' || c == ' ' || c == '\t')
            continue;
        int v = b64val(c);
        if (v < 0)
            continue;
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(uint8_t(buf >> bits));
        }
    }
    return out;
}
// extract the base64 body between BEGIN/END <kind> and return decoded DER
inline Bytes pem_to_der(const std::string& pem, const std::string& kind) {
    std::string begin = "-----BEGIN " + kind + "-----";
    std::string end = "-----END " + kind + "-----";
    auto b = pem.find(begin);
    if (b == std::string::npos)
        return {};
    b += begin.size();
    auto e = pem.find(end, b);
    if (e == std::string::npos)
        return {};
    return b64decode(pem.substr(b, e - b));
}
// Extract the 32-byte P-256 private scalar from a PKCS#8 or SEC1 EC key DER.
// Both contain the ECPrivateKey sequence: 02 01 01 (version=1) 04 20 <32 bytes>.
inline bool extract_p256_scalar(const Bytes& der, uint8_t out[32]) {
    static const uint8_t marker[5] = {0x02, 0x01, 0x01, 0x04, 0x20};
    for (size_t i = 0; i + 5 + 32 <= der.size(); i++) {
        if (std::memcmp(&der[i], marker, 5) == 0) {
            std::memcpy(out, &der[i + 5], 32);
            return true;
        }
    }
    return false;
}

// -------------------------------------------------------- ES256 (micro-ecc)
struct Sha256HashCtx {
    uECC_HashContext base;
    sha::Sha256 ctx;
};
inline Sha256HashCtx* hc_of(const uECC_HashContext* b) {
    return const_cast<Sha256HashCtx*>(reinterpret_cast<const Sha256HashCtx*>(b));
}
inline void hc_init(const uECC_HashContext* b) {
    hc_of(b)->ctx.init();
}
inline void hc_update(const uECC_HashContext* b, const uint8_t* m, unsigned n) {
    hc_of(b)->ctx.update(m, n);
}
inline void hc_finish(const uECC_HashContext* b, uint8_t* r) {
    hc_of(b)->ctx.final(r);
}

// Sign msg with ES256; returns raw r||s (64 bytes) — exactly COSE format.
inline bool es256_sign(const uint8_t priv[32], const Bytes& msg, uint8_t sig[64]) {
    auto digest = sha::sha256(msg);
    uint8_t tmp[2 * 32 + 64];
    Sha256HashCtx hc;
    hc.base.init_hash = &hc_init;
    hc.base.update_hash = &hc_update;
    hc.base.finish_hash = &hc_finish;
    hc.base.block_size = 64;
    hc.base.result_size = 32;
    hc.base.tmp = tmp;
    return uECC_sign_deterministic(priv, digest.data(), 32, &hc.base, sig, uECC_secp256r1()) == 1;
}

// ------------------------------------------------------------------ UUID v4
inline std::string uuid_v4() {
    std::random_device rd;
    uint8_t b[16];
    for (auto& x : b)
        x = uint8_t(rd());
    b[6] = uint8_t((b[6] & 0x0f) | 0x40); // version 4
    b[8] = uint8_t((b[8] & 0x3f) | 0x80); // variant
    static const char* hx = "0123456789abcdef";
    std::string s;
    for (int i = 0; i < 16; i++) {
        if (i == 4 || i == 6 || i == 8 || i == 10)
            s += '-';
        s += hx[b[i] >> 4];
        s += hx[b[i] & 0xf];
    }
    return s;
}

// ------------------------------------------------------- RIFF chunk locate
struct Chunk {
    size_t start;
    uint32_t size;
};
inline uint32_t rd_u32le(const uint8_t* p) {
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}

// ---------------------------------------------------------------- main entry
// Sign a WAV container with a C2PA manifest. certPem/keyPem: PEM strings.
// Returns the signed WAV, or an empty vector on any failure (caller keeps the
// unsigned WAV — still watermarked / metadata-tagged upstream).
Bytes sign_wav(const Bytes& wav, const std::string& cert_pem, const std::string& key_pem, const SignOptions& opts) {
    if (wav.size() < 12)
        return {};
    Bytes cert_der = pem_to_der(cert_pem, "CERTIFICATE");
    if (cert_der.empty())
        return {};
    uint8_t priv[32];
    {
        Bytes key_der = pem_to_der(key_pem, "PRIVATE KEY");
        if (key_der.empty())
            key_der = pem_to_der(key_pem, "EC PRIVATE KEY");
        if (key_der.empty() || !extract_p256_scalar(key_der, priv))
            return {};
    }

    const std::string manifest_urn = "urn:c2pa:" + uuid_v4();
    const std::string instance_id = "xmp:iid:" + uuid_v4();
    const std::array<uint8_t, 32> ZERO{};

    // --- static assertion: actions ---
    Bytes actions_cbor = cbor::map({
        {"actions", cbor::arr({cbor::map({
                        {"action", cbor::tstr("c2pa.created")},
                        {"softwareAgent", cbor::tstr(opts.software_agent)},
                        {"digitalSourceType",
                         cbor::tstr("http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia")},
                    })})},
    });
    Bytes actions_box = jumb("cbor", "c2pa.actions.v2", {cbor_box(actions_cbor)});
    // c2pa hashed-URI: hash of the assertion box WITHOUT its 8-byte outer header.
    auto assertion_hash = [](const Bytes& b) {
        auto h = sha::sha256(b.data() + 8, b.size() - 8);
        return Bytes(h.begin(), h.end());
    };
    Bytes actions_hash = assertion_hash(actions_box);

    // --- COSE protected header: {1:-7 (ES256), 33:[certDer]} (int keys) ---
    Bytes protected_hdr = cbor::map_raw({
        {cbor::uint_(1), cbor::nint(-7)},
        {cbor::uint_(33), cbor::arr({cbor::bstr(cert_der)})},
    });

    auto build_hashdata_cbor = [&](const std::array<uint8_t, 32>& file_hash, uint64_t excl_start, uint64_t excl_len) {
        return cbor::map({
            {"exclusions", cbor::arr({cbor::map({
                               {"start", cbor::uint_(excl_start)},
                               {"length", cbor::uint_(excl_len)},
                           })})},
            {"name", cbor::tstr("jumbf manifest")},
            {"alg", cbor::tstr("sha256")},
            {"hash", cbor::bstr(Bytes(file_hash.begin(), file_hash.end()))},
            {"pad", cbor::bstr(Bytes(8, 0))},
        });
    };
    auto build_claim = [&](const Bytes& hashdata_assn_hash) {
        return cbor::map({
            {"instanceID", cbor::tstr(instance_id)},
            {"claim_generator_info", cbor::map({
                                         {"name", cbor::tstr(opts.generator_name)},
                                         {"version", cbor::tstr(opts.generator_version)},
                                     })},
            {"signature", cbor::tstr("self#jumbf=/c2pa/" + manifest_urn + "/c2pa.signature")},
            {"created_assertions", cbor::arr({cbor::map({
                                       {"url", cbor::tstr("self#jumbf=c2pa.assertions/c2pa.hash.data")},
                                       {"hash", cbor::bstr(hashdata_assn_hash)},
                                   })})},
            {"gathered_assertions", cbor::arr({cbor::map({
                                        {"url", cbor::tstr("self#jumbf=c2pa.assertions/c2pa.actions.v2")},
                                        {"hash", cbor::bstr(actions_hash)},
                                    })})},
            {"alg", cbor::tstr("sha256")},
        });
    };

    struct Assembled {
        Bytes store, hash_data_box, claim_bytes;
    };
    auto build_cose_box = [&](const Bytes& claim_bytes) -> Bytes {
        Bytes sig_structure =
            cbor::arr({cbor::tstr("Signature1"), cbor::bstr(protected_hdr), cbor::bstr({}), cbor::bstr(claim_bytes)});
        uint8_t sig[64];
        if (!es256_sign(priv, sig_structure, sig))
            return {};
        Bytes cose = cbor::tag(
            18, cbor::arr({cbor::bstr(protected_hdr), cbor::map({}), cbor::null_(), cbor::bstr(Bytes(sig, sig + 64))}));
        return jumb("c2cs", "c2pa.signature", {cbor_box(cose)});
    };
    auto assemble = [&](const std::array<uint8_t, 32>& file_hash, uint64_t excl_start, uint64_t excl_len,
                        const Bytes& hashdata_assn_hash) -> Assembled {
        Bytes hash_data_box =
            jumb("cbor", "c2pa.hash.data", {cbor_box(build_hashdata_cbor(file_hash, excl_start, excl_len))});
        Bytes assertions_box = jumb("c2as", "c2pa.assertions", {actions_box, hash_data_box});
        Bytes claim_bytes = build_claim(hashdata_assn_hash);
        Bytes claim_box = jumb("c2cl", "c2pa.claim.v2", {cbor_box(claim_bytes)});
        Bytes sig_box = build_cose_box(claim_bytes);
        Bytes manifest_box = jumb("c2ma", manifest_urn, {assertions_box, claim_box, sig_box});
        Bytes store = jumb("c2pa", "c2pa", {manifest_box});
        return {std::move(store), std::move(hash_data_box), std::move(claim_bytes)};
    };

    const size_t chunk_start = wav.size(); // append at end
    const uint64_t excl_start = chunk_start;
    // The chunk length (excl_len) is embedded inside the hash.data exclusion; its
    // CBOR int width changes the store size, so iterate to a fixed point.
    uint64_t excl_len = 0;
    for (int i = 0; i < 6; i++) {
        Bytes st = assemble(ZERO, excl_start, excl_len, Bytes(ZERO.begin(), ZERO.end())).store;
        uint64_t n = 8 + st.size() + (st.size() & 1);
        if (n == excl_len)
            break;
        excl_len = n;
    }
    // build file with the chunk region present, compute file hash excluding it
    auto with_chunk = [&](const Bytes& store) {
        Bytes out(wav.begin(), wav.begin() + chunk_start);
        put_str(out, "C2PA");
        put(out, {uint8_t(store.size()), uint8_t(store.size() >> 8), uint8_t(store.size() >> 16),
                  uint8_t(store.size() >> 24)});
        put(out, store);
        if (store.size() & 1)
            out.push_back(0);
        uint32_t riff = uint32_t(out.size() - 8); // RIFF size = total - 8
        out[4] = uint8_t(riff);
        out[5] = uint8_t(riff >> 8);
        out[6] = uint8_t(riff >> 16);
        out[7] = uint8_t(riff >> 24);
        return out;
    };
    auto file_hash_excluding = [&](const Bytes& full) {
        Bytes h(full.begin(), full.begin() + excl_start);
        h.insert(h.end(), full.begin() + excl_start + excl_len, full.end());
        return sha::sha256(h);
    };

    Bytes tmp = with_chunk(assemble(ZERO, excl_start, excl_len, Bytes(ZERO.begin(), ZERO.end())).store);
    auto file_hash = file_hash_excluding(tmp);
    Assembled a3 = assemble(file_hash, excl_start, excl_len, Bytes(ZERO.begin(), ZERO.end()));
    Bytes hashdata_assn_hash = assertion_hash(a3.hash_data_box);
    Assembled a4 = assemble(file_hash, excl_start, excl_len, hashdata_assn_hash);
    if (a4.store.empty())
        return {};
    return with_chunk(a4.store);
}

// ============================================================================
// Verifier — the native twin of bindings/javascript/c2pa-verify.mjs.
// ============================================================================
namespace {

// ---- minimal CBOR decoder -> generic Value ----
struct Value {
    enum Type { UINT, NINT, BSTR, TSTR, ARRAY, MAP, TAG, BOOL, NUL } type = NUL;
    int64_t i = 0;                            // UINT / NINT / BOOL
    Bytes bytes;                              // BSTR
    std::string str;                          // TSTR
    std::vector<Value> arr;                   // ARRAY, or TAG(1 elem)
    std::vector<std::pair<Value, Value>> map; // MAP
    uint64_t tag = 0;                         // TAG

    const Value* get(const std::string& key) const { // map lookup by tstr key
        for (auto& kv : map)
            if (kv.first.type == TSTR && kv.first.str == key)
                return &kv.second;
        return nullptr;
    }
    const Value* get(int64_t key) const { // map lookup by integer key
        for (auto& kv : map)
            if ((kv.first.type == UINT || kv.first.type == NINT) && kv.first.i == key)
                return &kv.second;
        return nullptr;
    }
};

struct CborReader {
    const uint8_t* p;
    size_t n, pos = 0;
    bool ok = true;
    uint64_t readLen(uint8_t ai) {
        if (ai < 24)
            return ai;
        int nb = ai == 24 ? 1 : ai == 25 ? 2 : ai == 26 ? 4 : ai == 27 ? 8 : 0;
        if (!nb || pos + nb > n) {
            ok = false;
            return 0;
        }
        uint64_t v = 0;
        for (int k = 0; k < nb; k++)
            v = (v << 8) | p[pos++];
        return v;
    }
    Value value() {
        Value out;
        if (pos >= n) {
            ok = false;
            return out;
        }
        uint8_t ib = p[pos++];
        uint8_t major = ib >> 5, ai = ib & 0x1f;
        uint64_t len = readLen(ai);
        if (!ok)
            return out;
        switch (major) {
        case 0:
            out.type = Value::UINT;
            out.i = int64_t(len);
            break;
        case 1:
            out.type = Value::NINT;
            out.i = -1 - int64_t(len);
            break;
        case 2:
            if (pos + len > n) {
                ok = false;
                break;
            }
            out.type = Value::BSTR;
            out.bytes.assign(p + pos, p + pos + len);
            pos += len;
            break;
        case 3:
            if (pos + len > n) {
                ok = false;
                break;
            }
            out.type = Value::TSTR;
            out.str.assign(reinterpret_cast<const char*>(p + pos), len);
            pos += len;
            break;
        case 4:
            out.type = Value::ARRAY;
            for (uint64_t k = 0; k < len && ok; k++)
                out.arr.push_back(value());
            break;
        case 5:
            out.type = Value::MAP;
            for (uint64_t k = 0; k < len && ok; k++) {
                Value key = value();
                Value val = value();
                out.map.emplace_back(std::move(key), std::move(val));
            }
            break;
        case 6:
            out.type = Value::TAG;
            out.tag = len;
            out.arr.push_back(value());
            break;
        case 7:
            if (ai == 20) {
                out.type = Value::BOOL;
                out.i = 0;
            } else if (ai == 21) {
                out.type = Value::BOOL;
                out.i = 1;
            } else
                out.type = Value::NUL;
            break;
        default:
            ok = false;
        }
        return out;
    }
};
Value cbor_decode(const Bytes& b, bool& ok) {
    CborReader r{b.data(), b.size()};
    Value v = r.value();
    ok = r.ok;
    return v;
}

// ---- JUMBF walk: label -> {full box, cbor content} ----
struct JumbfBox {
    Bytes box;
    Bytes content;
    bool has_content = false;
};
uint32_t rd32be(const uint8_t* b) {
    return (uint32_t(b[0]) << 24) | (uint32_t(b[1]) << 16) | (uint32_t(b[2]) << 8) | b[3];
}
void jumbf_walk(const uint8_t* b, size_t len, std::vector<std::pair<std::string, JumbfBox>>& out) {
    size_t o = 0;
    while (o + 8 <= len) {
        uint32_t sz = rd32be(b + o);
        if (sz < 8 || o + sz > len)
            break;
        if (std::memcmp(b + o + 4, "jumb", 4) == 0) {
            const uint8_t* payload = b + o + 8;
            size_t plen = sz - 8;
            uint32_t jsz = rd32be(payload);
            size_t lblStart = 8 + 16 + 1;
            size_t e = lblStart;
            while (e < jsz && payload[e] != 0)
                e++;
            std::string label(reinterpret_cast<const char*>(payload + lblStart), e - lblStart);
            JumbfBox jb;
            jb.box.assign(b + o, b + o + sz);
            size_t po = jsz;
            while (po + 8 <= plen) {
                uint32_t psz = rd32be(payload + po);
                if (psz < 8 || po + psz > plen)
                    break;
                if (std::memcmp(payload + po + 4, "cbor", 4) == 0) {
                    jb.content.assign(payload + po + 8, payload + po + psz);
                    jb.has_content = true;
                }
                po += psz;
            }
            out.emplace_back(label, std::move(jb));
            jumbf_walk(payload, plen, out);
        }
        o += sz;
    }
}
const JumbfBox* find_box(const std::vector<std::pair<std::string, JumbfBox>>& boxes, const std::string& label) {
    for (auto& p : boxes)
        if (p.first == label)
            return &p.second;
    return nullptr;
}

// Extract the 64-byte EC public point (x||y, NO 0x04 prefix — uECC form) from an
// X.509 P-256 cert DER: locate the SPKI BIT STRING `03 42 00 04 <64>`.
bool extract_ec_point(const Bytes& der, uint8_t out[64]) {
    for (size_t i = 0; i + 4 + 65 <= der.size(); i++) {
        if (der[i] == 0x03 && der[i + 1] == 0x42 && der[i + 2] == 0x00 && der[i + 3] == 0x04) {
            std::memcpy(out, &der[i + 4], 64); // skip the 0x04 marker
            return true;
        }
    }
    return false;
}

} // namespace

VerifyResult verify_wav(const Bytes& wav) {
    VerifyResult res;
    auto& err = res.errors;

    // locate C2PA RIFF chunk
    if (wav.size() < 12) {
        err.push_back("input too small");
        return res;
    }
    size_t cstart = 0, csize = 0;
    bool found = false;
    for (size_t off = 12; off + 8 <= wav.size();) {
        uint32_t sz = uint32_t(wav[off + 4]) | (uint32_t(wav[off + 5]) << 8) | (uint32_t(wav[off + 6]) << 16) |
                      (uint32_t(wav[off + 7]) << 24);
        if (std::memcmp(&wav[off], "C2PA", 4) == 0) {
            cstart = off;
            csize = sz;
            found = true;
            break;
        }
        off += 8 + sz + (sz & 1);
    }
    if (!found) {
        err.push_back("no C2PA chunk in RIFF");
        return res;
    }

    std::vector<std::pair<std::string, JumbfBox>> boxes;
    jumbf_walk(&wav[cstart + 8], csize, boxes);
    const JumbfBox *claimBox = find_box(boxes, "c2pa.claim.v2"), *sigBox = find_box(boxes, "c2pa.signature"),
                   *hashBox = find_box(boxes, "c2pa.hash.data"), *actBox = find_box(boxes, "c2pa.actions.v2");
    if (!claimBox || !sigBox || !hashBox || !actBox) {
        err.push_back("missing required JUMBF box");
        return res;
    }

    bool ok = true;
    Value claim = cbor_decode(claimBox->content, ok);
    if (!ok) {
        err.push_back("claim CBOR decode failed");
        return res;
    }
    Value cose = cbor_decode(sigBox->content, ok);
    if (!ok) {
        err.push_back("signature CBOR decode failed");
        return res;
    }
    const Value& coseArr = (cose.type == Value::TAG && !cose.arr.empty()) ? cose.arr[0] : cose;
    if (coseArr.type != Value::ARRAY || coseArr.arr.size() < 4) {
        err.push_back("malformed COSE_Sign1");
        return res;
    }
    const Bytes& protectedBstr = coseArr.arr[0].bytes;
    const Bytes& signature = coseArr.arr[3].bytes;

    // cert from protected header {1:-7, 33:[cert]}
    Value prot = cbor_decode(protectedBstr, ok);
    const Value* chain = ok ? prot.get(int64_t(33)) : nullptr;
    const Bytes* certDer = nullptr;
    if (chain) {
        if (chain->type == Value::ARRAY && !chain->arr.empty())
            certDer = &chain->arr[0].bytes;
        else if (chain->type == Value::BSTR)
            certDer = &chain->bytes;
    }
    if (!certDer) {
        err.push_back("no certificate in COSE protected header");
        return res;
    }

    // verify COSE ES256 (uECC): message = Sig_structure, hash = sha256(message)
    uint8_t pub[64];
    if (!extract_ec_point(*certDer, pub)) {
        err.push_back("cannot extract EC public key from cert");
        return res;
    }
    // Sig_structure = ["Signature1", protected(bstr), external_aad(empty bstr), payload(claim bstr)]
    Bytes sigStruct;
    {
        put(sigStruct, cbor::head(4, 4));
        put(sigStruct, cbor::tstr("Signature1"));
        put(sigStruct, cbor::bstr(protectedBstr));
        put(sigStruct, cbor::bstr(Bytes{}));
        put(sigStruct, cbor::bstr(claimBox->content));
    }
    auto digest = sha::sha256(sigStruct);
    if (signature.size() == 64)
        res.signature_valid = uECC_verify(pub, digest.data(), 32, signature.data(), uECC_secp256r1()) == 1;
    if (!res.signature_valid)
        err.push_back("COSE ES256 signature does not verify");

    // assertion hashedURIs: hash = sha256(box without 8-byte header)
    res.assertions_valid = true;
    for (const char* grp : {"created_assertions", "gathered_assertions"}) {
        const Value* list = claim.get(std::string(grp));
        if (!list || list->type != Value::ARRAY)
            continue;
        for (const Value& a : list->arr) {
            const Value* url = a.get("url");
            const Value* h = a.get("hash");
            if (!url || !h)
                continue;
            std::string label = url->str.substr(url->str.find_last_of('/') + 1);
            const JumbfBox* bx = find_box(boxes, label);
            if (!bx) {
                err.push_back("assertion box not found: " + label);
                res.assertions_valid = false;
                continue;
            }
            auto actual = sha::sha256(bx->box.data() + 8, bx->box.size() - 8);
            if (h->bytes.size() != 32 || std::memcmp(actual.data(), h->bytes.data(), 32) != 0) {
                err.push_back("assertion hash mismatch: " + label);
                res.assertions_valid = false;
            }
        }
    }

    // hard binding: data hash over file minus the C2PA chunk exclusion
    Value hd = cbor_decode(hashBox->content, ok);
    const Value* excls = ok ? hd.get("exclusions") : nullptr;
    uint64_t exStart = cstart, exLen = 8 + csize + (csize & 1);
    if (excls && excls->type == Value::ARRAY && !excls->arr.empty()) {
        const Value* s = excls->arr[0].get("start");
        const Value* l = excls->arr[0].get("length");
        if (s)
            exStart = uint64_t(s->i);
        if (l)
            exLen = uint64_t(l->i);
    }
    const Value* storedHash = ok ? hd.get("hash") : nullptr;
    if (storedHash && exStart + exLen <= wav.size()) {
        Bytes concat(wav.begin(), wav.begin() + exStart);
        concat.insert(concat.end(), wav.begin() + exStart + exLen, wav.end());
        auto fh = sha::sha256(concat);
        res.data_hash_valid =
            storedHash->bytes.size() == 32 && std::memcmp(fh.data(), storedHash->bytes.data(), 32) == 0;
    }
    if (!res.data_hash_valid)
        err.push_back("data hash (hard binding) mismatch");

    // surface generator name
    const Value* gen = claim.get("claim_generator_info");
    if (gen) {
        const Value* name = gen->get("name");
        if (name)
            res.generator_name = name->str;
    }

    res.valid = res.signature_valid && res.data_hash_valid && res.assertions_valid;
    res.trusted = false;
    return res;
}

} // namespace c2pa_native
} // namespace crispasr
