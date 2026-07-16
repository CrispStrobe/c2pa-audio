// capi.cpp — C ABI implementation, wrapping the C++ signer/verifier.
#include "crispasr_c2pa.h"

#include <cstdlib>
#include <cstring>
#include <string>

#include "c2pa_native.h"
#include "default_cert.h"

using crispasr::c2pa_native::Bytes;
using crispasr::c2pa_native::sign_wav;
using crispasr::c2pa_native::verify_wav;
using crispasr::c2pa_native::VerifyResult;

extern "C" int crispasr_c2pa_sign_wav(const unsigned char* wav, size_t wav_len, const char* cert_pem,
                                      const char* key_pem, unsigned char** out, size_t* out_len) {
    if (!wav || !out || !out_len)
        return 1;
    *out = nullptr;
    *out_len = 0;
    std::string cert = cert_pem ? std::string(cert_pem) : std::string(crispasr_c2pa_default_cert_pem());
    std::string key = key_pem ? std::string(key_pem) : std::string(crispasr_c2pa_default_key_pem());
    Bytes in(wav, wav + wav_len);
    Bytes signed_ = sign_wav(in, cert, key);
    if (signed_.empty())
        return 2;
    unsigned char* buf = static_cast<unsigned char*>(std::malloc(signed_.size()));
    if (!buf)
        return 3;
    std::memcpy(buf, signed_.data(), signed_.size());
    *out = buf;
    *out_len = signed_.size();
    return 0;
}

extern "C" int crispasr_c2pa_verify_wav(const unsigned char* wav, size_t wav_len) {
    if (!wav)
        return 0;
    Bytes in(wav, wav + wav_len);
    VerifyResult r = verify_wav(in);
    int flags = 0;
    if (r.signature_valid)
        flags |= CRISPASR_C2PA_SIG_VALID;
    if (r.data_hash_valid)
        flags |= CRISPASR_C2PA_DATA_VALID;
    if (r.assertions_valid)
        flags |= CRISPASR_C2PA_ASSERT_VALID;
    if (r.valid)
        flags |= CRISPASR_C2PA_VALID;
    return flags;
}

extern "C" void crispasr_c2pa_free(unsigned char* p) { std::free(p); }

extern "C" const char* crispasr_c2pa_version(void) { return "0.1.0"; }
