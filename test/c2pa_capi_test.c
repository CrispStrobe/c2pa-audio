/* c2pa_capi_test.c — smoke test for the C ABI: sign a WAV, verify it, verify a
 * c2pa-rs reference vector, and confirm tamper is rejected. Pure C, no deps. */
#include "crispasr_c2pa.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char* make_wav(size_t* len) {
    int sr = 24000, n = 4800;
    size_t sz = 44 + (size_t)n * 2;
    unsigned char* w = (unsigned char*)malloc(sz);
    memcpy(w, "RIFF", 4);
    unsigned int riff = (unsigned int)(36 + n * 2);
    memcpy(w + 4, &riff, 4);
    memcpy(w + 8, "WAVE", 4);
    memcpy(w + 12, "fmt ", 4);
    unsigned int c16 = 16, sr_u = (unsigned int)sr, br = (unsigned int)(sr * 2), dn = (unsigned int)(n * 2);
    unsigned short one = 1, ch = 1, ba = 2, bps = 16;
    memcpy(w + 16, &c16, 4);
    memcpy(w + 20, &one, 2);
    memcpy(w + 22, &ch, 2);
    memcpy(w + 24, &sr_u, 4);
    memcpy(w + 28, &br, 4);
    memcpy(w + 32, &ba, 2);
    memcpy(w + 34, &bps, 2);
    memcpy(w + 36, "data", 4);
    memcpy(w + 40, &dn, 4);
    for (int i = 0; i < n; i++) {
        short s = (short)(3000.0 * sin(2.0 * 3.14159265358979 * 220.0 * i / sr));
        w[44 + i * 2] = (unsigned char)(s & 0xff);
        w[44 + i * 2 + 1] = (unsigned char)((s >> 8) & 0xff);
    }
    *len = sz;
    return w;
}

static unsigned char* read_file(const char* path, size_t* len) {
    FILE* f = fopen(path, "rb");
    if (!f)
        return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char* b = (unsigned char*)malloc((size_t)sz);
    if (fread(b, 1, (size_t)sz, f) != (size_t)sz) {
        fclose(f);
        free(b);
        return NULL;
    }
    fclose(f);
    *len = (size_t)sz;
    return b;
}

int main(void) {
    int failures = 0;
    printf("crispasr-c2pa version %s\n", crispasr_c2pa_version());

    /* sign with the bundled default cert */
    size_t wav_len = 0;
    unsigned char* wav = make_wav(&wav_len);
    unsigned char* signed_ = NULL;
    size_t signed_len = 0;
    int rc = crispasr_c2pa_sign_wav(wav, wav_len, NULL, NULL, &signed_, &signed_len);
    if (rc != 0 || signed_len <= wav_len) {
        printf("FAIL: sign rc=%d len=%zu\n", rc, signed_len);
        failures++;
    } else {
        printf("ok: signed %zu -> %zu bytes\n", wav_len, signed_len);
    }

    /* verify the round-trip */
    int flags = crispasr_c2pa_verify_wav(signed_, signed_len);
    if (flags != (CRISPASR_C2PA_SIG_VALID | CRISPASR_C2PA_DATA_VALID | CRISPASR_C2PA_ASSERT_VALID | CRISPASR_C2PA_VALID)) {
        printf("FAIL: round-trip verify flags=0x%x\n", flags);
        failures++;
    } else {
        printf("ok: round-trip verify VALID (0x%x)\n", flags);
    }

    /* tamper the audio -> data hash must fail */
    signed_[46] ^= 0xff;
    flags = crispasr_c2pa_verify_wav(signed_, signed_len);
    if (flags & CRISPASR_C2PA_VALID) {
        printf("FAIL: tamper not detected (flags=0x%x)\n", flags);
        failures++;
    } else {
        printf("ok: tamper rejected (flags=0x%x)\n", flags);
    }
    signed_[46] ^= 0xff;

    /* verify a c2pa-rs reference vector (their signer -> our verifier) */
#ifdef CRISPASR_C2PA_TEST_ASSETS
    {
        char path[1024];
        snprintf(path, sizeof(path), "%s/reference-c2pa-rs.wav", CRISPASR_C2PA_TEST_ASSETS);
        size_t rlen = 0;
        unsigned char* ref = read_file(path, &rlen);
        if (!ref) {
            printf("warn: reference vector missing (%s)\n", path);
        } else {
            flags = crispasr_c2pa_verify_wav(ref, rlen);
            if (!(flags & CRISPASR_C2PA_VALID)) {
                printf("FAIL: c2pa-rs reference vector did not validate (0x%x)\n", flags);
                failures++;
            } else {
                printf("ok: c2pa-rs reference vector VALID (0x%x)\n", flags);
            }
            free(ref);
        }
    }
#endif

    crispasr_c2pa_free(signed_);
    free(wav);
    printf(failures ? "FAILED (%d)\n" : "PASSED\n", failures);
    return failures ? 1 : 0;
}
