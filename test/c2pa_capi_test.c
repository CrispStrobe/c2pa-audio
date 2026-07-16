/* c2pa_capi_test.c — smoke test for the C ABI: sign a WAV, verify it, verify a
 * c2pa-rs reference vector, and confirm tamper is rejected. Pure C, no deps. */
#include "c2pa_audio.h"

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
    printf("c2pa-audio version %s\n", c2pa_audio_version());

    /* sign with the bundled default cert */
    size_t wav_len = 0;
    unsigned char* wav = make_wav(&wav_len);
    unsigned char* signed_ = NULL;
    size_t signed_len = 0;
    int rc = c2pa_audio_sign(wav, wav_len, "audio/wav", NULL, NULL, &signed_, &signed_len);
    if (rc != 0 || signed_len <= wav_len) {
        printf("FAIL: sign rc=%d len=%zu\n", rc, signed_len);
        failures++;
    } else {
        printf("ok: signed %zu -> %zu bytes\n", wav_len, signed_len);
    }

    /* verify the round-trip */
    int flags = c2pa_audio_verify(signed_, signed_len);
    if (flags != (C2PA_AUDIO_SIG_VALID | C2PA_AUDIO_DATA_VALID | C2PA_AUDIO_ASSERT_VALID | C2PA_AUDIO_VALID)) {
        printf("FAIL: round-trip verify flags=0x%x\n", flags);
        failures++;
    } else {
        printf("ok: round-trip verify VALID (0x%x)\n", flags);
    }

    /* tamper the audio -> data hash must fail */
    signed_[46] ^= 0xff;
    flags = c2pa_audio_verify(signed_, signed_len);
    if (flags & C2PA_AUDIO_VALID) {
        printf("FAIL: tamper not detected (flags=0x%x)\n", flags);
        failures++;
    } else {
        printf("ok: tamper rejected (flags=0x%x)\n", flags);
    }
    signed_[46] ^= 0xff;

#ifdef C2PA_AUDIO_TEST_ASSETS
    {
        char path[1024];
        size_t rlen;

        /* verify c2pa-rs reference vectors (their signer -> our verifier) */
        const char* refs[4];
        refs[0] = "reference-c2pa-rs.wav";
        refs[1] = "reference-c2pa-rs.mp3";
        refs[2] = "reference-c2pa-rs.m4a";
        refs[3] = "reference-c2pa-rs.flac";
        for (int i = 0; i < 4; i++) {
            snprintf(path, sizeof(path), "%s/%s", C2PA_AUDIO_TEST_ASSETS, refs[i]);
            unsigned char* ref = read_file(path, &rlen);
            if (!ref) { printf("warn: reference vector missing (%s)\n", path); continue; }
            flags = c2pa_audio_verify(ref, rlen);
            if (!(flags & C2PA_AUDIO_VALID)) { printf("FAIL: %s did not validate (0x%x)\n", refs[i], flags); failures++; }
            else { printf("ok: %s VALID (0x%x)\n", refs[i], flags); }
            free(ref);
        }

        /* MP3 + M4A round-trips: sign an unsigned sample, then verify */
        struct { const char* file; const char* mime; } samples[3];
        samples[0].file = "sample.mp3"; samples[0].mime = "audio/mpeg";
        samples[1].file = "sample.m4a"; samples[1].mime = "audio/mp4";
        samples[2].file = "sample.flac"; samples[2].mime = "audio/flac";
        for (int i = 0; i < 3; i++) {
            snprintf(path, sizeof(path), "%s/%s", C2PA_AUDIO_TEST_ASSETS, samples[i].file);
            unsigned char* raw = read_file(path, &rlen);
            if (!raw) continue;
            unsigned char* sig = NULL;
            size_t slen = 0;
            int src = c2pa_audio_sign(raw, rlen, samples[i].mime, NULL, NULL, &sig, &slen);
            if (src != 0 || slen <= rlen) { printf("FAIL: %s sign rc=%d\n", samples[i].file, src); failures++; }
            else {
                int mf = c2pa_audio_verify(sig, slen);
                if (mf != 0xF) { printf("FAIL: %s round-trip verify 0x%x\n", samples[i].file, mf); failures++; }
                else { printf("ok: %s round-trip VALID (%zu -> %zu)\n", samples[i].file, rlen, slen); }
                c2pa_audio_free(sig);
            }
            free(raw);
        }
    }
#endif

    /* negative cases */
    {
        unsigned char* out = NULL;
        size_t olen = 0;
        /* unsupported mime -> nonzero, *out untouched */
        if (c2pa_audio_sign(wav, wav_len, "audio/ogg", NULL, NULL, &out, &olen) == 0 || out != NULL) {
            printf("FAIL: unsupported mime should error\n"); failures++;
        } else { printf("ok: unsupported mime rejected\n"); }
        /* empty input -> nonzero */
        unsigned char dummy = 0;
        if (c2pa_audio_sign(&dummy, 0, "audio/wav", NULL, NULL, &out, &olen) == 0) {
            printf("FAIL: empty input should error\n"); failures++; if (out) c2pa_audio_free(out);
        } else { printf("ok: empty input rejected\n"); }
        /* verify a non-C2PA WAV -> 0 flags */
        if (c2pa_audio_verify(wav, wav_len) != 0) { printf("FAIL: non-C2PA verify should be 0\n"); failures++; }
        else { printf("ok: non-C2PA input verifies as 0\n"); }
    }

    c2pa_audio_free(signed_);
    free(wav);
    printf(failures ? "FAILED (%d)\n" : "PASSED\n", failures);
    return failures ? 1 : 0;
}
