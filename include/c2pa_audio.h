/* c2pa_audio.h — C ABI for the standalone CrispASR C2PA signer/verifier.
 *
 * A tiny, dependency-light implementation of C2PA (Content Credentials) signing
 * and verification for WAV audio: canonical CBOR, JUMBF, COSE_Sign1, ES256
 * (ECDSA P-256 + SHA-256 via vendored micro-ecc). No c2pa-rs / Rust, no OpenSSL,
 * no models. Output validates in the c2pa-rs reference reader and vice-versa.
 *
 * Language bindings (Dart/FFI, C#/P-Invoke, Python/ctypes, Go/cgo, ...) load the
 * shared library and call these four functions.
 */
#ifndef C2PA_AUDIO_H
#define C2PA_AUDIO_H

#include <stddef.h>

#if defined(_WIN32)
#  define C2PA_AUDIO_API __declspec(dllexport)
#else
#  define C2PA_AUDIO_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Bit flags returned by c2pa_audio_verify_wav(). */
#define C2PA_AUDIO_SIG_VALID 0x1    /* COSE ES256 signature verified          */
#define C2PA_AUDIO_DATA_VALID 0x2   /* hard binding (audio) hash matches      */
#define C2PA_AUDIO_ASSERT_VALID 0x4 /* every assertion hashedURI matches      */
#define C2PA_AUDIO_VALID 0x8        /* all of the above                       */

/* Sign a WAV container with a C2PA manifest (c2pa.created,
 * trainedAlgorithmicMedia). cert_pem/key_pem are NUL-terminated PEM strings
 * (X.509 P-256 cert + PKCS#8 or SEC1 EC private key); pass NULL for BOTH to use
 * the bundled self-signed default cert. On success writes a malloc'd signed WAV
 * to *out (length *out_len) and returns 0. Returns non-zero on failure, leaving
 * *out = NULL. Free *out with c2pa_audio_free(). */
C2PA_AUDIO_API int c2pa_audio_sign_wav(const unsigned char* wav, size_t wav_len, const char* cert_pem,
                                             const char* key_pem, unsigned char** out, size_t* out_len);

/* Verify a signed WAV. Returns the C2PA_AUDIO_* bit flags (0 if there is no
 * manifest or it is malformed). A fully valid manifest returns
 * C2PA_AUDIO_SIG_VALID|DATA_VALID|ASSERT_VALID|VALID (0xF). Note: trust-anchor
 * evaluation is out of scope — a self-signed cert still verifies cryptographically. */
C2PA_AUDIO_API int c2pa_audio_verify_wav(const unsigned char* wav, size_t wav_len);

/* Free a buffer returned by c2pa_audio_sign_wav(). */
C2PA_AUDIO_API void c2pa_audio_free(unsigned char* p);

/* Library version, e.g. "0.1.0". */
C2PA_AUDIO_API const char* c2pa_audio_version(void);

#ifdef __cplusplus
}
#endif

#endif /* C2PA_AUDIO_H */
