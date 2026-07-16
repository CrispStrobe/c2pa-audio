"""crispasr_c2pa — Python ctypes binding for the standalone C2PA signer/verifier.

Loads libcrispasr_c2pa and exposes sign_wav / verify_wav. No c2pa-rs.

    from crispasr_c2pa import Crispc2pa
    c = Crispc2pa()                       # uses CRISPASR_C2PA_LIB or default name
    signed = c.sign_wav(wav_bytes)        # -> bytes (bundled default cert)
    r = c.verify_wav(signed)              # -> VerifyResult(valid=True, ...)
"""
import ctypes
import os
import platform
from dataclasses import dataclass

SIG_VALID, DATA_VALID, ASSERT_VALID, VALID = 0x1, 0x2, 0x4, 0x8


def _default_libname() -> str:
    s = platform.system()
    if s == "Darwin":
        return "libcrispasr_c2pa.dylib"
    if s == "Windows":
        return "crispasr_c2pa.dll"
    return "libcrispasr_c2pa.so"


@dataclass
class VerifyResult:
    signature_valid: bool
    data_hash_valid: bool
    assertions_valid: bool
    valid: bool


class Crispc2pa:
    def __init__(self, path: str | None = None):
        path = path or os.environ.get("CRISPASR_C2PA_LIB") or _default_libname()
        lib = ctypes.CDLL(path)
        self._lib = lib
        lib.crispasr_c2pa_sign_wav.restype = ctypes.c_int
        lib.crispasr_c2pa_sign_wav.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_char_p,
            ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)), ctypes.POINTER(ctypes.c_size_t),
        ]
        lib.crispasr_c2pa_verify_wav.restype = ctypes.c_int
        lib.crispasr_c2pa_verify_wav.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
        lib.crispasr_c2pa_free.restype = None
        lib.crispasr_c2pa_free.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
        lib.crispasr_c2pa_version.restype = ctypes.c_char_p

    @property
    def version(self) -> str:
        return self._lib.crispasr_c2pa_version().decode()

    def sign_wav(self, wav: bytes, cert_pem: str | None = None, key_pem: str | None = None) -> bytes:
        out = ctypes.POINTER(ctypes.c_ubyte)()
        out_len = ctypes.c_size_t(0)
        rc = self._lib.crispasr_c2pa_sign_wav(
            wav, len(wav),
            cert_pem.encode() if cert_pem else None,
            key_pem.encode() if key_pem else None,
            ctypes.byref(out), ctypes.byref(out_len),
        )
        if rc != 0:
            raise RuntimeError(f"crispasr_c2pa_sign_wav failed (rc={rc})")
        try:
            return bytes(ctypes.cast(out, ctypes.POINTER(ctypes.c_ubyte * out_len.value)).contents)
        finally:
            self._lib.crispasr_c2pa_free(out)

    def verify_wav(self, wav: bytes) -> VerifyResult:
        f = self._lib.crispasr_c2pa_verify_wav(wav, len(wav))
        return VerifyResult(bool(f & SIG_VALID), bool(f & DATA_VALID), bool(f & ASSERT_VALID), bool(f & VALID))
