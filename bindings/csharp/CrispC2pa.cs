// CrispC2pa.cs — C# P/Invoke binding for the standalone C2PA signer/verifier.
//
// Loads libcrispasr_c2pa (native shared library) and exposes Sign / Verify.
// No c2pa-rs. Place the native lib next to the assembly, or set the
// CRISPASR_C2PA_LIB env var / use a runtimeconfig nativeLibrary probe.
using System;
using System.Runtime.InteropServices;

namespace CrispAsr.C2pa
{
    /// <summary>Which C2PA checks passed.</summary>
    public readonly struct VerifyResult
    {
        public bool SignatureValid { get; }
        public bool DataHashValid { get; }
        public bool AssertionsValid { get; }
        public bool Valid { get; }
        internal VerifyResult(int f)
        {
            SignatureValid = (f & 0x1) != 0;
            DataHashValid = (f & 0x2) != 0;
            AssertionsValid = (f & 0x4) != 0;
            Valid = (f & 0x8) != 0;
        }
        public override string ToString() =>
            $"VerifyResult(Valid={Valid}, Sig={SignatureValid}, Data={DataHashValid}, Assertions={AssertionsValid})";
    }

    /// <summary>Native C2PA signer/verifier for WAV audio.</summary>
    public static class CrispC2pa
    {
        private const string Lib = "crispasr_c2pa"; // resolves to lib*.dylib/.so/.dll

        [DllImport(Lib, EntryPoint = "crispasr_c2pa_sign_wav", CallingConvention = CallingConvention.Cdecl)]
        private static extern int SignWavNative(byte[] wav, nuint wavLen, string? certPem, string? keyPem,
            out IntPtr outPtr, out nuint outLen);

        [DllImport(Lib, EntryPoint = "crispasr_c2pa_verify_wav", CallingConvention = CallingConvention.Cdecl)]
        private static extern int VerifyWavNative(byte[] wav, nuint wavLen);

        [DllImport(Lib, EntryPoint = "crispasr_c2pa_free", CallingConvention = CallingConvention.Cdecl)]
        private static extern void FreeNative(IntPtr p);

        [DllImport(Lib, EntryPoint = "crispasr_c2pa_version", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr VersionNative();

        public static string Version() => Marshal.PtrToStringAnsi(VersionNative()) ?? "";

        /// <summary>Sign a WAV with a C2PA manifest. Null cert/key => bundled default cert.</summary>
        public static byte[] Sign(byte[] wav, string? certPem = null, string? keyPem = null)
        {
            int rc = SignWavNative(wav, (nuint)wav.Length, certPem, keyPem, out IntPtr outPtr, out nuint outLen);
            if (rc != 0) throw new InvalidOperationException($"crispasr_c2pa_sign_wav failed (rc={rc})");
            try
            {
                var result = new byte[(int)outLen];
                Marshal.Copy(outPtr, result, 0, (int)outLen);
                return result;
            }
            finally { FreeNative(outPtr); }
        }

        /// <summary>Verify a signed WAV.</summary>
        public static VerifyResult Verify(byte[] wav) => new VerifyResult(VerifyWavNative(wav, (nuint)wav.Length));
    }
}
