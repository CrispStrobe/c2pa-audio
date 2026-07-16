// c2pa_audio.dart — Dart FFI binding for the standalone C2PA signer/verifier.
//
// Loads libc2pa_audio (shared library) and exposes signWav / verifyWav.
// Pure dart:ffi + package:ffi. Works on Dart VM and Flutter (desktop/mobile).
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

// ---- C signatures ----
typedef _SignNative = Int32 Function(Pointer<Uint8> wav, IntPtr wavLen, Pointer<Utf8> cert, Pointer<Utf8> key,
    Pointer<Pointer<Uint8>> out, Pointer<IntPtr> outLen);
typedef _SignDart = int Function(Pointer<Uint8> wav, int wavLen, Pointer<Utf8> cert, Pointer<Utf8> key,
    Pointer<Pointer<Uint8>> out, Pointer<IntPtr> outLen);
typedef _VerifyNative = Int32 Function(Pointer<Uint8> wav, IntPtr wavLen);
typedef _VerifyDart = int Function(Pointer<Uint8> wav, int wavLen);
typedef _FreeNative = Void Function(Pointer<Uint8> p);
typedef _FreeDart = void Function(Pointer<Uint8> p);
typedef _VersionNative = Pointer<Utf8> Function();
typedef _VersionDart = Pointer<Utf8> Function();

/// Result of [C2paAudio.verifyWav].
class VerifyResult {
  final bool signatureValid;
  final bool dataHashValid;
  final bool assertionsValid;
  final bool valid;
  const VerifyResult(this.signatureValid, this.dataHashValid, this.assertionsValid, this.valid);
  @override
  String toString() =>
      'VerifyResult(valid: $valid, sig: $signatureValid, data: $dataHashValid, assertions: $assertionsValid)';
}

/// Native C2PA signer/verifier for WAV — no c2pa-rs.
class C2paAudio {
  final DynamicLibrary _lib;
  late final _SignDart _sign = _lib.lookupFunction<_SignNative, _SignDart>('c2pa_audio_sign_wav');
  late final _VerifyDart _verify = _lib.lookupFunction<_VerifyNative, _VerifyDart>('c2pa_audio_verify_wav');
  late final _FreeDart _free = _lib.lookupFunction<_FreeNative, _FreeDart>('c2pa_audio_free');
  late final _VersionDart _version = _lib.lookupFunction<_VersionNative, _VersionDart>('c2pa_audio_version');

  C2paAudio(this._lib);

  /// Open the shared library. Pass an explicit [path], else use C2PA_AUDIO_LIB
  /// env var, else the platform default (libc2pa_audio.{dylib,so,dll}).
  factory C2paAudio.open([String? path]) {
    path ??= Platform.environment['C2PA_AUDIO_LIB'];
    if (path == null) {
      if (Platform.isMacOS) path = 'libc2pa_audio.dylib';
      else if (Platform.isWindows) path = 'c2pa_audio.dll';
      else path = 'libc2pa_audio.so';
    }
    return C2paAudio(DynamicLibrary.open(path));
  }

  String get version => _version().toDartString();

  /// Sign [wav] with a C2PA manifest. Pass PEM strings for a custom identity,
  /// or leave null to use the bundled self-signed default cert. Returns the
  /// signed WAV, or throws [StateError] on failure.
  Uint8List signWav(Uint8List wav, {String? certPem, String? keyPem}) {
    final wavPtr = malloc<Uint8>(wav.length);
    wavPtr.asTypedList(wav.length).setAll(0, wav);
    final certPtr = certPem == null ? nullptr : certPem.toNativeUtf8();
    final keyPtr = keyPem == null ? nullptr : keyPem.toNativeUtf8();
    final outPtr = malloc<Pointer<Uint8>>();
    final outLenPtr = malloc<IntPtr>();
    try {
      final rc = _sign(wavPtr, wav.length, certPtr.cast(), keyPtr.cast(), outPtr, outLenPtr);
      if (rc != 0) throw StateError('c2pa_audio_sign_wav failed (rc=$rc)');
      final len = outLenPtr.value;
      final out = Uint8List.fromList(outPtr.value.asTypedList(len));
      _free(outPtr.value);
      return out;
    } finally {
      malloc.free(wavPtr);
      if (certPtr != nullptr) malloc.free(certPtr);
      if (keyPtr != nullptr) malloc.free(keyPtr);
      malloc.free(outPtr);
      malloc.free(outLenPtr);
    }
  }

  /// Verify a signed [wav]. Never throws; a WAV with no/invalid manifest returns
  /// all-false.
  VerifyResult verifyWav(Uint8List wav) {
    final wavPtr = malloc<Uint8>(wav.length);
    wavPtr.asTypedList(wav.length).setAll(0, wav);
    try {
      final f = _verify(wavPtr, wav.length);
      return VerifyResult((f & 0x1) != 0, (f & 0x2) != 0, (f & 0x4) != 0, (f & 0x8) != 0);
    } finally {
      malloc.free(wavPtr);
    }
  }
}
