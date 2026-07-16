// Dart FFI binding tests. Set CRISPASR_C2PA_LIB to the built shared library:
//   dart test  (with CRISPASR_C2PA_LIB=/path/to/libcrispasr_c2pa.dylib)
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:crispasr_c2pa/crispasr_c2pa.dart';
import 'package:test/test.dart';

Uint8List makeWav({int n = 4800, int sr = 24000}) {
  final b = BytesBuilder();
  void u32(int v) => b.add([v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >> 24) & 0xff]);
  void u16(int v) => b.add([v & 0xff, (v >> 8) & 0xff]);
  b.add('RIFF'.codeUnits); u32(36 + n * 2); b.add('WAVE'.codeUnits);
  b.add('fmt '.codeUnits); u32(16); u16(1); u16(1); u32(sr); u32(sr * 2); u16(2); u16(16);
  b.add('data'.codeUnits); u32(n * 2);
  for (var i = 0; i < n; i++) {
    final s = (3000 * sin(2 * pi * 220 * i / sr)).round();
    u16(s & 0xffff);
  }
  return b.toBytes();
}

void main() {
  final libEnv = Platform.environment['CRISPASR_C2PA_LIB'];
  final c2pa = Crispc2pa.open();

  test('version', () {
    expect(c2pa.version, isNotEmpty);
  });

  test('sign -> verify round-trip is valid', () {
    final signed = c2pa.signWav(makeWav());
    expect(signed.length, greaterThan(makeWav().length));
    final r = c2pa.verifyWav(signed);
    expect(r.valid, isTrue, reason: r.toString());
    expect(r.signatureValid, isTrue);
    expect(r.dataHashValid, isTrue);
    expect(r.assertionsValid, isTrue);
  });

  test('tampering the audio fails verification', () {
    final signed = c2pa.signWav(makeWav());
    signed[46] ^= 0xff;
    final r = c2pa.verifyWav(signed);
    expect(r.valid, isFalse);
    expect(r.dataHashValid, isFalse);
  });

  test('non-C2PA WAV is not valid', () {
    final r = c2pa.verifyWav(makeWav());
    expect(r.valid, isFalse);
  });

  test('c2pa-rs reference vector validates (their signer -> our verifier)', () {
    // fixture lives at repo test/assets; skip if not found from CWD
    final candidates = [
      'test/assets/reference-c2pa-rs.wav',
      '../../test/assets/reference-c2pa-rs.wav',
      if (libEnv != null) '${File(libEnv).parent.parent.path}/test/assets/reference-c2pa-rs.wav',
    ];
    final path = candidates.firstWhere((p) => File(p).existsSync(), orElse: () => '');
    if (path.isEmpty) return; // fixture optional
    final r = c2pa.verifyWav(File(path).readAsBytesSync());
    expect(r.valid, isTrue, reason: r.toString());
  });
}
