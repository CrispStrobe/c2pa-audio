## 0.1.0

- Initial release: FFI bindings for the native c2pa-audio library.
- Sign and verify C2PA Content Credentials in WAV and MP3 audio.
- `signWav` / `signMp3` / `sign(mime: ...)` and `verify` (auto-detects container).
- Interoperable with the c2pa-rs reference implementation.
