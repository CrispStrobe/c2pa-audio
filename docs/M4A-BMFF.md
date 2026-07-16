# M4A / MP4 (ISO BMFF) C2PA support — investigation notes

Status: **not implemented.** Unlike WAV and MP3 (which use a byte-range
`c2pa.hash.data` hard binding), M4A/MP4 uses **`c2pa.hash.bmff.v3`** — a
different, canonical box-tree hashing algorithm. This is NOT a container swap.

## Container layout (from a c2pa-rs-signed reference)

Top-level ISO BMFF boxes in a signed M4A:

```
ftyp   (28)
uuid   (C2PA)   uuid = d8fec3d61b0e483c92975828877ec481
free   (8)
mdat   (audio)
moov   (815)
```

The C2PA `uuid` box sits right after `ftyp`. Its payload (after the 16-byte
uuid) is:

```
00 00 00 00                      reserved (4)
"manifest\0"                     purpose string (9)
00 00 00 00 00 00 00 00          merkle offset = 0 (8, "manifest" purpose)
<JUMBF manifest store>           the same store bytes as WAV/MP3
```

## The hard binding: c2pa.hash.bmff.v3 (the hard part)

The `c2pa.hash.bmff.v3` assertion uses **box-path exclusions**, not byte ranges:

```
exclusions:
  - xpath: /uuid   data: [{offset: 8, value: <C2PA uuid 16 bytes>}]  (exclude only the c2pa box)
  - xpath: /ftyp
  - xpath: /mfra
  - xpath: /free
  - xpath: /skip
```

The stored `hash` could NOT be reproduced by any simple byte-range approach
(tried: mdat+moov, ftyp+mdat+moov, all-but-uuid, mdat-only, moov-only,
ftyp+moov — none matched). So BmffHash v3 is a **canonical** algorithm that
walks the box map and processes boxes in a specific way (likely hashing box
headers/content per a defined procedure, with nested-exclusion handling), not
`sha256(file minus excluded byte ranges)`.

## To implement (a focused task)

1. Read the c2pa-rs `BmffHash` implementation (`sdk/src/asset_handlers/bmff_io.rs`
   + the bmff hash assertion) to get the exact box-map construction and the
   canonical hashing procedure for v3.
2. Also handle: writing the `uuid` box with the `manifest` prefix at the right
   position (after ftyp), and rewriting `moov` chunk offsets (stco/co64) since
   inserting the uuid box shifts `mdat`.
3. Validate against `ref.m4a` (their signer → our verifier) AND our output in
   the c2pa-rs reader (our signer → their verifier), like WAV/MP3.
4. Cover fragmented MP4 (Merkle) only if needed.

Until then, M4A signing should use c2pa-rs (CrispASR links it optionally).
