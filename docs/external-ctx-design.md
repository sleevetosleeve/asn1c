# Proposal: external decode context (`-fno-ctx-members`)

Status: design implemented, 2026-11-26 (issue #15); all phases landed:
Phase 0 (BER/CER, shared machinery: `-fno-ctx-members`, the arena, dual-path
fetches, sentinel-aware guards/free paths, tests) plus Phases 1-4, which add
the remaining per-codec `_ctx` entry points (`xer_decode_ctx`,
`jer_decode_ctx`, `oer_decode_ctx`, `uper_decode_ctx`, `aper_decode_ctx`,
`cbor_decode_ctx`) on top of the existing `ber_decode_ctx` / `asn_decode_ctx`.
A local prototype validated the mechanism earlier (see "Experiment
evidence"). Responsible party: asn1c maintainers (fork).

## Motivation

Every constructed generated type embeds a mutable parser-state member:

```c
typedef struct NetMsg {
    long id;
    struct body {
        body_PR present;
        union NetMsg__body_u { /* ... */ } choice;
        asn_struct_ctx_t _asn_ctx;   /* "Context for parsing across buffer boundaries" */
    } body;
    asn_struct_ctx_t _asn_ctx;
} NetMsg_t;
```

`asn_struct_ctx_t` is 24 bytes on LP64, so this costs 24 bytes per
constructed struct instance (the example above: 2 in `NetMsg_t` plus 1 inside
each by-value choice member; measured `sizeof(NetMsg_t)` = 104 vs 32 without
the members). Beyond size, the embedded member makes generated structs
non-plain data: they cannot be blindly `memcpy`'d, memset, serialized, or
placed in bulk arrays (`SEQUENCE OF`) without dragging parser scratch along,
and the hidden mutable state is a thread-safety footgun.

The Rust backend of this fork already uses the target model: generated Rust
values are plain data (fields and `Option<T>` only; see
`docs/rust/code-generation.md`), decoders take an input slice plus caller-owned
budgets (`Limits`) and return `Decoded<T> { value, consumed_bits,
consumed_bytes }` (`rust/asn1c-runtime/src/lib.rs`), and the per-record parse
state (`RecordContext`, `SequenceReader` in `rust/asn1c-runtime/src/ber.rs`)
lives in decoder-owned cursor objects, not in the value. This proposal brings
the C backend to the same model: keep the value clean, move the "notebook"
out of the struct into a caller-owned external context passed at the call site:

```c
asn_struct_external_ctx_t ext = {0};   /* caller-owned, reused across RC_WMORE */
asn_dec_rval_t dr = ber_decode_ctx(0, &asn_DEF_NetMsg, (void **)&msg, &ext,
                                  pkt->data, pkt->dataLength);
```

## Background: how `_asn_ctx` is wired today

- Type: `asn_struct_ctx_t { short phase; short step; int context; void *ptr;
  ber_tlv_len_t left; }` (`skeletons/constr_TYPE.h:30`).
- Emission: one macro `PCTX_DEF` (`libasn1compiler/asn1c_C.c:119`) used at 5
  emission points, plus 6 `offsetof(T, _asn_ctx)` descriptor sites
  (`asn1c_C.c:470,738,899,1272,1710,2181`).
- Runtime coupling is offset-based, not name-based: the specifics structs
  (`asn_SEQUENCE_specifics_t`, `asn_SET_specifics_t`, `asn_CHOICE_specifics_t`,
  `asn_SET_OF_specifics_t`) carry `ctx_offset`, and decoders fetch the context
  with `ctx = (asn_struct_ctx_t *)((char *)st + specs->ctx_offset)` — 21 fetch
  sites across 37 skeleton files (86 `ctx_offset` references), spanning
  BER/CER, XER, JER, OER, UPER/APER, CBOR paths.
- Two free routines also touch it: `FREEMEM(ctx->ptr)` in
  `skeletons/constr_SEQUENCE.c` and `skeletons/constr_SET.c` (decoder scratch,
  e.g. open-type stacks).
- Fixed skeleton structs embed the member directly: `BIT_STRING.h:20`,
  `OCTET_STRING.h:18`.
- Several codecs guard with `sizeof(asn_struct_ctx_t) > struct_size -
  ctx_offset` (e.g. `constr_SEQUENCE_jer.c:128`, `ANY.c:202`,
  `constr_SET_uper.c:91`, `cer_encoder.c:2733`).
- Two facts make externalizing tractable: `ber_check_tags()` already takes
  `opt_ctx` explicitly (`ber_decoder.h:58`), and `asn_codec_ctx_t` is already
  threaded through every decoder call; `ber_decode()` already copies it onto
  the stack (`ber_decoder.c:40-56`).

## Experiment evidence (sandbox prototype, 2026-11-26, not committed)

The compiler was built from a clean `git archive` export with a pinned
conda-forge toolchain (autoconf 2.71, automake 1.16.5, bison 3.8.2, flex 2.6.4);
`tests/tests-asn1c-compiler` passed 14/14. For a NetMsg-like schema
(SEQUENCE { id INTEGER, body CHOICE { three SEQUENCE alternatives } }):

- Real generated code, embedded ctx: `sizeof(NetMsg_t)` = 104; full-buffer,
  1-byte-chunked and 3-byte-chunked `ber_decode` all pass.
- Prototype with external ctx (members removed from generated structs,
  `ctx_offset` set to sentinel `(unsigned)-1`, arena carried in a
  `asn_codec_ctx_t` field, entry point `ber_decode_ext(..., &arena, ...)`,
  only `constr_SEQUENCE_ber.c` / `constr_CHOICE_ber.c` / `constr_SEQUENCE.c`
  patched): `sizeof(NetMsg_t)` = 32; identical decodes all pass; AddressSanitizer
  reports no memory errors; the arena held 3 frames (NetMsg, inner CHOICE,
  chosen alternative), one per nested struct instance.
- Reset semantics match the embedded model: re-decoding into the same struct
  requires resetting the state (arena reset externally vs `ASN_STRUCT_RESET`
  embedded); forgetting it behaves the same in both designs.

## Proposal

### 1. Codegen flag: `-fno-ctx-members`

With the flag, the compiler omits the `PCTX_DEF` member from generated
constructed structs and emits the sentinel `ctx_offset = (unsigned)-1` in the
specifics; `struct_size` shrinks automatically. Without the flag, output is
byte-identical to today (upstream-compatible default).

Scope note: `BIT_STRING_t` and `OCTET_STRING_t` are fixed skeleton structs and
keep their embedded member; the dual-path decoders below make the mixed mode
work (arena path is valid for any struct). The flag is documented as
affecting generated types only.

### 2. External context type — one definition, shared by all types

Defined in `skeletons/constr_TYPE.h` next to `asn_struct_ctx_t`:

- `asn_struct_ctx_frame_t { void *st; asn_struct_ctx_t ctx; }` — one frame per
  struct instance currently being parsed; keyed by the instance address.
- `asn_struct_external_ctx_t` — the arena, one per top-level decode operation:
  an inline array of 8 frames (`ASN_EXT_CTX_INLINE_FRAMES = 8`) plus an
  optional heap overflow, so the common case needs no allocation.
- Helpers (type-agnostic, no vtable change):
  `asn_ext_ctx_get(arena, st)` (find-or-create a zeroed frame),
  `asn_struct_external_ctx_reset(arena)` (free every frame's `ctx->ptr`
  scratch, free the heap overflow, zero the arena),
  `asn_get_struct_ctx(opt_codec_ctx, st, ctx_offset)` (dual-path fetch used by
  all decoder sites), and `asn_ctx_offset_valid(struct_size, ctx_offset)`
  (sentinel-aware layout guard).
- Carried inside `asn_codec_ctx_t` as a `void *ext_struct_ctx` field (a `void *`
  avoids header cycles); set by the `*_decode_ctx` entry points on their stack
  copy of the codec context, so it reaches every nested decoder through the
  existing parameter.

### 3. Entry points: siblings, not signature changes

Per codec: `ber_decode_ctx`, `xer_decode_ctx`, `jer_decode_ctx`,
`oer_decode_ctx`, `uper_decode_ctx`, `aper_decode_ctx`, `cbor_decode_ctx`, plus
an `asn_decode_ctx` dispatcher, with signature

```c
asn_dec_rval_t ber_decode_ctx(const asn_codec_ctx_t *opt_codec_ctx,
    const asn_TYPE_descriptor_t *td, void **struct_ptr,
    asn_struct_external_ctx_t *ext_ctx, const void *buffer, size_t size);
```

Caller contract: `asn_struct_external_ctx_t ext = {0};` once, pass `&ext` on
every call, reuse it unchanged across `RC_WMORE` resumes (frames must survive
between calls — that is the point of externalizing), and call
`asn_struct_external_ctx_reset(&ext)` before a fresh decode into the same
structs. Encoders are untouched (they never use ctx).

Compatibility contract: plain `ber_decode()` & co. cannot resume
`-fno-ctx-members` output (a temporary arena would die on `RC_WMORE`), so
constructed types decoded through them fail with `RC_FAIL`. This is
documented; the flag and the `_ctx` entry points are used together.
Refined after Phases 1-4: the `RC_FAIL` contract holds for the resumable
codecs (BER/CER, XER, JER, OER), whose decoders fetch the context at decode
time. UPER/APER/CBOR decoders never fetch the embedded context at decode
time (PER is single-shot by design; the CBOR/PER `ctx_offset` uses are
layout guards only), so their plain entry points keep decoding
`-fno-ctx-members` output successfully; the `_ctx` variants exist for API
symmetry and pass the arena through `asn_codec_ctx_t` unchanged.

### 4. Decoder and runtime changes

- The 21 `st + specs->ctx_offset` fetch sites become dual-path:
  `ctx = arena ? asn_ext_ctx_get(arena, st) : (asn_struct_ctx_t *)((char *)st + specs->ctx_offset)`,
  failing cleanly when the sentinel is set but no arena is present.
- Free routines (`constr_SEQUENCE.c`, `constr_SET.c`) skip the embedded
  `FREEMEM(ctx->ptr)` when the sentinel is set; scratch is released through
  `asn_ext_ctx_release_frame` instead.
- The `sizeof(asn_struct_ctx_t) > struct_size - ctx_offset` guards are skipped
  when the sentinel is set (the arena provides the room).
- New macros `ASN_STRUCT_RESET_CTX(asn_DEF, ptr, ext)` and
  `ASN_STRUCT_FREE_CTX(asn_DEF, ptr, ext)`: existing `free_struct` (sentinel
  aware) plus `asn_struct_external_ctx_reset(ext)`. **Decision: no new field
  in `asn_TYPE_operation_s` and no `free_struct_ctx` method** — all scratch
  is generic `ctx->ptr`, so type-agnostic helpers suffice. Resetting the whole
  arena (not one frame) is what makes re-decoding into the same struct work,
  matching the embedded model where `ASN_STRUCT_RESET` zeroes nested ctxs too.
- Partial decoding: the arena's lifetime is caller-controlled; with
  `preserve_partial_decoding` the frames stay alive after `RC_FAIL` until the
  caller resets, so partially decoded structures remain inspectable.
- Thread safety: one arena per decode operation; never shared across threads
  (same rule as the stack-allocated `asn_codec_ctx_t` requirement).

## Rollout plan

1. Phase 0 — BER/CER (shared machinery), arena + helpers + `ber_decode_ctx`,
   regression harness.
2. Phase 1 — XER, JER. Phase 2 — OER. Phase 3 — UPER/APER (SET/SET-OF sites).
   Phase 4 — CBOR.
3. `converter-example.c` / PDU-collection helpers stay on the plain entry
   points until **all** codecs have `_ctx` versions — deliberately deferred to
   avoid tracking partial onboarding (decision recorded 2026-11-26).

Each phase lands with tests in `tests/tests-c-compiler`, expected-output tests
in `tests/tests-asn1c-compiler` for `-fno-ctx-members` (`-P` output contains
no `_asn_ctx` member and the sentinel offset), and both generation modes must
pass the existing suites.

## Testing

- Chunked-decode driver per type: encode once, then decode full-buffer,
  1-byte chunks and 3-byte chunks, using the accumulate/feed/consume pattern
  (append chunk to a pending buffer, decode, `memmove` away `dr.consumed`,
  repeat until `RC_OK`), asserting field equality with the original. This is
  the regression that proves `RC_WMORE` resume works with the external arena.
- AddressSanitizer/UBSan runs of the above; both `-fno-ctx-members` and default
  modes under `make check`.

## Decisions log

- 2026-11-26: one codegen flag `-fno-ctx-members`; runtime `_ctx` entry points
  always compiled; plain entry points incompatible with the flag (contract).
- 2026-11-26: caller-owned typed `asn_struct_external_ctx_t *` parameter (not a
  `void **` out-param); inline frame capacity 8 with heap overflow.
- 2026-11-26: type-agnostic arena helpers; no `asn_TYPE_operation_s` change.
- 2026-11-26: converter-example/PDU helpers deferred until all decoders are
  onboarded.
- 2026-11-26: sentinel value `(unsigned)-1` for `ctx_offset`.
- 2026-11-26: Phases 1-4 landed as one change: `xer_decode_ctx`,
  `jer_decode_ctx`, `oer_decode_ctx`, `uper_decode_ctx`, `aper_decode_ctx`,
  `cbor_decode_ctx` all follow the `ber_decode_ctx` pattern (always stack-copy
  the codec context, set `ext_struct_ctx`, dispatch). `uper_decode` /
  `aper_decode` were split into a static `*_impl` taking the arena so the
  plain entry points keep their exact former behavior. Decoder headers
  declare the arena parameter as `struct asn_struct_external_ctx_s *` (the
  tag forward-declared in `asn_application.h`), because `uper_decoder.h` /
  `aper_decoder.h` are included from `asn_internal.h` before the typedef in
  `constr_TYPE.h` is visible. PER/CBOR plain entry points intentionally still
  decode `-fno-ctx-members` output (they never fetch ctx at decode time).

## References

- `skeletons/constr_TYPE.h`, `skeletons/ber_decoder.{c,h}`,
  `skeletons/asn_codecs.h`, `libasn1compiler/asn1c_C.c` — current mechanism.
- `docs/rust/runtime.md`, `docs/rust/code-generation.md`,
  `rust/asn1c-runtime/src/{lib.rs,ber.rs}` — the Rust-side model this mirrors.
- `docs/jer-streaming-design.md` — related streaming/resume design.
