# Issue #15 (s2s) post-mortem: external decode context (`-fno-ctx-members`)

Post-mortem date: 2026-11-28. Scope: the full feature lifecycle for
[issue #15](https://github.com/sleevetosleeve/asn1c/issues/15) in this fork —
design PR #14, implementation PRs #17 (Phase 0), #18 (Phases 1-4), #21
(converter onboarding, docs, aliasing fix), #22 (allocator-macro amendment),
#26 (sentinel-only arena rule, stable heap frames).
The design rationale and decision log live in
[`external-ctx-design.md`](external-ctx-design.md); this document records what
actually happened, including the defects found late, and why.

## What shipped

`-fno-ctx-members` omits the embedded `asn_struct_ctx_t _asn_ctx` member from
generated structs (sentinel `ASN_CTX_OFFSET_EXTERNAL` in the type specifics)
and moves parser state into a caller-owned, type-agnostic arena
(`asn_struct_external_ctx_t`: 8 inline frames + heap overflow), passed to the
per-codec `*_decode_ctx()` entry points (`ber`/`xer`/`jer`/`oer`/`uper`/`aper`/
`cbor_decode_ctx` plus the `asn_decode_ctx` dispatcher). The generated
`converter-example` works unchanged in both codegen modes. Struct size win on
the 610 regression module: 104 → 32 bytes.

## Timeline and what went wrong

1. **Design (#14)** and **Phase 0 (#17)**: arena keyed by struct address alone.
   All local tests passed — the 610 module's nesting never places an inline
   member at offset 0 of its parent, so the address-only key never collided in
   the harnesses.
2. **Phases 1-4 (#18)**: per-codec entry points; same blind spot.
3. **#21 (converter-example onboarding)**: this is what caught the **frame
   aliasing bug**. A single-member SEQUENCE wrapper (`SEQUENCE { x [1]
   EXPLICIT ... }`) puts the child struct at the parent's base address, so
   parent and child frames collided and EXPLICIT-tag decoding failed under the
   arena. Surfaced by `check-BER-retag.sh` / `check-CER.sh` /
   `check-issue-617.sh` once the converter decoded through the arena.
   Fixed by keying frames on `(struct address, type specifics)`; regression
   locked by the `Wrap` type in the 610 module, `check-ext-ctx.c`, and
   `check-ext-ctx.sh`.
4. **Downstream integration** found the **allocator-macro escape** (comment on
   #15): the arena's heap-overflow array used raw `realloc`/`free` while all
   other feature memory used the overridable `CALLOC`/`MALLOC`/`REALLOC`/
   `FREEMEM` macros, so consumers patching those macros (e.g. to route
   allocations into a custom allocator) missed the overflow array. Fixed in
   #22 (`REALLOC`/`FREEMEM`), verified with a patched-`asn_internal.h`
   counting-allocator simulation (17 allocs routed, 17 freed, LSan-clean).
5. **#26 (manual CI run on `vlm_master`)**: the first manual `c-cpp.yml` run
   after the merges failed in `build-and-check` at the PKIX1 example
   (`sample-Certificate-1.der: Decode failed ...`), exposing two more arena
   defects that the small local harnesses never hit:
   - **"Arena wins whenever present" collided on ANY.** The ANY text/JER/XER
     adapters (`ANY.c` `ANY_text_prepare`) decode through stack-temporary
     view structs whose address and specifics are reused across sequential
     ANY values; arena frames keyed on them collided, so the certificate's
     second ANY decoded as already finished. Fixed by consulting the arena
     only for the `ASN_CTX_OFFSET_EXTERNAL` sentinel; a real `ctx_offset`
     always resolves to the embedded member.
   - **Realloc-moved frame array.** Heap-overflow frames lived in a
     realloc-grown array of frames, but decoders hold `asn_struct_ctx_t *`
     across nested decode calls; the PKIX1 certificate in ext mode needs 42
     frames, and growing the array left those pointers dangling
     (heap-use-after-free in `SET_OF_decode_ber`, ASan). Fixed by making the
     overflow an array of pointers to individually `CALLOC`'d frames;
     `check-ext-ctx` now asserts frame pointers survive array growth.

## Why existing tests did not catch these earlier

- The aliasing case requires an inline member at offset 0 *and* decoding
  through the arena. API-level tests used `NetMsg`, whose inline members sit
  at non-zero offsets, and nothing exercised the converter's decode path with
  wrapper-shaped types until #21 onboarded `converter-example.c` onto the
  `_ctx` entry points.
- The macro escape is invisible to functional tests: raw `realloc`/`free` are
  self-consistent. Only a consumer that redefines the macros can observe it.
- The PKIX1 example (a large real schema with ANY members and deep nesting,
  needing >8 arena frames) is only exercised by the `build-and-check` CI job's
  example step — the local suite never ran `examples/`, so the ANY stack-view
  collision and the frame-array UAF only surfaced in the manual CI run.

## Lessons / what would catch these earlier

- Onboard the reference consumer (`converter-example`) in the *first* phase,
  not last — it exercises the decode path end-to-end (chunked `RC_WMORE`
  resumes included) and caught the aliasing bug immediately.
- Add a wrapper-shaped type (inline member at offset 0) to the regression
  module from day one; it is the cheapest possible aliasing probe.
- Treat the allocator macros as a *contract*: grep feature diffs for raw
  `malloc`/`calloc`/`realloc`/`free` in skeletons, and add a build variant
  with redefined macros to CI.
- Run `examples/sample.source.PKIX1` `make check` locally (in both codegen
  modes) after any runtime/skeleton change — it is the only harness with a
  real-world schema big enough to overflow the arena and to hit ANY members.
- Arena design rule that fell out of #26: frames are addressed by value held
  across nested calls, so they must never move (individually allocated heap
  frames), and the arena must only key on addresses that are stable and
  unique per live parse state (real structs + type specifics — never stack
  temporaries).

## Validation at merge

Local suites on the final tree (after #26): `tests-skeletons` 71/71 (incl.
updated `check-ext-ctx` under ASan/LSan), `tests-asn1c-compiler` 19/19,
`tests-c-compiler` 94/94 (incl. check-610 in both modes), `tests-asn1c-smoke`
43/43 (incl. `check-ext-ctx.sh`), `libasn1fix` 5/5, f1ap/ioc-v2x/ieee1609-ioc
1/1 each, `tests-randomized` green; PKIX1 example `make check` passes in both
codegen modes (all formats, buffer sizes 1..8192, junk tests), and the
certificate decodes under ASan in `-fno-ctx-members` mode (42 frames) with a
clean free. Rust backend untouched (the flag is rejected as
rust-incompatible); its CI ran green on the PRs.

## Residual notes

- Plain (non-`_ctx`) entry points deliberately return `RC_FAIL` for resumable
  codecs on `-fno-ctx-members` code; this is documented in the README section
  and the man page.
- The arena is per-decode-operation and not thread-safe — same rule as the
  stack-allocated `asn_codec_ctx_t` requirement; documented in
  `external-ctx-design.md`.
