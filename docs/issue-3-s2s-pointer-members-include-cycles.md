# Issue #3 (s2s fork): pointer members for non-recursive references — discovery, root cause, and the include-cycle follow-up

Reviewed on 2026-11-23 against this fork's branch
`fix/3-non-recursive-pointer-members` on top of `vlm_master` @ `db38375b`.
Public issue: [sleevetosleeve/asn1c#3](https://github.com/sleevetosleeve/asn1c/issues/3)
("asn1c emits pointer members for non-recursive type references").
Related earlier analysis:
[issue-3-s2s-expr-defined-recursively.md](issue-3-s2s-expr-defined-recursively.md)
(the minimal fix).

Fix and post-mortem prepared with assistance from the Mistral Vibe agent (Mistral large 4).

## 1. The bug

For a **non-recursive** type reference, e.g.

```asn1
Node ::= SEQUENCE { value INTEGER, next Node }
Tree ::= SEQUENCE { root Node, label UTF8String }
```

the C generator marked the member `EM_INDIRECT` and emitted a pointer:

```c
typedef struct Tree {
        struct Node     *root;      /* wrong: Tree→Node is not recursive */
        ...
```

while genuine self-recursion (`Node.next`) correctly stayed a pointer.
Verified before/after (same schema, `asn1c -fcompound-names -fwide-types`):

| member | before | after fix |
|---|---|---|
| `Tree.root` (non-recursive) | `struct Node *root;` | `Node_t root;` |
| `Node.next` (true recursion) | `struct Node *next;` | `struct Node *next;` (unchanged) |

Because *every* reference member of a top-level type became a pointer, a
private downstream consumer project had to heap-allocate each sub-struct and
wire the pointers by hand.

## 2. Root cause

`expr_defined_recursively()` (`libasn1compiler/asn1c_C.c`) decides `EM_INDIRECT`.
Its "enhanced" fallback called

```c
result = check_is_refer_to_enhanced(arg, &ctx);
```

with the caller's `arg` unchanged, so inside the check
`terminal_structable(arg, arg->expr)` resolved the **containing** type's
terminal. For a top-level type that terminal *is* `ctx.target` (`topmost`), so
the check returned 2 ("explicit circular dependency") for **every** reference
member → everything became a pointer. (History: the enhanced check was added in
upstream commit `48ad4e8d` for F1AP deep cycles; at that time this
always-true behavior was what made F1AP compile — see §3.)

The first fix made the enhanced check start from the expression under test:

```c
arg_t tmp = *arg;
tmp.expr = expr;
result = check_is_refer_to_enhanced(&tmp, &ctx);
```

## 3. Why that alone was not enough: the include-cycle follow-up

After the first fix, `tests/f1ap-regression` failed to compile:

```
CompositeAvailableCapacityGroup.h:27:9: error: unknown type name 'CompositeAvailableCapacity_t'
```

Analysis: `emit_include_dependencies()` places a member's type include at the
**top** of the header (`OT_INCLUDES`) when the member is by-value, but in
`POST_INCLUDE` (after the typedefs) when it is a pointer (`EM_UNRECURSE`).
Previously everything was a pointer → all includes were post-includes → header
cycles were harmless. With by-value members, a header cycle becomes fatal:
`CompositeAvailableCapacityGroup.h` top-includes `CompositeAvailableCapacity.h`,
whose include chain leads back to the group header before
`CompositeAvailableCapacity_t` is defined.

The cycle runs through **OPTIONAL** members and **parameterized/IOC** edges
(`ProtocolExtensionContainer {{…}}`, class-field refs like
`F1AP-PROTOCOL-EXTENSION.&Extension`), which the cycle walk could not follow —
the type-level graph does not contain those edges (they exist only at the
object-set/value level and in the IOC table), so "no cycle found" was not proof
of acyclicity.

## 4. The complete fix (all in `libasn1compiler/asn1c_C.c`)

1. Start the enhanced check from the referenced expr (`tmp.expr = expr`) — §2.
2. `same_type_node()`: compare resolved terminals by module+identifier, not just
   pointer — parameterized instantiation returns substituted *clones*.
3. The walk now follows **all** reference members (dropped the
   `EM_INDIRECT | EM_OPTIONAL` skip — pointer/optional members still create
   header-include edges), resolves parameterized instances via
   `asn1f_find_terminal_type_ex` fallback, follows IOC class-field refs via
   `asn1f_class_access_ex`, and follows `rhs_pspecs` actual parameters.
4. **Taint rule**: if the walk encounters a dependency edge it cannot fully
   follow (parameterized instance actuals, IOC `CLASS.&field` refs, unresolved
   references), set `ctx->tainted`; `expr_defined_recursively()` then treats the
   member as cyclic (`result = 2` → pointer). Conservative, but guarantees the
   generated headers compile; plain acyclic schemas still get by-value members.

## 5. Verification

All suites run with the fixed binary (`make -j1 check -k` from a clean tree,
2026-11-23):

| check | result |
|---|---|
| `rec.asn1` repro (issue #3) | `Node_t root;` by-value; `Node.next` stays a pointer |
| cycles via optional / parameterized / SEQUENCE-OF hops | pointers (correct) |
| `92-circular-loops-OK` generated code compiles (gcc) | yes; real cycles stay pointers |
| `tests/tests-asn1c-compiler` | 14/14 PASS (goldens regenerated via `./check-parsing.sh regenerate`; `check-issue-592.sh` updated to by-value expectations) |
| `tests/tests-c-compiler` | 92/92 PASS (11 `check-src` tests updated from `->`/calloc pointer style to by-value `.` style) |
| `tests/tests-asn1c-smoke` / `tests-randomized` / `tests-skeletons` | 42/42, 20/20, 70/70 PASS |
| `tests/f1ap-regression` (full F1AP codegen + compile) | PASS |
| `tests/ieee1609-ioc`, `tests/ioc-v2x` | PASS |
| `tests-rust-compiler` | SKIP (no Rust toolchain installed) |

## 6. Files changed by the fix

- `libasn1compiler/asn1c_C.c` — the fix (§4)
- `tests/tests-asn1c-compiler/check-issue-592.sh` — updated to expect by-value
  members (`Collection_5P0_t field_REAL;`, `Alias_t a;`, `.` instead of `->` in
  the test `use.c`)
- 31 `tests/tests-asn1c-compiler/*.asn1.+*` golden files — regenerated
  (`./check-parsing.sh regenerate`); diffs are pointer→by-value /
  `ATF_POINTER`→`ATF_NOFLAGS` / fwd-decl→`#include`, plus harmless
  trailing-whitespace churn
- 11 `tests/tests-c-compiler/check-src/check-*.c` — updated from pointer-member
  usage (`->`, `calloc`, `assert(x->m != 0)`) to by-value usage (`.`, direct
  assignment); in two tests the member assignment was also moved after the
  source value is filled in, since by-value assignment copies

Note: the `AGENTS.md` → `UPSTREAM_AGENTS.md` rename in this fork's working tree
is unrelated to this fix and is not part of its PR.

## 7. Lessons

- "Aggressive pointers" were masking a second bug: include placement. Fixing one
  exposed the other — running the heavy compile suites (f1ap, c-compiler) is what
  caught it.
- Cycle detection over a type graph is only sound if the graph contains every
  edge that produces a header include. When in doubt, be conservative (pointer).
- Golden-file test suites (`check-parsing.sh` with its `regenerate` mode) are the
  right harness for intentional codegen changes — but always eyeball the diff.
- By-value members change C semantics at the use site: assignment is a copy, not
  an alias, and access uses `.` instead of `->`.
