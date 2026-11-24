# Issue #3 (s2s fork): `expr_defined_recursively` started the enhanced check from the wrong expression

Reviewed on 2026-11-23 against this fork's branch
`fix/3-non-recursive-pointer-members` on top of `vlm_master` @ `db38375b`.
Public issue: [sleevetosleeve/asn1c#3](https://github.com/sleevetosleeve/asn1c/issues/3)
("asn1c emits pointer members for non-recursive type references").

Scope: this document records the root cause of the pointer-member
misclassification and the minimal fix. That fix alone does not guarantee
compilable output for schemas with header include cycles — see
[issue-3-s2s-pointer-members-include-cycles.md](issue-3-s2s-pointer-members-include-cycles.md)
for the follow-up.

Fix and post-mortem prepared with assistance from the Mistral Vibe agent (Mistral large 4).

## The change

`libasn1compiler/asn1c_C.c`, `expr_defined_recursively()` (~line 6802): the
"enhanced" circular-dependency check now runs on a copy of `arg` whose `expr`
is replaced with the expression under test:

```c
arg_t tmp = *arg;
tmp.expr = expr;
result = check_is_refer_to_enhanced(&tmp, &ctx);
```

Previously `check_is_refer_to_enhanced(arg, &ctx)` was called with the
caller's `arg` unchanged.

## Why the old code was wrong

`expr_defined_recursively(arg, expr)` is called from `expr_break_recursion()`
with `arg->expr` = the *containing* type and `expr` = the member reference
being classified. `check_is_refer_to_enhanced()` begins with
`terminal_structable(arg, arg->expr)`; with the unmodified `arg` that resolves
the **container's** terminal. For a top-level type that terminal is exactly
`ctx.target` (`topmost`), so the enhanced path returned 2 ("explicit circular
dependency") for *every* reference member of a top-level type, and
`expr_break_recursion()` marked each of them `EM_INDIRECT`. Generated C then
used pointers for all such members — asn1c aggressively turned references into
pointer ("reference") types. The fast path
(`asn1c_recurse(arg, terminal, check_is_refer_to, topmost)`) already started
from the referenced type's terminal; only the enhanced path started from the
wrong node. Setting `tmp.expr = expr` aligns the enhanced path with the fast
path (and with the `tmp_arg` pattern used in the member loop just above).

## Verified effect (fixed binary vs. pre-fix build, same input)

Input: the public reproducer from issue #3, `rec.asn1`, run with
`asn1c -fcompound-names -fwide-types`:

```asn1
RecTest DEFINITIONS AUTOMATIC TAGS ::= BEGIN
Node ::= SEQUENCE { value INTEGER, next Node }
Tree ::= SEQUENCE { root Node, label UTF8String }
END
```

| generated member | before fix | after fix |
|---|---|---|
| `Tree.root` (`Tree ::= SEQUENCE { root Node, ... }`; `Tree→Node` is not recursive) | `struct Node *root;` | `Node_t root;` |
| `Node.next` (genuine self-recursion) | `struct Node *next;` | `struct Node *next;` (unchanged — still correctly indirect) |

A private downstream consumer project (the motivation for this fork) observed
the same flip on its own schema: referenced members such as a `Vec3
position` went from `struct NetVec3 *position;` to `NetVec3_t position;`,
which let that project delete hand-written heap-allocation helpers and
pointer wiring for those members.

By-value members need complete types, so the fixed output `#include`s the
member type's header instead of forward-declaring `struct Node;`.

## Reproducing the comparison

```sh
# fixed binary (branch fix/3-non-recursive-pointer-members)
make -C libasn1compiler -j1 && make -C asn1c -j1
mkdir -p out-fixed
asn1c/asn1c -fcompound-names -fwide-types -D out-fixed rec.asn1
grep -A3 'typedef struct Tree' out-fixed/Tree.h    # Node_t root;

# pre-fix build:
#   git stash push -- libasn1compiler/asn1c_C.c
#   make -C libasn1compiler -j1 && make -C asn1c -j1
#   <regenerate into out-buggy>  ->  struct Node *root;
#   git stash pop && make -C libasn1compiler -j1 && make -C asn1c -j1   # restore
```

## See also

[issue-3-s2s-pointer-members-include-cycles.md](issue-3-s2s-pointer-members-include-cycles.md) —
the full story: this minimal fix exposed a latent header include-cycle bug
(F1AP regression), which required the complete fix (clone-tolerant comparison,
full dependency walk, conservative "tainted" fallback) described there.
