# PolyDecomp 0.5.0

PolyDecomp 0.5 adds a second native-analysis pass focused on turning recovered control flow into substantially more readable pseudocode while preserving the raw assembly and CFG data.

Highlights:

- Bounded symbolic propagation for common x86/x64 register values across basic blocks.
- Windows x64 and System V x86_64 ABI-aware generic argument recovery (`arg0`, `arg1`, ...).
- Stack-slot names such as `local_20`, `stack_30`, and `stack_arg_10` instead of raw `[rbp-...]` / `[rsp+...]` expressions where recoverable.
- `cmp` / `test` plus `jcc` reconstruction into conditions such as `arg0 == 0`, signed comparisons, and unsigned comparisons.
- Function prologue/epilogue and no-op suppression in readable C/Rust/Python output while assembly/JSON keep the underlying instructions.
- Natural fallthrough cleanup to remove redundant `goto` statements.
- Loop-header detection from CFG back-edges.
- Direct-call names recovered from known functions.
- PE import-table parsing and IAT-backed indirect-call resolution for common RIP-relative Windows x64 calls.
- RIP-relative references can be associated with recovered strings or symbols when the address is known.
- C-like, Rust-like, Python-like, ASM, and enriched JSON output remain available from the same built-in engine.
- v0.4's native function recovery remains the raw CFG backend, reducing regression risk.

The generated source-like output is intentionally labeled pseudocode. Compiler-lost variable names, exact source types, function signatures, and high-level source structure cannot always be reconstructed. ABI-derived arguments, return expressions, and some call arguments are heuristics and are exposed as such rather than presented as original source.
