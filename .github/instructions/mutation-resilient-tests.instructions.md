---
description: "Use when writing, updating, or reviewing Rust tests. Ensures tests are mutation-resilient so that cargo-mutants cannot produce surviving mutants. Covers unit tests, integration tests, assertions, and test design patterns."
applyTo: ["**/tests/**", "**/src/**"]
---
# Mutation-Resilient Test Guidelines

This project runs `cargo-mutants` for mutation testing. Every test you write
must be designed to **kill mutants**, not just achieve line coverage.

## Core Principles

1. **Assert exact values, not just Ok/Some.** A test that only checks
   `result.is_ok()` will not catch a mutant that replaces the function body
   with `Ok(Default::default())`.

   ```rust
   // BAD — survives "replace with Ok(String::new())"
   assert!(build_hook_output(&cfg).is_ok());

   // GOOD — kills the mutant
   let output = build_hook_output(&cfg)?;
   assert!(output.contains("export FOO="));
   ```

2. **Test both sides of every boolean condition.** If code branches on a `!`
   operator or a `&&`/`||` chain, write one test for the truthy path *and*
   one for the falsy path. A "delete `!`" mutant survives when only one
   branch has a test.

   ```rust
   // Code: if !entry.no_migrate { … }
   // Test the "should migrate" path AND the "skip" path
   #[test]
   fn includes_migratable_entry() { /* entry with no_migrate=false */ }
   #[test]
   fn excludes_no_migrate_entry() { /* entry with no_migrate=true */ }
   ```

3. **Test boundary values for relational operators.** Mutations swap `>` with
   `>=`, `==`, or `<`. Always test the boundary itself plus values on both
   sides.

   ```rust
   // Code: if items.len() > 1 { … }
   // Tests must cover len=0, len=1, len=2
   ```

4. **Assert on specific match arms.** A "delete match arm" mutant survives
   when no test routes through that arm. Ensure every match arm has a
   dedicated test case.

5. **Verify that mutations in arithmetic produce wrong results.** If code uses
   `+`, `-`, `*`, `/`, or `+=`, assert on the computed value so that operator
   swaps (`+` → `-`, `+=` → `*=`) are caught.

6. **Test error paths and early returns.** If a function can bail early,
   write a test that triggers the early return and asserts the expected
   error or empty result. This kills "replace function body with
   `Ok(())`" mutants on those paths.

7. **Avoid tautological assertions.** `assert!(true)` or
   `assert_ne!(result, result)` never kill mutants. Every assertion should
   fail if the code under test is altered.

## Structural Rules

- **Prefer `assert_eq!` / `assert_ne!` over `assert!`** — they produce
  better diagnostics and are more precise.
- **One logical assertion per test.** A test that asserts too many things
  at once makes it hard to tell which mutant it targets. It is fine for
  a test to have multiple `assert_eq!` calls that set up sequential
  invariants, but each test should exercise one code path.
- **Name tests after the behaviour they verify**, not the function name.
  `rejects_empty_input` is better than `test_parse`.

## Common Missed-Mutant Patterns in This Codebase

| Mutation | Why it survives | Fix |
|----------|-----------------|-----|
| `\|\| → &&` in condition chains | Only the happy path is tested | Add a test where *only the second* condition is true |
| `delete !` on a boolean | Only one branch is covered | Test the inverted branch explicitly |
| `replace fn → Ok(Default::default())` | Test only checks `is_ok()` | Assert on the returned value's content |
| `> → >=` or `> → ==` | Boundary value untested | Add a test at the exact boundary |
| `delete match arm` | No test exercises that arm | Add a case that routes through it |
| `+= → *=` in counters | Result count not asserted | Assert the expected count after the loop |
| `&& → \|\|` in multi-condition guards | Test inputs satisfy all conditions | Add a test where exactly one condition is false |
