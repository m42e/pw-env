# Resolution model

pw-env classifies every `.env` entry before it decides whether the value should be exported as-is, resolved from a
backend, or ignored for migration.

## Entry types

| Entry form | Classification | Result |
| --- | --- | --- |
| `KEY=` | Empty | Resolve from the configured default backend |
| `KEY=op://vault/item/field` | 1Password reference | Always resolve through 1Password |
| `KEY=bw://folder/item/field` | Bitwarden reference | Always resolve through Bitwarden |
| `KEY=plaintext` | Plaintext | Leave as-is until migrated |

Quoted values are unwrapped for classification, but pw-env preserves the raw line when it rewrites `.env` during
migration.

## Resolution flow

1. Parse `.env` and classify each entry.
2. If at least one entry needs backend resolution, confirm that secret fetching is approved for the project.
3. Detect the project name from the nearest Git repository root. If no Git root is found, use the current directory
   name.
4. Send `op://...` references to 1Password.
5. Send `bw://...` references to Bitwarden.
6. Send empty values to the configured default backend.
7. Export only the keys that resolved successfully.

## Backend-specific behavior

### 1Password and Bitwarden

These backends resolve entries one key at a time. Explicit references bypass the default backend selection.

### GPG

The GPG backend decrypts the configured encrypted env file once, then pulls the requested empty keys out of the
decrypted content.

## Partial failures are nonfatal

If one key fails to resolve, pw-env warns and keeps going. Successfully resolved keys are still exported.

That makes `pw-env load .` the best inspection command when a project is only partially configured.

## Audit logging

When log file output is configured, successful credential fetches are written as `AUDIT credential_fetch ...` lines. The
log includes the project, working directory, `.env` path, backend, and key name, but never the secret value itself.
