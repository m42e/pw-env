# Migrating plaintext secrets

pw-env does not rewrite plaintext values automatically. Migration is an explicit, interactive step.

## Keep safe local values out of migration

Mark values that should remain plaintext with `pw-env:ignore` either on the same line or on the comment line directly
above the entry.

```dotenv [.env]
LOG_LEVEL=debug # pw-env:ignore

# pw-env:ignore
LOCAL_ONLY_TOKEN=dev-token
```

## Run the migration

```console
pw-env migrate .
```

To migrate into a different backend just for this run, pass `--backend op`, `--backend bw`, or `--backend gpg`.

The migration flow:

1. Parses the `.env` file and finds plaintext values.
2. Highlights entries that look like secrets.
3. Opens an interactive multi-select prompt.
4. Checks for existing 1Password values and offers to reuse one, create a new item, or skip. Other backends store the selected values directly.
5. Verifies each stored value before clearing it from `.env`.

Entries that look like secrets are selected by default in the prompt.

## Before and after

Before migration:

```dotenv [.env]
DATABASE_URL=postgres://user:pass@localhost:5432/app
API_KEY=super-secret-token
LOG_LEVEL=debug # pw-env:ignore
```

After a successful migration:

```dotenv [.env]
DATABASE_URL=
API_KEY=
LOG_LEVEL=debug # pw-env:ignore
```

Only values that were stored and verified are cleared. Skipped entries and failed writes stay in `.env`.

## Reusing existing 1Password values

Before storing a selected key, migration checks for existing items with that title (or the key's field on a configured
shared item). The prompt shows item titles, vaults, project metadata, and whether the stored value matches `.env`. You can reuse
an item, create a new item with the plaintext value, or skip migration for that key.

Reuse adds the current directory, repository, and project metadata while preserving existing project associations and
the stored secret. Reusing a different value requires confirmation that the plaintext value will be discarded. The
selected stored value is verified before `.env` is cleared. Failed lookups or updates keep the plaintext value.

When a shared item is configured, reuse is supported; creating a separate item requires changing that configuration
first so future lookups can find the separate item.

## Resolving duplicate 1Password items

When several items share a key's title, pw-env compares their `migrated_from` directory, repository, and project
metadata. If these still leave multiple matches, an interactive terminal offers an item chooser showing item titles, vaults, creation dates when available,
and existing metadata, without showing secret values.

Select an item and confirm to associate it with the current directory, repository, and project. This replaces those
metadata fields on the chosen item and preserves its other fields. Future loads use the saved metadata to resolve
the item. You can leave the ambiguity unresolved without changing any item. Noninteractive loads report the
conflicting item IDs instead of prompting. Migration keeps plaintext values unless the selected secret matches.

## Terminal requirements

`pw-env migrate` requires an interactive terminal. If stdin or stderr is not a terminal, the command exits instead of
attempting a partially interactive run.

## After migration

Run `pw-env load .` or your usual `pw-env export` command to confirm that the project now resolves the keys from the
backend.
