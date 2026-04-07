# Migrating plaintext secrets

pw-env does not rewrite plaintext values automatically. Migration is an explicit, interactive step.

## Keep safe local values out of migration

Mark values that should remain plaintext with `no-migrate` either on the same line or on the comment line directly above
the entry.

```dotenv [.env]
LOG_LEVEL=debug # no-migrate

# no-migrate
LOCAL_ONLY_TOKEN=dev-token
```

## Run the migration

```console
pw-env migrate .
```

The migration flow:

1. Parses the `.env` file and finds plaintext values.
2. Highlights entries that look like secrets.
3. Opens an interactive multi-select prompt.
4. Stores the selected values in the effective backend.
5. Verifies each stored value before clearing it from `.env`.

Entries that look like secrets are selected by default in the prompt.

## Before and after

Before migration:

```dotenv [.env]
DATABASE_URL=postgres://user:pass@localhost:5432/app
API_KEY=super-secret-token
LOG_LEVEL=debug # no-migrate
```

After a successful migration:

```dotenv [.env]
DATABASE_URL=
API_KEY=
LOG_LEVEL=debug # no-migrate
```

Only values that were stored and verified are cleared. Skipped entries and failed writes stay in `.env`.

## Terminal requirements

`pw-env migrate` requires an interactive terminal. If stdin or stderr is not a terminal, the command exits instead of
attempting a partially interactive run.

## After migration

Run `pw-env load .` or your usual `pw-env export` command to confirm that the project now resolves the keys from the
backend.
