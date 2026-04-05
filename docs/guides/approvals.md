# Approvals and trust

pw-env keeps two different trust boundaries separate.

## The two approval types

| Approval | Controls | Default scope |
| --- | --- | --- |
| Project override approval | Whether `.pw-env.toml` may change the effective config | The exact file content hash |
| Secret-fetch approval | Whether a project `.env` may trigger backend lookups | The exact `.env` hash for the project |

## Project-local overrides

Place a `.pw-env.toml` file in a project when that repository needs different backend settings than the global config.

pw-env searches upward from the current directory until it reaches the repository root. If it finds `.pw-env.toml` on that walk, it only loads the file after the current content hash is approved.

Useful commands:

```console
$ pw-env approvals show .
$ pw-env approvals approve .
$ pw-env approvals revoke .
$ pw-env approvals list
```

If the file changes after approval, pw-env prompts again in interactive sessions. In noninteractive sessions the changed override is skipped instead of being loaded silently.

## Secret-fetch approvals

Before pw-env resolves empty values or explicit backend references from `.env`, it checks whether the project is approved to fetch secrets.

By default, approval is tied to the current `.env` hash. That keeps a reviewed `.env` file approved while still forcing a fresh approval when the file changes.

Useful commands:

```console
$ pw-env approvals show-fetch .
$ pw-env approvals approve-fetch .
$ pw-env approvals approve-fetch . --project-wide
$ pw-env approvals revoke-fetch .
$ pw-env approvals list-fetch
```

Use `--project-wide` only when you want future `.env` changes in the same project to skip the reapproval step.

## Suggested team workflow

1. Review `.pw-env.toml` like any other project config change.
2. Approve the local override with `pw-env approvals approve .`.
3. Approve secret fetching with `pw-env approvals approve-fetch .`.
4. Revisit the approval when `.env` or `.pw-env.toml` changes.

## Where approval state lives

Approval data is stored in the platform state directory used by pw-env, not inside the project repository. That keeps approval state local to each machine.