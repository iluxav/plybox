# Sessions: diff, apply, resume

Staged edits, `diff`, `apply` and resume require `--isolation ns` with an
overlay workspace. New runs default to gVisor with a read-only workspace:
their sessions keep an audit record, have no saved workspace copy, and are
listed as `no copy (gvisor)`. `discard` and `sessions --prune` can still
remove those records. `--workspace-mode bind` writes directly in either tier.

Every `plybox run` is a session: a directory under
`~/.local/state/plybox/sessions/<name>/` (or `--session DIR`) that holds

- `upper/`: the files the box created, changed or deleted (overlay mode);
- `record.jsonl`: the run's record, one JSON line per event;
- `meta.json`: the workspace, command, saved policy (never secret values),
  and status.

Names are two words (`lively-fern`). Commands accept the name, a unique prefix
of at least 3 characters, the session directory, or `--last`. When the name
is omitted, the most recent session is used.

## Reviewing and applying

```sh
plybox diff lively-fern            # A / M / D per file
plybox diff lively-fern --patch    # unified diff, line by line
plybox apply lively-fern           # copy the changes onto the workspace
plybox discard lively-fern         # or delete them
```

`apply` treats the session as untrusted, because the box wrote it:

- it carries deletions as well as edits and new files;
- it never writes through a symlink: a symlink in your folder that points
  elsewhere is replaced, not followed;
- if any change would land outside your folder, it refuses the whole apply
  and applies nothing.

`diff --patch` names symlinks instead of reading what they point to.

After `apply`, the session keeps only `meta.json` and `record.jsonl`. A
second `apply` is refused. `plybox sessions --prune` removes applied and
empty sessions; pending ones stay until you apply or discard them.

## Resuming

```sh
plybox --resume lively-fern                      # repeat the last command
plybox --resume lively-fern -- claude -p "continue"   # or run something else
plybox run --resume lively-fern -- …             # the same
```

A resumed run starts fresh processes on the session's saved copy. Earlier
edits and deletions are visible again, and new ones add to them.

- **The policy is saved**: image, network rules, mounts, environment and
  limits are reused, even from another directory. Flags given on resume
  override it; `--policy FILE` replaces it.
- **Secret values are never saved.** Secrets from your environment or from a
  file are read again; inline values must be given again. Ordinary `--env`
  values *are* saved, so use `--secret` for credentials.
- **Learn mode is never resumed** automatically; pass `--learn` again.
- The workspace, namespace isolation and overlay mode must stay the same.
  Applied sessions can't be resumed: start a new one on the updated folder.
- A session in use can't be resumed, applied or discarded by another command.

What it does not restore: processes, `$HOME`, `/tmp`, or an agent's own
conversation history. Your real folder stays the lower layer, so edits you
made there show through wherever the session didn't replace the file. A
changed Git `HEAD` gives a warning; uncommitted edits are not merged.

Saved metadata or policies without an isolation field retain their original
namespace meaning; changing the default does not migrate old sessions.
The oldest sessions have no saved policy. Supply it once, selecting `ns`
in the policy or with a flag:

```sh
plybox --resume rosy-heron --isolation ns --policy examples/claude.toml
```

## The record

`record.jsonl` gets one line per event, appended across resumed runs:

| `event` | When |
|---|---|
| `start` | the run begins: command, tier, image, allow list, secrets (names and hosts), limits, and `exposure`, which lists every host path the box can read, each secret's source and destination, and every `map` |
| `net` | a connection decision: host, port, `verdict` (`allowed`/`refused`/`learned`), reason, bytes, and `secrets_substituted` |
| `net_limit` | a traffic budget ran out |
| `net_usage` | total traffic at the end of the run |
| `learned` | learn mode wrote a policy |
| `exit` | the box's exit code and the number of workspace changes |
| `error` | plybox failed during the run |

For gVisor, `start.runsc` records the executable's `path`, `source`
(`configured`, `embedded`, or `PATH`) and `sha512`. Embedded launches also
include `release`, `payload_sha512` (the cache directory name), and
`verification_us` (time spent checking cached executables, excluding
extraction). Namespace launches record `runsc: null`.
