# Examples

| File | What it shows |
|---|---|
| [`claude.toml`](claude.toml) | Claude Code working on a Rust project with explicit namespace isolation for staged edits: its install dir and the Rust toolchain mounted in, `api.anthropic.com` and crates.io allowed, a subscription token the box never sees, memory and process limits. |
| [`agent/`](agent/) | A hosted Python agent: baked into an image, run with `--image` on a machine without Docker, reaching only Anthropic, with the API key held outside the box. |

Start one from your project folder:

```sh
plybox run --policy path/to/examples/claude.toml -- claude -p "…" --dangerously-skip-permissions
plybox diff --patch
plybox apply
```
