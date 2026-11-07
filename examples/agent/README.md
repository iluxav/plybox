# A hosted agent under plybox

A minimal Python agent (`agent.py`) that asks Claude to do a task and writes
the answer to `ANSWER.md`. The point is not the agent — it is how plybox runs
it: reaching only Anthropic, never holding the real API key, writing to a
copy you review before accepting, under memory and process limits.

## The production path: build once, run fresh

1. Build the image on a machine you trust, and push it to a registry:
   ```sh
   docker build -t ghcr.io/you/my-agent:1 .
   docker push   ghcr.io/you/my-agent:1
   ```
2. Point `agent.toml`'s `image =` at it.
3. On the host that runs agents — no Docker needed — pull once, then run each
   job in a fresh box:
   ```sh
   plybox pull ghcr.io/you/my-agent:1
   ANTHROPIC_API_KEY=sk-…  plybox run --policy agent.toml \
     -- python /opt/agent/agent.py "summarize what this project does"
   plybox diff --last        # the agent wrote ANSWER.md into the copy
   plybox apply --last       # accept it
   ```

Dependencies are frozen in the image, so no run installs anything and the
allow list stays at one host. Rebuild and bump the tag to change a dependency.

## Verify the mechanism today, without building an image

The agent needs its dependency, so it wants the baked image above. But the
one thing worth seeing first — that the key never enters the box yet still
reaches Anthropic — needs no dependency. This stdlib probe, on a stock
image, calls the API with whatever key you pass and expects a 401 for a
bad one (a real key would get a 200): either proves the box reached
Anthropic through the proxy with the key substituted in.

```sh
ANTHROPIC_API_KEY=sk-whatever  plybox run --quiet \
  --image python:3.13-slim --work . \
  --allow api.anthropic.com --secret ANTHROPIC_API_KEY@api.anthropic.com \
  -- python3 -c 'import os,urllib.request,json;
r=urllib.request.Request("https://api.anthropic.com/v1/messages",
  data=json.dumps({"model":"claude-opus-5-5","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}).encode(),
  headers={"x-api-key":os.environ["ANTHROPIC_API_KEY"],"anthropic-version":"2023-06-01","content-type":"application/json"});
import urllib.error
try: urllib.request.urlopen(r,timeout=15); print("200")
except urllib.error.HTTPError as e: print("reached Anthropic; HTTP",e.code)'
```

`plybox diff --last` afterwards shows the box wrote nothing to your
directory. The real agent (`agent.py`) uses the SDK and belongs in the
image; installing packages inside a running box is unreliable (the image's
`site-packages` is root-owned and the box runs unprivileged), which is the
reason deps are baked at build time.

> **One wiring detail, measured.** The SDK's HTTP layer trusts certifi's
> roots, not the system CA, so it would reject the proxy's per-session
> certificate and secret injection would fail. `agent.py` points the SDK at
> `SSL_CERT_FILE` (which plybox sets) to fix this. Plain `curl`, `git` and
> Node need nothing — they read the system CA already.

## What to watch

- **The key stays out of the box.** `agent.py` reads `ANTHROPIC_API_KEY` and
  passes it to the SDK, but inside the box that variable is a placeholder like
  `PLYBOX_SECRET_ANTHROPIC_API_KEY_…`. plybox's proxy swaps in the real value
  only on the connection to `api.anthropic.com`. The session record shows the
  substitution; the real key appears nowhere the box can read or write.
- **The box can reach nothing else.** Point the agent at another host and the
  proxy refuses it; the refusal is in the session record.
- **Nothing lands until you apply.** `ANSWER.md` is written into the session's
  copy of the workspace. `plybox diff --last` shows it; `plybox apply --last`
  copies it out.
