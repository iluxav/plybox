#!/usr/bin/env python3
"""A minimal hosted agent, the kind plybox is built to run.

It reads a task from the command line, asks Claude, and writes the answer
to ANSWER.md in the workspace. Nothing here knows about plybox: it reads
ANTHROPIC_API_KEY from the environment and calls the API like any program.

What plybox adds around it, without the code changing:
  * the box reaches only api.anthropic.com — every other host is refused;
  * ANTHROPIC_API_KEY inside the box is a placeholder, not the real key;
    plybox's proxy swaps in the real value on the request to Anthropic and
    nowhere else, so a leaked environment or a poisoned dependency carries
    nothing usable out;
  * the answer lands in the workspace copy — `plybox diff` shows it,
    `plybox apply` accepts it, and until then the real directory is untouched;
  * memory and process limits bound the run.
"""
import os
import sys

import anthropic

MODEL = "claude-opus-5-5"


def make_client() -> anthropic.Anthropic:
    """The SDK's HTTP layer (httpx) trusts certifi's bundled roots, not the
    system's. Under plybox the proxy terminates TLS for the secret's host
    with a per-session CA and sets SSL_CERT_FILE to a bundle that includes
    it; point the SDK's client at that bundle so the injected key is
    accepted. Outside plybox the variable is unset and this is a no-op."""
    ca = os.environ.get("SSL_CERT_FILE")
    if ca and os.path.exists(ca):
        return anthropic.Anthropic(http_client=anthropic.DefaultHttpxClient(verify=ca))
    return anthropic.Anthropic()


def main() -> int:
    task = " ".join(sys.argv[1:]).strip()
    if not task:
        print("usage: agent.py <task>", file=sys.stderr)
        return 2

    client = make_client()  # reads ANTHROPIC_API_KEY from the environment
    try:
        response = client.messages.create(
            model=MODEL,
            max_tokens=4096,
            messages=[{"role": "user", "content": task}],
        )
    except anthropic.AuthenticationError:
        print("authentication failed: the API key the proxy injected was not accepted", file=sys.stderr)
        return 1
    except anthropic.APIConnectionError as e:
        print(f"could not reach the API: {e} (is api.anthropic.com in the policy's allow list?)", file=sys.stderr)
        return 1

    answer = "".join(b.text for b in response.content if b.type == "text")
    with open("ANSWER.md", "w") as f:
        f.write(f"# {task}\n\n{answer}\n")
    print(f"wrote ANSWER.md ({len(answer)} chars); stop reason: {response.stop_reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
