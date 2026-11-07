# Bake the agent and its dependencies into an image, once.
#
#   docker build -t ghcr.io/you/my-agent:1 examples/agent
#   docker push   ghcr.io/you/my-agent:1
#
# Then plybox pulls it straight from the registry — no Docker on the host
# that runs the agent — and runs each job in a fresh box from the frozen
# image (see agent.toml):
#
#   plybox pull ghcr.io/you/my-agent:1
#   ANTHROPIC_API_KEY=sk-… plybox run --policy examples/agent/agent.toml \
#     -- python /opt/agent/agent.py "summarize the README"
#
# Deps are frozen in the image, so no run installs anything or needs the
# package registry in its allow list. The build happens on a machine you
# trust; the host that runs agents only ever pulls.
FROM python:3.13-slim

COPY requirements.txt /opt/agent/requirements.txt
RUN pip install --no-cache-dir -r /opt/agent/requirements.txt

COPY agent.py /opt/agent/agent.py

# plybox ignores this (it runs the command you pass) — it documents intent
# and lets the image run under plain Docker too.
WORKDIR /work
ENTRYPOINT ["python", "/opt/agent/agent.py"]
