# plybox — build, install, test.
#
#   make install          build the static binary and copy it to $(BINDIR)
#   make uninstall        remove it (sessions and images are left alone)
#   make test             unit tests (seconds)
#   make test-sessions    session lifecycle and resume checks (no network, ~20 s)
#   make test-security    41 attacker probes + workloads against the binary,
#                         both tiers (network, ~2 min; gVisor tier needs `make tools`)
#   make test-image       the same inside an OCI image (network, ~2 min)
#   make test-all         all of the above
#   make tools            fetch gVisor's runsc for the gVisor-tier tests
#
# The shipped binary is static musl: it runs as the supervisor on the host
# and as `plybox __inner` inside any image, so it must not depend on a libc.

PREFIX ?= $(HOME)/.local
BINDIR ?= $(PREFIX)/bin
TARGET := x86_64-unknown-linux-musl
BIN    := target/$(TARGET)/release/plybox

.PHONY: build install uninstall test test-sessions test-security test-image test-all tools clean

build:
	@rustup target list --installed | grep -qx $(TARGET) || rustup target add $(TARGET)
	cargo build --release --target $(TARGET)

# A real copy, not a link: what you test is exactly what was just built,
# and later rebuilds do not change the installed binary behind your back.
install: build
	install -d $(BINDIR)
	rm -f $(BINDIR)/plybox
	install -m 755 $(BIN) $(BINDIR)/plybox
	@echo "installed $(BINDIR)/plybox — $$($(BINDIR)/plybox version)"
	@command -v plybox >/dev/null 2>&1 || echo "note: $(BINDIR) is not on your PATH"

uninstall:
	rm -f $(BINDIR)/plybox
	@echo "removed $(BINDIR)/plybox"
	@echo "kept: sessions in $${XDG_STATE_HOME:-$$HOME/.local/state}/plybox, images in $${XDG_DATA_HOME:-$$HOME/.local/share}/plybox"
	@echo "      (plybox sessions --prune before uninstalling clears applied/empty sessions)"

test:
	cargo test --release

test-sessions: build
	bash tests/sessions/run.sh $(abspath $(BIN))
	python3 tests/sessions/resume.py $(abspath $(BIN))

test-security: build
	bash tests/security/run.sh

test-image: build
	bash tests/image/run.sh

test-all: test test-sessions test-security test-image

tools:
	bash tests/tools/fetch.sh

clean:
	cargo clean
	rm -rf tests/probe/target tests/results
